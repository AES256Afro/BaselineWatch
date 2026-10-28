import type { DatabaseSync } from "node:sqlite";
import { adapterFor, fetchable } from "./adapters/index.ts";
import type { SourceRow } from "./adapters/types.ts";
import { digestDue, writeDigest } from "./digest.ts";
import { formatBytes, type HousekeepingResult } from "./housekeeping.ts";
import { httpGet } from "./http.ts";
import { ingestSource, listSources, type IngestDeps, type IngestResult } from "./ingest.ts";
import { notify } from "./notify.ts";
import { alertAfterHours, markAlerted, sourcesToAlert } from "./pipeline.ts";

/**
 * The in-process scheduler: a tick a minute, the sources that are due fetched a few hosts at a time
 * with a pause between requests to one host, then the digest, the network scan, the failure alerts
 * and the weekly housekeeping pass, each only when it is due.
 */
const intervalMs: Record<SourceRow["schedule"], number> = {
  hourly: 60 * 60 * 1000,
  daily: 24 * 60 * 60 * 1000,
  weekly: 7 * 24 * 60 * 60 * 1000,
  manual: Number.POSITIVE_INFINITY,
};

/** A source that failed is retried after this long, whatever its schedule says. */
const retryAfterErrorMs = 30 * 60 * 1000;

/** Enabled sources with an adapter whose interval has elapsed (or that have never been fetched). */
export function dueSources(db: DatabaseSync, now: Date): SourceRow[] {
  return listSources(db, { enabledOnly: true }).filter((source) => {
    if (source.schedule === "manual" || !fetchable(adapterFor(source))) return false;
    if (!source.last_fetch_at) return true;
    const elapsed = now.getTime() - new Date(source.last_fetch_at).getTime();
    const wait = source.last_status === "error" ? Math.min(intervalMs[source.schedule], retryAfterErrorMs) : intervalMs[source.schedule];
    return elapsed >= wait;
  });
}

export interface SchedulerOptions extends IngestDeps {
  db: DatabaseSync;
  dataDir: string;
  /** How often to look for due sources. */
  tickMs?: number;
  /** Hosts fetched at the same time. Sources on one host always go one after another. */
  concurrency?: number;
  /** Pause between two requests to the same host; Reddit answers 429 to a burst. */
  hostDelayMs?: number;
  log?: (line: string) => void;
  /** When set, the digest is written and sent on its schedule from the same ticks. */
  digest?: { period: "daily" | "weekly" | "off"; hour: number; timeZone: string };
  /** When set, called every tick: the network scan (M12.3) runs itself when due. True when one ran. */
  network?: () => Promise<boolean>;
  /** When set, called every tick: the weekly housekeeping pass (M13) runs itself when due. The pass's own numbers when one ran. */
  housekeeping?: () => HousekeepingResult | null;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return url;
  }
}

/** Due sources grouped by host, so one host is never asked twice at once. */
export function groupByHost(sources: SourceRow[]): SourceRow[][] {
  const groups = new Map<string, SourceRow[]>();
  for (const source of sources) {
    const host = hostOf(source.url);
    const list = groups.get(host) ?? [];
    list.push(source);
    groups.set(host, list);
  }
  return [...groups.values()];
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** Hosts that want a longer pause than the default between requests in one sweep. Reddit's
 * unauthenticated limit is tight, and six subreddits plus article-image fetches share it. */
const hostDelayOverrides: Record<string, number> = { "www.reddit.com": 12_000 };

export interface Scheduler {
  /** Fetches every due source now; resolves when all have finished. A run already in progress is joined, not duplicated. */
  runOnce(): Promise<IngestResult[]>;
  /** Writes and sends the digest if it is due; true when one was written. */
  runDigest(): Promise<boolean>;
  /** Runs the network scan if one is due; true when one ran. */
  runNetwork(): Promise<boolean>;
  /** Runs the housekeeping pass if one is due; true when one ran. */
  runHousekeeping(): boolean;
  /** Notifies once for each source that has been failing longer than a day; how many were told. */
  alertFailingSources(): Promise<number>;
  stop(): void;
}

/** Runs the tasks a few at a time. A task that throws is handed to `onError` for its result, so one failure never ends the others' run. */
async function runLimited<T>(tasks: (() => Promise<T>)[], limit: number, onError: (index: number, error: unknown) => T): Promise<T[]> {
  const results: T[] = [];
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, tasks.length) }, async () => {
    while (next < tasks.length) {
      const index = next;
      next += 1;
      try {
        results[index] = await tasks[index]!();
      } catch (error) {
        results[index] = onError(index, error);
      }
    }
  });
  await Promise.all(workers);
  return results;
}

export function formatResult(r: IngestResult): string {
  const detail = r.status === "error" ? r.error : r.status === "skipped" ? r.error : (r.detail ?? `${r.items} items, +${r.inserted} new, ~${r.updated} changed`);
  return `[fetch] ${r.sourceId.padEnd(22)} ${r.status.padEnd(9)} ${String(r.durationMs).padStart(6)} ms  ${detail ?? ""}`;
}

export function startScheduler(options: SchedulerOptions): Scheduler {
  const { db, dataDir } = options;
  const log = options.log ?? ((line: string) => console.log(line));
  const now = options.now ?? (() => new Date());
  let running: Promise<IngestResult[]> | null = null;

  const runOnce = (): Promise<IngestResult[]> => {
    if (running) return running;
    running = (async () => {
      const due = dueSources(db, now());
      if (due.length === 0) return [];
      log(`[scheduler] ${due.length} source(s) due`);
      const deps: IngestDeps = {
        now,
        log,
        ...(options.http ? { http: options.http } : {}),
        ...(options.settings ? { settings: options.settings } : {}),
        ...(options.transport !== undefined ? { transport: options.transport } : {}),
        ...(options.baseUrl ? { baseUrl: options.baseUrl } : {}),
      };
      const perHost = groupByHost(due).map((group) => async () => {
        // An explicit hostDelayMs (tests) wins; otherwise a host override, then the default.
        const hostDelayMs = options.hostDelayMs ?? hostDelayOverrides[hostOf(group[0]!.url)] ?? 3000;
        const results: IngestResult[] = [];
        for (const [index, source] of group.entries()) {
          if (index > 0) await sleep(hostDelayMs);
          results.push(await ingestSource(db, dataDir, source, deps));
        }
        return results;
      });
      const results = (
        await runLimited(perHost, options.concurrency ?? 3, (index, error) => {
          log(`[scheduler] host batch ${index} failed: ${error instanceof Error ? error.message : String(error)}`);
          return [];
        })
      ).flat();
      for (const r of results) log(formatResult(r));
      return results;
    })().finally(() => {
      running = null;
    });
    return running;
  };

  const runDigest = async (): Promise<boolean> => {
    const d = options.digest;
    if (!d || d.period === "off" || !digestDue(db, { now: now(), timeZone: d.timeZone, period: d.period, hour: d.hour })) return false;
    const row = writeDigest(db, { now: now(), baseUrl: options.baseUrl ?? "", period: d.period });
    log(`[digest] wrote ${d.period} digest #${row.id} covering ${row.covers_from.slice(0, 16)} to ${row.covers_to.slice(0, 16)}`);
    await notify(db, options.transport ?? null, { kind: "digest", title: `BaselineWatch ${d.period} digest`, body: row.text.slice(0, 3500), url: options.baseUrl ? `${options.baseUrl}/digest` : null }, options.http ?? httpGet, now);
    return true;
  };

  const runNetwork = async (): Promise<boolean> => {
    if (!options.network) return false;
    const ran = await options.network();
    if (ran) log("[netscan] daily network scan ran");
    return ran;
  };

  /**
   * One notification per failure episode, once a source has been failing for a day (M13.2). A
   * feed that 403s for an hour recovers by itself and is not news; a key that died on Tuesday is.
   * recordOutcome clears the marks the moment a source answers, so the next episode speaks again.
   */
  const alertFailingSources = async (): Promise<number> => {
    const stuck = sourcesToAlert(db, now());
    for (const source of stuck) {
      const at = now().toISOString();
      await notify(
        db,
        options.transport ?? null,
        {
          kind: "source",
          title: `${source.name} has been failing for ${source.hours} h`,
          body: `${source.error ?? "no error recorded"}\n\nNothing from this source has reached the timeline since ${source.since?.slice(0, 16).replace("T", " ") ?? "its last success"}. The Sources page says what to do about this failure.`,
          url: options.baseUrl ? `${options.baseUrl}/sources#src-${source.id}` : null,
        },
        options.http ?? httpGet,
        now,
      );
      markAlerted(db, source.id, at);
      log(`[scheduler] ${source.id} has failed for ${source.hours} h (over ${alertAfterHours}); notified once for this episode`);
    }
    return stuck.length;
  };

  const runHousekeeping = (): boolean => {
    if (!options.housekeeping) return false;
    const result = options.housekeeping();
    if (!result) return false;
    log(`[housekeeping] weekly pass: database ${formatBytes(result.bytesAfter)} after letting ${result.snapshotsDeleted} snapshot(s) and ${result.blobsDeleted} blob(s) go`);
    return true;
  };

  // One tick at a time. `runOnce` hands every tick the sweep in progress, so without this a long
  // sweep let a chain queue per minute behind it, and when it ended they all passed the network
  // scan's and the alert's due checks together — the same LAN scan and notification run many times.
  let ticking = false;
  const timer = setInterval(() => {
    if (ticking) return;
    ticking = true;
    // A full disk or a busy database throws from the sqlite calls; logged, never an unhandled rejection that ends the process.
    void runOnce()
      .then(() => runDigest())
      .then(() => runNetwork())
      .then(() => alertFailingSources())
      // Last on the tick: the pass takes the write lock for a moment, so it waits for the fetches.
      .then(() => runHousekeeping())
      .catch((error: unknown) => log(`[scheduler] tick failed: ${error instanceof Error ? error.message : String(error)}`))
      .finally(() => {
        ticking = false;
      });
  }, options.tickMs ?? 60_000);
  timer.unref();

  return {
    runOnce,
    runDigest,
    runNetwork,
    runHousekeeping,
    alertFailingSources,
    stop: () => clearInterval(timer),
  };
}
