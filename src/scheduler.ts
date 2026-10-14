import type { DatabaseSync } from "node:sqlite";
import { adapterFor } from "./adapters/index.ts";
import type { SourceRow } from "./adapters/types.ts";
import { ingestSource, listSources, type IngestDeps, type IngestResult } from "./ingest.ts";

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
    if (source.schedule === "manual" || !adapterFor(source)) return false;
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

export interface Scheduler {
  /** Fetches every due source now; resolves when all have finished. A run already in progress is joined, not duplicated. */
  runOnce(): Promise<IngestResult[]>;
  stop(): void;
}

async function runLimited<T>(tasks: (() => Promise<T>)[], limit: number): Promise<T[]> {
  const results: T[] = [];
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, tasks.length) }, async () => {
    while (next < tasks.length) {
      const index = next;
      next += 1;
      results[index] = await tasks[index]!();
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
      const deps: IngestDeps = { now, log, ...(options.http ? { http: options.http } : {}), ...(options.settings ? { settings: options.settings } : {}) };
      const hostDelayMs = options.hostDelayMs ?? 3000;
      const perHost = groupByHost(due).map((group) => async () => {
        const results: IngestResult[] = [];
        for (const [index, source] of group.entries()) {
          if (index > 0) await sleep(hostDelayMs);
          results.push(await ingestSource(db, dataDir, source, deps));
        }
        return results;
      });
      const results = (await runLimited(perHost, options.concurrency ?? 3)).flat();
      for (const r of results) log(formatResult(r));
      return results;
    })().finally(() => {
      running = null;
    });
    return running;
  };

  const timer = setInterval(() => {
    void runOnce();
  }, options.tickMs ?? 60_000);
  timer.unref();

  return {
    runOnce,
    stop: () => clearInterval(timer),
  };
}
