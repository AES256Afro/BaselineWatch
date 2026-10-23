import { cpeMatchesOf, type NvdConfiguration } from "../cpematches.ts";
import { isNotable, loadWatchlist, recordVulnItem, upsertVuln, type NormalizedVuln } from "../vulns.ts";
import type { Adapter, AlertDraft, PullContext, PullOutcome } from "./types.ts";

/** The parts of an NVD API 2.0 CVE record BaselineWatch reads. */
export interface NvdCve {
  id: string;
  sourceIdentifier?: string;
  published?: string;
  lastModified: string;
  vulnStatus?: string;
  descriptions?: { lang: string; value: string }[];
  metrics?: Record<string, { source?: string; type?: string; cvssData?: { version?: string; vectorString?: string; baseScore?: number; baseSeverity?: string }; baseSeverity?: string; ssvcData?: { options?: Record<string, string>[] } }[]>;
  cisaExploitAdd?: string;
  cisaActionDue?: string;
  cisaRequiredAction?: string;
  cisaVulnerabilityName?: string;
  weaknesses?: { source?: string; description?: { lang: string; value: string }[] }[];
  configurations?: NvdConfiguration[];
  references?: { url: string; tags?: string[] }[];
}

export interface NvdResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  timestamp?: string;
  vulnerabilities?: { cve: NvdCve }[];
}

const metricPreference = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] as const;

/** NVD timestamps have no zone and are UTC; make them ISO 8601 with a Z. */
export function nvdDate(value: string | undefined): string | null {
  if (!value) return null;
  const withZone = /[zZ]$|[+-]\d{2}:\d{2}$/.test(value) ? value : `${value}Z`;
  const date = new Date(withZone);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

export function normalizeNvd(cve: NvdCve): NormalizedVuln {
  let cvss: NormalizedVuln["cvss"] = null;
  for (const key of metricPreference) {
    const list = cve.metrics?.[key];
    if (!list?.length) continue;
    const primary = list.find((m) => m.type === "Primary") ?? list[0]!;
    const data = primary.cvssData;
    if (typeof data?.baseScore !== "number") continue;
    cvss = {
      version: data.version ?? key.replace("cvssMetricV", "").replace(/(\d)(\d)/, "$1.$2"),
      score: data.baseScore,
      severity: (data.baseSeverity ?? primary.baseSeverity ?? null)?.toUpperCase() ?? null,
      vector: data.vectorString ?? null,
      source: primary.source ?? null,
    };
    break;
  }

  let ssvc: Record<string, string> | null = null;
  const ssvcList = cve.metrics?.ssvcV203;
  if (ssvcList?.length) {
    const options = ssvcList[0]?.ssvcData?.options ?? [];
    ssvc = Object.assign({}, ...options) as Record<string, string>;
  }

  const cwes = [...new Set((cve.weaknesses ?? []).flatMap((w) => (w.description ?? []).map((d) => d.value)).filter((v) => /^CWE-\d+$/.test(v)))];

  const cpes: string[] = [];
  const seenCpe = new Set<string>();
  for (const configuration of cve.configurations ?? []) {
    for (const node of configuration.nodes ?? []) {
      for (const match of node.cpeMatch ?? []) {
        if (match.vulnerable && match.criteria && !seenCpe.has(match.criteria)) {
          seenCpe.add(match.criteria);
          if (cpes.length < 300) cpes.push(match.criteria);
        }
      }
    }
  }
  const vendors = new Set<string>();
  const products = new Set<string>();
  for (const cpe of cpes) {
    const parts = cpe.split(":");
    if (parts[3]) vendors.add(parts[3].toLowerCase());
    if (parts[4]) products.add(parts[4].toLowerCase());
  }

  const description = cve.descriptions?.find((d) => d.lang === "en")?.value ?? cve.descriptions?.[0]?.value ?? null;

  return {
    cveId: cve.id.toUpperCase(),
    sourceIdentifier: cve.sourceIdentifier ?? null,
    publishedAt: nvdDate(cve.published),
    lastModifiedAt: nvdDate(cve.lastModified) ?? new Date().toISOString(),
    vulnStatus: cve.vulnStatus ?? null,
    description: description ? description.replace(/\s+/g, " ").trim() : null,
    cvss,
    ssvc,
    cwes,
    cpes,
    cpeMatches: cpeMatchesOf(cve.configurations ?? []),
    vendors: [...vendors],
    products: [...products],
    references: (cve.references ?? []).slice(0, 150).map((r) => ({ url: r.url, tags: r.tags ?? [] })),
    kev: cve.cisaExploitAdd
      ? { dateAdded: cve.cisaExploitAdd, dueDate: cve.cisaActionDue ?? null, requiredAction: cve.cisaRequiredAction ?? null, name: cve.cisaVulnerabilityName ?? null }
      : null,
  };
}

/** NVD wants `YYYY-MM-DDTHH:MM:SS.mmm` in UTC, without a zone suffix. */
export function nvdStamp(date: Date): string {
  return date.toISOString().replace("Z", "");
}

const pageSize = 2000;
const maxWindowMs = 120 * 24 * 60 * 60 * 1000;
const maxPagesPerRun = 40;
const cursorKey = "nvd.cursor";

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function readSetting(ctx: PullContext, key: string): string | null {
  return (ctx.db.prepare("SELECT value FROM app_settings WHERE key = ?").get(key) as { value: string } | undefined)?.value ?? null;
}

function writeSetting(ctx: PullContext, key: string, value: string): void {
  ctx.db.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").run(
    key,
    value,
    ctx.now().toISOString(),
  );
}

/** Stores a page of records, returning counts and the alerts worth raising. Exported so tests and the CLI can load fixtures without the network. */
export function storeNvdRecords(ctx: Pick<PullContext, "db" | "now">, records: { cve: NvdCve }[]): { inserted: number; updated: number; alerts: AlertDraft[] } {
  const watch = loadWatchlist(ctx.db);
  const observedAt = ctx.now().toISOString();
  let inserted = 0;
  let updated = 0;
  const alerts: AlertDraft[] = [];
  ctx.db.exec("BEGIN IMMEDIATE");
  try {
    for (const { cve } of records) {
      const result = upsertVuln(ctx.db, normalizeNvd(cve), observedAt, watch);
      if (result.isNew) inserted += 1;
      else if (result.changes.length) updated += 1;
      if ((result.isNew || result.changes.length) && isNotable(result.row, result.isNew, observedAt)) {
        recordVulnItem(ctx.db, result.row, result.changes, observedAt);
        if (result.row.watch_hit === 1) {
          const what = result.isNew ? "new" : result.changes.map((c) => (c.field === "cvss" ? `CVSS ${c.before ?? "unscored"} → ${c.after ?? "unscored"}` : c.field)).join(", ");
          alerts.push({
            kind: "watch",
            title:
              result.isNew && result.watchPlatforms.length && result.watchPlatforms.length === result.watchLabels.length
                ? `New ${result.watchPlatforms.join(", ")} CVE: ${result.row.cve_id}`
                : `${result.row.cve_id}: ${result.watchLabels.join(", ")}`,
            body: `${what}. ${result.row.cvss_score !== null ? `CVSS ${result.row.cvss_score.toFixed(1)}. ` : ""}${result.row.kev ? "In CISA KEV. " : ""}${(result.row.description ?? "").slice(0, 240)}`,
            url: `/vulnerabilities/${result.row.cve_id}`,
          });
        }
      }
    }
    ctx.db.exec("COMMIT");
  } catch (error) {
    ctx.db.exec("ROLLBACK");
    throw error;
  }
  return { inserted, updated, alerts };
}

/**
 * Pulls every CVE modified since the last pull (or the backfill window on first run), in
 * 120-day windows and 2,000-record pages, politely: 5 requests per 30 s without a key, 50 with.
 */
export const nvdAdapter: Adapter = {
  id: "nvd",
  /** Forgets the cursor, so the next pull starts the backfill window over and normalises every record in it afresh. */
  rewind(db) {
    db.prepare("DELETE FROM app_settings WHERE key = ?").run(cursorKey);
  },
  async pull(ctx): Promise<PullOutcome> {
    const now = ctx.now();
    const cursor = readSetting(ctx, cursorKey);
    const start = cursor ? new Date(new Date(cursor).getTime() - 60_000) : new Date(now.getTime() - ctx.settings.nvdBackfillDays * 24 * 60 * 60 * 1000);
    const headers: Record<string, string> = { accept: "application/json" };
    if (ctx.settings.nvdApiKey) headers.apiKey = ctx.settings.nvdApiKey;
    const pauseMs = ctx.settings.nvdApiKey ? 700 : 6500;

    let inserted = 0;
    let updated = 0;
    let items = 0;
    let pages = 0;
    const alerts: AlertDraft[] = [];
    let windowStart = start;
    let newestSeen = cursor ? new Date(cursor) : start;
    let complete = true;

    outer: while (windowStart < now) {
      const windowEnd = new Date(Math.min(windowStart.getTime() + maxWindowMs, now.getTime()));
      let startIndex = 0;
      for (;;) {
        if (pages >= maxPagesPerRun) {
          complete = false;
          break outer;
        }
        const url = `${ctx.source.url}?lastModStartDate=${nvdStamp(windowStart)}&lastModEndDate=${nvdStamp(windowEnd)}&resultsPerPage=${pageSize}&startIndex=${startIndex}`;
        if (pages > 0) await sleep(pauseMs);
        const response = await ctx.http(url, { headers, timeoutMs: 120_000, maxBytes: 200 * 1024 * 1024 });
        pages += 1;
        const body = JSON.parse(new TextDecoder("utf-8").decode(response.bytes)) as NvdResponse;
        const records = body.vulnerabilities ?? [];
        const counts = storeNvdRecords(ctx, records);
        inserted += counts.inserted;
        updated += counts.updated;
        items += records.length;
        if (cursor) alerts.push(...counts.alerts); // a first pull is a backfill, not news
        for (const { cve } of records) {
          const modified = nvdDate(cve.lastModified);
          if (modified && new Date(modified) > newestSeen) newestSeen = new Date(modified);
        }
        ctx.log(`[nvd] ${nvdStamp(windowStart).slice(0, 16)} → ${nvdStamp(windowEnd).slice(0, 16)}: ${startIndex + records.length}/${body.totalResults} (${counts.inserted} new, ${counts.updated} changed)`);
        startIndex += body.resultsPerPage || pageSize;
        if (startIndex >= body.totalResults || records.length === 0) break;
      }
      windowStart = windowEnd;
    }

    const newCursor = complete ? now : newestSeen;
    writeSetting(ctx, cursorKey, newCursor.toISOString());
    return {
      items,
      inserted,
      updated,
      detail: `${pages} page(s), cursor ${newCursor.toISOString().slice(0, 16)}${complete ? "" : " (more to pull next run)"}`,
      alerts,
    };
  },
};
