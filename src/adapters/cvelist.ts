/**
 * The CVE Program's cvelistV5 repository on GitHub: hourly releases whose delta zip carries every
 * CVE JSON 5.x record added or changed in the last hour. Free and keyless, so it is the coverage
 * backbone; NVD remains authoritative for enrichment (CVSS, CPE) and its fields are never
 * overwritten here. The first pull starts at the newest release and moves forward only — the
 * multi-hundred-megabyte "all CVEs" baseline is never loaded; older records arrive through NVD.
 */
import { HttpError } from "../http.ts";
import { loadWatchlist, upsertVuln, type NormalizedVuln, type VulnRow } from "../vulns.ts";
import { unzipAll } from "../zip.ts";
import type { Adapter, PullContext, PullOutcome } from "./types.ts";
import { isoDate } from "./types.ts";

/** The parts of a CVE JSON 5.x record BaselineWatch reads. */
export interface CveRecord {
  dataType?: string;
  cveMetadata: {
    cveId: string;
    state?: string;
    assignerShortName?: string;
    datePublished?: string;
    dateUpdated?: string;
    dateRejected?: string;
  };
  containers?: {
    cna?: {
      descriptions?: { lang?: string; value?: string }[];
      rejectedReasons?: { lang?: string; value?: string }[];
      metrics?: Record<string, unknown>[];
      problemTypes?: { descriptions?: { cweId?: string }[] }[];
      affected?: { vendor?: string; product?: string; cpes?: string[] }[];
      references?: { url?: string; tags?: string[] }[];
    };
  };
}

interface GithubAsset {
  name: string;
  browser_download_url: string;
}

export interface GithubRelease {
  tag_name: string;
  created_at: string;
  assets?: GithubAsset[];
}

const cvssPreference = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"] as const;

function cnaText(entries: { lang?: string; value?: string }[] | undefined): string | null {
  const text = entries?.find((d) => (d.lang ?? "").toLowerCase().startsWith("en"))?.value ?? entries?.[0]?.value ?? null;
  return text ? text.replace(/\s+/g, " ").trim() : null;
}

export function normalizeCvelist(record: CveRecord, observedAt: string): NormalizedVuln {
  const meta = record.cveMetadata;
  const cna = record.containers?.cna ?? {};
  const rejected = (meta.state ?? "").toUpperCase() === "REJECTED";

  let cvss: NormalizedVuln["cvss"] = null;
  outer: for (const key of cvssPreference) {
    for (const metric of cna.metrics ?? []) {
      const data = metric[key] as { version?: string; baseScore?: number; baseSeverity?: string; vectorString?: string } | undefined;
      if (typeof data?.baseScore !== "number") continue;
      cvss = {
        version: data.version ?? key.replace("cvssV", "").replace("_", "."),
        score: data.baseScore,
        severity: data.baseSeverity?.toUpperCase() ?? null,
        vector: data.vectorString ?? null,
        source: meta.assignerShortName ?? "cvelist-v5",
      };
      break outer;
    }
  }

  const cwes = [...new Set((cna.problemTypes ?? []).flatMap((p) => (p.descriptions ?? []).map((d) => d.cweId)).filter((c): c is string => typeof c === "string" && /^CWE-\d+$/.test(c)))];

  const cpes: string[] = [];
  const vendors = new Set<string>();
  const products = new Set<string>();
  for (const affected of cna.affected ?? []) {
    const vendor = affected.vendor?.trim().toLowerCase();
    const product = affected.product?.trim().toLowerCase();
    if (vendor && vendor !== "n/a") vendors.add(vendor);
    if (product && product !== "n/a") products.add(product);
    for (const cpe of affected.cpes ?? []) {
      if (cpe.startsWith("cpe:2.3:") && !cpes.includes(cpe) && cpes.length < 300) cpes.push(cpe);
    }
  }

  return {
    cveId: meta.cveId.toUpperCase(),
    sourceIdentifier: "cvelist-v5",
    publishedAt: isoDate(meta.datePublished),
    lastModifiedAt: isoDate(meta.dateUpdated) ?? isoDate(meta.datePublished) ?? observedAt,
    vulnStatus: rejected ? "Rejected" : "Published",
    description: rejected ? (cnaText(cna.rejectedReasons) ?? cnaText(cna.descriptions)) : cnaText(cna.descriptions),
    cvss,
    ssvc: null,
    cwes,
    cpes,
    vendors: [...vendors],
    products: [...products],
    references: (cna.references ?? [])
      .filter((r): r is { url: string; tags?: string[] } => typeof r.url === "string" && r.url !== "")
      .slice(0, 150)
      .map((r) => ({ url: r.url, tags: (r.tags ?? []).map((t) => t.toLowerCase()) })),
    kev: null,
  };
}

/** NVD statuses that mean "not analysed yet"; a row in one of these has no NVD data worth keeping. */
const reservedish = new Set(["received", "awaiting analysis", "undergoing analysis", "reserved"]);

function hasNvdData(row: VulnRow): boolean {
  return row.cvss_source !== null && !reservedish.has((row.vuln_status ?? "").toLowerCase());
}

/**
 * Stores a delta's records conservatively: a CVE BaselineWatch has never seen is inserted; a row
 * this adapter owns, or one NVD has not enriched yet, gets the CNA's description, status and
 * dates; a row with NVD data is left alone — NVD is authoritative when present. Never puts
 * anything on the Wire: the NVD path and `isNotable` decide notability, and a delta echoes
 * records the NVD pull will announce.
 */
export function storeCvelistRecords(ctx: Pick<PullContext, "db" | "now">, records: CveRecord[]): { inserted: number; updated: number; skipped: number } {
  const watch = loadWatchlist(ctx.db);
  const observedAt = ctx.now().toISOString();
  let inserted = 0;
  let updated = 0;
  let skipped = 0;
  const touch = ctx.db.prepare(
    "UPDATE vulns SET description = COALESCE(?, description), vuln_status = ?, published_at = COALESCE(published_at, ?), last_modified_at = ?, last_seen_at = ? WHERE cve_id = ?",
  );
  const change = ctx.db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, nvd_modified_at, field, before_text, after_text) VALUES (?, ?, ?, ?, ?, ?)");
  ctx.db.exec("BEGIN IMMEDIATE");
  try {
    for (const record of records) {
      if (record.dataType !== undefined && record.dataType !== "CVE_RECORD") continue;
      const n = normalizeCvelist(record, observedAt);
      const existing = ctx.db.prepare("SELECT * FROM vulns WHERE cve_id = ?").get(n.cveId) as unknown as VulnRow | undefined;
      if (!existing) {
        upsertVuln(ctx.db, n, observedAt, watch);
        inserted += 1;
      } else if (existing.source_identifier === "cvelist-v5") {
        if (upsertVuln(ctx.db, n, observedAt, watch).changes.length) updated += 1;
      } else if (!hasNvdData(existing)) {
        // An NVD row still awaiting analysis: lend it the CNA's words and dates, nothing more.
        const moved = (n.description !== null && n.description !== existing.description) || (existing.vuln_status ?? null) !== n.vulnStatus;
        if (n.description !== null && n.description !== existing.description) change.run(n.cveId, observedAt, n.lastModifiedAt, "description", existing.description, n.description);
        if ((existing.vuln_status ?? null) !== n.vulnStatus) change.run(n.cveId, observedAt, n.lastModifiedAt, "status", existing.vuln_status, n.vulnStatus);
        touch.run(n.description, n.vulnStatus, n.publishedAt, n.lastModifiedAt, observedAt, n.cveId);
        if (moved) updated += 1;
      } else {
        skipped += 1;
      }
    }
    ctx.db.exec("COMMIT");
  } catch (error) {
    ctx.db.exec("ROLLBACK");
    throw error;
  }
  return { inserted, updated, skipped };
}

const cursorKey = "cvelist.cursor";
const maxReleasesPerRun = 12;
const pauseMs = 500;
const deltaName = /_delta_CVEs_at_.*\.zip$/i;
const recordName = /(?:^|\/)CVE-\d{4}-\d{4,}\.json$/i;

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

/**
 * One unauthenticated releases-API call per run (60/hour is the GitHub limit; a rate-limit answer
 * skips the run rather than failing the source), then the delta zip of each release newer than
 * the cursor, oldest first, the cursor advancing after each so an interrupted run never repeats.
 */
export const cvelistAdapter: Adapter = {
  id: "cvelist",
  async pull(ctx): Promise<PullOutcome> {
    const repo = new URL(ctx.source.url).pathname.replace(/\/+$/, "");
    const api = `https://api.github.com/repos${repo}/releases?per_page=30`;
    let response;
    try {
      response = await ctx.http(api, { headers: { accept: "application/vnd.github+json" }, timeoutMs: 60_000 });
    } catch (error) {
      if (error instanceof HttpError && (error.status === 403 || error.status === 429)) {
        return { items: 0, inserted: 0, updated: 0, detail: "GitHub API rate limited; nothing pulled, retrying next run" };
      }
      throw error;
    }
    const releases = (JSON.parse(new TextDecoder("utf-8").decode(response.bytes)) as GithubRelease[]).filter((r) => r.tag_name && r.created_at).sort((a, b) => a.created_at.localeCompare(b.created_at));

    const cursor = readSetting(ctx, cursorKey);
    // No cursor means a first pull: start at the newest release and go forward; never the baseline.
    const fresh = cursor ? releases.filter((r) => r.created_at > cursor) : releases.slice(-1);
    const run = fresh.slice(0, maxReleasesPerRun);

    let items = 0;
    let inserted = 0;
    let updated = 0;
    let skipped = 0;
    let zips = 0;
    let lastTag: string | null = null;
    for (const release of run) {
      const delta = (release.assets ?? []).find((a) => deltaName.test(a.name));
      if (delta) {
        if (zips > 0) await sleep(pauseMs);
        const zip = await ctx.http(delta.browser_download_url, { timeoutMs: 180_000, maxBytes: 100 * 1024 * 1024 });
        zips += 1;
        const entries = unzipAll(zip.bytes).filter((e) => recordName.test(e.name));
        const records = entries.map((e) => JSON.parse(new TextDecoder("utf-8").decode(e.bytes)) as CveRecord);
        const counts = storeCvelistRecords(ctx, records);
        items += records.length;
        inserted += counts.inserted;
        updated += counts.updated;
        skipped += counts.skipped;
        ctx.log(`[cvelist] ${release.tag_name}: ${records.length} records (${counts.inserted} new, ${counts.updated} touched, ${counts.skipped} NVD-owned)`);
      }
      writeSetting(ctx, cursorKey, release.created_at);
      lastTag = release.tag_name;
    }

    const behind = fresh.length - run.length;
    const detail =
      run.length === 0
        ? `no release newer than ${cursor ?? "(first run)"}`
        : `${run.length} release(s) to ${lastTag}${cursor ? "" : " (first pull: newest only, baseline never loaded)"}; ${skipped} NVD-owned left alone${behind > 0 ? `; ${behind} more next run` : ""}`;
    return { items, inserted, updated, detail };
  },
};
