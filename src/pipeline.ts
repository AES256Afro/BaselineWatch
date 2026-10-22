import type { DatabaseSync } from "node:sqlite";
import { productVersion, repositoryUrl } from "./version.ts";

/**
 * Whether the pipeline is actually running (M13.2).
 *
 * The lesson this is written from: NVD stalled for three days on an invalid key and nothing said
 * so until a person went looking. The digest has named a failing source since M13, but a digest
 * line is read once a day if it is read at all, and nothing watched how long a source had been
 * failing — the status column says a source is failing now, never since when, so a feed that 403s
 * for an hour looked exactly like a key that has been dead since Tuesday.
 *
 * Everything here is read from rows this instance already keeps. Nothing is fetched.
 */

export interface FailingSource {
  id: string;
  name: string;
  error: string | null;
  /** When this failure episode began, from sources.failing_since. */
  since: string | null;
  /** Whole hours it has been failing, or null when the episode's start was never recorded. */
  hours: number | null;
  /** Whether the one notification for this episode has been sent. */
  alerted: boolean;
}

export interface PipelineHealth {
  failing: FailingSource[];
  /** Sources enabled and fetchable; the denominator the tile counts against. */
  enabled: number;
  /** Hours since the newest CVE change this instance saw, null before the first one. */
  cveAgeHours: number | null;
  /** Article images: how many of the items that were looked at ended up with one. */
  images: { have: number; checked: number } | null;
  /** What this process is running. */
  version: string;
  /** The newest published release, as of the owner's last check; nothing polls for it. */
  release: LatestRelease;
  /** The worst thing true right now, which is what the tile colours itself by. */
  state: "ok" | "warn" | "bad";
}

/** A source failing longer than this is not a passing 403; it is something to tell a person about. */
export const alertAfterHours = 24;
/** The CVE pull running this far behind means the stream has stopped, not that it is quiet. */
export const staleCveHours = 36;

function hoursBetween(from: string | null, now: Date): number | null {
  if (!from) return null;
  const then = Date.parse(from);
  if (!Number.isFinite(then)) return null;
  return Math.max(0, Math.floor((now.getTime() - then) / 3_600_000));
}

/** Every enabled source failing right now, oldest episode first. */
export function failingSources(db: DatabaseSync, now: Date): FailingSource[] {
  const rows = db
    .prepare(
      `SELECT id, name, last_error AS error, failing_since AS since, failing_alerted_at AS alertedAt
         FROM sources
        WHERE enabled = 1 AND last_status = 'error'
        ORDER BY COALESCE(failing_since, last_fetch_at), name`,
    )
    .all() as { id: string; name: string; error: string | null; since: string | null; alertedAt: string | null }[];
  return rows.map((r) => ({ id: r.id, name: r.name, error: r.error, since: r.since, hours: hoursBetween(r.since, now), alerted: r.alertedAt !== null }));
}

export function pipelineHealth(db: DatabaseSync, now: Date): PipelineHealth {
  const failing = failingSources(db, now);
  const enabled = (db.prepare("SELECT COUNT(*) AS n FROM sources WHERE enabled = 1").get() as { n: number }).n;
  const newest = (db.prepare("SELECT MAX(observed_at) AS m FROM vuln_changes").get() as { m: string | null }).m;
  const cveAgeHours = hoursBetween(newest, now);
  const img = db
    .prepare("SELECT COUNT(*) AS checked, SUM(CASE WHEN image_blob IS NOT NULL THEN 1 ELSE 0 END) AS have FROM items WHERE image_checked_at IS NOT NULL OR image_blob IS NOT NULL")
    .get() as { checked: number; have: number | null };

  const stuck = failing.some((f) => (f.hours ?? 0) >= alertAfterHours);
  const stale = cveAgeHours !== null && cveAgeHours >= staleCveHours;
  const state: PipelineHealth["state"] = stuck || stale ? "bad" : failing.length > 0 ? "warn" : "ok";
  return {
    failing,
    enabled,
    cveAgeHours,
    images: img.checked > 0 ? { have: img.have ?? 0, checked: img.checked } : null,
    version: productVersion,
    release: knownRelease(db),
    state,
  };
}

/** The one line the tile shows under its figure: the worst thing true, in the fewest words. */
export function pipelineSummary(health: PipelineHealth): string {
  const stuck = health.failing.filter((f) => (f.hours ?? 0) >= alertAfterHours);
  if (stuck.length) {
    const worst = stuck[0];
    return `${worst?.name} has failed for ${worst?.hours} h`;
  }
  if (health.cveAgeHours !== null && health.cveAgeHours >= staleCveHours) {
    return `the CVE pull is ${Math.floor(health.cveAgeHours / 24)} day(s) behind`;
  }
  if (health.failing.length) return `${health.failing.map((f) => f.name).slice(0, 2).join(", ")} failing`;
  if (health.release.newer) return `every source answering · ${health.release.version} is published, this runs ${health.version}`;
  if (health.cveAgeHours !== null) return `CVEs ${health.cveAgeHours} h ago · every source answering`;
  return "every source answering";
}

/**
 * The sources that have been failing long enough to be worth a notification and have not had one
 * for this episode. Calling it does not send anything; `markAlerted` records that something did.
 */
export function sourcesToAlert(db: DatabaseSync, now: Date, afterHours = alertAfterHours): FailingSource[] {
  return failingSources(db, now).filter((f) => !f.alerted && (f.hours ?? 0) >= afterHours);
}

export function markAlerted(db: DatabaseSync, id: string, at: string): void {
  db.prepare("UPDATE sources SET failing_alerted_at = ? WHERE id = ?").run(at, id);
}

// ---------------------------------------------------------------------------------------------
// /metrics: the same facts in the one text format a dashboard can scrape, which section 4 of the
// plan promised and nothing has served until now. No new queries — the page, the digest and this
// all read the same rows, so they cannot disagree.

interface MetricsInput {
  health: PipelineHealth;
  now: Date;
  counts: { sources: number; items: number; vulns: number; changes: number; snapshots: number; exploits: number; msrcVulns: number; certificates: number; deviceReadings: number };
  bytes: { database: number; snapshots: number };
  images: number;
  housekeeping: { ranAt: string; snapshotsDeleted: number; blobsDeleted: number; networkScansDeleted: number; deviceReadingsDeleted: number; vacuumed: boolean } | null;
  uptimeSeconds: number;
}

/** A metric name's value, with the one-line help Prometheus's format wants above it. */
function metric(name: string, help: string, kind: "gauge" | "counter", lines: string[]): string {
  return [`# HELP ${name} ${help}`, `# TYPE ${name} ${kind}`, ...lines].join("\n");
}

const label = (value: string): string => value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, " ");

/** The text exposition format, which is plain enough to read by eye when nothing is scraping it. */
export function metricsText(input: MetricsInput): string {
  const { health, counts, bytes } = input;
  const blocks = [
    metric("baselinewatch_build_info", "The running version, as a label on a constant 1.", "gauge", [`baselinewatch_build_info{version="${label(health.version)}"} 1`]),
    metric("baselinewatch_uptime_seconds", "Seconds since this process started.", "gauge", [`baselinewatch_uptime_seconds ${input.uptimeSeconds}`]),
    metric("baselinewatch_sources", "Sources registered, enabled, and failing right now.", "gauge", [
      `baselinewatch_sources{state="registered"} ${counts.sources}`,
      `baselinewatch_sources{state="enabled"} ${health.enabled}`,
      `baselinewatch_sources{state="failing"} ${health.failing.length}`,
    ]),
    metric("baselinewatch_source_failing_seconds", "How long each failing source has been failing.", "gauge",
      health.failing.filter((f) => f.hours !== null).map((f) => `baselinewatch_source_failing_seconds{source="${label(f.id)}"} ${(f.hours ?? 0) * 3600}`)),
    metric("baselinewatch_rows", "Rows held, by what they are.", "gauge", [
      `baselinewatch_rows{table="items"} ${counts.items}`,
      `baselinewatch_rows{table="vulns"} ${counts.vulns}`,
      `baselinewatch_rows{table="changes"} ${counts.changes}`,
      `baselinewatch_rows{table="snapshots"} ${counts.snapshots}`,
      `baselinewatch_rows{table="exploits"} ${counts.exploits}`,
      `baselinewatch_rows{table="msrc_vulns"} ${counts.msrcVulns}`,
      `baselinewatch_rows{table="ct_certs"} ${counts.certificates}`,
      `baselinewatch_rows{table="device_readings"} ${counts.deviceReadings}`,
    ]),
    metric("baselinewatch_bytes", "Bytes on the volume, by what holds them.", "gauge", [
      `baselinewatch_bytes{store="database"} ${bytes.database}`,
      `baselinewatch_bytes{store="snapshots"} ${bytes.snapshots}`,
    ]),
    metric("baselinewatch_images", "Article images held in the blob store.", "gauge", [`baselinewatch_images ${input.images}`]),
  ];
  if (health.cveAgeHours !== null) {
    blocks.push(metric("baselinewatch_cve_age_seconds", "Age of the newest CVE change seen; it climbing is the pull being stuck.", "gauge", [`baselinewatch_cve_age_seconds ${health.cveAgeHours * 3600}`]));
  }
  if (input.housekeeping) {
    const h = input.housekeeping;
    const age = Math.max(0, Math.floor((input.now.getTime() - Date.parse(h.ranAt)) / 1000));
    blocks.push(
      metric("baselinewatch_housekeeping_age_seconds", "Seconds since the weekly pass last ran.", "gauge", [`baselinewatch_housekeeping_age_seconds ${age}`]),
      metric("baselinewatch_housekeeping_last", "What the last pass let go, and whether it rewrote the file.", "gauge", [
        `baselinewatch_housekeeping_last{freed="snapshots"} ${h.snapshotsDeleted}`,
        `baselinewatch_housekeeping_last{freed="blobs"} ${h.blobsDeleted}`,
        `baselinewatch_housekeeping_last{freed="network_scans"} ${h.networkScansDeleted}`,
        `baselinewatch_housekeeping_last{freed="device_readings"} ${h.deviceReadingsDeleted}`,
        `baselinewatch_housekeeping_last{freed="vacuumed"} ${h.vacuumed ? 1 : 0}`,
      ]),
    );
  }
  blocks.push(metric("baselinewatch_pipeline_state", "0 ok, 1 something failing, 2 stuck: the tile's own verdict.", "gauge",
    [`baselinewatch_pipeline_state ${health.state === "ok" ? 0 : health.state === "warn" ? 1 : 2}`]));
  return `${blocks.join("\n\n")}\n`;
}

// ---------------------------------------------------------------------------------------------
// Is a newer version published? The instance promises no outbound calls except to its declared
// sources and the configured notifier, and this product's own releases are neither. So nothing
// polls: the owner asks, on the Sources page, and the answer is kept until they ask again. A
// visitor sees what this instance runs and, if the owner has checked, what the newest release was
// when they did.

const latestKey = "release.latest";
const checkedKey = "release.checked_at";

export interface LatestRelease {
  /** The newest published version the owner's last check saw, without the leading v. */
  version: string | null;
  checkedAt: string | null;
  /** True when that version is ahead of the one running. */
  newer: boolean;
}

/** -1, 0 or 1 for two x.y.z strings; anything unparseable sorts as equal rather than as newer. */
export function compareVersions(a: string, b: string): number {
  const left = a.split(".").map(Number);
  const right = b.split(".").map(Number);
  if (left.length !== 3 || right.length !== 3 || [...left, ...right].some((n) => !Number.isFinite(n))) return 0;
  for (let i = 0; i < 3; i += 1) {
    if (left[i] !== right[i]) return (left[i] ?? 0) < (right[i] ?? 0) ? -1 : 1;
  }
  return 0;
}

function setting(db: DatabaseSync, key: string): string | null {
  return (db.prepare("SELECT value FROM app_settings WHERE key = ?").get(key) as { value: string } | undefined)?.value ?? null;
}

export function knownRelease(db: DatabaseSync): LatestRelease {
  const version = setting(db, latestKey);
  return { version, checkedAt: setting(db, checkedKey), newer: version !== null && compareVersions(version, productVersion) > 0 };
}

/**
 * Asks GitHub for this product's newest release, once, because the owner pressed the button.
 * A failure is recorded as a checked time with no version, so the page can say the check did not
 * get an answer rather than silently showing yesterday's.
 */
export async function checkLatestRelease(
  db: DatabaseSync,
  http: (url: string, options?: { headers?: Record<string, string> }) => Promise<{ bytes: Uint8Array }>,
  now: Date,
  repository = repositoryUrl,
): Promise<LatestRelease> {
  const api = `https://api.github.com/repos/${repository.replace(/^https?:\/\/github\.com\//, "").replace(/\/$/, "")}/releases/latest`;
  const at = now.toISOString();
  const write = db.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at");
  try {
    const response = await http(api, { headers: { accept: "application/vnd.github+json" } });
    const body = JSON.parse(new TextDecoder().decode(response.bytes)) as { tag_name?: string };
    const version = (body.tag_name ?? "").replace(/^v/, "");
    if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`no version in ${body.tag_name ?? "the answer"}`);
    write.run(latestKey, version, at);
    write.run(checkedKey, at, at);
  } catch {
    // The reason is not kept: it is a request to one known address, and a stale answer would be
    // worse than none. The page says when the check last ran and whether it brought a version.
    db.prepare("DELETE FROM app_settings WHERE key = ?").run(latestKey);
    write.run(checkedKey, at, at);
  }
  return knownRelease(db);
}
