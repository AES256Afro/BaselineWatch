import { existsSync, readdirSync, rmSync, statSync } from "node:fs";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { databaseBytes } from "./db.ts";

/**
 * What this instance keeps, what it lets go, and the weekly pass that does it (M13).
 *
 * One rule decides every number here: a standards snapshot is the product. The Register's
 * "before" a year from now is the exact bytes DISA or NIST served, so a snapshot whose source is
 * a requirement-set or setting-set is kept for good, and so is any snapshot a `documents` row
 * points at, whatever its source. A news or vulnerability feed's bytes are the van, not the
 * cargo: the items were normalised out of them on arrival, so once the newest fetch of each
 * document is kept — enough to re-parse and to diff against — the older ones are weight.
 *
 * Nothing here deletes a timeline item, a CVE, a requirement, a change or an explanation. Those
 * are the record; only the raw deliveries, the scan runs, the device readings and the alert log
 * are trimmed. The night of 2026-10-21 added seven tables, and each has its rule: Microsoft's
 * Security Update Guide rows, the exploit indexes, the certificates seen for the owner's domains
 * and the saved searches are kept; the Tor exit list and endoflife.date's cycles are swapped
 * whole on each read, so they never grow; a device's readings are history, kept a year, except
 * that each device's newest stays for good so the next reading can say what moved.
 */

/** Source kinds whose snapshots are the Register's evidence and are never swept. */
const keptKinds = new Set(["requirement-set", "setting-set"]);

export interface Retention {
  /** Snapshots of a feed, listing or vulnerability stream older than this go, except each document's newest. */
  feedSnapshotDays: number;
  /** Network scan runs older than this go, with their canary rows. */
  networkScanDays: number;
  /** A device's readings older than this go, except its newest, which the next reading diffs against. */
  deviceReadingDays: number;
  /** The alert log says what was sent, not what is true; it is trimmed. */
  alertDays: number;
  /** A blob nothing references is left alone until it is this old: a fetch may be mid-flight. */
  blobGraceHours: number;
  /** Rewrite the file when the free list is at least this share of it, and at least this many pages. */
  vacuumFreeShare: number;
  vacuumMinFreePages: number;
  /** Days between passes. */
  everyDays: number;
}

/**
 * Two weeks of raw feed bytes is enough to re-parse a bad release and to answer "what did they
 * serve on Tuesday"; six months of scan runs is enough for M14's history to show a trend. Both
 * are generous on purpose: this is a one-container product and disk is cheaper than a lost diff.
 */
export const defaultRetention: Retention = {
  feedSnapshotDays: 14,
  networkScanDays: 180,
  deviceReadingDays: 365,
  alertDays: 180,
  blobGraceHours: 24,
  vacuumFreeShare: 0.1,
  vacuumMinFreePages: 2_000,
  everyDays: 7,
};

export interface HousekeepingResult {
  ranAt: string;
  snapshotsDeleted: number;
  blobsDeleted: number;
  blobBytesFreed: number;
  networkScansDeleted: number;
  /** Absent in results recorded before 0.48.0; read it as 0. */
  deviceReadingsDeleted?: number;
  alertsDeleted: number;
  vacuumed: boolean;
  bytesBefore: number;
  bytesAfter: number;
  durationMs: number;
}

export interface StorageReport {
  /** The database file as SQLite sees it. */
  databaseBytes: number;
  /** Rows and bytes of the snapshots the index knows about. */
  snapshots: number;
  snapshotBytes: number;
  /** Snapshots kept for good because they are a standard's evidence. */
  keptSnapshots: number;
  /** Article and branding images in the blob store. */
  imageBlobs: number;
  /** When the oldest snapshot still held was fetched. */
  oldestSnapshotAt: string | null;
  /** The last housekeeping pass, as it recorded itself. */
  lastRun: HousekeepingResult | null;
}

const lastRunKey = "housekeeping.last_run";
const lastResultKey = "housekeeping.last_result";

function setSetting(db: DatabaseSync, key: string, value: string, at: string): void {
  db.prepare(
    "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
  ).run(key, value, at);
}

function getSetting(db: DatabaseSync, key: string): string | null {
  return (db.prepare("SELECT value FROM app_settings WHERE key = ?").get(key) as { value: string } | undefined)?.value ?? null;
}

/** "138 MB", "4.2 GB": the number a person reads, never a byte count on a page. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["kB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

/** The last pass, as it recorded itself; null before the first one. */
export function lastHousekeeping(db: DatabaseSync): HousekeepingResult | null {
  const raw = getSetting(db, lastResultKey);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as HousekeepingResult;
  } catch {
    return null;
  }
}

/** Due when no pass has run, or when the last one is `everyDays` old. */
export function housekeepingDue(db: DatabaseSync, now: Date, retention: Retention = defaultRetention): boolean {
  const last = getSetting(db, lastRunKey);
  if (!last) return true;
  const elapsed = now.getTime() - Date.parse(last);
  return !Number.isFinite(elapsed) || elapsed >= retention.everyDays * 86_400_000;
}

/** What the instance is holding, cheaply: SQL and the last pass's own numbers, never a walk of the store. */
export function storageReport(db: DatabaseSync): StorageReport {
  const snapshots = db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(bytes), 0) AS bytes, MIN(fetched_at) AS oldest FROM snapshots").get() as {
    n: number;
    bytes: number;
    oldest: string | null;
  };
  const kept = db
    .prepare(
      `SELECT COUNT(*) AS n FROM snapshots s JOIN sources src ON src.id = s.source_id
       WHERE src.kind IN ('requirement-set', 'setting-set') OR EXISTS (SELECT 1 FROM documents d WHERE d.snapshot_id = s.id)`,
    )
    .get() as { n: number };
  const images = db.prepare("SELECT COUNT(DISTINCT image_blob) AS n FROM items WHERE image_blob IS NOT NULL").get() as { n: number };
  return {
    databaseBytes: databaseBytes(db),
    snapshots: snapshots.n,
    snapshotBytes: snapshots.bytes,
    keptSnapshots: kept.n,
    imageBlobs: images.n,
    oldestSnapshotAt: snapshots.oldest,
    lastRun: lastHousekeeping(db),
  };
}

/**
 * Deletes the raw deliveries past their keep window: snapshots of article, vulnerability and
 * listing sources, except each document key's newest and anything a `documents` row points at.
 * The blobs they used go with the next sweep, which is the only thing that touches the store.
 */
export function sweepSnapshots(db: DatabaseSync, now: Date, retention: Retention = defaultRetention): number {
  const before = new Date(now.getTime() - retention.feedSnapshotDays * 86_400_000).toISOString();
  const rows = db
    .prepare(
      `SELECT s.id FROM snapshots s
         JOIN sources src ON src.id = s.source_id
        WHERE src.kind NOT IN (${[...keptKinds].map(() => "?").join(", ")})
          AND s.fetched_at < ?
          AND NOT EXISTS (SELECT 1 FROM documents d WHERE d.snapshot_id = s.id)
          AND s.id <> (SELECT n.id FROM snapshots n WHERE n.source_id = s.source_id AND n.document_key = s.document_key ORDER BY n.fetched_at DESC, n.id DESC LIMIT 1)`,
    )
    .all(...keptKinds, before) as { id: number }[];
  if (rows.length === 0) return 0;
  const remove = db.prepare("DELETE FROM snapshots WHERE id = ?");
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const row of rows) remove.run(row.id);
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
  return rows.length;
}

/**
 * Scan runs, device readings and the alert log past their windows. All three are history, not
 * evidence. A device keeps its newest reading whatever its age: it is what the next reading is
 * compared with, and the device list would otherwise lose a machine that has not been read in a year.
 */
export function sweepRuns(
  db: DatabaseSync,
  now: Date,
  retention: Retention = defaultRetention,
): { networkScans: number; deviceReadings: number; alerts: number } {
  const scanBefore = new Date(now.getTime() - retention.networkScanDays * 86_400_000).toISOString();
  const readingBefore = new Date(now.getTime() - retention.deviceReadingDays * 86_400_000).toISOString();
  const alertBefore = new Date(now.getTime() - retention.alertDays * 86_400_000).toISOString();
  // The canary rows go with their scan: net_canaries references net_scans ON DELETE CASCADE.
  const scans = db.prepare("DELETE FROM net_scans WHERE started_at < ?").run(scanBefore);
  const readings = db
    .prepare(
      `DELETE FROM device_readings WHERE read_at < ?
         AND id <> (SELECT n.id FROM device_readings n WHERE n.device = device_readings.device ORDER BY n.read_at DESC, n.id DESC LIMIT 1)`,
    )
    .run(readingBefore);
  const alerts = db.prepare("DELETE FROM alerts WHERE sent_at < ?").run(alertBefore);
  return { networkScans: Number(scans.changes), deviceReadings: Number(readings.changes), alerts: Number(alerts.changes) };
}

/** Every blob hash something still points at: a snapshot, an article image, or the owner's branding. */
export function referencedBlobs(db: DatabaseSync): Set<string> {
  const refs = new Set<string>();
  for (const row of db.prepare("SELECT sha256 FROM snapshots").all() as { sha256: string }[]) refs.add(row.sha256);
  for (const row of db.prepare("SELECT DISTINCT image_blob FROM items WHERE image_blob IS NOT NULL").all() as { image_blob: string }[]) {
    refs.add(row.image_blob);
  }
  for (const row of db.prepare("SELECT value FROM app_settings WHERE key LIKE 'branding.%'").all() as { value: string }[]) {
    if (/^[0-9a-f]{64}$/.test(row.value)) refs.add(row.value);
  }
  return refs;
}

/**
 * Deletes blob files nothing references any more. A file younger than the grace window is left
 * alone, because a fetch in flight has written its bytes before the row that points at them.
 */
export function sweepBlobs(
  db: DatabaseSync,
  dataDir: string,
  now: Date,
  retention: Retention = defaultRetention,
): { deleted: number; bytesFreed: number } {
  const root = path.join(dataDir, "blobs");
  if (!existsSync(root)) return { deleted: 0, bytesFreed: 0 };
  const refs = referencedBlobs(db);
  // A bug that lost the references would empty the store; a populated index with no references is not a state this can be in.
  if (refs.size === 0 && (db.prepare("SELECT COUNT(*) AS n FROM snapshots").get() as { n: number }).n > 0) {
    throw new Error("refusing to sweep blobs: the index holds snapshots but no references were read");
  }
  const cutoff = now.getTime() - retention.blobGraceHours * 3_600_000;
  let deleted = 0;
  let bytesFreed = 0;
  for (const shard of readdirSync(root, { withFileTypes: true })) {
    if (!shard.isDirectory() || !/^[0-9a-f]{2}$/.test(shard.name)) continue;
    const shardPath = path.join(root, shard.name);
    for (const entry of readdirSync(shardPath, { withFileTypes: true })) {
      if (!entry.isFile() || !/^[0-9a-f]{64}$/.test(entry.name)) continue;
      if (refs.has(entry.name)) continue;
      const file = path.join(shardPath, entry.name);
      const stat = statSync(file);
      if (stat.mtimeMs > cutoff) continue;
      rmSync(file);
      deleted += 1;
      bytesFreed += stat.size;
    }
  }
  return { deleted, bytesFreed };
}

/** Statistics and the FTS indexes, so the planner and the search stay fast as the tables grow. */
function optimize(db: DatabaseSync): void {
  db.exec("ANALYZE");
  db.exec("PRAGMA optimize");
  db.exec("INSERT INTO items_fts (items_fts) VALUES ('optimize')");
  db.exec("INSERT INTO vulns_fts (vulns_fts) VALUES ('optimize')");
}

/**
 * Rewrites the file when enough of it is free pages. `VACUUM` rather than `VACUUM INTO`: the
 * second writes a clean copy beside the original, which only this process could then adopt by
 * restarting, and a weekly pause of a second or two on a one-container product is the cheaper
 * trade. Writes wait for it; nothing is lost if it never runs.
 */
export function maybeVacuum(db: DatabaseSync, retention: Retention = defaultRetention): boolean {
  const row = db.prepare("SELECT freelist_count AS free, page_count AS pages FROM pragma_freelist_count(), pragma_page_count()").get() as {
    free: number;
    pages: number;
  };
  if (row.pages === 0) return false;
  if (row.free < retention.vacuumMinFreePages || row.free / row.pages < retention.vacuumFreeShare) return false;
  db.exec("VACUUM");
  return true;
}

export interface HousekeepingOptions {
  now?: () => Date;
  retention?: Retention;
  log?: (line: string) => void;
}

/** One pass: sweep what is past its window, free the blobs that fell out of use, optimize, and rewrite the file if it has gone loose. */
export function runHousekeeping(db: DatabaseSync, dataDir: string, options: HousekeepingOptions = {}): HousekeepingResult {
  const now = (options.now ?? (() => new Date()))();
  const retention = options.retention ?? defaultRetention;
  const log = options.log ?? (() => {});
  const started = Date.now();
  const bytesBefore = databaseBytes(db);
  const snapshotsDeleted = sweepSnapshots(db, now, retention);
  const runs = sweepRuns(db, now, retention);
  const blobs = sweepBlobs(db, dataDir, now, retention);
  optimize(db);
  const vacuumed = maybeVacuum(db, retention);
  const result: HousekeepingResult = {
    ranAt: now.toISOString(),
    snapshotsDeleted,
    blobsDeleted: blobs.deleted,
    blobBytesFreed: blobs.bytesFreed,
    networkScansDeleted: runs.networkScans,
    deviceReadingsDeleted: runs.deviceReadings,
    alertsDeleted: runs.alerts,
    vacuumed,
    bytesBefore,
    bytesAfter: databaseBytes(db),
    durationMs: Date.now() - started,
  };
  setSetting(db, lastRunKey, result.ranAt, result.ranAt);
  setSetting(db, lastResultKey, JSON.stringify(result), result.ranAt);
  log(
    `[housekeeping] ${result.snapshotsDeleted} snapshot(s), ${result.blobsDeleted} blob(s) (${formatBytes(result.blobBytesFreed)}), ` +
      `${result.networkScansDeleted} scan(s), ${result.deviceReadingsDeleted} reading(s), ${result.alertsDeleted} alert(s); database ${formatBytes(result.bytesBefore)} → ${formatBytes(result.bytesAfter)}` +
      `${result.vacuumed ? " (rewritten)" : ""} in ${result.durationMs} ms`,
  );
  return result;
}

/** Runs a pass if one is due. Null when it is not, which is every tick but one a week. */
export function maybeRunHousekeeping(db: DatabaseSync, dataDir: string, options: HousekeepingOptions = {}): HousekeepingResult | null {
  const now = (options.now ?? (() => new Date()))();
  if (!housekeepingDue(db, now, options.retention ?? defaultRetention)) return null;
  return runHousekeeping(db, dataDir, options);
}

/** The one line the digest carries: what is held, and what the last pass let go. */
export function storageLine(report: StorageReport, baseUrl: string): string {
  const parts = [`${formatBytes(report.databaseBytes)} database`, `${report.snapshots} snapshot(s) (${formatBytes(report.snapshotBytes)})`];
  if (report.lastRun) {
    const r = report.lastRun;
    const freed = r.snapshotsDeleted + r.blobsDeleted + r.networkScansDeleted + (r.deviceReadingsDeleted ?? 0) + r.alertsDeleted;
    parts.push(freed === 0 ? `nothing to let go on ${r.ranAt.slice(0, 10)}` : `${r.snapshotsDeleted} snapshot(s) and ${r.blobsDeleted} blob(s) let go on ${r.ranAt.slice(0, 10)}`);
  } else {
    parts.push("no housekeeping pass yet");
  }
  return `Storage: ${parts.join(", ")} ${baseUrl}/sources#storage`;
}

// ---------------------------------------------------------------------------------------------
// The restore rehearsal. A backup nobody has restored is a hope, not a backup, so the date of the
// last one is kept here and the digest asks for another every quarter. The rehearsal itself is a
// person's job on the box (docs/DEPLOY.md); this is only the record of it.

const rehearsalKey = "restore.last_rehearsal";
const rehearsalNoteKey = "restore.last_note";

/** Days between rehearsals before the digest starts asking. */
const rehearsalEveryDays = 90;

export interface Rehearsal {
  at: string;
  note: string | null;
}

export function lastRehearsal(db: DatabaseSync): Rehearsal | null {
  const at = getSetting(db, rehearsalKey);
  return at ? { at, note: getSetting(db, rehearsalNoteKey) } : null;
}

/** Records that the backup was restored and checked, with whatever the person wants to remember about it. */
export function recordRehearsal(db: DatabaseSync, at: string, note: string | null = null): Rehearsal {
  const stamp = new Date(at).toISOString();
  setSetting(db, rehearsalKey, stamp, stamp);
  if (note) setSetting(db, rehearsalNoteKey, note, stamp);
  else db.prepare("DELETE FROM app_settings WHERE key = ?").run(rehearsalNoteKey);
  return { at: stamp, note };
}

/** The digest's line, when one is wanted: never rehearsed, or not this quarter. Null while it is current. */
export function rehearsalLine(db: DatabaseSync, now: Date, baseUrl: string): string | null {
  const last = lastRehearsal(db);
  const where = `${baseUrl}/sources#storage`;
  if (!last) return `Restore: no rehearsal recorded yet — restore the backup into a throwaway instance and check it (docs/DEPLOY.md) ${where}`;
  const days = Math.floor((now.getTime() - Date.parse(last.at)) / 86_400_000);
  if (days < rehearsalEveryDays) return null;
  return `Restore: the last rehearsal was ${days} days ago (${last.at.slice(0, 10)}); a quarterly one is due ${where}`;
}
