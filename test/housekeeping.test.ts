import { existsSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { healthReport } from "../src/app.ts";
import { putBlob } from "../src/blobs.ts";
import { loadConfig } from "../src/config.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { buildDigest } from "../src/digest.ts";
import {
  defaultRetention,
  formatBytes,
  housekeepingDue,
  lastHousekeeping,
  maybeVacuum,
  referencedBlobs,
  runHousekeeping,
  storageLine,
  storageReport,
  sweepBlobs,
  sweepRuns,
  sweepSnapshots,
  type Retention,
} from "../src/housekeeping.ts";
import { renderSources } from "../src/pages/sources.ts";
import type { LookState } from "../src/look.ts";

/** The pass runs long after the rows were written, so the keep windows and the blob grace have both elapsed. */
const now = new Date("2026-11-20T03:00:00Z");
const daysBefore = (n: number): string => new Date(now.getTime() - n * 86_400_000).toISOString();

let db: DatabaseSync;
let dataDir: string;

/** A snapshot row and its blob, so sweeping can be watched from both sides. */
function snapshot(options: { source: string; key: string; body: string; fetchedAt: string; document?: boolean }): string {
  const blob = putBlob(dataDir, new TextEncoder().encode(options.body));
  const row = db
    .prepare("INSERT INTO snapshots (source_id, document_key, sha256, bytes, blob_path, fetched_at) VALUES (?, ?, ?, ?, ?, ?)")
    .run(options.source, options.key, blob.sha256, blob.bytes, blob.relativePath, options.fetchedAt);
  if (options.document) {
    db.prepare("INSERT INTO documents (source_id, document_key, snapshot_id, version_label, title, published_at, parsed_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
      options.source,
      options.key,
      Number(row.lastInsertRowid),
      "v1",
      "t",
      options.fetchedAt,
      options.fetchedAt,
    );
  }
  return blob.sha256;
}

beforeEach(() => {
  dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-housekeeping-"));
  db = openDatabase(":memory:");
  migrate(db);
});

afterEach(() => {
  db.close();
  rmSync(dataDir, { recursive: true, force: true });
});

describe("what the instance keeps", () => {
  it("keeps a standard's snapshots for good and lets an old feed fetch go", () => {
    // bleeping is an article source, nist-sp-800-53 a requirement-set: both are seeded.
    const ancientStandard = snapshot({ source: "nist-sp-800-53", key: "catalog", body: "rev 5.1.1", fetchedAt: daysBefore(400), document: true });
    const oldFeed = snapshot({ source: "bleeping", key: "feed", body: "<rss>old</rss>", fetchedAt: daysBefore(30) });
    const alsoOldFeed = snapshot({ source: "bleeping", key: "feed", body: "<rss>older still</rss>", fetchedAt: daysBefore(21) });
    const newestFeed = snapshot({ source: "bleeping", key: "feed", body: "<rss>newest</rss>", fetchedAt: daysBefore(20) });
    const recentFeed = snapshot({ source: "thehackernews", key: "feed", body: "<rss>recent</rss>", fetchedAt: daysBefore(2) });

    expect(sweepSnapshots(db, now)).toBe(2);
    const left = (db.prepare("SELECT sha256 FROM snapshots").all() as { sha256: string }[]).map((r) => r.sha256);
    // The standard stays although it is the oldest thing here; the newest fetch of a feed stays so the next diff has a "before".
    expect(left).toContain(ancientStandard);
    expect(left).toContain(newestFeed);
    expect(left).toContain(recentFeed);
    expect(left).not.toContain(oldFeed);
    expect(left).not.toContain(alsoOldFeed);
  });

  it("never deletes a snapshot a document points at, whatever its source's kind", () => {
    // A listing source whose fetch produced a document: the Register reads it, so it is evidence.
    snapshot({ source: "disa-stigs", key: "windows-11", body: "zip bytes", fetchedAt: daysBefore(300), document: true });
    expect(sweepSnapshots(db, now)).toBe(0);
    expect(db.prepare("SELECT COUNT(*) AS n FROM snapshots").get()).toEqual({ n: 1 });
  });

  it("sweeps scan runs and the alert log past their windows, and takes the canaries with the run", () => {
    const old = db.prepare("INSERT INTO net_scans (started_at) VALUES (?)").run(daysBefore(200));
    const fresh = db.prepare("INSERT INTO net_scans (started_at) VALUES (?)").run(daysBefore(3));
    const canary = db.prepare("INSERT INTO net_canaries (scan_id, category, source_id, name, outcome) VALUES (?, 'ads', 'canary-ads', 'a.example', 'sinkholed')");
    canary.run(Number(old.lastInsertRowid));
    canary.run(Number(fresh.lastInsertRowid));
    const alert = db.prepare("INSERT INTO alerts (kind, title, sent_at, status) VALUES ('kev', 't', ?, 'sent')");
    alert.run(daysBefore(200));
    alert.run(daysBefore(1));

    expect(sweepRuns(db, now)).toEqual({ networkScans: 1, alerts: 1 });
    expect(db.prepare("SELECT COUNT(*) AS n FROM net_scans").get()).toEqual({ n: 1 });
    expect(db.prepare("SELECT COUNT(*) AS n FROM net_canaries").get()).toEqual({ n: 1 });
    expect(db.prepare("SELECT COUNT(*) AS n FROM alerts").get()).toEqual({ n: 1 });
  });
});

describe("the blob sweep", () => {
  it("frees what nothing points at and leaves every reference alone", () => {
    const standard = snapshot({ source: "nist-sp-800-53", key: "catalog", body: "catalog", fetchedAt: daysBefore(400), document: true });
    const image = putBlob(dataDir, new TextEncoder().encode("an article image"));
    db.prepare(
      "INSERT INTO items (source_id, kind, external_id, title, fetched_at, image_blob, image_type, image_origin) VALUES ('bleeping', 'article', 'i-1', 't', ?, ?, 'image/png', 'enclosure')",
    ).run(daysBefore(5), image.sha256);
    const mark = putBlob(dataDir, new TextEncoder().encode("the owner's logo"));
    db.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES ('branding.logo', ?, ?)").run(mark.sha256, daysBefore(5));
    db.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES ('branding.logo_type', 'image/png', ?)").run(daysBefore(5));
    const orphan = putBlob(dataDir, new TextEncoder().encode("the bytes of a swept snapshot"));

    expect(referencedBlobs(db)).toEqual(new Set([standard, image.sha256, mark.sha256]));
    const swept = sweepBlobs(db, dataDir, now);
    expect(swept.deleted).toBe(1);
    expect(swept.bytesFreed).toBeGreaterThan(0);
    expect(existsSync(orphan.absolutePath)).toBe(false);
    for (const kept of [image.absolutePath, mark.absolutePath]) expect(existsSync(kept)).toBe(true);
  });

  it("leaves a blob written in the grace window alone, because a fetch may be mid-flight", () => {
    const inFlight = putBlob(dataDir, new TextEncoder().encode("bytes written a moment ago"));
    // The clock is the real one here: the file was written seconds ago, so the grace window holds.
    expect(sweepBlobs(db, dataDir, new Date()).deleted).toBe(0);
    expect(existsSync(inFlight.absolutePath)).toBe(true);
  });

  it("does nothing when the store has never been written", () => {
    expect(sweepBlobs(db, path.join(dataDir, "empty"), now)).toEqual({ deleted: 0, bytesFreed: 0 });
  });
});

describe("the weekly pass", () => {
  const eager: Retention = { ...defaultRetention, vacuumFreeShare: 0, vacuumMinFreePages: 0 };

  it("is due before the first pass, not the day after one, and again a week later", () => {
    expect(housekeepingDue(db, now)).toBe(true);
    runHousekeeping(db, dataDir, { now: () => now });
    expect(housekeepingDue(db, new Date(now.getTime() + 86_400_000))).toBe(false);
    expect(housekeepingDue(db, new Date(now.getTime() + 8 * 86_400_000))).toBe(true);
  });

  it("sweeps, optimizes, rewrites the file and records what it did", () => {
    snapshot({ source: "bleeping", key: "feed", body: "<rss>old</rss>", fetchedAt: daysBefore(30) });
    snapshot({ source: "bleeping", key: "feed", body: "<rss>newest</rss>", fetchedAt: daysBefore(20) });
    db.prepare("INSERT INTO net_scans (started_at) VALUES (?)").run(daysBefore(200));
    const lines: string[] = [];

    const result = runHousekeeping(db, dataDir, { now: () => now, retention: eager, log: (line) => lines.push(line) });
    expect(result.snapshotsDeleted).toBe(1);
    expect(result.blobsDeleted).toBe(1);
    expect(result.networkScansDeleted).toBe(1);
    expect(result.vacuumed).toBe(true);
    expect(result.ranAt).toBe(now.toISOString());
    expect(lines.join("\n")).toContain("[housekeeping]");
    // It reads its own record back, so the digest and the page can say what happened without re-running it.
    expect(lastHousekeeping(db)).toEqual(result);
  });

  it("leaves the file alone when little of it is free", () => {
    expect(maybeVacuum(db)).toBe(false);
  });

  it("holds the clock it is given, so a run against dated rows is repeatable", () => {
    const result = runHousekeeping(db, dataDir, { now: () => now });
    expect(result.ranAt).toBe("2026-11-20T03:00:00.000Z");
    expect(result.bytesBefore).toBeGreaterThan(0);
    expect(result.bytesAfter).toBeGreaterThan(0);
  });
});

describe("what it reports", () => {
  it("counts what is held and which snapshots are a standard's evidence", () => {
    snapshot({ source: "nist-sp-800-53", key: "catalog", body: "catalog bytes", fetchedAt: daysBefore(400), document: true });
    snapshot({ source: "bleeping", key: "feed", body: "<rss/>", fetchedAt: daysBefore(2) });
    const report = storageReport(db);
    expect(report.snapshots).toBe(2);
    expect(report.keptSnapshots).toBe(1);
    expect(report.snapshotBytes).toBeGreaterThan(0);
    expect(report.oldestSnapshotAt).toBe(daysBefore(400));
    expect(report.lastRun).toBeNull();
  });

  it("writes bytes the way a person reads them", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.0 kB");
    expect(formatBytes(138_354_688)).toBe("132 MB");
    expect(formatBytes(5 * 1024 ** 3)).toBe("5.0 GB");
  });

  it("gives the digest one line, and says so when no pass has run", () => {
    const before = storageLine(storageReport(db), "https://cybercard.net");
    expect(before).toContain("no housekeeping pass yet");
    expect(before).toContain("https://cybercard.net/sources#storage");
    runHousekeeping(db, dataDir, { now: () => now });
    expect(storageLine(storageReport(db), "https://cybercard.net")).toContain("nothing to let go on 2026-11-20");
  });

  it("carries the storage line into the digest", () => {
    const text = buildDigest(db, { from: daysBefore(1), to: now.toISOString(), baseUrl: "https://cybercard.net", period: "daily" });
    expect(text).toContain("Storage:");
  });

  it("puts what is stored in the health answer", () => {
    snapshot({ source: "nist-sp-800-53", key: "catalog", body: "catalog bytes", fetchedAt: daysBefore(400), document: true });
    const report = healthReport({ config: loadConfig({ BW_DATA_DIR: dataDir }), db, migrations: ["0001_init"], startedAt: Date.now() - 1000 });
    expect(report.storage.keptSnapshots).toBe(1);
    expect(report.storage.oldestSnapshotAt).toBe(daysBefore(400));
    expect(report.storage.lastHousekeepingAt).toBeNull();
    runHousekeeping(db, dataDir, { now: () => now });
    expect(healthReport({ config: loadConfig({ BW_DATA_DIR: dataDir }), db, migrations: [], startedAt: Date.now() }).storage.lastHousekeepingAt).toBe(now.toISOString());
  });

  it("shows the policy and the last pass on the Sources page", () => {
    snapshot({ source: "bleeping", key: "feed", body: "<rss/>", fetchedAt: daysBefore(2) });
    const look: LookState = { look: "console", scheme: "system", back: "/" };
    const before = renderSources({ db, owner: false, open: true, notice: null, look });
    expect(before).toContain('id="storage"');
    expect(before).toContain("What this instance keeps");
    expect(before).toContain("the rest go after 14 days");
    expect(before).toContain("not yet; the pass runs weekly");
    runHousekeeping(db, dataDir, { now: () => now });
    expect(renderSources({ db, owner: false, open: true, notice: null, look })).toContain("2026-11-20 03:00");
  });
});
