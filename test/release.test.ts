import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { buildDigest } from "../src/digest.ts";
import { lastRehearsal, recordRehearsal, rehearsalLine } from "../src/housekeeping.ts";
import { compareHealth, counted } from "../scripts/health-diff.ts";
import { applyBump, compareVersions, consistencyProblems, draftEntry, draftMarker, newestEntry, readVersions } from "../scripts/release.ts";

/** A released tree: one version in every file, and an entry that says something. */
const released = {
  package: "0.38.0",
  lock: "0.38.0",
  lockRoot: "0.38.0",
  manifestVersion: "0.38.0",
  manifestReference: "0.38.0",
  entry: { version: "0.38.0", date: "2026-10-21", body: "- **The thing that changed.** Said in enough words to be an entry rather than a placeholder." },
};

describe("the release invariant", () => {
  it("passes on this repository, which is what keeps a version from being tagged unwritten", () => {
    // The guard that would have caught 0.36.0, 0.36.1 and 0.37.0 shipping with no entry.
    expect(consistencyProblems(readVersions())).toEqual([]);
  });

  it("catches each place a version can disagree", () => {
    expect(consistencyProblems({ ...released, lock: "0.37.0" })[0]).toContain("package-lock.json version is 0.37.0");
    expect(consistencyProblems({ ...released, lockRoot: "0.37.0" })[0]).toContain('packages[""].version');
    expect(consistencyProblems({ ...released, manifestVersion: "0.37.0" })[0]).toContain("image.version");
    expect(consistencyProblems({ ...released, manifestReference: "0.37.0" })[0]).toContain("image.reference");
  });

  it("refuses a tag that names another version", () => {
    expect(consistencyProblems(released, { tag: "v0.38.0" })).toEqual([]);
    expect(consistencyProblems(released, { tag: "v0.39.0" })[0]).toContain("tag the release commit");
  });

  it("refuses an entry that is missing, still the draft, or empty", () => {
    expect(consistencyProblems({ ...released, entry: { version: "0.37.0", date: "2026-10-20", body: "- something" } })[0]).toContain("write the entry before the tag");
    expect(consistencyProblems({ ...released, entry: { ...released.entry, body: `- a line\n- ${draftMarker} — what changed.` } })[0]).toContain("still the draft");
    expect(consistencyProblems({ ...released, entry: { ...released.entry, body: "- tidy up" } })[0]).toContain("says almost nothing");
    expect(consistencyProblems({ ...released, entry: null })[0]).toContain("no `## x.y.z");
  });

  it("reads the newest entry of a changelog and stops at the next one", () => {
    const changelog = "# Changelog\n\nblurb\n\n## 0.38.0 — 2026-10-21\n\n- the newest thing\n\n## 0.37.0 — 2026-10-20\n\n- the older thing\n";
    const entry = newestEntry(changelog);
    expect(entry).toEqual({ version: "0.38.0", date: "2026-10-21", body: "- the newest thing" });
    expect(newestEntry("# Changelog\n\nnothing yet\n")).toBeNull();
  });

  it("orders versions the way a release goes", () => {
    expect(compareVersions("0.38.0", "0.37.0")).toBe(1);
    expect(compareVersions("0.9.1", "0.10.0")).toBe(-1);
    expect(compareVersions("1.0.0", "1.0.0")).toBe(0);
  });

  it("opens an entry that cannot ship as it stands", () => {
    const entry = draftEntry("0.38.0", "2026-10-21", ["Keep what is evidence", "Write the changelog entries"]);
    expect(entry).toContain("## 0.38.0 — 2026-10-21");
    expect(entry).toContain("- Keep what is evidence");
    expect(entry).toContain(draftMarker);
    // The marker is what the check trips on, so a drafted entry can never be tagged.
    expect(consistencyProblems({ ...released, entry: { version: "0.38.0", date: "2026-10-21", body: entry } }).join()).toContain("still the draft");
  });
});

describe("the bump", () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(path.join(os.tmpdir(), "bw-release-"));
    mkdirSync(path.join(root, "boxpilot"));
    writeFileSync(path.join(root, "package.json"), `${JSON.stringify({ name: "baselinewatch", version: "0.37.0" }, null, 2)}\n`);
    writeFileSync(path.join(root, "package-lock.json"), `${JSON.stringify({ name: "baselinewatch", version: "0.37.0", packages: { "": { name: "baselinewatch", version: "0.37.0" } } }, null, 2)}\n`);
    writeFileSync(
      path.join(root, "boxpilot/baselinewatch.yaml"),
      "# a comment the bump must keep\nid: baselinewatch\nimage:\n  reference: ghcr.io/aes256afro/baselinewatch:0.37.0\n  version: \"0.37.0\"\n",
    );
    writeFileSync(path.join(root, "CHANGELOG.md"), "# Changelog\n\nEach version is a tag.\n\n## 0.37.0 — 2026-10-20\n\n- the previous thing\n");
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it("writes the version everywhere and opens the entry, keeping the manifest's comments", () => {
    const result = applyBump("0.38.0", { root, date: "2026-10-21", subjects: ["Add the thing"] });
    expect(result).toEqual({ previous: "0.37.0", version: "0.38.0", wroteEntry: true });
    const versions = readVersions(root);
    expect([versions.package, versions.lock, versions.lockRoot, versions.manifestVersion, versions.manifestReference]).toEqual(Array(5).fill("0.38.0"));
    expect(readFileSync(path.join(root, "boxpilot/baselinewatch.yaml"), "utf8")).toContain("# a comment the bump must keep");
    const changelog = readFileSync(path.join(root, "CHANGELOG.md"), "utf8");
    expect(changelog.indexOf("## 0.38.0")).toBeLessThan(changelog.indexOf("## 0.37.0"));
    expect(changelog).toContain("- Add the thing");
    // The tree it leaves cannot be tagged until the entry is written up.
    expect(consistencyProblems(versions).join()).toContain("still the draft");
  });

  it("leaves an entry alone when the version already carries one", () => {
    applyBump("0.38.0", { root, date: "2026-10-21", subjects: ["Add the thing"] });
    writeFileSync(
      path.join(root, "CHANGELOG.md"),
      readFileSync(path.join(root, "CHANGELOG.md"), "utf8").replace(/- TODO.*\n/, ""),
    );
    const again = applyBump("0.38.0", { root, date: "2026-10-22", subjects: ["Something else"] });
    expect(again.wroteEntry).toBe(false);
    expect(readFileSync(path.join(root, "CHANGELOG.md"), "utf8")).not.toContain("Something else");
  });
});

describe("the restore rehearsal's health comparison", () => {
  const live = { name: "BaselineWatch", version: "0.37.0", database: { migrations: 30, sources: 73, snapshots: 1712, changes: 1591, items: 4990, vulns: 34276 } };

  it("passes a copy that is merely behind, as a backup is", () => {
    const restored = { ...live, database: { ...live.database, items: 4800, vulns: 33000 } };
    expect(compareHealth(live, restored).ok).toBe(true);
  });

  it("fails a copy that is ahead, missing a table, or carrying other migrations", () => {
    expect(compareHealth(live, { ...live, database: { ...live.database, items: 5200 } }).problems[0]).toContain("more than the live instance");
    expect(compareHealth(live, { ...live, database: { ...live.database, snapshots: 0 } }).problems[0]).toContain("holds none");
    expect(compareHealth(live, { ...live, database: { ...live.database, vulns: 1000 } }).problems[0]).toContain("behind");
    expect(compareHealth(live, { ...live, database: { ...live.database, migrations: 29 } }).problems[0]).toContain("not this app's");
  });

  it("names every count a person would check", () => {
    expect(counted).toEqual(["migrations", "sources", "snapshots", "changes", "items", "vulns"]);
  });
});

describe("the rehearsal's record", () => {
  let db: DatabaseSync;
  let dir: string;
  const now = new Date("2026-10-21T07:00:00Z");

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), "bw-rehearsal-"));
    db = openDatabase(":memory:");
    migrate(db);
  });
  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("asks in the digest until one is recorded, then goes quiet for a quarter", () => {
    expect(rehearsalLine(db, now, "https://cybercard.net")).toContain("no rehearsal recorded yet");
    recordRehearsal(db, now.toISOString(), "restored the 2026-10-20 archive, health-diff clean");
    expect(rehearsalLine(db, now, "https://cybercard.net")).toBeNull();
    expect(rehearsalLine(db, new Date("2026-11-30T07:00:00Z"), "https://cybercard.net")).toBeNull();
    const overdue = rehearsalLine(db, new Date("2027-02-01T07:00:00Z"), "https://cybercard.net");
    expect(overdue).toContain("103 days ago (2026-10-21)");
  });

  it("keeps what the rehearsal found, and replaces it next time", () => {
    recordRehearsal(db, "2026-07-01T00:00:00Z", "first one; blobs were missing from the archive");
    expect(lastRehearsal(db)).toEqual({ at: "2026-07-01T00:00:00.000Z", note: "first one; blobs were missing from the archive" });
    recordRehearsal(db, now.toISOString());
    expect(lastRehearsal(db)).toEqual({ at: "2026-10-21T07:00:00.000Z", note: null });
  });

  it("puts the ask in the digest itself", () => {
    const { text } = buildDigest(db, { from: "2026-10-20T07:00:00Z", to: now.toISOString(), baseUrl: "https://cybercard.net", period: "daily" });
    expect(text).toContain("Restore: no rehearsal recorded yet");
    recordRehearsal(db, now.toISOString());
    expect(buildDigest(db, { from: "2026-10-20T07:00:00Z", to: now.toISOString(), baseUrl: "https://cybercard.net", period: "daily" }).text).not.toContain("Restore:");
  });
});
