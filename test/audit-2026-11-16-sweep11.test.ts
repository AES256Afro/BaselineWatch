import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { vulnFilters } from "../src/routes/query.ts";
import { applyKev, getVuln, listVulns, matchWatchDetailed, recomputePlatforms, rowPlatforms, upsertVuln, type NormalizedVuln, type WatchEntry } from "../src/vulns.ts";

/** Bug sweep 11 of the 16 November audit. */

const at = "2026-11-16T12:00:00.000Z";
const now = new Date(at);

function freshDb() {
  const db = openDatabase(":memory:");
  migrate(db);
  return db;
}

const nvd = (over: Partial<NormalizedVuln>): NormalizedVuln => ({
  cveId: "CVE-2026-85880",
  sourceIdentifier: "secure@microsoft.com",
  publishedAt: at,
  lastModifiedAt: at,
  vulnStatus: "Awaiting Analysis",
  description: "A flaw in a component.",
  cvss: null,
  ssvc: null,
  cwes: [],
  cpes: [],
  vendors: [],
  products: [],
  references: [],
  kev: null,
  ...over,
});

const platformsOfRow = (db: ReturnType<typeof freshDb>, id: string): string[] =>
  (db.prepare("SELECT p.platform FROM vuln_platforms p JOIN vulns v ON v.id = p.vuln_id WHERE v.cve_id = ? ORDER BY 1").all(id) as { platform: string }[]).map((r) => r.platform);

describe("B11-1: NVD's record without CPEs keeps a KEV row's platforms", () => {
  it("keeps Windows in the view and the Windows watch hit", () => {
    const db = freshDb();
    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('platform', 'windows', NULL, ?)").run(at);
    applyKev(db, [{ cveId: "CVE-2026-85880", dateAdded: "2026-11-15", dueDate: "2026-12-06", ransomware: false, description: "Windows flaw", vendor: "Microsoft", product: "Windows" }], at);
    expect(getVuln(db, "CVE-2026-85880")!.platforms_json).toBe('["windows"]');
    const watch = db.prepare("SELECT id, kind, value, label FROM watchlist").all() as unknown as WatchEntry[];
    const result = upsertVuln(db, nvd({}), at, watch);
    expect(result.watchPlatforms).toEqual(["Windows"]);
    const row = getVuln(db, "CVE-2026-85880")!;
    expect(row).toMatchObject({ platforms_json: '["windows"]', watch_hit: 1, source_identifier: "secure@microsoft.com" });
    expect(platformsOfRow(db, "CVE-2026-85880")).toEqual(["windows"]);
    expect(listVulns(db, vulnFilters({ platform: "windows" }, now)).rows.map((r) => r.cve_id)).toEqual(["CVE-2026-85880"]);
    // Read again at a start: the same answer, without the source_identifier test.
    db.prepare("UPDATE vulns SET platforms_json = NULL").run();
    expect(recomputePlatforms(db)).toEqual(["CVE-2026-85880"]);
    expect(platformsOfRow(db, "CVE-2026-85880")).toEqual(["windows"]);
    db.close();
  });

  it("places a CPE-less NVD row from CISA's names when the catalogue reaches it later", () => {
    const db = freshDb();
    upsertVuln(db, nvd({}), at, []);
    expect(getVuln(db, "CVE-2026-85880")!.platforms_json).toBe("[]");
    applyKev(db, [{ cveId: "CVE-2026-85880", dateAdded: "2026-11-15", dueDate: "2026-12-06", ransomware: false, description: "Windows flaw", vendor: "Microsoft", product: "Windows" }], at);
    expect(platformsOfRow(db, "CVE-2026-85880")).toEqual(["windows"]);
    db.close();
  });

  it("reads CISA's names only where the row's own say no platform", () => {
    const cpes = ["cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*"];
    expect(rowPlatforms({ cpes, vendors: ["microsoft"], products: ["exchange_server"], description: null, kevVendor: "microsoft", kevProduct: "exchange server" })).toEqual([]);
    const linux = ["cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*"];
    expect(rowPlatforms({ cpes: linux, vendors: ["linux"], products: ["linux_kernel"], description: null, kevVendor: "microsoft", kevProduct: "windows" })).toEqual(["linux"]);
    expect(rowPlatforms({ cpes: [], vendors: [], products: [], description: null, kevVendor: "microsoft", kevProduct: "windows" })).toEqual(["windows"]);
    expect(rowPlatforms({ cpes: [], vendors: [], products: [], description: null, kevVendor: null, kevProduct: null })).toEqual([]);
  });
});

describe("B11-2: migration 0075 reads the News items' CVSS clause as 0074 read the changes", () => {
  it("drops a clause whose sides agree and strips X metrics from one whose sides differ", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const sql = readFileSync(new URL("../src/migrations/0075_cvss_spelling_items.sql", import.meta.url), "utf8");
    const insert = db.prepare("INSERT INTO items (source_id, kind, external_id, title, summary, published_at, fetched_at, signals_json) VALUES ('nvd-cves', 'vulnerability', ?, ?, ?, ?, ?, ?)");
    const v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N";
    const x = "/E:X/CR:X/IR:X/AR:X/MAV:X/U:X";
    insert.run("CVE-1", "CVE-1", `CVSS 5.3 (v4.0, ${v}) → 5.3 (v4.0, ${v}${x}); Analyzed. A flaw.`, at, at, JSON.stringify({ changes: ["cvss", "status"] }));
    insert.run("CVE-2", "CVE-2", `CVSS 5.3 (v4.0, ${v}) → 5.3 (v4.0, ${v}${x}). A flaw.`, at, at, JSON.stringify({ changes: ["cvss"] }));
    insert.run("CVE-3", "CVE-3", `CVSS 5.3 (v4.0, ${v}/E:P${x}) → 6.9 (v4.0, ${v}/E:A${x}); Analyzed. A flaw.`, at, at, JSON.stringify({ changes: ["cvss", "status"] }));
    db.exec(sql);
    const rows = db.prepare("SELECT external_id, summary, signals_json FROM items ORDER BY external_id").all() as { external_id: string; summary: string; signals_json: string }[];
    expect(rows[0]).toMatchObject({ summary: "Analyzed. A flaw.", signals_json: '{"changes":["status"]}' });
    expect(rows[1]).toMatchObject({ summary: "A flaw.", signals_json: '{"changes":[]}' });
    expect(rows[2]).toMatchObject({ summary: `CVSS 5.3 (v4.0, ${v}/E:P) → 6.9 (v4.0, ${v}/E:A); Analyzed. A flaw.`, signals_json: '{"changes":["cvss","status"]}' });
    db.close();
  });
});

describe("B11-3: a watch value is split on a lone colon only", () => {
  it("matches CISA's Perl entry by name and still reads a pair", () => {
    const row = { cpes: [], vendors: ["spreadsheet::parseexcel"], products: ["spreadsheet::parseexcel"], description: null, kevVendor: "spreadsheet::parseexcel", kevProduct: "spreadsheet::parseexcel" };
    const entry = (value: string) => ({ kind: "product", value, label: null }) as unknown as WatchEntry;
    expect(matchWatchDetailed(row, [entry("spreadsheet::parseexcel")])).toEqual([{ label: "spreadsheet::parseexcel", kind: "product" }]);
    expect(matchWatchDetailed(row, [entry("spreadsheet::parseexcel:spreadsheet::parseexcel")])).toEqual([{ label: "spreadsheet::parseexcel:spreadsheet::parseexcel", kind: "product" }]);
    expect(matchWatchDetailed(row, [entry("spreadsheet::writeexcel")])).toEqual([]);
    const ivanti = { cpes: ["cpe:2.3:a:ivanti:connect_secure:22.7:*:*:*:*:*:*:*"], vendors: ["ivanti"], products: ["connect_secure"], description: null };
    expect(matchWatchDetailed(ivanti, [entry("ivanti:connect secure")])).toHaveLength(1);
  });
});
