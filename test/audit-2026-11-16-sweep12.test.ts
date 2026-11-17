import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { kevPlatformKeys, kevReading } from "../src/platforms.ts";
import { applyAdvisory, applyKev, getVuln, loadWatchlist, recomputeWatchHits, rowPlatforms, upsertVuln, type NormalizedVuln } from "../src/vulns.ts";

/** Bug sweep 12 of the 16 November audit. */

const at = "2026-11-16T12:00:00.000Z";

function freshDb() {
  const db = openDatabase(":memory:");
  migrate(db);
  return db;
}

const nvd = (over: Partial<NormalizedVuln>): NormalizedVuln => ({
  cveId: "CVE-2026-7100",
  sourceIdentifier: "secure@microsoft.com",
  publishedAt: at,
  lastModifiedAt: at,
  vulnStatus: "Received",
  description: "A flaw.",
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

describe("B12-1: an advisory alias on a row it does not own keeps the row's platform watch", () => {
  it("still hits a Windows watch on a KEV-only Windows row after a GHSA alias arrives", () => {
    const db = freshDb();
    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('platform', 'windows', NULL, ?)").run(at);
    applyKev(db, [{ cveId: "CVE-2026-7100", dateAdded: "2026-11-15", dueDate: "2026-12-06", ransomware: false, description: "Kernel flaw", vendor: "Microsoft", product: "Win32k" }], at);
    expect(getVuln(db, "CVE-2026-7100")).toMatchObject({ watch_hit: 1, platforms_json: '["windows"]' });
    const result = applyAdvisory(
      db,
      {
        id: "GHSA-aaaa-bbbb-cccc",
        aliases: ["CVE-2026-7100"],
        summary: "x",
        details: null,
        publishedAt: at,
        modifiedAt: at,
        cvss: null,
        cwes: [],
        references: [],
        packages: [{ ecosystem: "NuGet", name: "Some.Package", introduced: ["0"], fixed: ["1.2.3"], lastAffected: [], advisory: "GHSA-aaaa-bbbb-cccc" }],
      },
      at,
      loadWatchlist(db),
    );
    expect(result.watchLabels).toEqual(["Windows"]);
    expect(result.watchPlatforms).toEqual(["Windows"]);
    expect(getVuln(db, "CVE-2026-7100")).toMatchObject({ watch_hit: 1, watch_labels_json: '["Windows"]' });
    db.close();
  });

  it("re-reads a row with no stored platforms from CISA's names too", () => {
    const db = freshDb();
    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('platform', 'windows', NULL, ?)").run(at);
    applyKev(db, [{ cveId: "CVE-2026-7100", dateAdded: "2026-11-15", dueDate: null, ransomware: false, description: "Kernel flaw", vendor: "Microsoft", product: "Win32k" }], at);
    db.prepare("UPDATE vulns SET platforms_json = NULL, watch_hit = 0, watch_labels_json = NULL").run();
    recomputeWatchHits(db);
    expect(getVuln(db, "CVE-2026-7100")).toMatchObject({ watch_hit: 1, watch_labels_json: '["Windows"]' });
    db.close();
  });
});

describe("B12-2: Microsoft's 'Multiple Products' is not read as Windows", () => {
  it("gives no reading, so an Office-only CPE row is placed nowhere", () => {
    expect(kevReading("Microsoft", "Multiple Products")).toBeNull();
    expect(kevPlatformKeys("microsoft", "multiple products")).toEqual([]);
    expect(kevReading("Microsoft", "Windows")).toBe("windows");
    expect(kevReading("Apple", "Multiple Products")).toBe("apple");
    const office = { cpes: ["cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*"], vendors: ["microsoft"], products: ["office"], description: "Office flaw" };
    expect(rowPlatforms({ ...office, kevVendor: "microsoft", kevProduct: "multiple products" })).toEqual([]);
  });
});

describe("B12-3: the catalogue re-places a row with no CPEs that NVD placed from its words", () => {
  it("moves an NVD-first row whose description says Windows to apple when CISA says Apple / iOS", () => {
    const db = freshDb();
    upsertVuln(db, nvd({ description: "A flaw in Microsoft Windows lets an attacker run code." }), at, []);
    const before = JSON.parse(getVuln(db, "CVE-2026-7100")!.platforms_json!) as string[];
    expect(before).toContain("windows");
    applyKev(db, [{ cveId: "CVE-2026-7100", dateAdded: "2026-11-15", dueDate: null, ransomware: false, vendor: "Apple", product: "iOS" }], at);
    expect(getVuln(db, "CVE-2026-7100")!.platforms_json).toBe('["apple"]');
    db.close();
  });
});

describe("B12-5: CISA's names are trimmed", () => {
  it("stores a trailing-space vendor and product trimmed, and migration 0076 trims old rows", () => {
    const db = freshDb();
    applyKev(db, [{ cveId: "CVE-2026-7100", dateAdded: "2026-11-15", dueDate: null, ransomware: false, vendor: "Microsoft ", product: "Windows " }], at);
    expect(getVuln(db, "CVE-2026-7100")).toMatchObject({ kev_vendor: "microsoft", kev_product: "windows", vendors_json: '["microsoft"]', products_json: '["windows"]' });
    db.close();
  });

  it("migration 0076 trims the names stored before", () => {
    const db = freshDb();
    applyKev(db, [{ cveId: "CVE-2026-7100", dateAdded: "2026-11-15", dueDate: null, ransomware: false, vendor: "Microsoft", product: "Windows" }], at);
    db.prepare("UPDATE vulns SET kev_vendor = 'microsoft ', kev_product = ' ' WHERE cve_id = 'CVE-2026-7100'").run();
    db.exec(readFileSync(new URL("../src/migrations/0076_kev_names_trimmed.sql", import.meta.url), "utf8"));
    expect(getVuln(db, "CVE-2026-7100")).toMatchObject({ kev_vendor: "microsoft", kev_product: null });
    db.close();
  });
});
