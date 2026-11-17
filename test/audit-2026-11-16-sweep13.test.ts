import { describe, expect, it } from "vitest";
import type { DatabaseSync } from "node:sqlite";
import { storeCvelistRecords } from "../src/adapters/cvelist.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { kevReading } from "../src/platforms.ts";
import { applyEpss, applyKev, getVuln, loadWatchlist, recomputePlatforms, recomputeWatchHits, rowPlatforms, upsertVuln, type NormalizedVuln } from "../src/vulns.ts";

/** Bug sweep 13 of the 16 November audit: one reading of a CVE's platforms. */

const at = "2026-11-16T12:00:00.000Z";
const now = () => new Date(at);

function freshDb() {
  const db = openDatabase(":memory:");
  migrate(db);
  db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('platform', 'windows', NULL, ?)").run(at);
  return db;
}

const nvd = (over: Partial<NormalizedVuln>): NormalizedVuln => ({
  cveId: "CVE-2026-7200",
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

const cvelist = (cveId: string, description: string) =>
  [{ dataType: "CVE_RECORD", cveMetadata: { cveId, state: "PUBLISHED", datePublished: "2026-11-01T00:00:00Z", dateUpdated: "2026-11-16T00:00:00Z" }, containers: { cna: { descriptions: [{ lang: "en", value: description }], affected: [] } } }] as unknown as Parameters<
    typeof storeCvelistRecords
  >[1];

const placed = (db: DatabaseSync, id: string) => {
  const row = getVuln(db, id)!;
  return { platforms: row.platforms_json, watch: row.watch_labels_json };
};

const exchange = ["cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_15:*:*:*:*:*:*"];

describe("B13-1: a Microsoft application CPE is not placed on Windows from CISA's words", () => {
  it("gives no CISA reading for a Microsoft product that is empty, the vendor's name or 'Multiple …'", () => {
    expect(kevReading("Microsoft", "")).toBeNull();
    expect(kevReading("Microsoft", null)).toBeNull();
    expect(kevReading("Microsoft", "Microsoft")).toBeNull();
    expect(kevReading("Microsoft", "Multiple Products")).toBeNull();
    expect(kevReading("Microsoft", "Win32k")).toBe("windows");
  });

  it("keeps an Exchange CVE off Windows whatever CISA names it", () => {
    for (const product of ["Microsoft", "", "Win32k"]) {
      expect(rowPlatforms({ cpes: exchange, vendors: ["microsoft"], products: ["exchange_server"], description: "Microsoft Exchange Server spoofing", kevVendor: "microsoft", kevProduct: product }), product).toEqual([]);
    }
    const db = freshDb();
    applyKev(db, [{ cveId: "CVE-2026-7200", dateAdded: "2026-11-15", dueDate: null, ransomware: false, description: "Microsoft Exchange Server contains a flaw.", vendor: "Microsoft", product: "Microsoft" }], at);
    upsertVuln(db, nvd({ vulnStatus: "Analyzed", cpes: exchange, vendors: ["microsoft"], products: ["exchange_server"] }), at, []);
    expect(placed(db, "CVE-2026-7200")).toEqual({ platforms: "[]", watch: null });
    recomputeWatchHits(db);
    expect(placed(db, "CVE-2026-7200")).toEqual({ platforms: "[]", watch: null });
    db.close();
  });
});

describe("B13-2: the CVE list's rewording reads a CPE-less row's platforms again", () => {
  it("places an unanalysed NVD row on Windows when the CNA's words name it, and the watch hits at once", () => {
    const db = freshDb();
    upsertVuln(db, nvd({ vulnStatus: "Awaiting Analysis", description: "Improper privilege management in a log rotation service." }), at, []);
    expect(placed(db, "CVE-2026-7200")).toEqual({ platforms: "[]", watch: null });
    storeCvelistRecords({ db, now }, cvelist("CVE-2026-7200", "A use-after-free in Microsoft Windows SMB allows remote code execution."));
    expect(placed(db, "CVE-2026-7200")).toEqual({ platforms: '["windows"]', watch: '["Windows"]' });
    db.close();
  });
});

describe("B13-3: a KEV-only 'Microsoft / Multiple Products' row is read from its words", () => {
  it("is on Windows from the catalogue alone and after NVD's unanalysed record arrives", () => {
    const db = freshDb();
    applyKev(db, [{ cveId: "CVE-2026-7200", dateAdded: "2026-11-15", dueDate: null, ransomware: false, description: "Microsoft Windows and Office contain a use-after-free vulnerability.", vendor: "Microsoft", product: "Multiple Products" }], at);
    expect(placed(db, "CVE-2026-7200")).toEqual({ platforms: '["windows"]', watch: '["Windows"]' });
    upsertVuln(db, nvd({ vulnStatus: "Awaiting Analysis", description: "Microsoft Windows and Office contain a use-after-free vulnerability." }), at, loadWatchlist(db));
    expect(placed(db, "CVE-2026-7200")).toEqual({ platforms: '["windows"]', watch: '["Windows"]' });
    db.close();
  });
});

describe("every entry point ends where a restart would", () => {
  /** A small fixture: KEV-only rows, NVD rows with and without CPEs, and a CVE-list row. */
  function fixture(): DatabaseSync {
    const db = freshDb();
    applyKev(
      db,
      [
        { cveId: "CVE-2026-7301", dateAdded: "2026-11-15", dueDate: null, ransomware: false, description: "Microsoft Windows and Office contain a flaw.", vendor: "Microsoft", product: "Multiple Products" },
        { cveId: "CVE-2026-7302", dateAdded: "2026-11-15", dueDate: null, ransomware: false, description: "Microsoft Exchange Server contains a flaw.", vendor: "Microsoft", product: "Microsoft" },
        { cveId: "CVE-2026-7303", dateAdded: "2026-11-15", dueDate: null, ransomware: false, description: "Microsoft Win32k contains a flaw.", vendor: "Microsoft", product: "Win32k" },
      ],
      at,
    );
    upsertVuln(db, nvd({ cveId: "CVE-2026-7302", vulnStatus: "Analyzed", cpes: exchange, vendors: ["microsoft"], products: ["exchange_server"] }), at, []);
    upsertVuln(db, nvd({ cveId: "CVE-2026-7304", vulnStatus: "Awaiting Analysis", description: "A flaw in a log service." }), at, []);
    upsertVuln(db, nvd({ cveId: "CVE-2026-7305", vulnStatus: "Analyzed", cpes: ["cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:*:*"], vendors: ["microsoft"], products: ["windows_11_24h2"] }), at, []);
    recomputeWatchHits(db);
    return db;
  }
  const ids = ["CVE-2026-7301", "CVE-2026-7302", "CVE-2026-7303", "CVE-2026-7304", "CVE-2026-7305"];
  const snapshot = (db: DatabaseSync) => ids.map((id) => placed(db, id));
  const restart = (db: DatabaseSync) => {
    db.prepare("UPDATE vulns SET platforms_json = NULL").run();
    recomputeWatchHits(db, recomputePlatforms(db));
    recomputeWatchHits(db);
  };
  const kevAgain = (db: DatabaseSync) =>
    applyKev(
      db,
      [
        { cveId: "CVE-2026-7301", dateAdded: "2026-11-15", dueDate: null, ransomware: false, vendor: "Microsoft", product: "Multiple Products" },
        { cveId: "CVE-2026-7302", dateAdded: "2026-11-15", dueDate: null, ransomware: false, vendor: "Microsoft", product: "" },
        { cveId: "CVE-2026-7304", dateAdded: "2026-11-15", dueDate: null, ransomware: false, vendor: "Microsoft", product: "Multiple Products" },
      ],
      at,
    );
  const entryPoints: Record<string, (db: DatabaseSync) => void> = {
    watchEdit: (db) => recomputeWatchHits(db),
    kev: kevAgain,
    cvelistReworded: (db) => storeCvelistRecords({ db, now }, ids.flatMap((id) => cvelist(id, "A use-after-free in Microsoft Windows SMB."))),
    nvdAwaiting: (db) => {
      for (const id of ids) upsertVuln(db, nvd({ cveId: id, vulnStatus: "Awaiting Analysis", description: "Microsoft Windows and Office contain a flaw." }), at, loadWatchlist(db));
    },
    epss: (db) => applyEpss(db, ids.map((cveId) => ({ cveId, epss: 0.6, percentile: 0.99 })), "2026-11-16", at),
  };

  for (const [name, run] of Object.entries(entryPoints)) {
    it(`agrees after ${name}`, () => {
      const db = fixture();
      run(db);
      const after = snapshot(db);
      restart(db);
      expect(after).toEqual(snapshot(db));
      db.close();
    });
  }

  it("reads the fixture as a person would", () => {
    const db = fixture();
    expect(snapshot(db).map((s) => s.platforms)).toEqual(['["windows"]', "[]", '["windows"]', "[]", '["windows"]']);
    db.close();
  });
});
