import { copyFileSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { vulnFeed } from "../src/feeds.ts";
import { untaggedReferences, vendorDomainNames } from "../src/fix.ts";
import { renderGuide } from "../src/pages/guide.ts";
import { renderStigsIndex } from "../src/pages/stigs.ts";
import { renderVulnList, watchCandidates } from "../src/pages/vulnerabilities.ts";
import { ignoredVulnParams, vulnFilters } from "../src/routes/query.ts";
import { applyKev, getVuln, matchWatchDetailed, squash, upsertVuln, type NormalizedVuln, type WatchEntry } from "../src/vulns.ts";
import { kevChip } from "../src/wire.ts";

/** Bug sweep 10 of the 16 November audit. */

const at = "2026-11-16T12:00:00.000Z";
const now = new Date(at);
const look = { look: "register" as const, scheme: "system" as const, back: "/" };

function freshDb() {
  const db = openDatabase(":memory:");
  migrate(db);
  return db;
}

const nvd = (over: Partial<NormalizedVuln>): NormalizedVuln => ({
  cveId: "CVE-2026-7000",
  sourceIdentifier: "psirt@ivanti.com",
  publishedAt: at,
  lastModifiedAt: at,
  vulnStatus: "Analyzed",
  description: "A flaw in the gateway.",
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

describe("B10-1: a watch made from a KEV-only page still matches once NVD's record arrives", () => {
  it("keeps CISA's vendor and product in their own columns and matches the pair against them", () => {
    const db = freshDb();
    applyKev(db, [{ cveId: "CVE-2026-7000", dateAdded: "2026-11-15", dueDate: "2026-12-06", ransomware: false, description: "Gateway flaw", vendor: "Ivanti", product: "Connect Secure" }], at);
    const row = getVuln(db, "CVE-2026-7000")!;
    expect(row).toMatchObject({ kev_vendor: "ivanti", kev_product: "connect secure" });
    const offered = watchCandidates([], JSON.parse(row.vendors_json!), JSON.parse(row.products_json!), { vendor: row.kev_vendor, product: row.kev_product });
    expect(offered).toEqual(["ivanti", "ivanti:connect secure"]);
    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('product', 'ivanti:connect secure', NULL, ?)").run(at);
    const watch = db.prepare("SELECT id, kind, value, label FROM watchlist").all() as unknown as WatchEntry[];
    // NVD's record names the product by CPE, never as CISA spells it.
    const result = upsertVuln(db, nvd({ cpes: ["cpe:2.3:a:ivanti:connect_secure:22.7:*:*:*:*:*:*:*"], vendors: ["ivanti"], products: ["connect_secure"] }), at, watch);
    expect(result.watchLabels).toEqual(["ivanti:connect secure"]);
    expect(getVuln(db, "CVE-2026-7000")).toMatchObject({ watch_hit: 1, kev_vendor: "ivanti", kev_product: "connect secure", source_identifier: "psirt@ivanti.com" });
    db.close();
  });

  it("offers no pair for CISA's 'multiple products' and none from a CPE-less row's lists", () => {
    expect(watchCandidates([], ["apple"], ["multiple products"], { vendor: "apple", product: "multiple products" })).toEqual(["apple"]);
    expect(watchCandidates([], ["acme"], ["widget"])).toEqual(["acme"]);
    const entry = { kind: "product", value: "apple:multiple products", label: null } as unknown as WatchEntry;
    expect(matchWatchDetailed({ cpes: [], vendors: ["apple"], products: ["multiple products"], description: null, kevVendor: "apple", kevProduct: "multiple products" }, [entry])).toEqual([]);
    // The rule sweep 9 added, a CPE-less row's one vendor and one product, is gone.
    expect(matchWatchDetailed({ cpes: [], vendors: ["acme"], products: ["widget"], description: null }, [{ kind: "product", value: "acme:widget", label: null } as unknown as WatchEntry])).toEqual([]);
  });
});

describe("B10-2: squash keeps + and # and reads a CPE's escapes", () => {
  it("tells notepad++ from notepad and 8+ gen 1 from 8 gen 1", () => {
    expect(squash("notepad\\+\\+")).toBe("notepad++");
    expect(squash("Notepad++")).toBe("notepad++");
    expect(squash("notepad")).not.toBe(squash("notepad++"));
    expect(squash("Snapdragon 8+ Gen 1")).not.toBe(squash("Snapdragon 8 Gen 1"));
    expect(squash("vite+")).not.toBe(squash("vite"));
    expect(squash("palo_alto_networks")).toBe(squash("Palo Alto Networks"));
    const entry = { kind: "product", value: "notepad-plus-plus:notepad++", label: null } as unknown as WatchEntry;
    expect(matchWatchDetailed({ cpes: ["cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.6:*:*:*:*:*:*:*"], vendors: [], products: [], description: null }, [entry])).toHaveLength(1);
  });
});

describe("B10-3: a vendor's first word stands for it only before a company suffix", () => {
  it("does not read Justice AV Solutions as justice.gov, and still reads QNAP Systems Inc. as qnap.com", () => {
    expect(vendorDomainNames("Justice AV Solutions")).toEqual(["justiceavsolutions"]);
    expect(vendorDomainNames("QNAP Systems Inc.")).toEqual(["qnapsystemsinc", "qnap"]);
    expect(vendorDomainNames("Ricoh K.K.")).toEqual(["ricohkk", "ricoh"]);
    expect(vendorDomainNames("Fuji Electric K.K.")).toEqual(["fujielectrickk"]);
    const justice = untaggedReferences([{ url: "https://www.justice.gov/advisory", tags: [] }, { url: "https://example.org/x", tags: [] }], ["Justice AV Solutions"], null);
    expect(justice.lead?.whose).toBeNull();
    const qnap = untaggedReferences([{ url: "https://www.qnap.com/en/security-advisory/qsa-24-01", tags: [] }], ["QNAP Systems Inc."], null);
    expect(qnap.lead).toMatchObject({ host: "qnap.com", whose: "vendor" });
  });
});

describe("B10-4: the table's feed title names every filter in the table's words", () => {
  it("names EPSS, due, new, changed, moved and a label", () => {
    const db = freshDb();
    const title = (q: Record<string, string>, owner = false): string => /<title>([^<]*)<\/title>/.exec(vulnFeed(db, "https://example.test", vulnFilters(q, now, owner), "x", owner))![1]!;
    expect(title({ min_epss: "0.1", max_epss: "0.5" })).toContain("EPSS 10% to 50%");
    expect(title({ epss: "none" })).toContain("EPSS no score");
    expect(title({ min_epss: "0.5" })).toContain("EPSS ≥ 50%");
    expect(title({ due: "7" })).toContain("Due this week (KEV)");
    expect(title({ new: "1" })).toContain("New, 24 h");
    expect(title({ changed: "72" })).toContain("Changed, 3 days");
    expect(title({ moved: "168" })).toContain("Moved, 7 days");
    expect(title({ label: "Edge" }, true)).toContain("Watch: Edge");
    db.close();
  });
});

describe("B10-5, B10-6, B10-9: the guide's anchors and the watchlist links", () => {
  it("has #api, #watchlist and a glossary entry for each chip", () => {
    const visitor = renderGuide({ owner: false, open: true, look });
    for (const id of ["api", "watchlist", "chips", "chip-ransomware", "chip-overdue", "chip-msrc-severity", "chip-unscored", "chip-new", "chip-draft", "chip-current", "chip-untagged", "chip-disclosed"]) expect(visitor).toContain(`id="${id}"`);
    expect(visitor).not.toContain('href="/watchlist"');
    expect(renderGuide({ owner: true, open: false, look })).toContain('href="/watchlist"');
  });

  it("sends a visitor on /stigs to the guide, the owner to the watchlist", () => {
    const db = freshDb();
    expect(renderStigsIndex({ db, now, owner: false, open: true, look })).not.toContain('href="/watchlist"');
    expect(renderStigsIndex({ db, now, owner: false, open: true, look })).toContain('href="/guide#watchlist"');
    expect(renderStigsIndex({ db, now, owner: true, open: false, look })).toContain('href="/watchlist"');
    db.close();
  });
});

describe("B10-7: one KEV chip, overdue marked the same everywhere", () => {
  it("marks a past due date overdue and a future one not", () => {
    expect(String(kevChip("2026-11-15", now))).toContain('class="chip kev overdue"');
    expect(String(kevChip("2026-11-15", now))).toContain("· overdue");
    expect(String(kevChip("2026-11-16", now))).not.toContain("overdue");
    expect(String(kevChip(null, now))).toBe('<span class="chip kev">KEV</span>');
  });

  it("is what the CVE table draws", () => {
    const db = freshDb();
    applyKev(db, [{ cveId: "CVE-2026-7100", dateAdded: "2026-10-01", dueDate: "2026-10-22", ransomware: false, description: "x", vendor: "Acme", product: "Widget" }], at);
    expect(renderVulnList({ db, filters: vulnFilters({ kev: "1" }, now), owner: false, open: true, now, look })).toContain("KEV · due 2026-10-22 · overdue");
    db.close();
  });
});

describe("B10-8: CVSS change rows that were NVD's spelling alone", () => {
  it("deletes a row equal without its X metrics and rewrites the rest without them", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "bw-mig-"));
    const src = path.join(import.meta.dirname, "..", "src", "migrations");
    try {
      for (const f of readdirSync(src).filter((f) => f < "0074")) copyFileSync(path.join(src, f), path.join(dir, f));
      const db = openDatabase(":memory:");
      migrate(db, dir);
      const v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
      const x = "/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X";
      const insert = db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field, before_text, after_text) VALUES ('CVE-2026-1', ?, 'cvss', ?, ?)");
      insert.run(at, `9.3 (v4.0, ${v})`, `9.3 (v4.0, ${v}${x})`);
      insert.run(at, `9.3 (v4.0, ${v}${x})`, `8.7 (v4.0, ${v.replace("AC:L", "AC:H")}/E:X/CR:X)`);
      insert.run(at, null, "9.8 (v3.1)");
      db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field, before_text, after_text) VALUES ('CVE-2026-1', ?, 'description', 'a:X)', 'b')").run(at);
      copyFileSync(path.join(src, "0074_cvss_spelling_changes.sql"), path.join(dir, "0074_cvss_spelling_changes.sql"));
      migrate(db, dir);
      const rows = db.prepare("SELECT field, before_text, after_text FROM vuln_changes ORDER BY id").all();
      expect(rows).toEqual([
        { field: "cvss", before_text: `9.3 (v4.0, ${v})`, after_text: `8.7 (v4.0, ${v.replace("AC:L", "AC:H")})` },
        { field: "cvss", before_text: null, after_text: "9.8 (v3.1)" },
        { field: "description", before_text: "a:X)", after_text: "b" },
      ]);
      db.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("B10-10: the table names a filter it ignored, and the filters that matched nothing", () => {
  it("says due=30 is not a filter it takes", () => {
    const db = freshDb();
    upsertVuln(db, nvd({ cveId: "CVE-2026-7200" }), at, []);
    const q = { due: "30", severity: "huge", kev: "1" };
    const filters = vulnFilters(q, now);
    const ignored = ignoredVulnParams(q, filters);
    expect(ignored).toEqual(["due=30", "severity=huge"]);
    expect(ignoredVulnParams({ watch: "1" }, vulnFilters({ watch: "1" }, now))).toEqual(["watch=1"]);
    expect(ignoredVulnParams({ due: "7", sort: "risk" }, vulnFilters({ due: "7", sort: "risk" }, now))).toEqual([]);
    const page = renderVulnList({ db, filters, owner: false, open: true, now, look, ignored });
    expect(page).toContain("<code>due=30</code>; <code>severity=huge</code> are not filters this table takes; showing the rest.");
    expect(page).toMatch(/Nothing matches <a href="\/vulnerabilities" title="Take this filter off">Known exploited \(KEV\)<\/a>\. Loosen/);
    const one = renderVulnList({ db, filters: vulnFilters({ due: "30" }, now), owner: false, open: true, now, look, ignored: ["due=30"] });
    expect(one).toContain("<code>due=30</code> is not a filter this table takes; showing all.");
    db.close();
  });
});
