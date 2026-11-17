import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { registrableDomain, registrableName, untaggedReferences } from "../src/fix.ts";
import { releaseForVisitor, type Release } from "../src/fleet.ts";
import { pathName } from "../src/pages/digest.ts";
import { patchTuesdayCsv, renderPatchTuesday, type PatchTuesdayOptions } from "../src/pages/patch-tuesday.ts";
import { addSaved, listSaved, savedCounts } from "../src/saved.ts";
import { cookieFrom, formPost, startTestApp } from "./helpers.ts";

/**
 * The fourth round of the 16 November audit: the fleet's "verify" notes kept from a visitor's test
 * plan and its exports, the News saved search counted as the page lists it, Patch Tuesday's CSV and
 * fleet filter, and the CNA's mail domain read through the registrable domain.
 */

const at = "2026-11-16T12:00:00.000Z";
const now = new Date(at);
const look = { look: "register" as const, scheme: "system" as const, back: "/" };

function freshDb() {
  const db = openDatabase(":memory:");
  migrate(db);
  return db;
}

describe("B7-1: the fleet's to-do notes stay the owner's on the test plan and its exports", () => {
  it("drops the verify marks for a visitor, page and export alike, and keeps them for the owner", async () => {
    const app = await startTestApp({ now: () => now, env: { BW_ADMIN_PASSWORD: "hunter2hunter2" } });
    try {
      const visitor = await (await fetch(`${app.base}/baselines/ios/tests?version=27`)).text();
      expect(visitor).toContain("NIST macOS Security Compliance Project, ios_27 branch");
      expect(visitor).not.toContain("ios_27 branch (verify)");
      expect(visitor).not.toContain("(verify it has been published)");
      const md = await (await fetch(`${app.base}/baselines/ios/tests/export?format=md&version=27`)).text();
      expect(md).toContain("ios_27 branch");
      expect(md).not.toMatch(/\bverify\b/i);
      const macJson = await (await fetch(`${app.base}/baselines/macos/tests/export?format=json&version=27`)).text();
      expect(macJson).toContain("about September 2029)");
      expect(macJson).not.toContain("verify)");

      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
      const owner = await (await fetch(`${app.base}/baselines/ios/tests/export?format=md&version=27`, { headers: { cookie } })).text();
      expect(owner).toContain("ios_27 branch (verify)");
    } finally {
      await app.close();
    }
  });

  it("leaves out an ended release's notes, as /fleet does", () => {
    const release: Release = {
      platform: "windows",
      id: "23h2",
      label: "Windows 11, version 23H2",
      status: "supported",
      released: "2023-10-31",
      supportEnds: "Enterprise and Education 2026-11-10 (verify)",
      hardware: [],
      models: "Any (verify)",
      baselines: ["A baseline (verify the date)"],
      documents: {},
      notes: ["Weeks left on Enterprise (verify)"],
      sources: [],
    };
    expect(releaseForVisitor(release, new Date("2026-11-01T00:00:00Z"))).toMatchObject({ supportEnds: "Enterprise and Education 2026-11-10", models: "Any", baselines: ["A baseline"], notes: ["Weeks left on Enterprise"] });
    expect(releaseForVisitor(release, now).notes).toEqual([]);
  });
});

describe("B7-2: a News saved search counts what the page lists", () => {
  it("counts every matching copy, folded by story among the matching rows alone", () => {
    const db = freshDb();
    const item = db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, canonical_url, published_at, fetched_at) VALUES (?, 'article', ?, ?, ?, ?, ?, ?)");
    item.run("bleeping", "a", "A long headline about one patched flaw", "https://example.net/a", "https://example.net/a", "2026-11-16T08:00:00.000Z", at);
    item.run("krebs", "b", "A long headline about one patched flaw", "https://example.net/a", "https://example.net/a", "2026-11-16T09:00:00.000Z", at);
    item.run("darkreading", "c", "A long headline about one patched flaw", "https://example.org/c", "https://example.org/c", "2026-11-16T10:00:00.000Z", at);
    addSaved(db, "Krebs", "/?source=krebs", at);
    addSaved(db, "All", "/", at);
    const saved = (name: string) => listSaved(db).find((s) => s.name === name)!;
    // The krebs copy is a later copy of bleeping's address: hidden among all items it counted none.
    expect(savedCounts(db, saved("Krebs"), now)).toEqual({ total: 1, fresh: 1 });
    // Three rows, one story: the same address and the same headline fold into one card.
    expect(savedCounts(db, saved("All"), now)).toEqual({ total: 1, fresh: 1 });
    db.close();
  });
});

describe("B7-3 to B7-5: Patch Tuesday's CSV and fleet filter", () => {
  const insert = (db: ReturnType<typeof freshDb>, cve: string, fixes: unknown[]) =>
    db.prepare("INSERT INTO msrc_vulns (cve_id, release_id, title, family, vendor, severity, fixes_json, released_at, seen_at) VALUES (?, '2026-Nov', ?, 'Windows Shell', 'Microsoft', 'Important', ?, '2026-11-10T08:00:00Z', ?)").run(cve, `Flaw ${cve}`, JSON.stringify(fixes), at);
  const options = (db: ReturnType<typeof freshDb>, over: Partial<PatchTuesdayOptions> = {}): PatchTuesdayOptions => ({ db, releaseId: undefined, family: undefined, q: undefined, all: false, owner: true, open: false, now, look, ...over });

  it("separates the updates with '; ', lists their addresses, and matches a no-KB fix by its own key", () => {
    const db = freshDb();
    insert(db, "CVE-2026-1001", [
      { kb: null, url: "https://learn.microsoft.com/notes/one", label: "Release Notes", products: ["Microsoft 365 Apps"], fixedBuild: null, restart: null },
      { kb: null, url: "https://learn.microsoft.com/notes/two", label: "Release Notes", products: ["Office for Mac"], fixedBuild: null, restart: null },
    ]);
    // One entry naming 24H2 twice under two cases: the summary holds it once, so fixKey(summary) is not the entry's key.
    insert(db, "CVE-2026-1002", [{ kb: null, url: "https://learn.microsoft.com/notes/win", label: "Release Notes", products: ["Windows 11 Version 24H2", "Windows 11 version 24H2"], fixedBuild: null, restart: null }]);
    const lines = patchTuesdayCsv(options(db), "https://example.test")!.trim().split("\r\n");
    expect(lines[0]).toBe("cve,severity,cvss,component,title,exploited,disclosed,updates,update_urls,release,url");
    expect(lines.find((l) => l.startsWith("CVE-2026-1001"))).toContain("Release Notes; Release Notes,https://learn.microsoft.com/notes/one; https://learn.microsoft.com/notes/two,2026-Nov");

    const fleet = patchTuesdayCsv(options(db, { fleet: true }), "https://example.test")!.trim().split("\r\n");
    expect(fleet.map((l) => l.split(",")[0])).toEqual(["cve", "CVE-2026-1002"]);

    // Every fleet release ended: ?fleet=1 lists none and says why, rather than everything.
    const later = new Date("2040-01-01T00:00:00Z");
    expect(patchTuesdayCsv(options(db, { fleet: true, now: later }), "https://example.test")!.trim().split("\r\n")).toHaveLength(1);
    const page = renderPatchTuesday(options(db, { fleet: true, now: later }))!;
    expect(page).toContain("No Windows release in your fleet has an update in this release.");
    expect(page).not.toContain("CVE-2026-1001</");
    db.close();
  });

  it("serves the same rows at /vulnerabilities/microsoft.csv", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      insert(app.db, "CVE-2026-1001", [
        { kb: null, url: "https://learn.microsoft.com/notes/one", label: "Release Notes", products: ["Microsoft 365 Apps"], fixedBuild: null, restart: null },
        { kb: "5127648", url: "https://support.microsoft.com/help/5127648", label: null, products: ["Windows 11 Version 25H2"], fixedBuild: null, restart: null },
      ]);
      const res = await fetch(`${app.base}/vulnerabilities/microsoft.csv`);
      expect(res.headers.get("content-type")).toContain("text/csv");
      expect(res.headers.get("content-disposition")).toContain("patch-tuesday-latest.csv");
      const csv = await res.text();
      expect(csv).toContain("Release Notes; KB5127648,https://learn.microsoft.com/notes/one; https://support.microsoft.com/help/5127648,2026-Nov,");
    } finally {
      await app.close();
    }
  });
});

describe("C7-1, C7-2: the registrable domain and the menu's names", () => {
  it("matches a CNA's mail domain under a two-level suffix, and names an address as the menu does", () => {
    expect(registrableDomain("www.bbc.co.uk")).toBe("bbc.co.uk");
    expect(registrableDomain("support.citrix.com")).toBe("citrix.com");
    expect(registrableName("www.bbc.co.uk")).toBe("bbc");
    const refs = [
      { url: "https://other.co.uk/advisory", tags: [] },
      { url: "https://psirt.vendor.co.uk/advisory", tags: [] },
    ];
    // The last two labels of both were "co.uk"; the first reference was named the CNA's.
    expect(untaggedReferences(refs, [], "psirt@vendor.co.uk").lead).toMatchObject({ url: "https://psirt.vendor.co.uk/advisory", whose: "CNA" });
    expect(pathName("/scan")).toBe("This browser");
    expect(pathName("/scan/domain")).toBe("A domain");
    expect(pathName("/vulnerabilities/microsoft")).toBe("Patch Tuesday");
    expect(pathName("/")).toBe("News");
    expect(pathName("/register?x=1")).toBe("Change register");
  });
});
