import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { buildDigest } from "../src/digest.ts";
import { untaggedReferences } from "../src/fix.ts";
import { renderSearch } from "../src/pages/search.ts";
import { watchCandidates } from "../src/pages/vulnerabilities.ts";
import { buildTestPlan, exportPlan } from "../src/testplans.ts";
import { matchWatchDetailed, type WatchEntry } from "../src/vulns.ts";
import { cookieFrom, formPost, startTestApp } from "./helpers.ts";

/**
 * The sixth round of the 16 November audit: a watch offered from a KEV-only CVE matches it, the
 * test plan's unticked checks are named in every export, the digest's triage line counts the
 * inbox Today shows, the triage form refuses a subject with no row, a vendor written with its
 * company suffix finds its domain, and the search heading says when a section was cut off.
 */

const at = "2026-11-16T12:00:00.000Z";
const now = new Date(at);

function freshDb() {
  const db = openDatabase(":memory:");
  migrate(db);
  return db;
}

describe("B9-1: every pair the CVE page offers matches its own row", () => {
  it("holds for a KEV-only row (no CPEs) and an NVD row", () => {
    const rows = [
      { cpes: [], vendors: ["qnap systems inc."], products: ["qts"], description: null, kevVendor: "qnap systems inc.", kevProduct: "qts" },
      { cpes: ["cpe:2.3:o:fortinet:fortios:7.0.1:*:*:*:*:*:*:*"], vendors: ["fortinet"], products: ["fortios"], description: null, kevVendor: null, kevProduct: null },
    ];
    for (const row of rows) {
      const offered = watchCandidates(row.cpes, row.vendors, row.products, { vendor: row.kevVendor, product: row.kevProduct });
      expect(offered.some((v) => v.includes(":")), offered.join()).toBe(true);
      for (const value of offered) {
        const entry = { kind: "product", value, label: null } as unknown as WatchEntry;
        expect(matchWatchDetailed(row, [entry]), value).toHaveLength(1);
      }
    }
    // Two products and no CPE name no pair, offered or matched.
    expect(matchWatchDetailed({ cpes: [], vendors: ["acme"], products: ["a", "b"], description: null }, [{ kind: "product", value: "acme:a", label: null } as unknown as WatchEntry])).toEqual([]);
  });
});

describe("B9-2: an unticked check is named in every export", () => {
  it("lists it as not tested and counts it in the summary of md, csv and json", () => {
    const db = freshDb();
    const dir = mkdtempSync(path.join(os.tmpdir(), "bw-r6-"));
    try {
      writeFileSync(path.join(dir, "fw.yaml"), "id: fw\ntitle: Firewall\nplatforms: [linux]\narea: network\nsteps:\n  - do: Check the firewall\n    expect: Active\n  - do: Check the rules\n    expect: Listed\n");
      const plan = buildTestPlan(db, { platform: "linux", drop: ["template:fw:2"] }, dir);
      expect(plan.counts.dropped).toBe(1);
      const meta = { baseUrl: "https://example.test", generatedAt: at, version: "0.0.0" };
      const md = String(exportPlan(plan, "md", meta).body);
      expect(md.split("\n")[2]).toContain("1 unticked.");
      expect(md).toContain("- **fw 2** Check the rules: unticked for this plan.");
      expect(md).not.toContain("- [ ] **fw 2**");
      const csv = String(exportPlan(plan, "csv", meta).body).split("\r\n");
      expect(csv.some((l) => l.startsWith("fw 2") || l.includes(",fw 2,"))).toBe(false);
      expect(csv.at(-2)).toContain("1 unticked.");
      expect(csv.at(-2)).toContain("Unticked: fw 2.");
      const json = JSON.parse(String(exportPlan(plan, "json", meta).body)) as { counts: { dropped: number }; notTested: { label: string; why: string }[] };
      expect(json.counts.dropped).toBe(1);
      expect(json.notTested).toContainEqual({ label: "fw 2", title: "Check the rules", why: "unticked for this plan" });
      const all = buildTestPlan(db, { platform: "linux" }, dir);
      expect(String(exportPlan(all, "md", meta).body)).not.toContain("unticked");
      expect(String(exportPlan(all, "csv", meta).body)).not.toContain("unticked");
    } finally {
      rmSync(dir, { recursive: true, force: true });
      db.close();
    }
  });
});

describe("B9-3: the digest's triage line counts the inbox Today shows", () => {
  it("says N waiting, the owner's with the watchlist arm and a visitor's the window alone", () => {
    const db = freshDb();
    const kev = (cve: string, published: string) =>
      db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at) VALUES ('cisa-kev', 'kev', ?, 'x', 'https://example.test', ?, ?)").run(cve, published, published);
    kev("CVE-2026-0001", "2026-11-15T00:00:00.000Z");
    kev("CVE-2026-0002", "2026-11-14T00:00:00.000Z");
    // Older than the window, but on the watchlist: the owner's inbox holds it, a visitor's does not.
    kev("CVE-2025-0003", "2025-01-01T00:00:00.000Z");
    db.prepare("INSERT INTO vulns (cve_id, last_modified_at, vuln_status, description, cwes_json, cpes_json, vendors_json, products_json, kev, watch_hit, first_seen_at, last_seen_at) VALUES ('CVE-2025-0003', ?, 'Analyzed', 'x', '[]', '[]', '[]', '[]', 1, 1, ?, ?)").run(at, at, at);
    const { text, publicText } = buildDigest(db, { from: "2026-11-15T12:00:00.000Z", to: at, baseUrl: "https://bw.example", period: "daily" });
    expect(text).toMatch(/^Triage: 0 affects us, 0 reviewing, 3 waiting https:\/\/bw\.example\/triage$/m);
    expect(publicText).toMatch(/^Triage: 0 affects us, 0 reviewing, 2 waiting https:\/\/bw\.example\/triage$/m);
    expect(text).not.toMatch(/^Triage:.* new/m);
    db.close();
  });
});

describe("B9-4: the triage form refuses a CVE or an item it has no row for", () => {
  it("answers 400 and writes no card", async () => {
    const app = await startTestApp({ now: () => now, env: { BW_ADMIN_PASSWORD: "hunter2hunter2" } });
    try {
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
      expect((await formPost(app.base, "/triage", { kind: "vuln", id: "424242", state: "reviewing" }, cookie)).status).toBe(400);
      expect((await formPost(app.base, "/triage", { kind: "item", id: "424242", state: "reviewing" }, cookie)).status).toBe(400);
      expect(app.db.prepare("SELECT COUNT(*) AS n FROM triage").get()).toEqual({ n: 0 });
      const item = Number(app.db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at) VALUES ('cisa-kev', 'kev', 'CVE-2026-0009', 'x', 'https://example.test', ?, ?)").run(at, at).lastInsertRowid);
      expect((await formPost(app.base, "/triage", { kind: "item", id: String(item), state: "reviewing" }, cookie)).status).toBe(303);
      expect(app.db.prepare("SELECT COUNT(*) AS n FROM triage").get()).toEqual({ n: 1 });
    } finally {
      await app.close();
    }
  });
});

describe("B9-5: a vendor written with its company suffix finds its own domain", () => {
  it("compares the name's first word too, and still skips user-content hosts", () => {
    const refs = [
      { url: "https://example.org/writeup", tags: [] },
      { url: "https://www.qnap.com/en/security-advisory/qsa-26-01", tags: [] },
    ];
    expect(untaggedReferences(refs, ["QNAP Systems Inc."], null).lead).toMatchObject({ host: "qnap.com", whose: "vendor" });
    expect(untaggedReferences([{ url: "https://example.org/x", tags: [] }, { url: "https://raw.githubusercontent.com/x", tags: [] }], ["GitHub Inc."], null).lead?.whose).toBeNull();
    // A first word under three letters is no name.
    expect(untaggedReferences([{ url: "https://example.org/x", tags: [] }, { url: "https://hp.com/x", tags: [] }], ["HP Inc."], null).lead?.whose).toBeNull();
  });
});

describe("B9-6: the search heading says when a section was cut off", () => {
  it("prints N+ results when a section is at its limit", () => {
    const db = freshDb();
    const look = { look: "register" as const, scheme: "system" as const, back: "/" };
    for (let i = 0; i < 11; i++) {
      db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at) VALUES ('cisa-kev', 'article', ?, 'Zyxelquux router flaw', 'https://example.test', ?, ?)").run(`a${i}`, at, at);
    }
    const page = renderSearch({ db, q: "zyxelquux", owner: true, open: true, now, look });
    expect(page).toMatch(/\d+\+ results for/);
    const one = renderSearch({ db, q: "no-such-wordxyz", owner: true, open: true, now, look });
    expect(one).toContain("Nothing for");
    db.close();
  });
});
