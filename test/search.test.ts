import { describe, expect, it } from "vitest";
import { upsertItems } from "../src/items.ts";
import { startTestApp } from "./helpers.ts";

/** The masthead's one search (N6): CVEs, the News, controls, Microsoft's rows and sources in one page. */

const now = new Date("2026-10-21T22:00:00Z");
const at = now.toISOString();

describe("/search", () => {
  it("is on every masthead, opens a CVE typed whole, and sections everything else", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      const db = app.db;
      db.prepare("INSERT INTO vulns (cve_id, last_modified_at, cvss_score, cvss_severity, description, kev, first_seen_at, last_seen_at, vendors_json) VALUES ('CVE-2026-5555', ?, 9.1, 'CRITICAL', 'Widget overflow in Acme Router', 1, ?, ?, '[\"acme\"]')").run(at, at, at);
      upsertItems(db, "bleeping", [{ kind: "article", externalId: "w1", title: "Acme widget overflow exploited in the wild", url: "https://b/w1", summary: "Patch now.", publishedAt: at, signals: { cves: ["CVE-2026-5555"] } }], at);
      db.prepare("INSERT INTO msrc_vulns (cve_id, release_id, title, severity, exploited, disclosed, fixes_json, released_at, seen_at) VALUES ('CVE-2026-7777', '2026-Oct', 'Windows Widget Service Elevation of Privilege', 'Important', 1, 0, '[{\"kb\":\"5127648\",\"url\":null,\"label\":null,\"products\":[],\"fixedBuild\":null,\"restart\":null}]', ?, ?)").run(at, at);

      const home = await (await fetch(`${app.base}/`)).text();
      expect(home).toContain('<form class="mast-search" method="get" action="/search" role="search">');

      const direct = await fetch(`${app.base}/search?q=cve-2026-5555`, { redirect: "manual" });
      expect(direct.status).toBe(302);
      expect(direct.headers.get("location")).toBe("/vulnerabilities/CVE-2026-5555");
      // An id this instance does not hold is searched, not redirected into a 404.
      expect((await fetch(`${app.base}/search?q=CVE-2026-9999`, { redirect: "manual" })).status).toBe(200);

      const page = await (await fetch(`${app.base}/search?q=widget`)).text();
      expect(page).toContain("hit(s) for “widget”");
      expect(page).toContain('<a href="/vulnerabilities/CVE-2026-5555">CVE-2026-5555</a>');
      expect(page).toContain("Acme widget overflow exploited in the wild");
      expect(page).toContain('href="/vulnerabilities?q=widget"');
      expect(page).toContain("Microsoft&#39;s updates");
      expect(page).toContain("Windows Widget Service Elevation of Privilege");

      const kb = await (await fetch(`${app.base}/search?q=5127648`)).text();
      expect(kb).toContain("CVE-2026-7777");
      const nothing = await (await fetch(`${app.base}/search?q=zzzzqqq`)).text();
      expect(nothing).toContain("Nothing for “zzzzqqq”");
      const empty = await (await fetch(`${app.base}/search`)).text();
      expect(empty).toContain("in one go");
      const source = await (await fetch(`${app.base}/search?q=bleeping`)).text();
      expect(source).toContain('<a href="/?source=bleeping">BleepingComputer</a>');
    } finally {
      await app.close();
    }
  });
});
