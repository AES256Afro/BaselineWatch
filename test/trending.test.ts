import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { upsertItems } from "../src/items.ts";
import { cveMentions, newsFor, trendingCves } from "../src/trending.ts";
import { startTestApp } from "./helpers.ts";

/** Which CVEs the News is talking about (N6): counted by distinct source, in a window. */

const now = new Date("2026-10-21T22:00:00Z");
const at = now.toISOString();
const since = new Date(now.getTime() - 7 * 86_400_000).toISOString();

function seed(db: DatabaseSync): void {
  upsertItems(db, "bleeping", [
    { kind: "article", externalId: "b1", title: "Everyone is talking about CVE-2026-1010", url: "https://b/1", summary: null, publishedAt: "2026-10-21T10:00:00.000Z", signals: { cves: ["CVE-2026-1010", "CVE-2026-1011"] } },
    { kind: "article", externalId: "b2", title: "Still talking about CVE-2026-1010", url: "https://b/2", summary: null, publishedAt: "2026-10-20T10:00:00.000Z", signals: { cves: ["CVE-2026-1010"] } },
    { kind: "article", externalId: "b3", title: "Old news about CVE-2026-1012", url: "https://b/3", summary: null, publishedAt: "2026-09-01T10:00:00.000Z", signals: { cves: ["CVE-2026-1012"] } },
  ], at);
  upsertItems(db, "krebs", [{ kind: "article", externalId: "k1", title: "Krebs on CVE-2026-1010", url: "https://k/1", summary: null, publishedAt: "2026-10-19T10:00:00.000Z", signals: { cves: ["CVE-2026-1010"] } }], at);
  upsertItems(db, "ubuntu-usn", [{ kind: "article", externalId: "u1", title: "USN for CVE-2026-1010 and CVE-2026-1011", url: "https://u/1", summary: null, publishedAt: "2026-10-18T10:00:00.000Z", signals: { cves: ["CVE-2026-1010", "CVE-2026-1011"] } }], at);
}

describe("mentions", () => {
  let db: DatabaseSync;
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    seed(db);
  });
  afterEach(() => db.close());

  it("count distinct sources and items per CVE inside the window", () => {
    const m = cveMentions(db, ["cve-2026-1010", "CVE-2026-1011", "CVE-2026-1012", "CVE-2026-9999"], since);
    expect(m.get("CVE-2026-1010")).toEqual({ sources: 3, items: 4 });
    expect(m.get("CVE-2026-1011")).toEqual({ sources: 2, items: 2 });
    // Named a month ago only: outside the window.
    expect(m.has("CVE-2026-1012")).toBe(false);
    expect(m.has("CVE-2026-9999")).toBe(false);
  });

  it("rank the talked-about CVEs by sources, needing two, and say whether each is in the table", () => {
    db.prepare("INSERT INTO vulns (cve_id, last_modified_at, first_seen_at, last_seen_at) VALUES ('CVE-2026-1010', ?, ?, ?)").run(at, at, at);
    const top = trendingCves(db, since, 5);
    expect(top.map((t) => [t.cveId, t.sources, t.items, t.known])).toEqual([["CVE-2026-1010", 3, 4, true], ["CVE-2026-1011", 2, 2, false]]);
    expect(top[0]?.headline).toBe("Everyone is talking about CVE-2026-1010");
    expect(trendingCves(db, "2026-10-21T20:00:00.000Z")).toEqual([]);
  });

  it("count one page two feeds both carry as one mention", () => {
    // CISA's advisories feed and its ICS feed carry the same advisory under one URL.
    upsertItems(db, "cisa-advisories", [{ kind: "article", externalId: "c1", title: "ICSA-26-300-01 on CVE-2026-2020", url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-300-01", summary: null, publishedAt: "2026-10-21T09:00:00.000Z", signals: { cves: ["CVE-2026-2020"] } }], at);
    upsertItems(db, "krebs", [{ kind: "article", externalId: "c2", title: "ICSA-26-300-01 on CVE-2026-2020", url: "https://WWW.cisa.gov/news-events/ics-advisories/icsa-26-300-01/#top", summary: null, publishedAt: "2026-10-21T08:00:00.000Z", signals: { cves: ["CVE-2026-2020"] } }], at);
    expect(cveMentions(db, ["CVE-2026-2020"], since).get("CVE-2026-2020")).toEqual({ sources: 1, items: 1 });
    expect(trendingCves(db, since).some((t) => t.cveId === "CVE-2026-2020")).toBe(false);
  });

  it("read one page by the canonical URL the News de-duplicates on: tracking parameters, www and http dropped", () => {
    upsertItems(db, "cisa-advisories", [{ kind: "article", externalId: "d1", title: "On CVE-2026-3030", url: "https://www.example.org/advisory/1?utm_source=rss", summary: null, publishedAt: "2026-10-21T09:00:00.000Z", signals: { cves: ["CVE-2026-3030"] } }], at);
    upsertItems(db, "krebs", [{ kind: "article", externalId: "d2", title: "On CVE-2026-3030", url: "http://example.org/advisory/1", summary: null, publishedAt: "2026-10-21T08:00:00.000Z", signals: { cves: ["CVE-2026-3030"] } }], at);
    expect(cveMentions(db, ["CVE-2026-3030"], since).get("CVE-2026-3030")).toEqual({ sources: 1, items: 1 });
  });

  it("list the news items naming a CVE, not the vendor advisories the Fix panel already lists", () => {
    const news = newsFor(db, "CVE-2026-1010");
    expect(news.map((n) => n.source_id)).toEqual(["bleeping", "bleeping", "krebs"]);
    expect(news[0]?.title).toBe("Everyone is talking about CVE-2026-1010");
  });
});

describe("on the pages", () => {
  it("marks a talked-about CVE in the table, lists the news on its page, and names it on Today", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      seed(app.db);
      app.db.prepare("INSERT INTO vulns (cve_id, last_modified_at, cvss_score, cvss_severity, description, first_seen_at, last_seen_at) VALUES ('CVE-2026-1010', ?, 8.8, 'HIGH', 'Talked about', ?, ?)").run(at, at, at);
      const table = await (await fetch(`${app.base}/vulnerabilities`)).text();
      expect(table).toContain('<span class="chip news" title="Named by 3 sources in the last 7 days">news ×3</span>');
      const cve = await (await fetch(`${app.base}/vulnerabilities/CVE-2026-1010`)).text();
      expect(cve).toContain("In the news");
      expect(cve).toContain("Krebs on CVE-2026-1010");
      expect(cve).not.toContain("USN for CVE-2026-1010 and CVE-2026-1011</a> <span class=\"small\"><a href=\"/?source=ubuntu-usn\">");
      const today = await (await fetch(`${app.base}/today`)).text();
      expect(today).toContain("Talked about");
      expect(today).toContain('<a href="/vulnerabilities/CVE-2026-1010">CVE-2026-1010</a> <span class="small">3 sources');
    } finally {
      await app.close();
    }
  });
});
