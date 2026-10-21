import { describe, expect, it } from "vitest";
import { foldIcsLine, robotsText, rssDocument } from "../src/feeds.ts";
import { upsertItems } from "../src/items.ts";
import { startTestApp } from "./helpers.ts";

/**
 * Feeds out (N6): the News and the table as RSS under their own filters, the sources as OPML,
 * KEV due dates as a calendar, and what a crawler is told.
 */

const now = new Date("2026-10-21T22:00:00Z");

describe("the RSS document", () => {
  it("escapes what XML must, and dates the items as RFC 822", () => {
    const text = rssDocument({ title: "T & U", link: "http://x", description: "d", self: "http://x/feed.xml" }, [{ title: "a <b> & c", link: "http://x/1?a=1&b=2", guid: "g", date: "2026-10-21T12:00:00.000Z", description: null }]);
    expect(text.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
    expect(text).toContain("<title>T &amp; U</title>");
    expect(text).toContain("<title>a &lt;b&gt; &amp; c</title>");
    expect(text).toContain("<link>http://x/1?a=1&amp;b=2</link>");
    expect(text).toContain("<pubDate>Wed, 21 Oct 2026 12:00:00 GMT</pubDate>");
    expect(text).not.toContain("<description></description>");
  });
});

describe("the calendar's lines", () => {
  it("fold at 74 characters with a continuation space, and short ones stay whole", () => {
    expect(foldIcsLine("SUMMARY:short")).toBe("SUMMARY:short");
    const folded = foldIcsLine(`DESCRIPTION:${"x".repeat(200)}`);
    for (const line of folded.split("\r\n")) expect(line.length).toBeLessThanOrEqual(75);
    expect(folded.split("\r\n")[1]?.startsWith(" ")).toBe(true);
    expect(folded.replace(/\r\n /g, "")).toBe(`DESCRIPTION:${"x".repeat(200)}`);
  });
});

describe("robots.txt", () => {
  it("closes a closed instance and names the sitemap on an open one", () => {
    expect(robotsText(false, "http://x")).toBe("User-agent: *\nDisallow: /\n");
    const open = robotsText(true, "http://x");
    expect(open).toContain("Disallow: /login");
    expect(open).toContain("Disallow: /api/");
    expect(open).toContain("Sitemap: http://x/sitemap.xml");
  });
});

describe("on the instance", () => {
  it("serves the News and the table as RSS under their filters, the OPML, the calendar and the sitemap", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      const db = app.db;
      const at = now.toISOString();
      upsertItems(db, "bleeping", [{ kind: "article", externalId: "n1", title: "A story about CVE-2026-1 & more", url: "https://example.test/story", summary: "Said <b>plainly</b>.", publishedAt: "2026-10-21T10:00:00.000Z", signals: { cves: ["CVE-2026-1"] } }], at);
      upsertItems(db, "ubuntu-usn", [{ kind: "article", externalId: "usn-1", title: "USN-1: a fix", url: "https://ubuntu.com/security/notices/USN-1", summary: null, publishedAt: "2026-10-21T09:00:00.000Z", signals: { cves: ["CVE-2026-1"] } }], at);
      db.prepare("INSERT INTO vulns (cve_id, last_modified_at, cvss_score, cvss_severity, description, kev, kev_date_added, kev_due_date, first_seen_at, last_seen_at, vendors_json) VALUES ('CVE-2026-1', ?, 9.8, 'CRITICAL', 'A flaw, with a comma; and a semicolon', 1, '2026-10-20', '2026-11-10', ?, ?, '[\"acme\"]')").run(at, at, at);
      db.prepare("INSERT INTO vulns (cve_id, last_modified_at, cvss_score, cvss_severity, description, kev, first_seen_at, last_seen_at) VALUES ('CVE-2026-2', ?, 5.0, 'MEDIUM', 'Quiet', 0, ?, ?)").run(at, at, at);

      // Links in the bodies carry the configured base address, not the loopback one the test dials.
      const site = /Sitemap: (\S+)\/sitemap\.xml/.exec(await (await fetch(`${app.base}/robots.txt`)).text())?.[1] ?? "";
      expect(site).toMatch(/^http:\/\//);
      const all = await fetch(`${app.base}/feed.xml`);
      expect(all.headers.get("content-type")).toContain("application/rss+xml");
      expect(all.headers.get("cache-control")).toBe("public, max-age=300");
      const allText = await all.text();
      expect(allText).toContain("<title>A story about CVE-2026-1 &amp; more</title>");
      expect(allText).toContain("<guid isPermaLink=\"false\">bleeping:n1</guid>");
      expect(allText).toContain("<title>USN-1: a fix</title>");
      expect(allText).toContain(`<atom:link href="${site}/feed.xml" rel="self"`);
      const vendors = await (await fetch(`${app.base}/feed.xml?group=vulnerabilities`)).text();
      expect(vendors).toContain("USN-1");
      expect(vendors).not.toContain("A story about");

      const kev = await (await fetch(`${app.base}/vulnerabilities/feed.xml?kev=1`)).text();
      expect(kev).toContain("<title>CVE-2026-1 · CVSS 9.8 critical · KEV</title>");
      expect(kev).toContain(`<link>${site}/vulnerabilities/CVE-2026-1</link>`);
      expect(kev).toContain("<description>acme. A flaw, with a comma; and a semicolon</description>");
      expect(kev).not.toContain("CVE-2026-2");
      expect(await (await fetch(`${app.base}/vulnerabilities/feed.xml`)).text()).toContain("CVE-2026-2");

      const opml = await fetch(`${app.base}/sources.opml`);
      expect(opml.headers.get("content-type")).toContain("text/x-opml");
      const opmlText = await opml.text();
      expect(opmlText).toContain('xmlUrl="https://ubuntu.com/security/notices/rss.xml"');
      expect(opmlText).toContain(`xmlUrl="${site}/vulnerabilities/feed.xml?kev=1"`);

      const ics = await fetch(`${app.base}/vulnerabilities/kev.ics`);
      expect(ics.headers.get("content-type")).toContain("text/calendar");
      const icsText = await ics.text();
      expect(icsText.startsWith("BEGIN:VCALENDAR\r\n")).toBe(true);
      expect(icsText).toContain("UID:kev-CVE-2026-1@baselinewatch");
      expect(icsText).toContain("DTSTART;VALUE=DATE:20261110");
      expect(icsText).toContain("DTEND;VALUE=DATE:20261111");
      expect(icsText).toContain("SUMMARY:KEV due: CVE-2026-1 — A flaw\\, with a comma\\; and a semicolon");
      expect(icsText).toContain(`URL:${site}/vulnerabilities/CVE-2026-1`);
      // The watchlist narrowing leaves a CVE no entry matched out.
      expect(await (await fetch(`${app.base}/vulnerabilities/kev.ics?watch=1`)).text()).not.toContain("CVE-2026-1");

      const sitemap = await (await fetch(`${app.base}/sitemap.xml`)).text();
      expect(sitemap).toContain(`<loc>${site}/vulnerabilities</loc>`);
      expect(sitemap).toContain(`<loc>${site}/standards/nist-sp-800-53</loc>`);
      expect(sitemap).toContain(`<loc>${site}/baselines/windows</loc>`);
      const robots = await (await fetch(`${app.base}/robots.txt`)).text();
      expect(robots).toContain(`Sitemap: ${site}/sitemap.xml`);

      // Readers find the feeds from the pages, and the Feeds page names them.
      const news = await (await fetch(`${app.base}/?group=news`)).text();
      expect(news).toContain('<link rel="alternate" type="application/rss+xml" title="News" href="/feed.xml?group=news">');
      const table = await (await fetch(`${app.base}/vulnerabilities?kev=1`)).text();
      expect(table).toContain('href="/vulnerabilities/feed.xml?kev=1">');
      const feeds = await (await fetch(`${app.base}/feeds`)).text();
      expect(feeds).toContain(`${site}/vulnerabilities/kev.ics?watch=1`);
      expect(feeds).toContain("Feeds");
    } finally {
      await app.close();
    }
  });

  it("tells a crawler a closed instance has nothing, before the gate", async () => {
    const app = await startTestApp({ env: { BW_PUBLIC_READ: "false", BW_ADMIN_PASSWORD: "x" }, now: () => now });
    try {
      const robots = await fetch(`${app.base}/robots.txt`);
      expect(robots.status).toBe(200);
      expect(await robots.text()).toBe("User-agent: *\nDisallow: /\n");
      expect((await fetch(`${app.base}/feed.xml`)).status).toBe(401);
      expect((await fetch(`${app.base}/sitemap.xml`)).status).toBe(401);
    } finally {
      await app.close();
    }
  });
});
