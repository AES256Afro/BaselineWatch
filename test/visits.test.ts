import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import type { DnsLookup } from "../src/domaincheck.ts";
import { runHousekeeping } from "../src/housekeeping.ts";
import { classifyAgent, maxPagesPerPerson, networkOf, publicAddress, referrerHost, visitKind, visitReport, VisitRecorder, type VisitFacts } from "../src/visits.ts";
import { cookieFrom, formPost, startTestApp } from "./helpers.ts";

/** Who reads the site: counted on the server, no address kept, the owner's page to read it on. */

const chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
const iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1";
const googlebot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const browser = { acceptLanguage: true, fetchMetadata: true };
const bare = { acceptLanguage: false, fetchMetadata: false };

describe("what kind of program asked", () => {
  it("names people's browsers, assistants, crawlers, readers and tools", () => {
    expect(classifyAgent(chrome, browser)).toEqual({ kind: "person", name: "Chrome", os: "Windows", device: "desktop" });
    expect(classifyAgent(iphone, browser)).toEqual({ kind: "person", name: "Safari", os: "iOS", device: "phone" });
    // A browser's name without the headers every browser sends is a script wearing it.
    expect(classifyAgent(chrome, { acceptLanguage: false, fetchMetadata: true })).toMatchObject({ kind: "unknown", name: "Chrome, no Accept-Language" });
    expect(classifyAgent(chrome, { acceptLanguage: true, fetchMetadata: false })).toMatchObject({ kind: "unknown", name: "Chrome, no Sec-Fetch headers" });
    expect(classifyAgent("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot", bare)).toMatchObject({ kind: "assistant", name: "ChatGPT-User" });
    expect(classifyAgent("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.4; +https://openai.com/gptbot)", bare)).toMatchObject({ kind: "crawler", name: "GPTBot" });
    expect(classifyAgent("Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)", bare)).toMatchObject({ kind: "crawler", name: "PerplexityBot" });
    expect(classifyAgent(googlebot, bare)).toMatchObject({ kind: "crawler", name: "Googlebot" });
    expect(classifyAgent("Feedly/1.0 (+http://www.feedly.com/fetcher.html; 3 subscribers)", bare)).toMatchObject({ kind: "reader", name: "Feedly" });
    expect(classifyAgent("curl/8.7.1", bare)).toMatchObject({ kind: "tool", name: "curl" });
    // A crawler not on the list is still named by the token it sends.
    expect(classifyAgent("Mozilla/5.0 (compatible; ElevenlabsCrawler/1.0; +https://elevenlabs.io/docs/bots)", bare)).toMatchObject({ kind: "crawler", name: "ElevenlabsCrawler" });
    expect(classifyAgent("", bare)).toMatchObject({ kind: "unknown", name: "no User-Agent" });
  });
});

describe("which answers are visits", () => {
  it("counts pages, feeds and the API, and nothing else", () => {
    expect(visitKind("GET", "/", 200, "text/html; charset=utf-8")).toBe("page");
    expect(visitKind("GET", "/vulnerabilities", 304, "")).toBe("page");
    expect(visitKind("GET", "/wp-login.php", 404, "text/html")).toBe("page");
    expect(visitKind("GET", "/feed.xml", 200, "application/rss+xml")).toBe("feed");
    expect(visitKind("GET", "/api/v1/items", 200, "application/json")).toBe("api");
    expect(visitKind("POST", "/mcp", 200, "application/json")).toBe("api");
    expect(visitKind("GET", "/assets/app.css", 200, "text/css")).toBeNull();
    expect(visitKind("GET", "/vulnerabilities.csv", 304, "")).toBeNull();
    expect(visitKind("GET", "/health", 200, "application/json")).toBeNull();
    expect(visitKind("POST", "/login", 200, "text/html")).toBeNull();
    expect(visitKind("GET", "/wire", 301, "text/html")).toBeNull();
    expect(visitKind("GET", "/triage", 403, "text/html")).toBeNull();
  });

  it("keeps a referrer's host only when it is another site's", () => {
    expect(referrerHost("https://www.google.com/", "cybercard.net")).toBe("google.com");
    expect(referrerHost("https://cybercard.net/vulnerabilities", "cybercard.net")).toBeNull();
    expect(referrerHost("https://www.cybercard.net/", "cybercard.net")).toBeNull();
    expect(referrerHost("android-app://com.google.android.gm/", "cybercard.net")).toBe("com.google.android.gm");
    expect(referrerHost("not a url", "cybercard.net")).toBeNull();
  });

  it("counts public addresses only", () => {
    expect(publicAddress("::ffff:203.0.113.9")).toBe("203.0.113.9");
    expect(publicAddress("2001:DB8:0:0::1")).toBe("2001:db8::1");
    expect(publicAddress("192.168.8.20")).toBeNull();
    expect(publicAddress("127.0.0.1")).toBeNull();
    expect(publicAddress("::1")).toBeNull();
    expect(publicAddress("fd7a:115c:a1e0::1")).toBeNull();
    expect(publicAddress("")).toBeNull();
  });
});

/** A forward resolver that answers A records from a table. */
const forwardFrom = (table: Record<string, string[]>): DnsLookup => async (name) => ({ records: table[name] ?? [], code: table[name] ? "ok" : "nxdomain" });

describe("the network an address belongs to", () => {
  it("keeps the registered domain, and says whether the name resolves back", async () => {
    const reverse = async (ip: string) => (ip === "66.249.66.1" ? ["crawl-66-249-66-1.googlebot.com."] : ip === "203.0.113.4" ? ["host.example.co.uk"] : []);
    const forward = forwardFrom({ "crawl-66-249-66-1.googlebot.com": ["66.249.66.1"], "host.example.co.uk": ["198.51.100.1"] });
    expect(await networkOf("66.249.66.1", reverse, forward)).toEqual({ name: "googlebot.com", confirmed: true });
    expect(await networkOf("203.0.113.4", reverse, forward)).toEqual({ name: "example.co.uk", confirmed: false });
    expect(await networkOf("203.0.113.5", reverse, forward)).toBeNull();
    expect(await networkOf("203.0.113.6", async () => Promise.reject(new Error("ENOTFOUND")), forward)).toBeNull();
  });
});

const facts = (over: Partial<VisitFacts> = {}): VisitFacts => ({
  at: new Date("2026-11-17T15:00:00Z"),
  ip: "203.0.113.7",
  host: "cybercard.net",
  path: "/",
  kind: "page",
  status: 200,
  userAgent: chrome,
  acceptLanguage: true,
  fetchMetadata: true,
  country: "de",
  referer: "https://news.ycombinator.com/item?id=1",
  optOut: false,
  ...over,
});

const count = (db: ReturnType<typeof openDatabase>, table: string): number => (db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n;

describe("the recorder", () => {
  it("keeps no address, writes a person's row once the network is named, and rotates the salt by the day", async () => {
    const db = openDatabase(":memory:");
    migrate(db);
    let lookups = 0;
    const recorder = new VisitRecorder(db, {
      reverse: async (ip) => {
        lookups += 1;
        return ip === "203.0.113.7" ? ["pool-7.example.net"] : [];
      },
      forward: forwardFrom({ "pool-7.example.net": ["203.0.113.7"] }),
      timeZone: "America/Chicago",
    });
    expect(recorder.record(facts())).toBe(true);
    expect(recorder.record(facts({ path: "/vulnerabilities" }))).toBe(true);
    await recorder.settled();
    // The second visit asked while the first lookup was out: one question, both rows named.
    expect(lookups).toBe(1);
    const rows = db.prepare("SELECT * FROM visits ORDER BY id").all() as Record<string, unknown>[];
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ day: "2026-11-17", host: "cybercard.net", agent: "person", agent_name: "Chrome", country: "DE", referrer: "news.ycombinator.com", network: "example.net", network_confirmed: 1 });
    expect(rows[0]!.visitor).toBe(rows[1]!.visitor);
    expect(JSON.stringify(rows)).not.toContain("203.0.113.7");
    // Known for the rest of the day: the third visit is written at once, named, with no new lookup.
    recorder.record(facts({ path: "/today" }));
    expect(lookups).toBe(1);
    expect((db.prepare("SELECT network FROM visits ORDER BY id DESC").get() as { network: string }).network).toBe("example.net");

    // The next day (Chicago's, not UTC's): a new salt, the old one gone, so the same reader is a new hash.
    expect((db.prepare("SELECT day FROM visit_salts").all() as { day: string }[]).map((s) => s.day)).toEqual(["2026-11-17"]);
    recorder.record(facts({ at: new Date("2026-11-18T07:00:00Z") }));
    await recorder.settled();
    expect((db.prepare("SELECT day FROM visits ORDER BY id DESC").get() as { day: string }).day).toBe("2026-11-18");
    expect((db.prepare("SELECT day FROM visit_salts").all() as { day: string }[]).map((s) => s.day)).toEqual(["2026-11-18"]);
    const [today, yesterday] = db.prepare("SELECT DISTINCT visitor FROM visits ORDER BY day DESC").all() as { visitor: string }[];
    expect(today!.visitor).not.toBe(yesterday!.visitor);

    // Global Privacy Control: counted, and the address's name is not asked for.
    const asked = lookups;
    recorder.record(facts({ ip: "198.51.100.20", at: new Date("2026-11-18T08:00:00Z"), optOut: true }));
    await recorder.settled();
    expect(lookups).toBe(asked);
    // An address on this side of the router is not a visitor.
    expect(recorder.record(facts({ ip: "192.168.8.30" }))).toBe(false);
    db.close();
  });

  it("counts a crawler by the day, not by the request, and asks where it comes from a few times only", async () => {
    const db = openDatabase(":memory:");
    migrate(db);
    let lookups = 0;
    const recorder = new VisitRecorder(db, {
      reverse: async () => {
        lookups += 1;
        return ["crawler.example.com"];
      },
      forward: forwardFrom({}),
      timeZone: "Etc/UTC",
    });
    const perplexity = "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)";
    for (let i = 0; i < 500; i += 1) {
      recorder.record(facts({ ip: `198.51.100.${i % 250}`, userAgent: perplexity, acceptLanguage: false, fetchMetadata: false, path: `/vulnerabilities`, country: "US", referer: null, at: new Date(Date.parse("2026-11-17T10:00:00Z") + i * 1000) }));
      // A handful at a time, as requests arrive, so the lookups answer between them.
      if (i % 5 === 4) await recorder.settled();
    }
    await recorder.settled();
    expect(count(db, "visits")).toBe(0);
    expect(lookups).toBe(20);
    const rows = db.prepare("SELECT agent, agent_name, network, requests FROM visit_counts ORDER BY requests DESC").all();
    // One row for the addresses looked up and named, one for the rest: two rows for five hundred requests.
    expect(rows).toHaveLength(2);
    expect((rows as { requests: number }[]).reduce((n, r) => n + r.requests, 0)).toBe(500);
    expect(rows).toContainEqual(expect.objectContaining({ agent: "crawler", agent_name: "PerplexityBot", network: "" }));
    expect(rows).toContainEqual(expect.objectContaining({ agent: "crawler", agent_name: "PerplexityBot", network: "example.com" }));

    // A browser that reads more than a person could in a day is counted as a program from then on.
    for (let i = 0; i < maxPagesPerPerson + 5; i += 1) recorder.record(facts({ ip: "203.0.113.50", path: `/vulnerabilities/CVE-2026-${i}`, at: new Date("2026-11-17T12:00:00Z") }));
    await recorder.settled();
    expect(count(db, "visits")).toBe(maxPagesPerPerson);
    expect(db.prepare("SELECT agent, agent_name, requests FROM visit_counts WHERE agent = 'unknown'").get()).toEqual({ agent: "unknown", agent_name: `Chrome, over ${maxPagesPerPerson} pages a day`, requests: 5 });
    db.close();
  });

  it("reports a window by day, page, origin and program, and housekeeping lets old visits go", async () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const recorder = new VisitRecorder(db, { reverse: async () => [], forward: forwardFrom({}), timeZone: "Etc/UTC" });
    const at = (iso: string) => new Date(iso);
    recorder.record(facts({ at: at("2026-11-17T10:00:00Z") }));
    recorder.record(facts({ at: at("2026-11-17T10:01:00Z"), path: "/vulnerabilities", referer: "https://cybercard.net/" }));
    recorder.record(facts({ at: at("2026-11-17T11:00:00Z"), ip: "198.51.100.9", userAgent: iphone, country: "US", referer: null }));
    recorder.record(facts({ at: at("2026-11-17T11:30:00Z"), ip: "198.51.100.10", host: "baselinewatch.org", referer: null }));
    recorder.record(facts({ at: at("2026-11-15T09:00:00Z"), ip: "198.51.100.11" }));
    recorder.record(facts({ at: at("2026-11-17T12:00:00Z"), ip: "66.249.66.1", userAgent: googlebot, acceptLanguage: false, fetchMetadata: false }));
    recorder.record(facts({ at: at("2026-11-17T12:01:00Z"), ip: "66.249.66.2", userAgent: googlebot, acceptLanguage: false, fetchMetadata: false, path: "/learn" }));
    recorder.record(facts({ at: at("2026-11-17T12:05:00Z"), ip: "203.0.113.99", userAgent: "curl/8.7.1", acceptLanguage: false, fetchMetadata: false, path: "/.env", status: 404 }));
    recorder.record(facts({ at: at("2026-07-01T00:00:00Z"), ip: "198.51.100.12" }));
    recorder.record(facts({ at: at("2026-07-01T00:00:00Z"), ip: "66.249.66.3", userAgent: googlebot, acceptLanguage: false, fetchMetadata: false }));
    await recorder.settled();

    const week = visitReport(db, { now: at("2026-11-17T18:00:00Z"), timeZone: "Etc/UTC", days: 7, host: null });
    expect(week.from).toBe("2026-11-11");
    expect(week.totals).toEqual({ visits: 4, views: 5, assistants: 0, crawlers: 2, readers: 0, tools: 1, unknown: 0, missing: 1, api: 0 });
    expect(week.byDay).toHaveLength(7);
    expect(week.byDay[0]).toEqual({ day: "2026-11-17", visits: 3, views: 4, assistants: 0, crawlers: 2, others: 1 });
    expect(week.byDay.find((d) => d.day === "2026-11-16")).toMatchObject({ visits: 0, views: 0, crawlers: 0 });
    expect(week.pages[0]).toMatchObject({ path: "/", visits: 4, views: 4 });
    expect(week.referrers).toEqual([{ name: "news.ycombinator.com", visits: 2 }]);
    expect(week.countries.map((c) => c.name)).toEqual(["DE", "US"]);
    // Two Googlebot requests to two pages are one line: the path of a found page is not kept for a program.
    expect(week.automated.map((a) => [a.kind, a.name, a.requests])).toEqual([["crawler", "Googlebot", 2], ["tool", "curl", 1]]);
    expect(week.missing).toMatchObject([{ path: "/.env", requests: 1 }]);
    expect(week.hosts.map((h) => h.host)).toEqual(["cybercard.net", "baselinewatch.org"]);
    expect(week.lastAt).toBe("2026-11-17T12:05:00.000Z");

    const org = visitReport(db, { now: at("2026-11-17T18:00:00Z"), timeZone: "Etc/UTC", days: 1, host: "baselinewatch.org" });
    expect(org.totals.visits).toBe(1);
    expect(org.totals.crawlers).toBe(0);
    expect(org.byDay).toHaveLength(1);

    const dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-visits-"));
    try {
      const result = runHousekeeping(db, dataDir, { now: () => at("2026-11-17T18:00:00Z") });
      expect(result.visitsDeleted).toBe(2);
      expect(count(db, "visits")).toBe(5);
      expect(count(db, "visit_counts")).toBe(2);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
      db.close();
    }
  });
});

describe("counting in the app", () => {
  const from = (address: string, extra: Record<string, string> = {}): RequestInit => ({
    headers: { "x-forwarded-for": address, "user-agent": chrome, "accept-language": "en-US", "sec-fetch-mode": "navigate", "cf-ipcountry": "DE", referer: "https://news.ycombinator.com/", ...extra },
  });

  it("counts a stranger's page, not the owner's, not an asset, and shows it to the owner alone", async () => {
    const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "owner-pass-1234", BW_PUBLIC_READ: "true" }, reverse: async () => ["cpe-1.example.net"], dns: forwardFrom({ "cpe-1.example.net": ["203.0.113.7"] }) });
    try {
      expect((await fetch(`${app.base}/guide`, from("203.0.113.7"))).status).toBe(200);
      expect((await fetch(`${app.base}/assets/app.css`, from("203.0.113.7"))).status).toBe(200);
      expect((await fetch(`${app.base}/no-such-page`, from("203.0.113.7"))).status).toBe(404);
      expect((await fetch(`${app.base}/learn`, from("203.0.113.9", { "user-agent": googlebot, "accept-language": "", "sec-fetch-mode": "" }))).status).toBe(200);
      // From this side of the router: the owner's household, not a reader.
      expect((await fetch(`${app.base}/guide`, from("192.168.8.20"))).status).toBe(200);
      // A stranger is refused the page.
      expect((await fetch(`${app.base}/visitors`, from("203.0.113.7"))).status).toBe(403);
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "owner-pass-1234" }));
      expect((await fetch(`${app.base}/guide`, { headers: { ...(from("198.51.100.3").headers as Record<string, string>), cookie } })).status).toBe(200);
      await app.visits!.settled();
      expect(app.db.prepare("SELECT path, status, kind, agent, country, referrer, network FROM visits ORDER BY id").all()).toEqual([
        { path: "/guide", status: 200, kind: "page", agent: "person", country: "DE", referrer: "news.ycombinator.com", network: "example.net" },
      ]);
      expect(app.db.prepare("SELECT path, status, agent, agent_name, requests FROM visit_counts ORDER BY status").all()).toEqual([
        { path: "", status: 200, agent: "crawler", agent_name: "Googlebot", requests: 1 },
        { path: "/no-such-page", status: 404, agent: "person", agent_name: "Chrome", requests: 1 },
      ]);
      const page = await (await fetch(`${app.base}/visitors?days=7`, { headers: { cookie } })).text();
      expect(page).toContain("<h1>Visitors");
      expect(page).toContain("news.ycombinator.com");
      expect(page).toContain("Germany");
      expect(page).toContain("example.net");
      expect(page).toContain("Googlebot");
      expect(page).toContain("/no-such-page");
      expect(page).toContain('href="/visitors"');
      // The menu entry is the owner's: a stranger's Desk has no Visitors line.
      expect(await (await fetch(`${app.base}/guide`, from("203.0.113.8"))).text()).not.toContain('href="/visitors"');
    } finally {
      await app.close();
    }
  });

  it("counts nothing when BW_VISITS is off", async () => {
    const app = await startTestApp({ env: { BW_VISITS: "false" } });
    try {
      expect((await fetch(`${app.base}/guide`, from("203.0.113.7"))).status).toBe(200);
      expect(app.visits).toBeUndefined();
      expect(count(app.db, "visits") + count(app.db, "visit_counts")).toBe(0);
    } finally {
      await app.close();
    }
  });
});
