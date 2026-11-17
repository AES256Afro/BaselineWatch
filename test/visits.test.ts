import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import type { DnsLookup } from "../src/domaincheck.ts";
import { runHousekeeping } from "../src/housekeeping.ts";
import { classifyAgent, networkOf, publicAddress, referrerHost, visitKind, visitReport, VisitRecorder, type VisitFacts } from "../src/visits.ts";
import { cookieFrom, formPost, startTestApp } from "./helpers.ts";

/** Who reads the site: counted on the server, no address kept, the owner's page to read it on. */

const chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
const iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1";

describe("what kind of program asked", () => {
  it("names people's browsers, assistants, crawlers, readers and tools", () => {
    expect(classifyAgent(chrome, true)).toEqual({ kind: "person", name: "Chrome", os: "Windows", device: "desktop" });
    expect(classifyAgent(iphone, true)).toEqual({ kind: "person", name: "Safari", os: "iOS", device: "phone" });
    // A browser's name with no Accept-Language is a script wearing it.
    expect(classifyAgent(chrome, false)).toMatchObject({ kind: "unknown", name: "Chrome, no Accept-Language" });
    expect(classifyAgent("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot", false)).toMatchObject({ kind: "assistant", name: "ChatGPT-User" });
    expect(classifyAgent("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)", false)).toMatchObject({ kind: "crawler", name: "GPTBot" });
    expect(classifyAgent("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", false)).toMatchObject({ kind: "crawler", name: "Googlebot" });
    expect(classifyAgent("Feedly/1.0 (+http://www.feedly.com/fetcher.html; 3 subscribers)", false)).toMatchObject({ kind: "reader", name: "Feedly" });
    expect(classifyAgent("curl/8.7.1", false)).toMatchObject({ kind: "tool", name: "curl" });
    expect(classifyAgent("Mozilla/5.0 (compatible; NewThingBot/0.3; +https://example.com)", false)).toMatchObject({ kind: "crawler", name: "NewThingBot" });
    expect(classifyAgent("", false)).toMatchObject({ kind: "unknown", name: "no User-Agent" });
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

describe("the recorder", () => {
  const facts = (over: Partial<VisitFacts> = {}): VisitFacts => ({
    at: new Date("2026-11-17T15:00:00Z"),
    ip: "203.0.113.7",
    host: "cybercard.net",
    path: "/",
    kind: "page",
    status: 200,
    userAgent: chrome,
    acceptLanguage: true,
    country: "de",
    referer: "https://news.ycombinator.com/item?id=1",
    optOut: false,
    ...over,
  });

  it("keeps no address, names the network after the fact, and rotates the salt by the day", async () => {
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
    expect(recorder.record(facts())).not.toBeNull();
    expect(recorder.record(facts({ path: "/vulnerabilities" }))).not.toBeNull();
    await recorder.settled();
    // The second visit asked while the first lookup was out: one question, both rows named.
    expect(lookups).toBe(1);
    const rows = db.prepare("SELECT * FROM visits ORDER BY id").all() as Record<string, unknown>[];
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ day: "2026-11-17", host: "cybercard.net", agent: "person", agent_name: "Chrome", country: "DE", referrer: "news.ycombinator.com", network: "example.net", network_confirmed: 1 });
    expect(rows[0]!.visitor).toBe(rows[1]!.visitor);
    expect(JSON.stringify(rows)).not.toContain("203.0.113.7");
    // Known for the rest of the day: the third visit is named at once, with no new lookup.
    recorder.record(facts({ path: "/today" }));
    expect(lookups).toBe(1);
    expect((db.prepare("SELECT network FROM visits ORDER BY id DESC").get() as { network: string }).network).toBe("example.net");

    // The next day (Chicago's, not UTC's): a new salt, the old one gone, so the same reader is a new hash.
    const firstSalt = (db.prepare("SELECT day, salt FROM visit_salts").all() as { day: string }[]).map((s) => s.day);
    expect(firstSalt).toEqual(["2026-11-17"]);
    recorder.record(facts({ at: new Date("2026-11-18T07:00:00Z") }));
    expect((db.prepare("SELECT day FROM visits ORDER BY id DESC").get() as { day: string }).day).toBe("2026-11-18");
    expect((db.prepare("SELECT day FROM visit_salts").all() as { day: string }[]).map((s) => s.day)).toEqual(["2026-11-18"]);
    const [today, yesterday] = db.prepare("SELECT DISTINCT visitor FROM visits ORDER BY day DESC").all() as { visitor: string }[];
    expect(today!.visitor).not.toBe(yesterday!.visitor);
    await recorder.settled();

    // Global Privacy Control: counted, and the address's name is not asked for.
    const asked = lookups;
    recorder.record(facts({ ip: "198.51.100.20", at: new Date("2026-11-18T08:00:00Z"), optOut: true }));
    await recorder.settled();
    expect(lookups).toBe(asked);
    // An address on this side of the router is not a visitor.
    expect(recorder.record(facts({ ip: "192.168.8.30" }))).toBeNull();
    db.close();
  });

  it("reports a window by day, page, origin and program, and housekeeping lets old visits go", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const recorder = new VisitRecorder(db, { reverse: async () => [], forward: forwardFrom({}), timeZone: "Etc/UTC" });
    const at = (iso: string) => new Date(iso);
    recorder.record(facts({ at: at("2026-11-17T10:00:00Z") }));
    recorder.record(facts({ at: at("2026-11-17T10:01:00Z"), path: "/vulnerabilities", referer: "https://cybercard.net/" }));
    recorder.record(facts({ at: at("2026-11-17T11:00:00Z"), ip: "198.51.100.9", userAgent: iphone, country: "US", referer: null }));
    recorder.record(facts({ at: at("2026-11-17T11:30:00Z"), ip: "198.51.100.10", host: "baselinewatch.org", referer: null }));
    recorder.record(facts({ at: at("2026-11-15T09:00:00Z"), ip: "198.51.100.11" }));
    recorder.record(facts({ at: at("2026-11-17T12:00:00Z"), ip: "66.249.66.1", userAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", acceptLanguage: false }));
    recorder.record(facts({ at: at("2026-11-17T12:05:00Z"), ip: "203.0.113.99", userAgent: "curl/8.7.1", acceptLanguage: false, path: "/.env", status: 404 }));
    recorder.record(facts({ at: at("2026-07-01T00:00:00Z"), ip: "198.51.100.12" }));

    const week = visitReport(db, { now: at("2026-11-17T18:00:00Z"), timeZone: "Etc/UTC", days: 7, host: null });
    expect(week.from).toBe("2026-11-11");
    expect(week.totals).toMatchObject({ visits: 4, views: 5, crawlers: 1, tools: 1, missing: 1 });
    expect(week.byDay).toHaveLength(7);
    expect(week.byDay[0]).toMatchObject({ day: "2026-11-17", visits: 3, views: 4, crawlers: 1 });
    expect(week.byDay.find((d) => d.day === "2026-11-16")).toMatchObject({ visits: 0, views: 0 });
    expect(week.pages[0]).toMatchObject({ path: "/", visits: 4, views: 4 });
    expect(week.referrers).toEqual([{ name: "news.ycombinator.com", visits: 2 }]);
    expect(week.countries.map((c) => c.name)).toEqual(["DE", "US"]);
    expect(week.automated.map((a) => [a.kind, a.name])).toEqual([["crawler", "Googlebot"], ["tool", "curl"]]);
    expect(week.missing).toMatchObject([{ path: "/.env", requests: 1 }]);
    expect(week.hosts.map((h) => h.host)).toEqual(["cybercard.net", "baselinewatch.org"]);

    const org = visitReport(db, { now: at("2026-11-17T18:00:00Z"), timeZone: "Etc/UTC", days: 1, host: "baselinewatch.org" });
    expect(org.totals.visits).toBe(1);
    expect(org.byDay).toHaveLength(1);

    const dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-visits-"));
    try {
      const result = runHousekeeping(db, dataDir, { now: () => at("2026-11-17T18:00:00Z") });
      expect(result.visitsDeleted).toBe(1);
      expect((db.prepare("SELECT COUNT(*) AS n FROM visits").get() as { n: number }).n).toBe(7);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
      db.close();
    }
  });
});

describe("counting in the app", () => {
  const from = (address: string, extra: Record<string, string> = {}): RequestInit => ({
    headers: { "x-forwarded-for": address, "user-agent": chrome, "accept-language": "en-US", "cf-ipcountry": "DE", referer: "https://news.ycombinator.com/", ...extra },
  });

  it("counts a stranger's page, not the owner's, not an asset, and shows it to the owner alone", async () => {
    const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "owner-pass-1234", BW_PUBLIC_READ: "true" }, reverse: async () => ["cpe-1.example.net"], dns: forwardFrom({ "cpe-1.example.net": ["203.0.113.7"] }) });
    try {
      expect((await fetch(`${app.base}/guide`, from("203.0.113.7"))).status).toBe(200);
      expect((await fetch(`${app.base}/assets/app.css`, from("203.0.113.7"))).status).toBe(200);
      expect((await fetch(`${app.base}/no-such-page`, from("203.0.113.7"))).status).toBe(404);
      // From this side of the router: the owner's household, not a reader.
      expect((await fetch(`${app.base}/guide`, from("192.168.8.20"))).status).toBe(200);
      // A stranger is refused the page.
      expect((await fetch(`${app.base}/visitors`, from("203.0.113.7"))).status).toBe(403);
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "owner-pass-1234" }));
      expect((await fetch(`${app.base}/guide`, { headers: { ...(from("198.51.100.3").headers as Record<string, string>), cookie } })).status).toBe(200);
      await app.visits!.settled();
      const rows = app.db.prepare("SELECT path, status, kind, agent, country, referrer, network FROM visits ORDER BY id").all();
      expect(rows).toEqual([
        { path: "/guide", status: 200, kind: "page", agent: "person", country: "DE", referrer: "news.ycombinator.com", network: "example.net" },
        { path: "/no-such-page", status: 404, kind: "page", agent: "person", country: "DE", referrer: "news.ycombinator.com", network: "example.net" },
      ]);
      const page = await (await fetch(`${app.base}/visitors?days=7`, { headers: { cookie } })).text();
      expect(page).toContain("<h1>Visitors");
      expect(page).toContain("news.ycombinator.com");
      expect(page).toContain("Germany");
      expect(page).toContain("example.net");
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
      expect((app.db.prepare("SELECT COUNT(*) AS n FROM visits").get() as { n: number }).n).toBe(0);
    } finally {
      await app.close();
    }
  });
});
