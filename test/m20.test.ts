import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { SourceRow } from "../src/adapters/types.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { addSource, feedAddress, feedTitle, probeFeed, readNewSource, sourceIdFor, sourceLog, type NewSource } from "../src/newsource.ts";
import { adoptFallback, alternateFeeds, findRepairs, proposedRepairs, sameSite, useRepair } from "../src/repairs.ts";
import { cookieFrom, fakeHttp, fixture, formPost, startTestApp, type TestApp } from "./helpers.ts";

/**
 * M20's thin slice: a source declares where else its document lives and is answered from there
 * when its own address fails; a feed that still fails is looked into and a repair proposed; and
 * the owner adds a feed by its address, probed before it is saved. The URLhaus episode of
 * October 2026 — six red days and a migration — is the case the first half is written against.
 */

const hostfile = fixture("blocklists/urlhaus-filter-hosts.txt");
const own = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt";
const mirror = "https://curbengh.github.io/malware-filter/urlhaus-filter-hosts.txt";
const at = new Date("2026-10-28T12:00:00Z");

describe("fallbacks: the source's other addresses", () => {
  let db: ReturnType<typeof openDatabase>;
  let dataDir = "";
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-m20-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("answers from the first fallback that works, says so, and goes back when its own address answers", async () => {
    const source = getSource(db, "canary-malware")!;
    expect(source.url).toBe(own);
    const gone = fakeHttp({ [own]: { status: 410 }, [mirror]: { bytes: hostfile } });
    const first = await ingestSource(db, dataDir, source, { http: gone, now: () => at });
    expect(first.status).toBe("ok");
    expect(first.detail).toContain(`answered from its fallback ${mirror}`);
    let row = getSource(db, "canary-malware")!;
    expect(row).toMatchObject({ last_status: "ok", answered_from: mirror, failing_since: null, etag: null });
    expect(row.primary_error).toContain("HTTP 410");
    // Nothing is proposed for a source a fallback answers, and nothing moves its address.
    expect(row.url).toBe(own);
    expect(proposedRepairs(db, "canary-malware")).toEqual([]);

    const back = fakeHttp({ [own]: { bytes: hostfile } });
    expect((await ingestSource(db, dataDir, row, { http: back, now: () => at })).status).not.toBe("error");
    row = getSource(db, "canary-malware")!;
    expect(row.answered_from).toBeNull();
    expect(row.primary_error).toBeNull();
    expect(back.calls.map((c) => c.url)).toEqual([own]);
  });

  it("names the source's own failure, not the last fallback's, when none answers", async () => {
    const source = getSource(db, "canary-malware")!;
    const down = fakeHttp({ [own]: { status: 410 }, [mirror]: { status: 503 } });
    const result = await ingestSource(db, dataDir, source, { http: down, now: () => at });
    expect(result.status).toBe("error");
    const row = getSource(db, "canary-malware")!;
    expect(row.last_error).toMatch(/HTTP 410 from .*gitlab\.io.*\(and 2 fallbacks failed too\)$/);
    expect((row as SourceRow & { failing_since: string | null }).failing_since).not.toBeNull();
  });

  it("makes the fallback that has been answering the address when the owner says so, and logs it", async () => {
    const source = getSource(db, "canary-malware")!;
    await ingestSource(db, dataDir, source, { http: fakeHttp({ [own]: { status: 410 }, [mirror]: { bytes: hostfile } }), now: () => at });
    expect(adoptFallback(db, getSource(db, "canary-malware")!, at.toISOString())).toBe(mirror);
    const row = getSource(db, "canary-malware")!;
    expect(row.url).toBe(mirror);
    expect(JSON.parse(row.fallback_urls!)).toEqual(["https://malware-filter.pages.dev/urlhaus-filter-hosts.txt"]);
    expect(row.answered_from).toBeNull();
    expect(sourceLog(db)[0]).toMatchObject({ source_id: "canary-malware", action: "address", before: own, after: mirror });
  });
});

describe("repairs: what a person would try, done by the instance", () => {
  let db: ReturnType<typeof openDatabase>;
  let dataDir = "";
  const feedUrl = "https://news.example.org/old/feed.xml";
  let source: SourceRow;
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-m20-"));
    db.prepare("INSERT INTO sources (id, name, kind, group_name, url, format, schedule) VALUES ('example-news', 'Example News', 'article', 'news', ?, 'rss', 'daily')").run(feedUrl);
    source = getSource(db, "example-news")!;
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("reads the feeds a page announces, absolute, and only RSS, Atom or RDF", () => {
    const page = `<head><link rel="stylesheet" href="/a.css"><link rel="alternate" type="application/rss+xml" title="All" href="/feed/?a=1&amp;b=2">
      <link type='application/atom+xml' rel='alternate home' href='https://example.org/atom'><link rel=alternate type=text/html href=/fr/></head>`;
    expect(alternateFeeds(page, "https://example.org/blog/")).toEqual(["https://example.org/feed/?a=1&b=2", "https://example.org/atom"]);
    expect(sameSite("https://feeds.example.org/x", "https://www.example.org/y")).toBe(true);
    expect(sameSite("https://feeds.feedburner.com/x", "https://example.org/y")).toBe(false);
  });

  it("proposes the feed the home page links, probed and parsed, ignoring other sites, once a day", async () => {
    const http = fakeHttp({
      [feedUrl]: { status: 410 },
      "https://news.example.org/": { text: `<link rel="alternate" type="application/rss+xml" href="/rss/latest.xml"><link rel="alternate" type="application/rss+xml" href="https://feeds.feedburner.com/examplenews">` },
      "https://news.example.org/rss/latest.xml": { bytes: fixture("rss.xml") },
      "https://news.example.org/feed/": { text: "<html>not a feed</html>" },
    });
    const result = await ingestSource(db, dataDir, source, { http, now: () => at });
    expect(result.status).toBe("error");
    const repairs = proposedRepairs(db, "example-news");
    expect(repairs).toHaveLength(1);
    expect(repairs[0]).toMatchObject({ url: "https://news.example.org/rss/latest.xml", how: "linked from https://news.example.org/" });
    expect(repairs[0]!.items).toBeGreaterThan(0);
    expect(http.calls.some((c) => c.url.includes("feedburner"))).toBe(false);

    // A day has not passed: the next failure does not search again.
    const before = http.calls.length;
    await ingestSource(db, dataDir, getSource(db, "example-news")!, { http, now: () => new Date(at.getTime() + 3_600_000) });
    expect(http.calls.length - before).toBe(1);
    expect(await findRepairs(db, getSource(db, "example-news")!, http, new Date(at.getTime() + 3_600_000))).toBe(0);
  });

  it("proposes the new address an old one moved to for good", async () => {
    const moved = "https://news.example.org/feeds/all.rss";
    const http = fakeHttp({ [feedUrl]: { status: 301, headers: { location: "/feeds/all.rss" } }, [moved]: { bytes: fixture("atom.xml") } });
    await findRepairs(db, source, http, at);
    expect(proposedRepairs(db, "example-news").map((r) => [r.url, r.how])).toEqual([[moved, "the old address now moves here permanently"]]);
  });

  it("moves the source when the owner uses a repair, clears the rest, and the next fetch reads it", async () => {
    const http = fakeHttp({ [feedUrl]: { status: 410 }, "https://news.example.org/rss.xml": { bytes: fixture("rss.xml") } });
    await ingestSource(db, dataDir, source, { http, now: () => at });
    const [repair] = proposedRepairs(db, "example-news");
    expect(repair!.how).toBe("a usual feed address on the same site");
    expect(useRepair(db, getSource(db, "example-news")!, repair!.id, at.toISOString())!.url).toBe("https://news.example.org/rss.xml");
    expect(proposedRepairs(db, "example-news")).toEqual([]);
    expect(sourceLog(db)[0]).toMatchObject({ action: "address", before: feedUrl, after: "https://news.example.org/rss.xml" });
    const next = await ingestSource(db, dataDir, getSource(db, "example-news")!, { http, now: () => at });
    expect(next.status).toBe("ok");
    expect(next.inserted).toBeGreaterThan(0);
  });

  it("does not go looking while the server refuses or is unwell, only when the address may be wrong", async () => {
    const http = fakeHttp({ [feedUrl]: { status: 429 } });
    await ingestSource(db, dataDir, source, { http, now: () => at });
    expect(http.calls.map((c) => c.url)).toEqual([feedUrl]);
    expect(getSource(db, "example-news")!.repair_checked_at).toBeNull();
  });

  it("does not propose an address another source already reads", async () => {
    db.prepare("INSERT INTO sources (id, name, kind, group_name, url, format, schedule) VALUES ('other', 'Other', 'article', 'news', 'https://news.example.org/rss.xml', 'rss', 'daily')").run();
    const http = fakeHttp({ [feedUrl]: { status: 410 }, "https://news.example.org/rss.xml": { bytes: fixture("rss.xml") } });
    await findRepairs(db, source, http, at);
    expect(proposedRepairs(db, "example-news")).toEqual([]);
  });
});

describe("a source the owner adds", () => {
  it("reads the form, refusing an address that is not plain http or https", () => {
    expect(feedAddress("javascript:alert(1)")).toBeNull();
    expect(feedAddress("https://user:pw@example.org/feed")).toBeNull();
    expect(feedAddress("file:///etc/passwd")).toBeNull();
    expect(feedAddress(" https://example.org/feed ")).toBe("https://example.org/feed");
    expect(readNewSource({ url: "https://example.org/feed", group: "standards", schedule: "minutely", topic: "ai" })).toEqual({
      url: "https://example.org/feed",
      name: "",
      group: "news",
      topic: "ai",
      schedule: "daily",
      licence: null,
    });
    expect(typeof readNewSource({ url: "nope" })).toBe("string");
    expect(feedTitle("<rss><channel><title><![CDATA[Ex &amp; Co]]></title><item><title>x</title></item></channel></rss>")).toBe("Ex & Co");
  });

  it("probes before saving: a feed with entries, an HTML page, an empty feed", async () => {
    const http = fakeHttp({
      "https://example.org/rss": { bytes: fixture("rss.xml") },
      "https://example.org/atom": { bytes: fixture("atom.xml") },
      "https://example.org/page": { text: "<html><body>hello</body></html>" },
      "https://example.org/empty": { text: "<rss><channel><title>Quiet</title></channel></rss>" },
    });
    const rss = await probeFeed(http, "https://example.org/rss");
    expect(rss.ok && rss.feed.format).toBe("rss");
    expect(rss.ok && rss.feed.items.length).toBeGreaterThan(0);
    const atom = await probeFeed(http, "https://example.org/atom");
    expect(atom.ok && atom.feed.format).toBe("atom");
    expect(await probeFeed(http, "https://example.org/page")).toMatchObject({ ok: false, error: expect.stringContaining("not with a feed") });
    expect(await probeFeed(http, "https://example.org/empty")).toMatchObject({ ok: false, error: expect.stringContaining("no entries") });
  });

  it("gives the row a readable id that does not collide, marks it the owner's, and logs it", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const input: NewSource = { url: "https://www.example.org/security/feed.xml", name: "", group: "vulnerabilities", topic: null, schedule: "weekly", licence: null };
    expect(sourceIdFor(db, input.url)).toBe("example-org-security-feed");
    const id = addSource(db, input, { url: input.url, format: "rss", title: "Example Security", count: 3, items: [] }, at.toISOString());
    expect(getSource(db, id)).toMatchObject({ name: "Example Security", origin: "owner", group_name: "vulnerabilities", schedule: "weekly", format: "rss", enabled: 1 });
    expect(sourceIdFor(db, input.url.replace("feed.xml", "feed.rss"))).toBe("example-org-security-feed-2");
    expect(sourceLog(db)[0]).toMatchObject({ source_id: id, action: "added", after: input.url });
    db.close();
  });
});

describe("the Sources page, end to end", () => {
  let app: TestApp;
  let cookie: string;
  const now = new Date("2026-10-28T12:00:00Z");
  const http = fakeHttp({
    "https://feeds.example.net/security.xml": { bytes: fixture("rss.xml") },
    "https://feeds.example.net/not-a-feed": { text: "<html>hello</html>" },
  });

  beforeAll(async () => {
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2", BW_PUBLIC_READ: "true" }, http, now: () => now });
    cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
  });
  afterAll(async () => {
    await app.close();
  });

  it("shows the ledger to everyone and the form and change log to the owner only", async () => {
    const visitor = await (await fetch(`${app.base}/sources`)).text();
    expect(visitor).toContain("Kept by hand");
    expect(visitor).toContain("data/platforms.yaml");
    expect(visitor).not.toContain("Add a source");
    expect(visitor).not.toContain("Changes made here");
    const owner = await (await fetch(`${app.base}/sources`, { headers: { cookie } })).text();
    expect(owner).toContain("Add a source");
    expect(owner).toContain("Changes made here");
  });

  it("refuses a visitor's probe and add", async () => {
    expect((await formPost(app.base, "/sources/probe", { url: "https://feeds.example.net/security.xml" })).status).toBeGreaterThanOrEqual(401);
    expect((await formPost(app.base, "/sources/add", { url: "https://feeds.example.net/security.xml" })).status).toBeGreaterThanOrEqual(401);
  });

  it("probes, then adds, then fetches at once, so the entries are on the News", async () => {
    const probe = await formPost(app.base, "/sources/probe", { url: "https://feeds.example.net/not-a-feed" }, cookie);
    expect(probe.status).toBe(422);
    expect(await probe.text()).toContain("not with a feed");

    const good = await formPost(app.base, "/sources/probe", { url: "https://feeds.example.net/security.xml", group: "news", schedule: "daily" }, cookie);
    expect(good.status).toBe(200);
    const page = await good.text();
    expect(page).toContain("It answers");
    expect(page).toContain('action="/sources/add"');
    expect(app.db.prepare("SELECT COUNT(*) AS n FROM sources WHERE url = 'https://feeds.example.net/security.xml'").get()).toEqual({ n: 0 });

    const added = await formPost(app.base, "/sources/add", { url: "https://feeds.example.net/security.xml", group: "news", schedule: "daily", name: "Example Net" }, cookie);
    expect(added.status).toBe(303);
    const row = app.db.prepare("SELECT id, origin, name FROM sources WHERE url = 'https://feeds.example.net/security.xml'").get() as { id: string; origin: string; name: string };
    expect(row).toMatchObject({ origin: "owner", name: "Example Net" });
    expect((app.db.prepare("SELECT COUNT(*) AS n FROM items WHERE source_id = ?").get(row.id) as { n: number }).n).toBeGreaterThan(0);
    expect(added.headers.get("location")).toBe(`/sources#src-${row.id}`);

    const again = await formPost(app.base, "/sources/add", { url: "https://feeds.example.net/security.xml" }, cookie);
    expect(again.status).toBe(409);
    const owner = await (await fetch(`${app.base}/sources`, { headers: { cookie } })).text();
    expect(owner).toContain("added here");
  });
});
