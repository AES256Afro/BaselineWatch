import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { nistCatalogAdapter } from "../src/adapters/oscal-nist.ts";
import { storeNvdRecords, type NvdResponse } from "../src/adapters/nvd.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { buildDigest, digestDue, localClock, writeDigest } from "../src/digest.ts";
import { HttpError, type HttpGet } from "../src/http.ts";
import { getSource, ingestDocumentTarget, ingestSource } from "../src/ingest.ts";
import { notify, parseNotifyUrl, recentAlerts, send } from "../src/notify.ts";
import { linkified } from "../src/pages/digest.ts";
import { startScheduler } from "../src/scheduler.ts";
import { clearTriage, listTriage, setTriage, triageCounts, triageCsv, triageInbox } from "../src/triage.ts";
import { cookieFrom, fakeHttp, fixture, formPost, startTestApp, type TestApp } from "./helpers.ts";

const at = new Date("2026-10-15T06:00:00Z");

/** Records every request as a notifier would see it. */
function recorder(): HttpGet & { calls: { url: string; body: string; headers: Record<string, string>; redirect: string | undefined }[] } {
  const calls: { url: string; body: string; headers: Record<string, string>; redirect: string | undefined }[] = [];
  const get: HttpGet = async (url, options = {}) => {
    calls.push({ url, body: options.body ?? "", headers: options.headers ?? {}, redirect: options.redirect });
    return { url, status: 200, notModified: false, bytes: new Uint8Array(0), etag: null, lastModified: null, contentType: null };
  };
  return Object.assign(get, { calls });
}

describe("notifier", () => {
  it("parses the three transports and refuses the rest", () => {
    expect(parseNotifyUrl("ntfy://bigbox:8093/baselinewatch")).toEqual({ scheme: "ntfy", endpoint: "http://bigbox:8093/baselinewatch" });
    expect(parseNotifyUrl("ntfys://ntfy.sh/topic/")).toEqual({ scheme: "ntfy", endpoint: "https://ntfy.sh/topic" });
    expect(parseNotifyUrl("gotify://bigbox:8080/AbC123")).toEqual({ scheme: "gotify", endpoint: "http://bigbox:8080/message", token: "AbC123" });
    expect(parseNotifyUrl("https://hooks.example/x")).toEqual({ scheme: "webhook", endpoint: "https://hooks.example/x" });
    expect(parseNotifyUrl("mailto:me@example.test")).toBeNull();
    expect(parseNotifyUrl("ntfy://hostonly")).toBeNull();
    expect(parseNotifyUrl("")).toBeNull();
  });

  it("sends in each transport's shape and logs every attempt", async () => {
    const http = recorder();
    const n = { kind: "kev" as const, title: "KEV: Thing", body: "Due soon.", url: "https://cybercard.net/wire" };
    expect(await send(parseNotifyUrl("ntfy://h/t"), n, http)).toEqual({ status: "sent", error: null });
    expect(http.calls[0]).toMatchObject({ url: "http://h/t", body: "Due soon." });
    expect(http.calls[0]?.headers).toMatchObject({ title: "KEV: Thing", click: "https://cybercard.net/wire", tags: "rotating_light" });
    await send(parseNotifyUrl("gotify://h/tok"), n, http);
    expect(http.calls[1]?.headers["x-gotify-key"]).toBe("tok");
    expect(JSON.parse(http.calls[1]!.body)).toMatchObject({ title: "KEV: Thing", priority: 7 });
    await send(parseNotifyUrl("https://hook"), n, http);
    expect(JSON.parse(http.calls[2]!.body)).toEqual({ kind: "kev", title: "KEV: Thing", body: "Due soon.", url: "https://cybercard.net/wire" });
    expect(await send(null, n, http)).toEqual({ status: "unconfigured", error: null });
    const broken: HttpGet = async () => {
      throw new Error("refused");
    };
    // The log keeps the kind of failure, never the message: an HTTP error's message names the endpoint, which is the credential.
    expect(await send(parseNotifyUrl("ntfy://h/t"), n, broken)).toEqual({ status: "failed", error: "send failed (Error)" });
    const unauthorized: HttpGet = async (url) => {
      throw new HttpError(url, 401);
    };
    expect(await send(parseNotifyUrl("https://hooks.example/services/SECRET"), n, unauthorized)).toEqual({ status: "failed", error: "HTTP 401" });
    // Non-ASCII in an ntfy header is RFC 2047-encoded rather than refused by fetch.
    await send(parseNotifyUrl("ntfy://h/t"), { ...n, title: "Windows — update" }, http);
    expect(http.calls[3]?.headers.title).toBe(`=?UTF-8?B?${Buffer.from("Windows — update", "utf8").toString("base64")}?=`);
    expect(http.calls[3]?.redirect).toBe("manual");

    const db = openDatabase(":memory:");
    migrate(db);
    await notify(db, parseNotifyUrl("ntfy://h/t"), n, http, () => at);
    await notify(db, null, n, http, () => at);
    const log = recentAlerts(db);
    expect(log.map((a) => a.status)).toEqual(["unconfigured", "sent"]);
    db.close();
  });
});

describe("triage", () => {
  let db: DatabaseSync;
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
  });
  afterEach(() => db.close());

  it("places items, CVEs and controls, lists them with their own data, and exports CSV", () => {
    const kev = getSource(db, "cisa-kev")!;
    db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at, signals_json) VALUES (?, 'kev', 'CVE-2026-1', 'Vendor Thing: RCE', 'https://nvd/1', ?, ?, ?)").run(kev.id, at.toISOString(), at.toISOString(), JSON.stringify({ kev: true, dueDate: "2026-11-01" }));
    const item = (db.prepare("SELECT id FROM items").get() as { id: number }).id;
    expect(triageInbox(db).map((i) => i.id)).toEqual([item]);

    const first = setTriage(db, { kind: "item", id: item }, { state: "reviewing" }, at.toISOString());
    expect(first.state).toBe("reviewing");
    expect(triageInbox(db)).toHaveLength(0);
    const second = setTriage(db, { kind: "item", id: item }, { note: "Checked edge firewalls.", dueAt: "2026-10-20" }, at.toISOString());
    expect(second).toMatchObject({ state: "reviewing", note: "Checked edge firewalls.", due_at: "2026-10-20" });
    setTriage(db, { kind: "item", id: item }, { state: "affects" }, at.toISOString());

    storeNvdRecords({ db, now: () => at }, (JSON.parse(new TextDecoder().decode(fixture("nvd-window.json"))) as NvdResponse).vulnerabilities!);
    const vulnId = (db.prepare("SELECT id FROM vulns WHERE cve_id = 'CVE-2021-44228'").get() as { id: number }).id;
    setTriage(db, { kind: "vuln", id: vulnId }, { state: "done", note: "Patched." }, at.toISOString());
    db.prepare("INSERT INTO snapshots (id, source_id, document_key, sha256, bytes, blob_path, fetched_at) VALUES (1, 'nist-sp-800-53', 'catalog', 'x', 1, 'p', ?)").run(at.toISOString());
    db.prepare("INSERT INTO documents (source_id, document_key, snapshot_id, version_label, title, published_at, parsed_at) VALUES ('nist-sp-800-53', 'catalog', 1, '5.2.0', 'cat', ?, ?)").run(at.toISOString(), at.toISOString());
    db.prepare("INSERT INTO requirements (document_id, ref, label, title, sort_key) VALUES (1, 'sa-24', 'SA-24', 'Design For Cyber Resiliency', 'sa-24')").run();
    setTriage(db, { kind: "control", id: 1, key: "sa-24" }, { state: "reviewing" }, at.toISOString());

    const cards = listTriage(db, { notes: true, restrictedLabels: true });
    expect(cards.map((c) => [c.subject_kind, c.state])).toEqual([
      ["item", "affects"],
      ["control", "reviewing"],
      ["vuln", "done"],
    ]);
    expect(cards[0]).toMatchObject({ title: "Vendor Thing: RCE", url: "https://nvd/1", note: "Checked edge firewalls." });
    expect(cards[1]?.title).toContain("SA-24 Design For Cyber Resiliency");
    expect(cards[1]?.url).toBe("/standards/nist-sp-800-53/1/sa-24");
    expect(cards[2]?.title).toContain("CVE-2021-44228");
    expect(triageCounts(db)).toMatchObject({ affects: 1, reviewing: 1, done: 1 });
    const csv = triageCsv(db);
    expect(csv.split("\n")[0]).toBe("state,kind,title,url,note,due,updated");
    expect(csv).toContain("affects,item,Vendor Thing: RCE,https://nvd/1,Checked edge firewalls.,2026-10-20");
    expect(clearTriage(db, { kind: "vuln", id: vulnId })).toBe(true);
    expect(clearTriage(db, { kind: "vuln", id: vulnId })).toBe(false);
  });
});

describe("alerts from the pipeline", () => {
  let db: DatabaseSync;
  let dataDir = "";
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-m6-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("stays quiet on a KEV catalog's first load and alerts on later additions, five singly then one summary", async () => {
    const source = getSource(db, "cisa-kev")!;
    const notifier = recorder();
    const transport = parseNotifyUrl("ntfy://h/t");
    const catalog = JSON.parse(new TextDecoder().decode(fixture("kev.json"))) as { vulnerabilities: Record<string, unknown>[] };
    const serve = (body: unknown) => fakeHttp({ [source.url]: { text: JSON.stringify(body) } });
    const first = await ingestSource(db, dataDir, source, { http: serve(catalog), now: () => at, transport, baseUrl: "https://cybercard.net" });
    expect(first.inserted).toBe(3);
    expect(recentAlerts(db)).toHaveLength(0);

    const more = { ...catalog, catalogVersion: "2026.10.16", vulnerabilities: [...catalog.vulnerabilities, ...Array.from({ length: 7 }, (_, i) => ({ ...catalog.vulnerabilities[0], cveID: `CVE-2026-9000${i}`, vulnerabilityName: `Thing ${i}`, dateAdded: "2026-10-16", dueDate: "2026-11-06" }))] };
    // Notifications go out through the same http the ingester uses; the fake serves the catalog and records the rest.
    const combined: HttpGet = async (url, options) => (url === source.url ? serve(more)(url, options) : notifier(url, options));
    const second = await ingestSource(db, dataDir, getSource(db, "cisa-kev")!, { http: combined, now: () => at, transport, baseUrl: "https://cybercard.net" });
    expect(second.inserted).toBe(7);
    const log = recentAlerts(db, 50);
    expect(log).toHaveLength(6);
    expect(log.every((a) => a.status === "sent" && a.kind === "kev")).toBe(true);
    expect(log.some((a) => a.title === "2 more KEV additions")).toBe(true);
    expect(notifier.calls).toHaveLength(6);
    expect(notifier.calls[0]?.headers.title).toMatch(/^KEV: /);
  });

  it("alerts on a standard's new version with changes but not on its first load, and on watched CVE changes after the first pull", async () => {
    const notifier = recorder();
    const transport = parseNotifyUrl("https://hook");
    const files: Record<string, Uint8Array> = { "https://c/511.json": fixture("oscal-catalog-5.1.1.json"), "https://c/520.json": fixture("oscal-catalog-5.2.0.json") };
    const http: HttpGet = async (url, options) => {
      if (files[url]) return { url, status: 200, notModified: false, bytes: files[url]!, etag: null, lastModified: null, contentType: "application/json" };
      if (url.startsWith("https://csrc")) throw new Error("no page in this test");
      return notifier(url, options);
    };
    db.prepare("UPDATE sources SET url = 'https://c/511.json' WHERE id = 'nist-sp-800-53'").run();
    await ingestSource(db, dataDir, getSource(db, "nist-sp-800-53")!, { http, now: () => at, transport, baseUrl: "https://cybercard.net" });
    expect(recentAlerts(db)).toHaveLength(0);
    const outcome = await ingestDocumentTarget(db, dataDir, getSource(db, "nist-sp-800-53")!, nistCatalogAdapter, { key: "catalog", url: "https://c/520.json" }, { http, now: () => at });
    expect(outcome.alert).toMatchObject({ kind: "release", url: expect.stringMatching(/^\/standards\/nist-sp-800-53\/\d+$/) });
    expect(outcome.alert?.title).toContain("3 added");

    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('product', 'siemens', 'Plant', ?)").run(at.toISOString());
    const records = (JSON.parse(new TextDecoder().decode(fixture("nvd-window.json"))) as NvdResponse).vulnerabilities!;
    const firstStore = storeNvdRecords({ db, now: () => at }, records);
    expect(firstStore.alerts).toHaveLength(1);
    expect(firstStore.alerts[0]).toMatchObject({ kind: "watch", title: "CVE-2021-44228: Plant", url: "/vulnerabilities/CVE-2021-44228" });
    expect(firstStore.alerts[0]?.body).toContain("new");
  });
});

describe("digest links on the page", () => {
  it("turns the stored text's URLs into links, this instance's and localhost's as paths", () => {
    expect(linkified("Triage: 2 open https://cybercard.net/triage", "https://cybercard.net").value).toBe('Triage: 2 open <a href="/triage">/triage</a>');
    expect(linkified("old http://localhost:8080/vulnerabilities/CVE-2026-0001", "https://cybercard.net").value).toBe('old <a href="/vulnerabilities/CVE-2026-0001">/vulnerabilities/CVE-2026-0001</a>');
    expect(linkified("A story https://example.com/a?b=1 worth reading", "https://cybercard.net").value).toBe(
      'A story <a href="https://example.com/a?b=1" target="_blank" rel="noopener">https://example.com/a?b=1</a> worth reading',
    );
    expect(linkified("no links here", "https://cybercard.net").value).toBe("no links here");
  });
});

describe("digest", () => {
  let db: DatabaseSync;
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
  });
  afterEach(() => db.close());

  it("summarises the period and knows when it is due in a time zone", () => {
    const kev = getSource(db, "cisa-kev")!;
    db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at, signals_json) VALUES (?, 'kev', 'CVE-2026-1', 'Vendor Thing: RCE', 'https://nvd/1', ?, ?, ?)").run(kev.id, at.toISOString(), at.toISOString(), JSON.stringify({ kev: true, dueDate: "2026-11-01" }));
    db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at) VALUES ('nist-sp-800-53', 'release', 'catalog#9', 'NIST SP 800-53 (controls) 5.2.0: 3 added', '/standards/nist-sp-800-53/9', ?, ?)").run(at.toISOString(), at.toISOString());
    db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at, starred) VALUES ('bleeping', 'article', 'a1', 'Big story', 'https://b/1', ?, ?, 1)").run(at.toISOString(), at.toISOString());
    db.prepare("UPDATE sources SET last_status = 'error' WHERE id = 'krebs'").run();
    const { text } = buildDigest(db, { from: "2026-10-14T06:00:00.000Z", to: "2026-10-15T06:00:00.000Z", baseUrl: "https://cybercard.net", period: "daily" });
    expect(text).toContain("Known exploited (CISA KEV): 1 added");
    expect(text).toContain("- Vendor Thing: RCE (due 2026-11-01)");
    expect(text).toContain("Standards: 1 release(s)");
    expect(text).toContain("https://cybercard.net/standards/nist-sp-800-53/9");
    expect(text).toContain("1 new stories, 0 notable CVEs");
    // What the owner starred is their own reading, so it sits in the owner's half.
    expect(text).toContain("Starred: 1");
    expect(text).toContain("Sources failing: Krebs on Security");

    expect(localClock(new Date("2026-10-15T06:30:00Z"), "America/New_York")).toMatchObject({ hour: 2, weekday: 4, dateKey: "2026-10-15" });
    expect(localClock(new Date("2026-10-15T06:30:00Z"), "Etc/UTC")).toMatchObject({ hour: 6 });
    expect(localClock(new Date("2026-10-15T06:30:00Z"), "Not/AZone").hour).toBe(6);
    const opts = { timeZone: "Etc/UTC", period: "daily" as const, hour: 7 };
    expect(digestDue(db, { ...opts, now: new Date("2026-10-15T06:59:00Z") })).toBe(false);
    expect(digestDue(db, { ...opts, now: new Date("2026-10-15T07:00:00Z") })).toBe(true);
    const row = writeDigest(db, { now: new Date("2026-10-15T07:00:00Z"), baseUrl: "https://cybercard.net", period: "daily" });
    expect(row.text).toContain("daily digest");
    expect(digestDue(db, { ...opts, now: new Date("2026-10-15T09:00:00Z") })).toBe(false);
    expect(digestDue(db, { ...opts, now: new Date("2026-10-16T07:30:00Z") })).toBe(true);
    const next = writeDigest(db, { now: new Date("2026-10-16T07:30:00Z"), baseUrl: "https://cybercard.net", period: "daily" });
    expect(next.covers_from).toBe(row.covers_to);
    expect(digestDue(db, { ...opts, period: "off", now: new Date("2026-10-17T07:30:00Z") })).toBe(false);
    expect(digestDue(db, { ...opts, period: "weekly", now: new Date("2026-10-20T07:30:00Z") })).toBe(false); // Tuesday
    expect(digestDue(db, { ...opts, period: "weekly", now: new Date("2026-10-19T07:30:00Z") })).toBe(true); // Monday
  });

  it("is written and sent by the scheduler when due", async () => {
    const notifier = recorder();
    const scheduler = startScheduler({ db, dataDir: os.tmpdir(), http: notifier, now: () => new Date("2026-10-15T07:05:00Z"), transport: parseNotifyUrl("ntfy://h/t"), baseUrl: "https://cybercard.net", digest: { period: "daily", hour: 7, timeZone: "Etc/UTC" }, log: () => {} });
    db.prepare("UPDATE sources SET enabled = 0").run();
    expect(await scheduler.runDigest()).toBe(true);
    expect(await scheduler.runDigest()).toBe(false);
    scheduler.stop();
    expect(notifier.calls).toHaveLength(1);
    expect(notifier.calls[0]?.headers.title).toBe("BaselineWatch daily digest");
    expect(notifier.calls[0]?.headers.click).toBe("https://cybercard.net/digest");
    expect(recentAlerts(db)[0]).toMatchObject({ kind: "digest", status: "sent" });
  });
});

describe("triage and digest pages", () => {
  let app: TestApp;
  afterEach(async () => {
    await app?.close();
  });

  it("shows the board, moves things through it, saves notes, and writes a digest on request", async () => {
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2", BW_BASE_URL: "https://cybercard.net" }, now: () => at });
    const kev = getSource(app.db, "cisa-kev")!;
    await ingestSource(app.db, app.dataDir, kev, { http: fakeHttp({ [kev.url]: { bytes: fixture("kev.json") } }), now: () => at });
    const board = await (await fetch(`${app.base}/triage`)).text();
    expect(board).toContain('<h2><a href="#new">Inbox</a> <span class="count"><a href="#new">3</a></span></h2>');
    expect(board).toContain('<a href="#affects">0 affect us</a> · <a href="#reviewing">0 reviewing</a> · <a href="#done">0 done</a>');
    expect(board).toContain("Ahsay AhsayCBS");
    expect(board).not.toContain("Affects us</button>");

    const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
    const itemId = (app.db.prepare("SELECT id FROM items WHERE external_id = 'CVE-2026-105134'").get() as { id: number }).id;
    expect((await formPost(app.base, "/triage", { kind: "item", id: String(itemId), key: "", state: "affects", back: "/triage" })).status).toBe(403);
    const moved = await formPost(app.base, "/triage", { kind: "item", id: String(itemId), key: "", state: "affects", back: "/triage" }, cookie);
    expect(moved.status).toBe(303);
    const after = await (await fetch(`${app.base}/triage`, { headers: { cookie } })).text();
    expect(after).toContain('<h2><a href="#new">Inbox</a> <span class="count"><a href="#new">2</a></span></h2>');
    expect(after).toContain('<h2><a href="#affects">Affects us</a> <span class="count"><a href="#affects">1</a></span></h2>');
    // Dismissed cards stay out of the way under Done; their count opens them.
    expect((await formPost(app.base, "/triage", { kind: "item", id: String(itemId), key: "", state: "dismissed", back: "/triage" }, cookie)).status).toBe(303);
    const hidden = await (await fetch(`${app.base}/triage`, { headers: { cookie } })).text();
    expect(hidden).toContain('<a href="/triage?dismissed=1#dismissed">1 marked not ours</a>');
    expect(hidden).not.toContain("Not ours</a>");
    const shown = await (await fetch(`${app.base}/triage?dismissed=1`, { headers: { cookie } })).text();
    expect(shown).toContain('<h3 class="small" id="dismissed"><a href="#dismissed">Not ours</a> <span class="count"><a href="#dismissed">1</a></span></h3>');
    expect(shown.indexOf("Not ours</a>")).toBeLessThan(shown.indexOf("Ahsay AhsayCBS"));
    expect((await formPost(app.base, "/triage", { kind: "item", id: String(itemId), state: "bogus" }, cookie)).status).toBe(400);
    expect((await formPost(app.base, "/triage", { kind: "item", id: String(itemId), state: "affects", due: "soon" }, cookie)).status).toBe(400);
    const noted = await formPost(app.base, "/triage", { kind: "item", id: String(itemId), key: "", state: "reviewing", note: "Two devices.", due: "2026-10-30", back: "/wire" }, cookie);
    expect(noted.headers.get("location")).toBe("/wire");
    expect(listTriage(app.db, { notes: true })[0]).toMatchObject({ state: "reviewing", note: "Two devices.", due_at: "2026-10-30" });
    // The owner's own note is theirs: a caller that does not ask as the owner gets the card without it.
    expect(listTriage(app.db)[0]).toMatchObject({ state: "reviewing", note: null, due_at: "2026-10-30" });
    const csv = await fetch(`${app.base}/triage.csv`, { headers: { cookie } });
    expect(csv.status).toBe(200);
    expect(await csv.text()).toContain("Two devices.");
    expect((await fetch(`${app.base}/triage.csv`)).status).toBe(403);
    expect((await formPost(app.base, "/triage/clear", { kind: "item", id: String(itemId), key: "" }, cookie)).status).toBe(303);
    expect(listTriage(app.db)).toHaveLength(0);

    const wire = await (await fetch(`${app.base}/wire?kind=kev`, { headers: { cookie } })).text();
    expect(wire).toContain('action="/triage"');
    // A source's unread count opens that source's unread items, keeping the kind filter.
    expect(wire).toMatch(/<a href="\/\?source=cisa-kev&amp;kind=kev">CISA Known Exploited Vulnerabilities<\/a><b><a href="\/\?source=cisa-kev&amp;kind=kev&amp;unread=1">\d+<\/a><\/b>/);
    expect(wire).toContain('<h2><a href="/?kind=kev">In the KEV lately</a></h2>');
    expect(wire).toMatch(/<li><a href="\/triage">Triage<\/a><a class="when" href="\/triage#affects">\d+ open<\/a><\/li>/);
    const detailId = (app.db.prepare("SELECT id FROM items LIMIT 1").get() as { id: number }).id;
    void detailId;

    const digestBefore = await (await fetch(`${app.base}/digest`)).text();
    expect(digestBefore).toContain("No digest yet.");
    expect(digestBefore).toContain("No notifier is configured");
    expect((await formPost(app.base, "/digest/run", {}, cookie)).status).toBe(303);
    const digestAfter = await (await fetch(`${app.base}/digest`)).text();
    expect(digestAfter).toContain('<section class="box digest" id="latest"><h2><a href="#latest">Daily digest</a> <span class="count"><a href="#latest">');
    expect(digestAfter).toContain("Known exploited (CISA KEV): 3 added");
    expect(digestAfter).toContain("digest · unconfigured");
    expect(digestAfter).toContain('<h2><a href="#alerts">Alerts sent</a> <span class="count"><a href="#alerts">1</a></span></h2>');
    // The digest's own URLs are links on the page, this instance's as paths.
    expect(digestAfter).toContain('<a href="/triage">/triage</a>');
    const home = await (await fetch(`${app.base}/register`)).text();
    expect(home).toContain("Needs you");
    expect(home).toMatch(/<dt>Inbox<\/dt><dd><a href="\/triage#new">\d+ not yet placed<\/a><\/dd>/);
    expect(home).toContain('<dt>Last digest</dt><dd><a href="/digest#latest">');
    expect(home).toContain('<dt>Last alert</dt><dd><a href="/digest#alerts">');
    expect(home).toContain('<span class="count"><a href="/standards/cisa-kev">catalog ');
  });
});
