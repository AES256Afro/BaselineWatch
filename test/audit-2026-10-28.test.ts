import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { apiItems } from "../src/api.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { nextActions } from "../src/agenda.ts";
import { kevCalendar } from "../src/feeds.ts";
import { fixListCandidates, fixListTotal } from "../src/fixlist.ts";
import { setTriage } from "../src/triage.ts";
import { platformsOf } from "../src/platforms.ts";
import { listVulns, platformFigures } from "../src/vulns.ts";
import { listWire } from "../src/wire.ts";
import { cookieFrom, formPost, startTestApp, type TestApp } from "./helpers.ts";

/**
 * The audit of 2026-10-28: seven sweeps (two security, one bug, two performance, sources, and
 * readability with usability), and what they changed. Each case is one a sweep reproduced.
 */

const now = new Date("2026-10-28T12:00:00Z");

function freshDb() {
  const db = openDatabase(":memory:");
  migrate(db);
  return db;
}

function addVuln(db: ReturnType<typeof freshDb>, cveId: string, over: Record<string, string | number | null> = {}): number {
  const row: Record<string, string | number | null> = { cve_id: cveId, last_modified_at: now.toISOString(), first_seen_at: now.toISOString(), last_seen_at: now.toISOString(), published_at: now.toISOString(), description: `${cveId} in a widget`, ...over };
  const cols = Object.keys(row);
  db.prepare(`INSERT INTO vulns (${cols.join(", ")}) VALUES (${cols.map(() => "?").join(", ")})`).run(...cols.map((c) => row[c] ?? null));
  return (db.prepare("SELECT id FROM vulns WHERE cve_id = ?").get(cveId) as { id: number }).id;
}

function addCertItem(db: ReturnType<typeof freshDb>): void {
  db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at) VALUES ('crtsh', 'article', 'login.example.com:1', 'New certificate for login.example.com (R13)', 'https://crt.sh/?id=1', ?, ?)").run(now.toISOString(), now.toISOString());
  db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at, read, starred) VALUES ('bleeping', 'article', 'story-1', 'A public story', 'https://example.net/a', ?, ?, 1, 1)").run(now.toISOString(), now.toISOString());
}

describe("the owner's facts stay the owner's", () => {
  let app: TestApp;
  let cookie: string;
  let cveId: number;

  beforeAll(async () => {
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2", BW_PUBLIC_READ: "true" }, now: () => now });
    cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
    cveId = addVuln(app.db, "CVE-2026-90001");
    setTriage(app.db, { kind: "vuln", id: cveId }, { state: "reviewing", note: "only on the build server", dueAt: "2026-11-01" }, now.toISOString());
    app.db.prepare("INSERT INTO saved_searches (name, path, created_at) VALUES ('Fortinet this week', '/vulnerabilities?q=fortinet', ?)").run(now.toISOString());
    app.db.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES ('scan.domains', 'ownersite.net', ?)").run(now.toISOString());
    addCertItem(app.db);
  });

  afterAll(async () => {
    await app.close();
  });

  it("keeps a triage note off the CVE page for a visitor and on it for the owner", async () => {
    const visitor = await (await fetch(`${app.base}/vulnerabilities/CVE-2026-90001`)).text();
    expect(visitor).toContain("reviewing");
    expect(visitor).not.toContain("only on the build server");
    expect(await (await fetch(`${app.base}/vulnerabilities/CVE-2026-90001`, { headers: { cookie } })).text()).toContain("only on the build server");
  });

  it("does not list the owner's saved searches to a visitor", async () => {
    expect(await (await fetch(`${app.base}/saved`)).text()).not.toContain("Fortinet this week");
    expect(await (await fetch(`${app.base}/saved`, { headers: { cookie } })).text()).toContain("Fortinet this week");
  });

  it("does not name the owner's domains on the domain check", async () => {
    expect(await (await fetch(`${app.base}/scan/domain`)).text()).not.toContain("ownersite.net");
    expect(await (await fetch(`${app.base}/scan/domain`, { headers: { cookie } })).text()).toContain("ownersite.net");
  });

  it("keeps the certificates logged for the owner's domains out of a visitor's News, feed and API", async () => {
    expect(await (await fetch(`${app.base}/`)).text()).not.toContain("login.example.com");
    expect(await (await fetch(`${app.base}/feed.xml`)).text()).not.toContain("login.example.com");
    expect(await (await fetch(`${app.base}/api/v1/items`)).text()).not.toContain("login.example.com");
    expect(await (await fetch(`${app.base}/`, { headers: { cookie } })).text()).toContain("login.example.com");
  });

  it("keeps what the owner has read and starred to the owner", async () => {
    const visitor = (await (await fetch(`${app.base}/api/v1/items`)).json()) as { items: Record<string, unknown>[] };
    expect(visitor.items.length).toBeGreaterThan(0);
    for (const i of visitor.items) {
      expect(i).not.toHaveProperty("read");
      expect(i).not.toHaveProperty("starred");
    }
    const page = await (await fetch(`${app.base}/`)).text();
    expect(page).not.toContain(">starred<");
    expect(page).not.toContain("Unread only");
    const owner = (await (await fetch(`${app.base}/api/v1/items`, { headers: { cookie } })).json()) as { items: Record<string, unknown>[] };
    expect(owner.items.find((i) => i.externalId === "story-1")).toMatchObject({ read: true, starred: true });
  });

  it("lets a visitor look up the address they came from, and no other", async () => {
    const other = await formPost(app.base, "/scan/exposure", { ip: "8.8.8.8" });
    expect(other.status).toBe(403);
  });
});

describe("sign-in behind a tunnel", () => {
  let app: TestApp;

  beforeAll(async () => {
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" } });
  });

  afterAll(async () => {
    await app.close();
  });

  const attempt = (password: string, forwarded: string, cookie?: string): Promise<Response> =>
    fetch(`${app.base}/login`, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded", origin: app.base, "sec-fetch-site": "same-origin", "x-forwarded-for": forwarded, ...(cookie ? { cookie } : {}) },
      body: new URLSearchParams({ password, next: "/" }).toString(),
    });

  it("lets a browser the owner signed in from before past the peer's brake that wrong guesses from elsewhere closed", async () => {
    const first = await attempt("hunter2hunter2", "203.0.113.200");
    expect(first.status).toBe(303);
    const known = (first.headers.getSetCookie?.() ?? []).find((c) => c.startsWith("bw_known="))?.split(";")[0];
    expect(known).toBeTruthy();
    // Eight addresses, five wrong guesses each: forty failures through the one peer, the tunnel.
    for (let a = 1; a <= 8; a++) for (let n = 0; n < 5; n++) await attempt("wrong", `198.51.100.${a}`);
    expect((await attempt("hunter2hunter2", "203.0.113.201")).status).toBe(429);
    // A forged mark is refused…
    expect((await attempt("hunter2hunter2", "203.0.113.202", "bw_known=9999999999999.forged")).status).toBe(429);
    // …and the real one gets the owner in.
    expect((await attempt("hunter2hunter2", "203.0.113.201", known)).status).toBe(303);
  });
});

describe("Today's work and dates", () => {
  const since = new Date(now.getTime() - 24 * 3600_000).toISOString();

  it("leaves a CVE out of the fix list once it is marked done", () => {
    const db = freshDb();
    const id = addVuln(db, "CVE-2026-90002", { kev: 1 });
    expect(fixListCandidates(db, since).map((v) => v.cve_id)).toEqual(["CVE-2026-90002"]);
    setTriage(db, { kind: "vuln", id }, { state: "done" }, now.toISOString());
    expect(fixListCandidates(db, since)).toEqual([]);
    expect(fixListTotal(db, since)).toBe(0);
  });

  it("puts a CVE whose date has passed on the list, and not one due today", () => {
    const db = freshDb();
    setTriage(db, { kind: "vuln", id: addVuln(db, "CVE-2026-90003") }, { state: "affects", dueAt: "2026-10-27" }, now.toISOString());
    setTriage(db, { kind: "vuln", id: addVuln(db, "CVE-2026-90004") }, { state: "affects", dueAt: "2026-10-28" }, now.toISOString());
    const overdue = nextActions(db, { since, now }).filter((a) => a.kind === "overdue");
    expect(overdue.map((a) => a.href)).toEqual(["/vulnerabilities/CVE-2026-90003"]);
  });

  it("does not call a years-old release loaded by a history backfill a standard that moved today", () => {
    const db = freshDb();
    db.prepare("INSERT INTO items (source_id, kind, external_id, title, published_at, fetched_at, signals_json) VALUES ('nist-sp-800-53', 'release', 'catalog@old', 'NIST SP 800-53 5.1.1: 3 revised', '2023-10-12T00:00:00Z', ?, '{\"modified\":3}')").run(now.toISOString());
    expect(nextActions(db, { since, now }).filter((a) => a.kind === "release")).toEqual([]);
  });
});

describe("the table, the calendar and the order", () => {
  it("exports as many rows as the CSV asks for, not one page", () => {
    const db = freshDb();
    db.exec("BEGIN");
    for (let n = 0; n < 260; n++) addVuln(db, `CVE-2026-${String(80000 + n)}`);
    db.exec("COMMIT");
    expect(listVulns(db, { limit: 1000 }).rows.length).toBe(200);
    expect(listVulns(db, { limit: 1000 }, { maxLimit: 5000 }).rows.length).toBe(260);
  });

  it("leaves a KEV row with an unreadable due date out of the calendar instead of failing it", () => {
    const db = freshDb();
    addVuln(db, "CVE-2026-90005", { kev: 1, kev_due_date: "TBD" });
    addVuln(db, "CVE-2026-90006", { kev: 1, kev_due_date: "2026-11-03" });
    const ics = kevCalendar(db, "https://example.test", { watch: false, now });
    expect(ics).toContain("CVE-2026-90006");
    expect(ics).not.toContain("CVE-2026-90005");
  });

  it("keeps the public-exploit column in step with the exploits table, whichever arrives first", () => {
    const db = freshDb();
    const insertExploit = db.prepare("INSERT INTO exploits (cve_id, source_id, ref, title, url, published_at, verified, seen_at) VALUES (?, 'exploit-db', ?, 't', 'https://example.net', NULL, 0, ?)");
    addVuln(db, "CVE-2026-90007");
    insertExploit.run("CVE-2026-90007", "1", now.toISOString());
    insertExploit.run("CVE-2026-90008", "2", now.toISOString());
    addVuln(db, "CVE-2026-90008");
    const flag = (cve: string) => (db.prepare("SELECT has_exploit FROM vulns WHERE cve_id = ?").get(cve) as { has_exploit: number }).has_exploit;
    expect(flag("CVE-2026-90007")).toBe(1);
    expect(flag("CVE-2026-90008")).toBe(1);
    db.prepare("DELETE FROM exploits WHERE cve_id = 'CVE-2026-90007'").run();
    expect(flag("CVE-2026-90007")).toBe(0);
    const plan = db.prepare(`EXPLAIN QUERY PLAN SELECT v.* FROM vulns v ORDER BY v.kev DESC, v.has_exploit DESC, COALESCE(v.epss, 0) DESC, COALESCE(v.cvss_score, 0) DESC, v.last_modified_at DESC LIMIT 50 OFFSET 20000`).all() as { detail: string }[];
    expect(plan.map((p) => p.detail).join(" ")).toContain("vulns_risk");
  });

  it("leaves the owner-only sources out of a list nobody said was the owner's", () => {
    const db = freshDb();
    addCertItem(db);
    expect(listWire(db).map((i) => i.source_id)).toEqual(["bleeping"]);
    expect(listWire(db, {}, { owner: true }).map((i) => i.source_id).sort()).toEqual(["bleeping", "crtsh"]);
    expect(apiItems(db, {}, "https://example.test").map((i) => i.source)).toEqual(["bleeping"]);
  });
});

describe("the watchlist is the owner's, and the platforms are everyone's", () => {
  let app: TestApp;
  let cookie: string;

  beforeAll(async () => {
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2", BW_PUBLIC_READ: "true" }, now: () => now });
    cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
    app.db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('product', 'widgetd', 'Widget daemon', ?)").run(now.toISOString());
    addVuln(app.db, "CVE-2026-91001", { kev: 1, cvss_score: 9.8, platforms_json: '["windows"]', watch_hit: 1, watch_labels_json: '["Widget daemon"]' });
    addVuln(app.db, "CVE-2026-91002", { cvss_score: 8.1, platforms_json: '["chrome"]' });
    addVuln(app.db, "CVE-2026-91003", { cvss_score: 5.0, platforms_json: '["linux"]', epss: 0.7 });
  });

  afterAll(async () => {
    await app.close();
  });

  it("sends a visitor to sign in from the watchlist, and shows the owner theirs", async () => {
    const visitor = await fetch(`${app.base}/watchlist`);
    expect(visitor.status).toBe(401);
    expect(await visitor.text()).not.toContain("Widget daemon");
    expect(await (await fetch(`${app.base}/watchlist`, { headers: { cookie } })).text()).toContain("Widget daemon");
  });

  it("leaves the watch marks out of everything a visitor can read", async () => {
    const page = await (await fetch(`${app.base}/vulnerabilities`)).text();
    expect(page).not.toContain("Widget daemon");
    expect(page).not.toContain("My stack");
    expect(page).not.toContain("Match watchlist");
    // A link that asks for the watchlist gets the whole list, not the owner's slice of it.
    expect(await (await fetch(`${app.base}/vulnerabilities?watch=1`)).text()).toContain("CVE-2026-91002");
    expect(await (await fetch(`${app.base}/vulnerabilities/CVE-2026-91001`)).text()).not.toContain("Widget daemon");
    expect(await (await fetch(`${app.base}/vulnerabilities.csv`)).text()).not.toContain("Widget daemon");
    expect(await (await fetch(`${app.base}/vulnerabilities/feed.xml`)).text()).not.toContain("your stack");
    const api = (await (await fetch(`${app.base}/api/v1/vulns`)).json()) as { vulns: Record<string, unknown>[] };
    for (const v of api.vulns) expect(v).not.toHaveProperty("watch");
    const owner = await (await fetch(`${app.base}/vulnerabilities`, { headers: { cookie } })).text();
    expect(owner).toContain("Widget daemon");
    expect(owner).toContain("My stack");
  });

  it("opens the table on what is affecting each platform, each figure a link to its list", async () => {
    const page = await (await fetch(`${app.base}/vulnerabilities`)).text();
    expect(page).toContain("What is affecting");
    expect(page).toContain('href="/vulnerabilities?platform=windows"');
    expect(page).toContain('href="/vulnerabilities?platform=windows&amp;kev=1"');
    expect(page).toContain('href="/vulnerabilities?danger=1"');
    const browsers = await (await fetch(`${app.base}/vulnerabilities?platform=browsers`)).text();
    expect(browsers).toContain("CVE-2026-91002");
    expect(browsers).not.toContain("CVE-2026-91001");
    const danger = await (await fetch(`${app.base}/vulnerabilities?danger=1`)).text();
    expect(danger).toContain("CVE-2026-91001");
    expect(danger).toContain("CVE-2026-91003");
    expect(danger).not.toContain("CVE-2026-91002");
  });

  it("counts each platform from the side table the triggers keep", () => {
    const since = new Date(now.getTime() - 7 * 86_400_000).toISOString();
    const figures = platformFigures(app.db, since);
    expect(figures.find((f) => f.id === "windows")).toMatchObject({ total: 1, kev: 1, worst: { cve_id: "CVE-2026-91001" } });
    expect(figures.find((f) => f.id === "browsers")).toMatchObject({ total: 1, kev: 0 });
    expect(figures.find((f) => f.id === "danger")).toMatchObject({ total: 2 });
    app.db.prepare("UPDATE vulns SET platforms_json = '[\"apple\"]' WHERE cve_id = 'CVE-2026-91002'").run();
    expect(app.db.prepare("SELECT platform FROM vuln_platforms WHERE vuln_id = (SELECT id FROM vulns WHERE cve_id = 'CVE-2026-91002')").all()).toEqual([{ platform: "apple" }]);
  });

  it("narrows the News and Today to a platform by address, without a picker on either", async () => {
    const insert = app.db.prepare("INSERT INTO items (source_id, kind, external_id, title, summary, url, published_at, fetched_at, signals_json) VALUES ('bleeping', 'article', ?, ?, ?, 'https://example.net', ?, ?, ?)");
    insert.run("w1", "Patch now: a Windows SMB flaw", null, now.toISOString(), now.toISOString(), null);
    insert.run("w2", "A long post about tooling", "It also mentions Windows in passing.", now.toISOString(), now.toISOString(), null);
    insert.run("w3", "Researchers detail a new widget flaw", null, now.toISOString(), now.toISOString(), '{"cves":["CVE-2026-91001"]}');
    insert.run("c1", "Chrome ships a fix for a V8 bug", null, now.toISOString(), now.toISOString(), null);
    const windows = await (await fetch(`${app.base}/?platform=windows`)).text();
    expect(windows).toContain("Patch now: a Windows SMB flaw");
    // Placed by the CVE it names, which is a Windows CVE.
    expect(windows).toContain("Researchers detail a new widget flaw");
    // A headline that does not name the platform is not its story, whatever the summary says.
    expect(windows).not.toContain("A long post about tooling");
    expect(windows).not.toContain("Chrome ships a fix");
    // The filter works from a link; the chips stay on Vulnerabilities, and the heading says how to undo it.
    expect(windows).not.toContain('class="filters platform-pick"');
    expect(windows).toContain(">show all</a>");
    const danger = await (await fetch(`${app.base}/?danger=1`)).text();
    expect(danger).toContain("Researchers detail a new widget flaw");
    expect(danger).not.toContain("Chrome ships a fix");
    const today = await (await fetch(`${app.base}/today?platform=browsers&since=168`)).text();
    expect(today).not.toContain('class="filters platform-pick"');
    expect(today).toContain('<a class="show-all" href="/today?since=168">show all</a>');
  });

  it("files a CVE by its CPE, not by a browser its description mentions", () => {
    const ray = { cpes: ["cpe:2.3:a:anyscale:ray:*:*:*:*:*:*:*:*"], vendors: ["anyscale"], products: ["ray"], description: "Ray … exploitable via Firefox and Safari." };
    expect(platformsOf(ray)).toEqual([]);
    expect(platformsOf({ cpes: [], vendors: [], products: [], description: "A use after free in Google Chrome prior to 150.0" })).toEqual(["chrome"]);
  });
});
