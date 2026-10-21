import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.ts";
import { isLook, isScheme, lookAttributes, lookCookieHeaders, lookState, lookSwitch, readLook } from "../src/look.ts";
import { safeBack } from "../src/paths.ts";
import { setTriage } from "../src/triage.ts";
import { formPost, startTestApp, type TestApp } from "./helpers.ts";

const defaults = { look: "console", scheme: "system" } as const;

describe("the look and the scheme", () => {
  it("come from the cookies when they hold a known word, else from the defaults", () => {
    expect(readLook(undefined, defaults)).toEqual(defaults);
    expect(readLook("bw_look=register; bw_scheme=dark", defaults)).toEqual({ look: "register", scheme: "dark" });
    expect(readLook("bw_look=neon; bw_scheme=%3Cscript%3E", defaults)).toEqual(defaults);
    expect(readLook("bw_scheme=light", defaults)).toEqual({ look: "console", scheme: "light" });
    expect(isLook("console") && isScheme("system") && !isLook("x") && !isScheme(1) && !isLook(null)).toBe(true);
  });

  it("are two cookies a year long, HttpOnly, Lax, and Secure behind TLS", () => {
    const [look, scheme] = lookCookieHeaders({ look: "register", scheme: "dark" }, false);
    expect(look).toBe("bw_look=register; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax");
    expect(scheme).toBe("bw_scheme=dark; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax");
    expect(lookCookieHeaders(defaults, true)[0]).toMatch(/; Secure$/);
  });

  it("set the root attributes, with no scheme when the device decides", () => {
    expect(lookAttributes({ look: "console", scheme: "system" }).value).toBe(' data-look="console"');
    expect(lookAttributes({ look: "register", scheme: "dark" }).value).toBe(' data-look="register" data-scheme="dark"');
  });

  it("take the request's path as the way back, on this site only", () => {
    expect(lookState({ headers: {}, originalUrl: "/today?since=72" }, defaults)).toEqual({ ...defaults, back: "/today?since=72" });
    expect(lookState({ headers: { cookie: "bw_look=register" }, originalUrl: "https://evil.example/" }, defaults)).toEqual({ look: "register", scheme: "system", back: "/" });
    expect(safeBack("//evil.example", "/x")).toBe("/x");
    expect(safeBack("/a\\b", "/x")).toBe("/x");
    expect(safeBack("/wire?q=a", "/x")).toBe("/wire?q=a");
    expect(safeBack(42, "/x")).toBe("/x");
  });

  it("draw the switch with the current choice pressed and the way back escaped", () => {
    const text = lookSwitch({ look: "console", scheme: "dark", back: '/wire?q="x"' }).value;
    expect(text).toContain('name="scheme" value="dark" aria-pressed="true"');
    expect(text).toContain('name="scheme" value="light" aria-pressed="false"');
    expect(text).toContain('name="look" value="console" aria-pressed="true"');
    expect(text).toContain('name="look" value="register" aria-pressed="false"');
    expect(text).toContain('value="/wire?q=&quot;x&quot;"');
    expect(text).not.toContain('q="x"');
  });

  it("default to the console and the device's scheme, from BW_LOOK and BW_SCHEME, and refuse other words", () => {
    expect(loadConfig({})).toMatchObject({ look: "console", scheme: "system" });
    expect(loadConfig({ BW_LOOK: "register", BW_SCHEME: " Dark " })).toMatchObject({ look: "register", scheme: "dark" });
    expect(() => loadConfig({ BW_LOOK: "neon" })).toThrow(/BW_LOOK must be one of register, console/);
    expect(() => loadConfig({ BW_SCHEME: "auto" })).toThrow(/BW_SCHEME must be one of system, light, dark/);
  });
});

describe("the switch on the site", () => {
  let app: TestApp;
  const now = new Date("2026-10-15T12:00:00.000Z");

  beforeAll(async () => {
    app = await startTestApp({ now: () => now });
  });

  afterAll(async () => {
    await app.close();
  });

  it("draws every page in the instance's defaults until a browser chooses", async () => {
    const text = await (await fetch(`${app.base}/today`)).text();
    expect(text).toContain('<html lang="en" data-look="console">');
    expect(text).not.toContain("data-scheme");
    expect(text).toContain('<meta name="color-scheme" content="light dark">');
    // The switch left the masthead for the Desk's Appearance page (M17); no page but that one carries it.
    expect(text).not.toContain('class="look-group"');
    expect(text).toContain('<b>Appearance</b><small>the look and the colour scheme</small>');
    const appearance = await (await fetch(`${app.base}/appearance`)).text();
    expect(appearance).toContain('class="look-group" aria-label="Colours"');
    expect(appearance).toContain('value="/appearance"');
    const missing = await fetch(`${app.base}/nope`);
    expect(missing.status).toBe(404);
    expect(await missing.text()).toContain('<html lang="en" data-look="console">');
  });

  it("keeps a choice in two cookies and comes back to the page it was made on", async () => {
    const response = await formPost(app.base, "/look", { scheme: "dark", back: "/wire?kind=kev" });
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/wire?kind=kev");
    expect(response.headers.getSetCookie()).toEqual([
      "bw_look=console; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax",
      "bw_scheme=dark; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax",
    ]);
    const page = await (await fetch(`${app.base}/wire`, { headers: { cookie: "bw_look=console; bw_scheme=dark" } })).text();
    expect(page).toContain('<html lang="en" data-look="console" data-scheme="dark">');
    expect(page).toContain('<meta name="color-scheme" content="dark">');
    const chooser = await (await fetch(`${app.base}/appearance`, { headers: { cookie: "bw_look=console; bw_scheme=dark" } })).text();
    expect(chooser).toContain('name="scheme" value="dark" aria-pressed="true"');
    // Changing the look keeps the scheme already chosen, and the other way round.
    const next = await formPost(app.base, "/look", { look: "register", back: "/" }, "bw_look=console; bw_scheme=dark");
    expect(next.headers.getSetCookie().map((c) => c.split(";")[0])).toEqual(["bw_look=register", "bw_scheme=dark"]);
    const light = await formPost(app.base, "/look", { scheme: "light", back: "/" }, "bw_look=register; bw_scheme=dark");
    expect(light.headers.getSetCookie().map((c) => c.split(";")[0])).toEqual(["bw_look=register", "bw_scheme=light"]);
  });

  it("refuses a word it does not know, a way back off this site, and a post from elsewhere", async () => {
    const unknown = await formPost(app.base, "/look", { look: "neon" });
    expect(unknown.status).toBe(400);
    expect(unknown.headers.getSetCookie()).toEqual([]);
    expect((await formPost(app.base, "/look", { look: "register", back: "https://evil.example/" })).headers.get("location")).toBe("/");
    expect((await formPost(app.base, "/look", { look: "register", back: "//evil.example/" })).headers.get("location")).toBe("/");
    const foreign = await fetch(`${app.base}/look`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://evil.example" },
      body: "scheme=dark",
      redirect: "manual",
    });
    expect(foreign.status).toBe(403);
    expect(foreign.headers.getSetCookie()).toEqual([]);
  });

  it("draws Today's glance panels from the data, with the figures in words and the feeds' words escaped", async () => {
    const db = app.db;
    const day = (iso: string) => iso;
    const item = db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at, signals_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    item.run("cisa-kev", "kev", "CVE-2026-1", "Ahsay AhsayCBS: one", "https://nvd/1", day("2026-10-14T18:00:00.000Z"), now.toISOString(), JSON.stringify({ kev: true, vendor: "Ahsay", dueDate: "2026-11-01" }));
    item.run("cisa-kev", "kev", "CVE-2026-2", "Ahsay AhsayCBS: two", "https://nvd/2", day("2026-10-14T18:00:00.000Z"), now.toISOString(), JSON.stringify({ kev: true, vendor: "Ahsay" }));
    item.run("cisa-kev", "kev", "CVE-2026-3", "Acme: three", "https://nvd/3", day("2026-10-14T18:00:00.000Z"), now.toISOString(), JSON.stringify({ kev: true, vendor: "<Acme> & Sons" }));
    item.run("bleeping", "article", "a1", "A story", "https://b/1", day("2026-10-15T09:00:00.000Z"), now.toISOString(), null);
    db.prepare("INSERT INTO vulns (cve_id, last_modified_at, cvss_score, cvss_severity, epss, watch_hit, first_seen_at, last_seen_at) VALUES ('CVE-2026-1', ?, 9.8, 'CRITICAL', 0.7, 1, ?, ?)").run(now.toISOString(), now.toISOString(), now.toISOString());
    db.prepare("INSERT INTO vulns (cve_id, last_modified_at, cvss_score, cvss_severity, epss, watch_hit, first_seen_at, last_seen_at) VALUES ('CVE-2026-9', ?, 4.0, 'MEDIUM', 0.002, 0, ?, ?)").run(now.toISOString(), now.toISOString(), now.toISOString());
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-1', ?, 'cvss')").run(now.toISOString());
    const first = (db.prepare("SELECT id FROM items WHERE external_id = 'CVE-2026-1'").get() as { id: number }).id;
    setTriage(db, { kind: "item", id: first, key: "" }, { state: "affects" }, now.toISOString());
    db.prepare("UPDATE sources SET last_status = 'ok', last_fetch_at = ? WHERE id = 'cisa-kev'").run("2026-10-15T11:58:00.000Z");
    db.prepare("UPDATE sources SET last_status = 'error', last_error = 'HTTP 503', last_fetch_at = ? WHERE id = 'bleeping'").run("2026-10-15T11:00:00.000Z");

    const text = await (await fetch(`${app.base}/today`)).text();
    expect(text).toContain('aria-label="Known exploited by vendor, 30 days: Ahsay 2, &lt;Acme&gt; &amp; Sons 1"');
    expect(text).not.toContain("<Acme>");
    expect(text).toContain('aria-label="News items a day, 14 days: News 1 in all, 1 on 10-15; Vulnerabilities 3 in all, 0 on 10-15; Standards 0 in all, 0 on 10-15"');
    expect(text).toContain(">10-02</text>");
    // Four panels of charts gave their room to lists that lead somewhere (M17): what to do next,
    // and the window's CVEs by the platform they affect.
    expect(text).not.toContain("by EPSS band");
    expect(text).not.toContain("Triage by state");
    expect(text).toContain('<section class="box wide" id="next">');
    expect(text).toContain('<section class="box wide" id="platforms">');
    // A failing source is named with its error in the side column, where it was always drawn too.
    expect(text).toContain('<a href="/sources#src-bleeping"><b>BleepingComputer</b></a> <span class="small">HTTP 503</span>');
    expect(text).toContain("<b>3</b>");
    expect(text).toContain('<a class="tile warn" href="/triage"><small>Needs you</small><b>1</b>');
  });
});

describe("the instance's own defaults", () => {
  it("come from BW_LOOK and BW_SCHEME, and a browser's cookies win over them", async () => {
    const app = await startTestApp({ env: { BW_LOOK: "register", BW_SCHEME: "light" } });
    try {
      const text = await (await fetch(`${app.base}/`)).text();
      expect(text).toContain('<html lang="en" data-look="register" data-scheme="light">');
      expect(text).toContain('<meta name="color-scheme" content="light">');
      const chosen = await (await fetch(`${app.base}/`, { headers: { cookie: "bw_scheme=dark" } })).text();
      expect(chosen).toContain('<html lang="en" data-look="register" data-scheme="dark">');
    } finally {
      await app.close();
    }
  });

  it("hold on a closed instance: the sign-in page is drawn in the chosen look, and the switch works before signing in", async () => {
    const app = await startTestApp({ env: { BW_PUBLIC_READ: "false", BW_ADMIN_PASSWORD: "correct horse battery" } });
    try {
      const closed = await fetch(`${app.base}/today`, { headers: { cookie: "bw_look=register" } });
      expect(closed.status).toBe(401);
      expect(await closed.text()).toContain('<html lang="en" data-look="register">');
      const response = await formPost(app.base, "/look", { scheme: "dark", back: "/today" });
      expect(response.status).toBe(303);
      expect(response.headers.getSetCookie()[1]).toMatch(/^bw_scheme=dark;/);
    } finally {
      await app.close();
    }
  });
});
