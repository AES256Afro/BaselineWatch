import { afterEach, describe, expect, it } from "vitest";
import { LoginThrottle, parseCookies, passwordMatches, signSession, verifySession } from "../src/auth.ts";
import { cookieFrom, fakeHttp, fixture, formPost, startTestApp, type TestApp } from "./helpers.ts";

describe("session tokens", () => {
  it("verify only what was signed with the same secret and has not expired", () => {
    const token = signSession("s1", 2_000_000);
    expect(verifySession("s1", token, 1_000_000)).toBe(true);
    expect(verifySession("s1", token, 3_000_000)).toBe(false);
    expect(verifySession("s2", token, 1_000_000)).toBe(false);
    expect(verifySession("s1", `${token}x`, 1_000_000)).toBe(false);
    expect(verifySession("s1", "9999999999.", 1_000_000)).toBe(false);
    expect(verifySession("s1", undefined, 1_000_000)).toBe(false);
  });

  it("compares passwords in constant time regardless of length", () => {
    expect(passwordMatches("correct horse", "correct horse")).toBe(true);
    expect(passwordMatches("correct horse", "correct hors")).toBe(false);
    expect(passwordMatches("a", "")).toBe(false);
  });

  it("parses cookies and throttles repeated failures", () => {
    expect(parseCookies("a=1; bw_session=x.y; c=%20z")).toEqual({ a: "1", bw_session: "x.y", c: " z" });
    const t = new LoginThrottle(2, 1000);
    expect(t.blocked("ip", 0)).toBe(false);
    t.fail("ip", 0);
    t.fail("ip", 1);
    expect(t.blocked("ip", 2)).toBe(true);
    expect(t.blocked("ip", 1002)).toBe(false);
  });
});

describe("owner session over HTTP", () => {
  let app: TestApp;
  afterEach(async () => {
    await app?.close();
  });

  it("opens reading, gates writes behind sign-in, and refuses cross-site posts", async () => {
    const kevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" }, http: fakeHttp({ [kevUrl]: { bytes: fixture("kev.json") } }) });

    const home = await fetch(`${app.base}/`);
    expect(home.status).toBe(200);
    expect(await home.text()).toContain("Owner sign-in");

    // Writes without a session are refused, and so is a cross-site post even with one.
    expect((await formPost(app.base, "/sources/cisa-kev/fetch", {})).status).toBe(403);
    const wrong = await formPost(app.base, "/login", { password: "nope", next: "/wire" });
    expect(wrong.status).toBe(401);
    expect(await wrong.text()).toContain("not right");

    const ok = await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/wire" });
    expect(ok.status).toBe(303);
    expect(ok.headers.get("location")).toBe("/wire");
    const cookie = cookieFrom(ok);
    expect(cookie).toMatch(/^bw_session=\d+\./);
    expect(ok.headers.get("set-cookie")).toContain("HttpOnly");
    expect(ok.headers.get("set-cookie")).toContain("SameSite=Strict");

    const crossSite = await fetch(`${app.base}/sources/cisa-kev/fetch`, {
      method: "POST",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded", origin: "https://evil.example", "sec-fetch-site": "cross-site" },
      body: "",
      redirect: "manual",
    });
    expect(crossSite.status).toBe(403);

    const fetched = await formPost(app.base, "/sources/cisa-kev/fetch", {}, cookie);
    expect(fetched.status).toBe(303);
    expect(fetched.headers.get("location")).toBe("/sources#src-cisa-kev");
    const flash = (fetched.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
    expect(decodeURIComponent(flash)).toContain('"status":"ok"');
    const sources = await (await fetch(`${app.base}/sources`, { headers: { cookie: `${cookie}; ${flash}` } })).text();
    expect(sources).toContain("3 items, 3 new");
    expect(sources).toContain("Fetch now");

    const wire = await (await fetch(`${app.base}/wire?kind=kev`, { headers: { cookie } })).text();
    expect(wire).toContain("Ahsay AhsayCBS");
    expect(wire).toContain("Mark read");
    expect(wire).toContain("Sign out");
    const anonymousWire = await (await fetch(`${app.base}/wire?kind=kev`)).text();
    expect(anonymousWire).toContain("Ahsay AhsayCBS");
    expect(anonymousWire).not.toContain("Mark read");

    const id = (app.db.prepare("SELECT id FROM items WHERE external_id = 'CVE-2026-105134'").get() as { id: number }).id;
    const read = await formPost(app.base, `/items/${id}/read`, { back: "/wire?kind=kev" }, cookie);
    expect(read.status).toBe(303);
    expect(read.headers.get("location")).toBe("/wire?kind=kev");
    expect((app.db.prepare("SELECT read FROM items WHERE id = ?").get(id) as { read: number }).read).toBe(1);
    const evilBack = await formPost(app.base, `/items/${id}/star`, { back: "//evil.example/x" }, cookie);
    expect(evilBack.headers.get("location")).toBe("/");

    const readAll = await formPost(app.base, "/wire/read-all", { kind: "kev", back: "/wire" }, cookie);
    expect(readAll.status).toBe(303);
    expect((app.db.prepare("SELECT COUNT(*) AS n FROM items WHERE read = 0").get() as { n: number }).n).toBe(0);

    const out = await formPost(app.base, "/logout", {}, cookie);
    expect(out.headers.get("set-cookie")).toContain("Max-Age=0");
  });

  it("closes reading entirely when BW_PUBLIC_READ is off", async () => {
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2", BW_PUBLIC_READ: "false" } });
    const home = await fetch(`${app.base}/`);
    expect(home.status).toBe(401);
    expect(await home.text()).toContain("Owner sign-in");
    expect((await fetch(`${app.base}/health`)).status).toBe(200);
    const ok = await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" });
    const cookie = cookieFrom(ok);
    expect((await fetch(`${app.base}/`, { headers: { cookie } })).status).toBe(200);
  });

  it("is single-user when no password is set: writes open, no sign-in drawn", async () => {
    app = await startTestApp();
    const home = await (await fetch(`${app.base}/register`)).text();
    expect(home).not.toContain("Owner sign-in");
    expect(home).toContain("open (no owner password set)");
    const login = await (await fetch(`${app.base}/login`)).text();
    expect(login).toContain("single-user mode");
    expect((await formPost(app.base, "/wire/read-all", { back: "/wire" })).status).toBe(303);
  });
});
