import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { exposureChanges, exposureDue, exposureKeys, judgeExposure, latestExposure, matchFirmware, readRouter, runExposureScan, traceUrl, validRouterUrl } from "../src/exposure.ts";
import { setSetting } from "../src/netscan.ts";
import { internetDbUrl } from "../src/seen.ts";
import { cookieFrom, fakeHttp, formPost, startTestApp } from "./helpers.ts";

/** Router and exposure (Scan 2.0, S4): the daily run from recorded answers, and what it alerts on. */

const now = new Date("2026-10-21T22:00:00Z");
const at = now.toISOString();

describe("the router address", () => {
  it("is a private address or a LAN name over http or https, with no credentials", () => {
    expect(validRouterUrl("192.168.1.1")).toBe("http://192.168.1.1");
    expect(validRouterUrl("https://10.0.0.1:8443/")).toBe("https://10.0.0.1:8443");
    expect(validRouterUrl("http://router.local")).toBe("http://router.local");
    expect(validRouterUrl("http://fritz.box")).toBeNull();
    expect(validRouterUrl("http://admin:pw@192.168.1.1")).toBeNull();
    expect(validRouterUrl("http://203.0.113.1")).toBeNull();
    expect(validRouterUrl("ftp://192.168.1.1")).toBeNull();
  });
});

function seedVulns(db: ReturnType<typeof openDatabase>): void {
  const insert = db.prepare("INSERT INTO vulns (cve_id, last_modified_at, cvss_score, cvss_severity, description, kev, first_seen_at, last_seen_at, vendors_json, products_json) VALUES (?, ?, ?, 'HIGH', ?, ?, ?, ?, ?, ?)");
  insert.run("CVE-2026-2001", at, 9.8, "Netgear RAX50 remote code execution", 1, at, at, '["netgear"]', '["rax50_firmware"]');
  insert.run("CVE-2026-2002", at, 7.5, "Netgear WAX206 bug", 0, at, at, '["netgear"]', '["wax206_firmware"]');
  insert.run("CVE-2026-2003", at, 9.0, "TP-Link Archer thing", 1, at, at, '["tp-link"]', '["archer_ax21_firmware"]');
}

describe("the firmware match", () => {
  it("finds the vendor's KEV entries, and with a model only the CVEs that name it", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    seedVulns(db);
    expect(matchFirmware(db, "Netgear", null)).toMatchObject({ vendor: "Netgear", model: null, kev: ["CVE-2026-2001"] });
    expect(matchFirmware(db, "netgear", "WAX206").cves.map((c) => c.cve_id)).toEqual(["CVE-2026-2002"]);
    expect(matchFirmware(db, "netgear", "RAX50").kev).toEqual(["CVE-2026-2001"]);
    expect(matchFirmware(db, "asus", null).cves).toEqual([]);
    db.close();
  });
});

describe("the router read", () => {
  it("sees a redirect to HTTPS, a page over plain HTTP, and nothing at all", async () => {
    const redirecting = fakeHttp({ "http://192.168.1.1/": { status: 301, headers: { location: "https://192.168.1.1/", server: "lighttpd" } }, "https://192.168.1.1/": { text: "<html><title>NETGEAR Router RAX50</title></html>" } });
    expect(await readRouter(redirecting, "http://192.168.1.1")).toMatchObject({ plainStatus: 301, redirectsToHttps: true, tlsStatus: 200, server: "lighttpd", title: "NETGEAR Router RAX50" });
    const plain = fakeHttp({ "http://192.168.1.1/": { text: "<title>Login</title>", headers: { server: "GoAhead-Webs" } } });
    expect(await readRouter(plain, "http://192.168.1.1")).toMatchObject({ plainStatus: 200, redirectsToHttps: false, tlsStatus: null, server: "GoAhead-Webs", title: "Login" });
    expect(await readRouter(fakeHttp({}), "http://192.168.1.1")).toMatchObject({ plainStatus: null, tlsStatus: null });
  });
});

describe("the judges and the changes", () => {
  const base = { at, publicIp: "203.0.113.9", internet: { ip: "203.0.113.9", ports: [], hostnames: [], cpes: [], vulns: [], tags: [], nothing: true }, router: null, firmware: null };
  it("read the facts into findings", () => {
    const quiet = judgeExposure(base);
    expect(quiet.map((f) => [f.id, f.state])).toEqual([["public-address", "ok"], ["internet", "ok"], ["router-admin", "na"], ["router-firmware", "na"]]);
    const loud = judgeExposure({ ...base, internet: { ...base.internet, ports: [22, 8080], vulns: ["CVE-2026-9"], nothing: false }, router: { url: "http://192.168.1.1", plainStatus: 200, redirectsToHttps: false, tlsStatus: null, server: "GoAhead-Webs", title: "Login", error: null }, firmware: { vendor: "netgear", model: "RAX50", kev: ["CVE-2026-2001"], cves: [{ cve_id: "CVE-2026-2001", cvss_score: 9.8, kev: 1, description: "RCE" }] } });
    expect(loud.map((f) => [f.id, f.state])).toEqual([["public-address", "ok"], ["internet", "bad"], ["router-admin", "warn"], ["router-firmware", "bad"]]);
    expect(loud[1]?.quoted).toContain("Ports: 22, 8080");
    expect(loud[3]?.quoted[0]).toContain("CVE-2026-2001 (KEV) CVSS 9.8");
  });
  it("name only what moved between two runs", () => {
    const first = { ...base, findings: [] };
    expect(exposureChanges(null, first)).toEqual([]);
    expect(exposureChanges(first, first)).toEqual([]);
    const second = { ...first, publicIp: "203.0.113.10", internet: { ...base.internet, ports: [443], nothing: false }, firmware: { vendor: "netgear", model: null, kev: ["CVE-2026-2001"], cves: [] } };
    expect(exposureChanges(first, second)).toEqual(["The public address changed: 203.0.113.9 → 203.0.113.10.", "Newly open on the public address: port(s) 443.", "Router firmware: CVE-2026-2001 added to the KEV."]);
  });
});

describe("a run", () => {
  it("stores the facts, is due once a day while on, and notifies only on a change", async () => {
    const db = openDatabase(":memory:");
    migrate(db);
    seedVulns(db);
    setSetting(db, exposureKeys.routerUrl, "http://192.168.1.1", at);
    setSetting(db, exposureKeys.vendor, "netgear", at);
    const routes = {
      [traceUrl]: { text: "fl=1\nh=cloudflare-dns.com\nip=203.0.113.9\nts=1\n" },
      [internetDbUrl("203.0.113.9")]: { text: '{"ip":"203.0.113.9","ports":[443],"hostnames":[],"cpes":[],"vulns":[],"tags":[]}' },
      "http://192.168.1.1/": { status: 301, headers: { location: "https://192.168.1.1/" } },
      "https://192.168.1.1/": { text: "<title>Router</title>" },
      "https://ntfy.example/bw": { text: "ok" },
    };
    const http = fakeHttp(routes);
    const transport = { scheme: "ntfy" as const, endpoint: "https://ntfy.example/bw" };
    const first = await runExposureScan(db, { http, now: () => now, transport });
    expect(first.publicIp).toBe("203.0.113.9");
    expect(first.findings.map((f) => f.state)).toEqual(["ok", "warn", "ok", "bad"]);
    expect(latestExposure(db)?.at).toBe(at);
    // The first run has nothing to compare with: no notification.
    expect(http.calls.filter((c) => c.url === transport.endpoint).length).toBe(0);
    expect(exposureDue(db, "UTC", now)).toBe(false);
    setSetting(db, exposureKeys.enabled, "1", at);
    expect(exposureDue(db, "UTC", now)).toBe(false);
    expect(exposureDue(db, "UTC", new Date("2026-10-22T06:00:00Z"))).toBe(true);
    // The same facts again: silence. A new port: one notification.
    await runExposureScan(db, { http, now: () => now, transport });
    expect(http.calls.filter((c) => c.url === transport.endpoint).length).toBe(0);
    const changed = fakeHttp({ ...routes, [internetDbUrl("203.0.113.9")]: { text: '{"ip":"203.0.113.9","ports":[443,8080],"hostnames":[],"cpes":[],"vulns":[],"tags":[]}' } });
    await runExposureScan(db, { http: changed, now: () => now, transport });
    expect(changed.calls.filter((c) => c.url === transport.endpoint).length).toBe(1);
    db.close();
  });
});

describe("on the network page", () => {
  it("shows the owner the section and the switches, a visitor only the words, and takes the settings", async () => {
    const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" }, now: () => now, http: fakeHttp({ [traceUrl]: { text: "ip=203.0.113.9\n" }, [internetDbUrl("203.0.113.9")]: { status: 404 } }) });
    try {
      const visitor = await (await fetch(`${app.base}/scan/network`)).text();
      expect(visitor).toContain("the owner alone sees it");
      expect(visitor).not.toContain('action="/scan/exposure/settings"');
      expect((await formPost(app.base, "/scan/exposure/settings", { on: "1" })).status).toBe(403);
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
      expect((await formPost(app.base, "/scan/exposure/settings", { on: "1", router_url: "http://203.0.113.1", vendor: "netgear" }, cookie)).status).toBe(400);
      const saved = await formPost(app.base, "/scan/exposure/settings", { on: "1", router_url: "192.168.1.1", vendor: "Netgear", model: "RAX50" }, cookie);
      expect(saved.status).toBe(303);
      expect(app.db.prepare("SELECT key, value FROM app_settings WHERE key LIKE 'exposure.%' ORDER BY key").all()).toEqual([
        { key: "exposure.enabled", value: "1" },
        { key: "exposure.router_model", value: "RAX50" },
        { key: "exposure.router_url", value: "http://192.168.1.1" },
        { key: "exposure.router_vendor", value: "netgear" },
      ]);
      const ran = await formPost(app.base, "/scan/exposure/run", {}, cookie);
      expect(ran.status).toBe(303);
      const page = await (await fetch(`${app.base}/scan/network`, { headers: { cookie } })).text();
      expect(page).toContain("This network reaches the internet as 203.0.113.9");
      expect(page).toContain("Shodan has nothing on record for this address");
      expect(page).toContain('value="http://192.168.1.1"');
      expect(page).toContain("Turn the daily exposure check off");
    } finally {
      await app.close();
    }
  });
});
