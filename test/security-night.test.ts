import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { RateWindow, throttleKey } from "../src/auth.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { judgeTls, nodeTls, privateAddressError } from "../src/domaincheck.ts";
import { matchFirmware } from "../src/exposure.ts";
import { osvBatchUrl } from "../src/inventory.ts";
import { readSbom } from "../src/sbom.ts";
import { cookieFrom, fakeHttp, formPost, startTestApp } from "./helpers.ts";

/**
 * The security read of the night of 2026-10-21's additions, and what it changed: the public
 * domain check's TLS probe, the public routes' rate windows, the device report's size, the
 * owner's router model as a pattern, the LAN's facts on public pages, and a nested SBOM.
 */

const now = new Date("2026-10-22T02:00:00Z");

describe("the TLS probe", () => {
  it("answers a name that points at a private address without a packet, and the verdict says so", async () => {
    const probe = nodeTls(async () => [{ address: "192.168.1.1" }]);
    expect(await probe("probe.attacker.example")).toEqual({ error: privateAddressError });
    expect(judgeTls({ error: privateAddressError }, "probe.attacker.example", now)).toMatchObject({ state: "na", text: expect.stringContaining("private address") });
    const loopback = nodeTls(async () => [{ address: "2606:4700::1111" }, { address: "::1" }]);
    expect(await loopback("mixed.example")).toEqual({ error: privateAddressError });
    expect(await nodeTls(async () => [])("gone.example")).toEqual({ error: "ENOTFOUND" });
    const failing = nodeTls(async () => {
      throw Object.assign(new Error("no such name"), { code: "ENOTFOUND" });
    });
    expect(await failing("nowhere.example")).toEqual({ error: "ENOTFOUND" });
  });
});

describe("a rate window", () => {
  it("allows the limit in the window, refuses the rest without counting them, and opens again after", () => {
    const window = new RateWindow(2, 600_000);
    const t = now.getTime();
    expect(window.allow("a", t)).toBe(true);
    expect(window.allow("a", t + 1)).toBe(true);
    expect(window.allow("a", t + 2)).toBe(false);
    expect(window.allow("a", t + 3)).toBe(false);
    expect(window.allow("b", t + 3)).toBe(true);
    expect(window.allow("a", t + 600_001)).toBe(true);
  });

  it("is keyed by the /64 for an IPv6 visitor, so rotating addresses inside it buys nothing", () => {
    expect(throttleKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd")).toBe(throttleKey("2001:db8:1:2:1:2:3:4"));
    expect(throttleKey("2001:db8:1:2::1")).not.toBe(throttleKey("2001:db8:1:3::1"));
    expect(throttleKey("::ffff:203.0.113.9")).toBe("203.0.113.9");
  });

  it("sweeps itself once it is large, so many addresses cannot grow it without bound", () => {
    const window = new RateWindow(1, 1_000);
    const t = now.getTime();
    for (let i = 0; i < 10_000; i += 1) window.allow(`k${i}`, t);
    expect(window.size).toBe(10_000);
    window.allow("late", t + 2_000);
    expect(window.size).toBe(1);
  });
});

describe("the router model as a pattern", () => {
  let db: DatabaseSync;
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    const at = now.toISOString();
    const insert = db.prepare("INSERT INTO vulns (cve_id, last_modified_at, cvss_score, kev, description, vendors_json, products_json, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    insert.run("CVE-2026-3001", at, 9.8, 1, "Netgear R7000 command injection", '["netgear"]', '["r7000"]', at, at);
    insert.run("CVE-2026-3002", at, 7.5, 0, "Netgear WAX206 stack overflow", '["netgear"]', '["wax206"]', at, at);
  });
  afterEach(() => db.close());

  it("matches letters, not wildcards: a % in the model finds nothing", () => {
    expect(matchFirmware(db, "Netgear", "R7000").cves.map((c) => c.cve_id)).toEqual(["CVE-2026-3001"]);
    expect(matchFirmware(db, "Netgear", "%").cves).toEqual([]);
    expect(matchFirmware(db, "Netgear", "R_000").cves).toEqual([]);
    expect(matchFirmware(db, "%", null).cves).toEqual([]);
  });
});

describe("a nested bill of materials", () => {
  it("is read to a depth and no further, rather than running the stack out", () => {
    // Two thousand levels, written as text: an object literal that deep cannot even be stringified.
    const depth = 2_000;
    let open = "";
    for (let i = 0; i < depth; i += 1) open += `{"name":"level-${i}","purl":"pkg:npm/level-${i}@1.0.0","components":[`;
    const doc = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[${open}{"name":"deepest","purl":"pkg:npm/deepest@1.0.0"}${"]}".repeat(depth)}]}`;
    const parsed = readSbom(doc);
    expect(parsed.format).toBe("cyclonedx");
    // Levels 0 to 32 are read, the rest left.
    expect(parsed.packages.length).toBe(33);
    expect(parsed.packages.some((p) => p.name === "deepest")).toBe(false);
  });
});

describe("on the pages", () => {
  it("takes a Linux report of a few thousand packages, which is larger than any other form", async () => {
    const results = JSON.stringify({ results: Array.from({ length: 1000 }, () => ({ vulns: [] })) });
    const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" }, now: () => now, http: fakeHttp({ [osvBatchUrl]: { text: results } }) });
    try {
      const packages = Array.from({ length: 3000 }, (_, i) => ({ name: `package-${i}`, version: `1.${i}.0-1+deb12u1` }));
      const body = { bw: 1, os: { family: "linux", name: "Debian GNU/Linux", version: "12", build: null, display: null, id: "debian", version_id: "12" }, browsers: [], packages, package_source: "dpkg" };
      const report = `BW-REPORT-BEGIN\n${JSON.stringify(body)}\nBW-REPORT-END`;
      expect(report.length).toBeGreaterThan(16 * 1024);
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
      const response = await formPost(app.base, "/scan/devices", { device: "big box", report }, cookie);
      expect(response.status).toBe(200);
      const page = await response.text();
      expect(page).toContain("big box");
      expect(page).toContain("any of the 3000 installed versions");
      // Every other form keeps its small limit.
      const large = await formPost(app.base, "/saved", { name: "x".repeat(20_000), path: "/vulnerabilities?kev=1" }, cookie);
      expect(large.status).toBe(413);
    } finally {
      await app.close();
    }
  });

  it("shows the LAN resolver's address and a run's error to the owner alone", async () => {
    const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" }, now: () => now });
    try {
      const at = new Date(now.getTime() - 3_600_000).toISOString();
      app.db
        .prepare("INSERT INTO net_scans (started_at, finished_at, resolver, resolver_source, upstream, doh, error) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .run(at, at, "192.168.77.1", "/etc/resolv.conf", "203.0.113.53", "blocked", "pihole: HTTP 401");
      for (const path of ["/scan/network", "/scan/history"]) {
        const visitor = await (await fetch(`${app.base}${path}`)).text();
        expect(visitor).not.toContain("192.168.77.1");
        expect(visitor).not.toContain("203.0.113.53");
        expect(visitor).not.toContain("pihole: HTTP 401");
        expect(visitor).toContain("owner");
      }
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
      for (const path of ["/scan/network", "/scan/history"]) {
        const owner = await (await fetch(`${app.base}${path}`, { headers: { cookie } })).text();
        expect(owner).toContain("192.168.77.1");
      }
      expect(await (await fetch(`${app.base}/scan/history`, { headers: { cookie } })).text()).toContain("pihole: HTTP 401");
    } finally {
      await app.close();
    }
  });
});
