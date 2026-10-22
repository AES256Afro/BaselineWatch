import { describe, expect, it } from "vitest";
import { msrcApi } from "../src/adapters/msrc.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { latestBrowser, matchOs, matchPackages, matchWindows, osvBatchUrl, osvEcosystem, queryOsv, readReport, windowsProduct } from "../src/inventory.ts";
import { upsertItems } from "../src/items.ts";
import { compareDotted, newestVersion } from "../src/versions.ts";
import { cookieFrom, fakeHttp, fixture, formPost, startTestApp } from "./helpers.ts";

/**
 * Is this device affected? (S7): the inventory report read against the Security Update Guide
 * rows (the MSRC fixture), the vendors' release items, endoflife.date's cycles and OSV's batch
 * answer as captured on 2026-10-21 for an old Debian 12 openssl, an Ubuntu curl, a package that
 * does not exist and an Alpine openssl.
 */

const now = new Date("2026-10-21T22:00:00Z");
const at = now.toISOString();

describe("versions", () => {
  it("compare as people read them", () => {
    expect(compareDotted("10.0.26100.9711", "10.0.26100.9445")).toBeGreaterThan(0);
    expect(compareDotted("10.0.26100", "10.0.26100.1")).toBeLessThan(0);
    expect(compareDotted("156.0.8078.47", "156.0.8078.47")).toBe(0);
    expect(compareDotted("26.7.1", "27")).toBeLessThan(0);
    expect(newestVersion(["26.7", "27.0.1", "26.7.1"])).toBe("27.0.1");
  });
});

describe("the report", () => {
  it("is read between its markers, or refused with the reason", () => {
    const text = `some noise\nBW-REPORT-BEGIN\n{"bw":1,"os":{"family":"windows","name":"Windows 11 Pro","version":"24H2","build":"10.0.26100.9445","display":"24H2"},"browsers":[{"name":"Edge","version":"156.0.3351.55"}],"packages":[],"package_source":""}\nBW-REPORT-END\n`;
    const report = readReport(text);
    expect(report.os).toMatchObject({ family: "windows", build: "10.0.26100.9445", display: "24H2" });
    expect(report.browsers).toEqual([{ name: "Edge", version: "156.0.3351.55" }]);
    expect(() => readReport("{}")).toThrow(/not a report/);
    expect(() => readReport('{"bw":1,"os":{"family":"beos"}}')).toThrow(/windows, macos or linux/);
    expect(windowsProduct("24H2", "10.0.26100.9445")).toBe("Windows 11 Version 24H2");
    expect(windowsProduct("22H2", "10.0.19045.5000")).toBe("Windows 10 Version 22H2");
    expect(windowsProduct(null, "10.0.26100.9445")).toBeNull();
  });
});

describe("a Windows build", () => {
  it("is judged against the guide's fixed builds: behind means the CVEs the missing KB fixes", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      const db = app.db;
      await ingestSource(db, app.dataDir, getSource(db, "msrc")!, { http: fakeHttp({ [`${msrcApi}/updates`]: { bytes: fixture("msrc/updates.json") }, [`${msrcApi}/cvrf/2026-Oct`]: { bytes: fixture("msrc/2026-Oct.json") } }), now: () => now });
      const base = { bw: 1 as const, browsers: [] as { name: string; version: string }[], packages: [] as { name: string; version: string }[], packageSource: null };
      const behind = matchWindows(db, { ...base, os: { family: "windows", name: "Windows 11 Pro", version: "24H2", build: "10.0.26100.9445", display: "24H2", id: null, versionId: null } });
      expect(behind.state).toBe("bad");
      expect(behind.text).toContain("KB5127648");
      expect(behind.text).toContain("exploited");
      expect(behind.refs.some((r) => r.id === "CVE-2026-100200" && r.href === "/vulnerabilities/CVE-2026-100200")).toBe(true);
      expect(behind.refs[0]?.note).toContain("exploited");
      const current = matchWindows(db, { ...base, os: { family: "windows", name: "Windows 11 Pro", version: "24H2", build: "10.0.26100.9711", display: "24H2", id: null, versionId: null } });
      expect(current.state).toBe("ok");
      expect(current.text).toContain("carries every security update");
      const unknown = matchWindows(db, { ...base, os: { family: "windows", name: null, version: null, build: null, display: null, id: null, versionId: null } });
      expect(unknown.state).toBe("na");
    } finally {
      await app.close();
    }
  });
});

describe("browsers and the OS", () => {
  it("are judged against the vendors' newest announced releases and endoflife.date", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    upsertItems(db, "chrome-releases", [
      { kind: "article", externalId: "c1", title: "Stable Channel Update for Desktop", url: "https://chromereleases.googleblog.com/1", summary: "The Chrome team is delighted to announce the promotion of Chrome 156 to the stable channel for Windows, Mac and Linux. Chrome 156.0.8078.47 contains a number of fixes.", publishedAt: "2026-10-20T20:09:05.710Z" },
      { kind: "article", externalId: "c2", title: "Stable Channel Update for Desktop", url: "https://chromereleases.googleblog.com/2", summary: "The Stable channel has been updated to 155.0.8059.130 for Windows, Mac and Linux.", publishedAt: "2026-10-15T20:50:35.703Z" },
      { kind: "article", externalId: "c3", title: "Chrome for Android Update", url: "https://chromereleases.googleblog.com/3", summary: "Chrome 156 (156.0.8078.47) for Android.", publishedAt: "2026-10-20T20:10:45.076Z" },
    ], at);
    upsertItems(db, "mozilla-mfsa", [
      { kind: "article", externalId: "mfsa2026-111", title: "MFSA 2026-111: Security Vulnerabilities fixed in Firefox 158.0.1", url: "https://www.mozilla.org/en-US/security/advisories/mfsa2026-111/", summary: null, publishedAt: "2026-10-14T12:00:00.000Z", signals: { impact: "high", product: "Firefox 158.0.1" } },
      { kind: "article", externalId: "mfsa2026-116", title: "MFSA 2026-116: Security Vulnerabilities fixed in Firefox for Android 158.0.2", url: "https://x", summary: null, publishedAt: "2026-10-21T12:00:00.000Z", signals: { impact: "high", product: "Firefox for Android 158.0.2" } },
    ], at);
    upsertItems(db, "apple-security", [
      { kind: "article", externalId: "149228", title: "macOS Tahoe 26.7.1", url: "https://support.apple.com/en-us/149228", summary: null, publishedAt: "2026-09-28T12:00:00.000Z", signals: { line: "macOS" } },
      { kind: "article", externalId: "149200", title: "macOS Tahoe 26.7", url: "https://support.apple.com/en-us/149200", summary: null, publishedAt: "2026-09-15T12:00:00.000Z", signals: { line: "macOS" } },
      { kind: "article", externalId: "149230", title: "macOS Golden Gate 27.0.1", url: "https://support.apple.com/en-us/149230", summary: null, publishedAt: "2026-09-28T12:00:00.000Z", signals: { line: "macOS" } },
      { kind: "article", externalId: "149231", title: "Safari 26.1", url: "https://support.apple.com/en-us/149231", summary: null, publishedAt: "2026-09-29T12:00:00.000Z", signals: { line: "Safari" } },
    ], at);
    const chrome = latestBrowser(db, "chrome", "155.0.8059.85")!;
    expect(chrome.version).toBe("156.0.8078.47");
    expect(chrome.newer.map((n) => n.version)).toEqual(["156.0.8078.47", "155.0.8059.130"]);
    expect(latestBrowser(db, "firefox", "158.0")!).toMatchObject({ version: "158.0.1" });
    expect(latestBrowser(db, "firefox", "158.0")!.newer.length).toBe(1);
    expect(latestBrowser(db, "safari", "26.1")!.newer).toEqual([]);
    expect(latestBrowser(db, "edge", "1.0")?.version).toBe("156.0.8078.47");
    const base = { bw: 1 as const, browsers: [] as { name: string; version: string }[], packages: [] as { name: string; version: string }[], packageSource: null };
    const mac = matchOs(db, { ...base, os: { family: "macos", name: "macOS", version: "26.7", build: "25G100", display: null, id: null, versionId: null } });
    expect(mac).toMatchObject({ state: "warn", text: expect.stringContaining("behind 26.7.1") });
    expect(matchOs(db, { ...base, os: { family: "macos", name: "macOS", version: "27.0.1", build: null, display: null, id: null, versionId: null } }).state).toBe("ok");
    // endoflife.date rows, for Windows and a distribution.
    db.prepare("INSERT INTO eol_cycles (product, cycle, label, release_date, eol, support, latest, latest_release_date, lts, link, seen_at) VALUES ('windows', '11-24h2-w', '11 24H2 (W)', '2024-10-01', '2026-10-13', '2026-10-13', '10.0.26100', NULL, 0, NULL, ?), ('windows', '11-24h2-e', '11 24H2 (E)', '2024-10-01', '2027-10-12', '2027-10-12', '10.0.26100', NULL, 0, NULL, ?), ('ubuntu', '22.04', 'Jammy', '2022-04-21', '2027-06-01', '2027-06-01', '22.04.5', NULL, 1, NULL, ?)").run(at, at, at);
    const win = matchOs(db, { ...base, os: { family: "windows", name: "Windows 11 Pro", version: "24H2", build: "10.0.26100.9711", display: "24H2", id: null, versionId: null } });
    expect(win).toMatchObject({ state: "warn", text: expect.stringContaining("Home and Pro") });
    const ubuntu = matchOs(db, { ...base, os: { family: "linux", name: "Ubuntu", version: "22.04", build: null, display: null, id: "ubuntu", versionId: "22.04" } });
    expect(ubuntu).toMatchObject({ state: "ok", text: "In support until 2027-06-01." });
    db.close();
  });
});

describe("packages", () => {
  it("name OSV's ecosystem for a distribution, ask OSV in one batch, and read the hits", async () => {
    expect(osvEcosystem("debian", "12", "dpkg")).toBe("Debian:12");
    expect(osvEcosystem("ubuntu", "24.04", "dpkg")).toBe("Ubuntu:24.04:LTS");
    expect(osvEcosystem("ubuntu", "25.10", "dpkg")).toBe("Ubuntu:25.10");
    expect(osvEcosystem("alpine", "3.20.1", "apk")).toBe("Alpine:v3.20");
    expect(osvEcosystem("rhel", "9.4", "rpm")).toBe("Red Hat");
    expect(osvEcosystem("fedora", "40", "rpm")).toBeNull();
    const packages = [{ name: "openssl", version: "3.0.11-1~deb12u1" }, { name: "curl", version: "8.5.0-2ubuntu10" }, { name: "nothing-here", version: "1.0" }, { name: "openssl", version: "3.3.0-r0" }];
    const http = fakeHttp({ [osvBatchUrl]: { bytes: fixture("osv/querybatch.json") } });
    const hits = await queryOsv(http, "Debian:12", packages);
    expect(hits.map((h) => [h.name, h.ids.length])).toEqual([["openssl", 54], ["curl", 59], ["openssl", 26]]);
    expect(hits[0]?.ids[0]).toBe("DEBIAN-CVE-2023-5363");
    expect(JSON.parse(http.calls.length ? "1" : "0")).toBe(1);
    const db = openDatabase(":memory:");
    migrate(db);
    db.prepare("INSERT INTO vulns (cve_id, last_modified_at, cvss_score, kev, first_seen_at, last_seen_at) VALUES ('CVE-2023-5363', ?, 7.5, 1, ?, ?)").run(at, at, at);
    const finding = await matchPackages(db, fakeHttp({ [osvBatchUrl]: { bytes: fixture("osv/querybatch.json") } }), { bw: 1, os: { family: "linux", name: "Debian GNU/Linux", version: "12", build: null, display: null, id: "debian", versionId: "12" }, browsers: [], packages, packageSource: "dpkg" });
    expect(finding.state).toBe("bad");
    expect(finding.text).toContain("3 package(s) have open advisories");
    expect(finding.text).toContain("on the KEV");
    expect(finding.refs.find((r) => r.id === "CVE-2023-5363")).toMatchObject({ href: "/vulnerabilities/CVE-2023-5363", note: expect.stringContaining("KEV") });
    expect(finding.refs.some((r) => r.href.startsWith("https://osv.dev/vulnerability/"))).toBe(true);
    const silent = await matchPackages(db, fakeHttp({ [osvBatchUrl]: { text: '{"results":[{"vulns":[]}]}' } }), { bw: 1, os: { family: "linux", name: "Debian", version: "12", build: null, display: null, id: "debian", versionId: "12" }, browsers: [], packages: [{ name: "x", version: "1" }], packageSource: "dpkg" });
    expect(silent.state).toBe("ok");
    db.close();
  });
});

describe("the page", () => {
  it("takes a report from the owner alone, reads it, stores nothing, and answers the browser check", async () => {
    const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" }, now: () => now, http: fakeHttp({ [`${msrcApi}/updates`]: { bytes: fixture("msrc/updates.json") }, [`${msrcApi}/cvrf/2026-Oct`]: { bytes: fixture("msrc/2026-Oct.json") } }) });
    try {
      const db = app.db;
      await ingestSource(db, app.dataDir, getSource(db, "msrc")!, { http: fakeHttp({ [`${msrcApi}/updates`]: { bytes: fixture("msrc/updates.json") }, [`${msrcApi}/cvrf/2026-Oct`]: { bytes: fixture("msrc/2026-Oct.json") } }), now: () => now });
      const page = await (await fetch(`${app.base}/scan/devices`)).text();
      expect(page).toContain("Is this device affected?");
      expect(page).toContain('href="/scan/scripts/bw-inventory.ps1"');
      expect(page).toContain('href="/scan/scripts/bw-inventory.sh"');
      expect(page).not.toContain('action="/scan/devices"');
      const report = 'BW-REPORT-BEGIN\n{"bw":1,"os":{"family":"windows","name":"Windows 11 Pro","version":"24H2","build":"10.0.26100.9445","display":"24H2"},"browsers":[],"packages":[],"package_source":""}\nBW-REPORT-END';
      expect((await formPost(app.base, "/scan/devices", { device: "laptop", report })).status).toBe(403);
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
      expect((await formPost(app.base, "/scan/devices", { device: "<script>", report }, cookie)).status).toBe(400);
      const bad = await formPost(app.base, "/scan/devices", { device: "laptop", report: "hello" }, cookie);
      expect(bad.status).toBe(400);
      expect(await bad.text()).toContain("not a report from bw-inventory");
      const read = await formPost(app.base, "/scan/devices", { device: "laptop", report }, cookie);
      expect(read.status).toBe(200);
      const text = await read.text();
      expect(text).toContain("KB5127648");
      expect(text).toContain('<a href="/vulnerabilities/CVE-2026-100200">CVE-2026-100200</a>');
      expect(text).toContain('<span class="state bad">Exposed</span>');
      expect(text).toContain("What applies to laptop");
      expect(text).toContain("Recorded under <b>laptop</b>");
      // The reading is kept as verdicts and ids, never the report; a second reading says what moved.
      const kept = app.db.prepare("SELECT device, os, worst, findings_json FROM device_readings").all() as { device: string; os: string; worst: string; findings_json: string }[];
      expect(kept).toHaveLength(1);
      expect(kept[0]).toMatchObject({ device: "laptop", os: "windows", worst: "bad" });
      expect(kept[0]!.findings_json).not.toContain("26100.9445\"}");
      const current = report.replace("10.0.26100.9445", "10.0.26100.9711");
      const again = await (await formPost(app.base, "/scan/devices", { device: "laptop", report: current }, cookie)).text();
      expect(again).toContain("<b>Since the last reading:</b>");
      expect(again).toContain("cleared (CVE-");
      const list = await (await fetch(`${app.base}/scan/devices`, { headers: { cookie } })).text();
      expect(list).toContain('<a href="/scan/devices?device=laptop"><b>laptop</b></a> <span class="state ok">Up to date</span>');
      const history = await (await fetch(`${app.base}/scan/devices?device=laptop`, { headers: { cookie } })).text();
      expect(history).toContain("laptop <span class=\"count\">2 reading(s)</span>");
      const today = await (await fetch(`${app.base}/today`, { headers: { cookie } })).text();
      expect(today).toContain("<small>Devices</small><b>0</b><span>exposed of 1 read</span>");
      expect(await (await fetch(`${app.base}/today`)).text()).not.toContain("<small>Devices</small>");
      expect((await formPost(app.base, "/scan/devices/forget", { device: "laptop" }, cookie)).status).toBe(303);
      expect((await formPost(app.base, "/scan/devices/forget", { device: "laptop" }, cookie)).status).toBe(404);
      // The scripts are served with their sums.
      const sums = await (await fetch(`${app.base}/scan/scripts/SHA256SUMS`)).text();
      expect(sums).toContain("bw-inventory.sh");
      // The browser check's answer.
      const check = await (await fetch(`${app.base}/scan/browser-check?browser=chrome&version=1.0`)).json();
      expect(check).toEqual({ browser: "chrome", latest: null, newer: [] });
      expect((await fetch(`${app.base}/scan/browser-check?browser=netscape`)).status).toBe(400);
    } finally {
      await app.close();
    }
  });
});
