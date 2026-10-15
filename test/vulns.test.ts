import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { epssAdapter, parseEpssCsv } from "../src/adapters/epss.ts";
import { normalizeNvd, nvdAdapter, nvdDate, nvdStamp, storeNvdRecords, type NvdCve, type NvdResponse } from "../src/adapters/nvd.ts";
import { countRows, migrate, openDatabase } from "../src/db.ts";
import type { HttpGet } from "../src/http.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { applyKev, getVuln, isNotable, listVulns, matchWatch, recomputeWatchHits, vulnChanges, type WatchEntry } from "../src/vulns.ts";
import { listWire } from "../src/wire.ts";
import { cookieFrom, fakeHttp, fixture, formPost, startTestApp, type TestApp } from "./helpers.ts";

const windowFixture = (): NvdResponse => JSON.parse(new TextDecoder().decode(fixture("nvd-window.json"))) as NvdResponse;
const log4j = (): NvdCve => windowFixture().vulnerabilities!.find((v) => v.cve.id === "CVE-2021-44228")!.cve;
const at = new Date("2026-10-14T23:30:00Z");

describe("normalizeNvd", () => {
  it("reads scores, SSVC, CWEs, vulnerable CPEs, vendors, references and KEV fields from a real record", () => {
    const n = normalizeNvd(log4j());
    expect(n.cveId).toBe("CVE-2021-44228");
    expect(n.publishedAt).toBe("2021-12-10T10:15:09.143Z");
    expect(n.cvss).toMatchObject({ version: "3.1", score: 10, severity: "CRITICAL", source: "nvd@nist.gov" });
    expect(n.cvss?.vector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
    expect(n.ssvc).toEqual({ exploitation: "active", automatable: "yes", technicalImpact: "total" });
    expect(n.cwes).toEqual(["CWE-20", "CWE-400", "CWE-502", "CWE-917"]);
    expect(n.cpes.length).toBeGreaterThan(0);
    expect(n.cpes.every((c) => c.startsWith("cpe:2.3:"))).toBe(true);
    expect(n.vendors).toContain("siemens");
    expect(n.references).toHaveLength(5);
    expect(n.references[0]?.tags).toContain("Third Party Advisory");
    expect(n.kev).toMatchObject({ dateAdded: "2021-12-10" });
    expect(n.description).toMatch(/^Apache Log4j2/);
  });

  it("falls back to CVSS v2 and copes with records that have nothing", () => {
    const first = windowFixture().vulnerabilities![0]!.cve;
    const n = normalizeNvd(first);
    expect(n.cvss?.version).toBe("2.0");
    expect(n.cvss?.severity).toBeTruthy();
    const bare = normalizeNvd({ id: "cve-2026-1", lastModified: "2026-10-14T00:00:00.000" });
    expect(bare.cveId).toBe("CVE-2026-1");
    expect(bare.cvss).toBeNull();
    expect(bare.cpes).toEqual([]);
    expect(bare.lastModifiedAt).toBe("2026-10-14T00:00:00.000Z");
  });

  it("formats NVD timestamps both ways", () => {
    expect(nvdDate("2026-10-14T22:17:01.677")).toBe("2026-10-14T22:17:01.677Z");
    expect(nvdDate("2026-10-14T22:17:01.677Z")).toBe("2026-10-14T22:17:01.677Z");
    expect(nvdDate(undefined)).toBeNull();
    expect(nvdStamp(new Date("2026-10-14T22:17:01.677Z"))).toBe("2026-10-14T22:17:01.677");
  });
});

describe("watchlist matching", () => {
  const v = { cpes: ["cpe:2.3:o:fortinet:fortios:7.4.7:*:*:*:*:*:*:*", "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"], vendors: ["fortinet", "apache"], products: ["fortios", "log4j"], description: "A heap overflow in the SSL-VPN daemon." };
  const entry = (kind: WatchEntry["kind"], value: string, label: string | null = null): WatchEntry => ({ id: 1, kind, value, label });
  it("matches names, pairs, cpe prefixes and keywords", () => {
    expect(matchWatch(v, [entry("product", "FortiOS", "Edge firewalls")])).toEqual(["Edge firewalls"]);
    expect(matchWatch(v, [entry("product", "fortinet:fortios")])).toEqual(["fortinet:fortios"]);
    expect(matchWatch(v, [entry("product", "cpe:2.3:a:apache:log4j")])).toEqual(["cpe:2.3:a:apache:log4j"]);
    expect(matchWatch(v, [entry("keyword", "ssl-vpn")])).toEqual(["ssl-vpn"]);
    expect(matchWatch(v, [entry("product", "cisco"), entry("keyword", "kerberos"), entry("baseline", "fortios")])).toEqual([]);
  });
});

describe("vulnerability store", () => {
  let db: ReturnType<typeof openDatabase>;
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
  });
  afterEach(() => db.close());

  it("records first sight, then field-level changes, and resurfaces notable CVEs on the Wire", () => {
    // The fixture keeps only the first two configurations of the Log4j record, which name Siemens firmware.
    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('product', 'siemens', 'Plant', ?)").run(at.toISOString());
    const first = storeNvdRecords({ db, now: () => at }, windowFixture().vulnerabilities!);
    expect(first).toMatchObject({ inserted: 3, updated: 0 });
    expect(countRows(db, "vulns")).toBe(3);
    const row = getVuln(db, "cve-2021-44228")!;
    expect(row.kev).toBe(1);
    expect(row.watch_hit).toBe(1);
    expect(JSON.parse(row.watch_labels_json!)).toEqual(["Plant"]);
    expect(vulnChanges(db, "CVE-2021-44228").map((c) => c.field)).toEqual(["new"]);
    // Log4j is notable (KEV, watched, SSVC active); the 2015 CVEs are not.
    const wire = listWire(db, { kind: "vulnerability" });
    expect(wire.map((i) => i.external_id)).toEqual(["CVE-2021-44228"]);
    expect(wire[0]?.title).toContain("CVSS 10.0");

    // A second sighting with a changed score, description and a new CPE.
    const changed = log4j();
    changed.lastModified = "2026-10-15T01:00:00.000";
    changed.metrics!.cvssMetricV31![0]!.cvssData!.baseScore = 9.8;
    changed.descriptions![0]!.value = `${changed.descriptions![0]!.value} Updated by the CNA.`;
    changed.configurations![0]!.nodes![0]!.cpeMatch!.push({ vulnerable: true, criteria: "cpe:2.3:a:example:thing:1.0:*:*:*:*:*:*:*" });
    db.prepare("UPDATE items SET read = 1 WHERE external_id = 'CVE-2021-44228'").run();
    const later = new Date("2026-10-15T02:00:00Z");
    const second = storeNvdRecords({ db, now: () => later }, [{ cve: changed }]);
    expect(second).toMatchObject({ inserted: 0, updated: 1 });
    const fields = vulnChanges(db, "CVE-2021-44228").map((c) => c.field);
    expect(fields).toEqual(expect.arrayContaining(["cvss", "description", "cpes"]));
    const cvss = vulnChanges(db, "CVE-2021-44228").find((c) => c.field === "cvss")!;
    expect(cvss.before_text).toMatch(/^10\.0/);
    expect(cvss.after_text).toMatch(/^9\.8/);
    const item = db.prepare("SELECT read, summary FROM items WHERE external_id = 'CVE-2021-44228'").get() as { read: number; summary: string };
    expect(item.read).toBe(0);
    expect(item.summary).toContain("CVSS 10.0");
    expect(item.summary).toContain("→ 9.8");

    // The same record again changes nothing.
    expect(storeNvdRecords({ db, now: () => later }, [{ cve: changed }])).toMatchObject({ inserted: 0, updated: 0, alerts: [] });
  });

  it("joins KEV and EPSS onto known CVEs only, and re-marks the watchlist", () => {
    storeNvdRecords({ db, now: () => at }, windowFixture().vulnerabilities!);
    const flagged = applyKev(db, [{ cveId: "CVE-2015-0204", dateAdded: "2026-10-14", dueDate: "2026-11-04", ransomware: false }, { cveId: "CVE-1999-0001", dateAdded: null, dueDate: null, ransomware: false }], at.toISOString());
    expect(flagged).toBe(1);
    expect(getVuln(db, "CVE-2015-0204")?.kev).toBe(1);
    expect(vulnChanges(db, "CVE-2015-0204").map((c) => c.field)).toContain("kev");

    const csv = parseEpssCsv(new TextDecoder().decode(fixture("epss-head.csv")));
    expect(csv.modelVersion).toBe("v2026.06.15");
    expect(csv.scoreDate).toBe("2026-10-14T12:00:24Z");
    expect(csv.scores).toHaveLength(4);
    expect(csv.scores.find((s) => s.cveId === "CVE-2021-44228")).toEqual({ cveId: "CVE-2021-44228", epss: 0.99999, percentile: 1 });

    expect(countRows(db, "watchlist")).toBe(0);
    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('product', 'siemens', NULL, ?)").run(at.toISOString());
    expect(recomputeWatchHits(db)).toBe(1);
    expect(getVuln(db, "CVE-2021-44228")?.watch_hit).toBe(1);
    expect(listVulns(db, { watch: true }).rows.map((r) => r.cve_id)).toEqual(["CVE-2021-44228"]);
    db.prepare("DELETE FROM watchlist").run();
    expect(recomputeWatchHits(db)).toBe(1);

    expect(listVulns(db, { kev: true }).total).toBe(2);
    expect(listVulns(db, { minCvss: 9 }).rows.map((r) => r.cve_id)).toEqual(["CVE-2021-44228"]);
    expect(listVulns(db, { q: "log4j" }).rows.map((r) => r.cve_id)).toEqual(["CVE-2021-44228"]);
    expect(listVulns(db, { q: "CVE-2015-0204" }).total).toBe(1);
    expect(listVulns(db, { sort: "cvss" }).rows[0]?.cve_id).toBe("CVE-2021-44228");
  });

  it("decides what is notable", () => {
    storeNvdRecords({ db, now: () => at }, windowFixture().vulnerabilities!);
    const quiet = getVuln(db, "CVE-2015-1197")!;
    const seen = at.toISOString();
    expect(isNotable(quiet, true, seen)).toBe(false);
    // A critical score only counts as news when the CVE itself is recent.
    expect(isNotable({ ...quiet, cvss_score: 9.1 }, true, seen)).toBe(false);
    expect(isNotable({ ...quiet, cvss_score: 9.1, published_at: "2026-10-10T00:00:00.000Z" }, true, seen)).toBe(true);
    expect(isNotable({ ...quiet, cvss_score: 9.1, published_at: "2026-10-10T00:00:00.000Z" }, false, seen)).toBe(false);
    expect(isNotable({ ...quiet, epss: 0.7 }, false, seen)).toBe(true);
    expect(isNotable({ ...quiet, ssvc_json: JSON.stringify({ exploitation: "active" }) }, false, seen)).toBe(true);
  });
});

describe("NVD and EPSS pulls", () => {
  let db: ReturnType<typeof openDatabase>;
  let dataDir = "";
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-vuln-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("pulls pages within the backfill window, stores the cursor, and continues from it", async () => {
    const source = getSource(db, "nvd-cves")!;
    const page = windowFixture();
    const pageOne = { ...page, totalResults: 4, resultsPerPage: 2, startIndex: 0, vulnerabilities: page.vulnerabilities!.slice(0, 2) };
    const pageTwo = { ...page, totalResults: 4, resultsPerPage: 2, startIndex: 2, vulnerabilities: page.vulnerabilities!.slice(2) };
    const seen: string[] = [];
    const scripted: HttpGet = async (url) => {
      seen.push(url);
      const body = url.includes("startIndex=0") ? pageOne : pageTwo;
      return { url, status: 200, notModified: false, bytes: new TextEncoder().encode(JSON.stringify(body)), etag: null, lastModified: null, contentType: "application/json" };
    };
    const result = await ingestSource(db, dataDir, source, { http: scripted, now: () => at, settings: { nvdApiKey: "k", nvdBackfillDays: 2 }, log: () => {} });
    expect(result.status).toBe("ok");
    expect(result).toMatchObject({ items: 3, inserted: 3 });
    expect(seen).toHaveLength(2);
    expect(seen[0]).toContain("lastModStartDate=2026-10-12T23:30:00.000");
    expect(seen[0]).toContain("lastModEndDate=2026-10-14T23:30:00.000");
    expect(seen[1]).toContain("startIndex=2");
    const cursor = (db.prepare("SELECT value FROM app_settings WHERE key = 'nvd.cursor'").get() as { value: string }).value;
    expect(cursor).toBe(at.toISOString());
    expect(getSource(db, "nvd-cves")?.last_status).toBe("ok");

    seen.length = 0;
    const later = new Date("2026-10-15T00:30:00Z");
    await ingestSource(db, dataDir, getSource(db, "nvd-cves")!, { http: scripted, now: () => later, settings: { nvdApiKey: "k", nvdBackfillDays: 2 }, log: () => {} });
    expect(seen[0]).toContain("lastModStartDate=2026-10-14T23:29:00.000");
  });

  it("applies a gzipped EPSS file through the source", async () => {
    storeNvdRecords({ db, now: () => at }, windowFixture().vulnerabilities!);
    db.prepare("UPDATE vulns SET epss = 0.5 WHERE cve_id = 'CVE-2021-44228'").run();
    const source = getSource(db, "first-epss")!;
    const gz = gzipSync(Buffer.from(fixture("epss-head.csv")));
    const result = await ingestSource(db, dataDir, source, { http: fakeHttp({ [source.url]: { bytes: new Uint8Array(gz) } }), now: () => at, log: () => {} });
    expect(result.status).toBe("ok");
    expect(result.detail).toContain("3 CVEs updated");
    expect(result.detail).toContain("1 notable jumps");
    expect(getVuln(db, "CVE-2015-0204")?.epss).toBe(0.99);
    expect(getVuln(db, "CVE-2021-44228")?.epss_date).toBe("2026-10-14");
    expect(vulnChanges(db, "CVE-2021-44228").find((c) => c.field === "epss")).toMatchObject({ before_text: "0.50", after_text: "1.00" });
    expect(epssAdapter.id).toBe("epss");
    expect(nvdAdapter.id).toBe("nvd");
  });

  it("flags vulns from the KEV catalog after the KEV items are stored", async () => {
    storeNvdRecords({ db, now: () => at }, windowFixture().vulnerabilities!);
    db.prepare("UPDATE vulns SET kev = 0, kev_date_added = NULL, kev_due_date = NULL").run();
    const source = getSource(db, "cisa-kev")!;
    await ingestSource(db, dataDir, source, { http: fakeHttp({ [source.url]: { bytes: fixture("kev.json") } }), now: () => at });
    const row = getVuln(db, "CVE-2021-44228")!;
    expect(row.kev).toBe(1);
    expect(row.kev_due_date).toBe("2021-12-24");
    expect(row.kev_ransomware).toBe(1);
  });
});

describe("vulnerability pages", () => {
  let app: TestApp;
  afterEach(async () => {
    await app?.close();
  });

  it("lists, filters, details and manages the watchlist", async () => {
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" }, now: () => at });
    storeNvdRecords({ db: app.db, now: () => at }, windowFixture().vulnerabilities!);

    const list = await (await fetch(`${app.base}/vulnerabilities`)).text();
    expect(list).toContain("CVE-2021-44228");
    expect(list).toContain("CVE-2015-0204");
    expect(list).toContain("10.0 critical");
    const kevOnly = await (await fetch(`${app.base}/vulnerabilities?kev=1`)).text();
    expect(kevOnly).toContain("CVE-2021-44228");
    expect(kevOnly).not.toContain("CVE-2015-1197");
    const search = await (await fetch(`${app.base}/vulnerabilities?q=siemens`)).text();
    expect(search).toContain("1 of 1");

    const detail = await fetch(`${app.base}/vulnerabilities/cve-2021-44228`);
    expect(detail.status).toBe(200);
    const detailText = await detail.text();
    expect(detailText).toContain("Change history");
    expect(detailText).toContain("First seen");
    expect(detailText).toContain("SSVC exploitation: active");
    expect(detailText).toContain("cpe:2.3:");
    expect((await fetch(`${app.base}/vulnerabilities/CVE-2026-0`)).status).toBe(404);
    expect((await fetch(`${app.base}/vulnerabilities/not-a-cve`)).status).toBe(404);

    const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
    expect((await formPost(app.base, "/watchlist", { kind: "product", value: "siemens", label: "Plant" })).status).toBe(403);
    const added = await formPost(app.base, "/watchlist", { kind: "product", value: "siemens", label: "Plant" }, cookie);
    expect(added.status).toBe(303);
    expect(added.headers.get("location")).toContain("1%20CVE(s)%20re-marked");
    const watchPage = await (await fetch(`${app.base}/watchlist`, { headers: { cookie } })).text();
    expect(watchPage).toContain("Plant");
    expect(watchPage).toContain("Remove");
    const mine = await (await fetch(`${app.base}/vulnerabilities?watch=1`)).text();
    expect(mine).toContain("CVE-2021-44228");
    expect(mine).not.toContain("CVE-2015-1197");
    const id = (app.db.prepare("SELECT id FROM watchlist").get() as { id: number }).id;
    expect((await formPost(app.base, `/watchlist/${id}/delete`, {}, cookie)).status).toBe(303);
    expect(countRows(app.db, "watchlist")).toBe(0);
    expect(getVuln(app.db, "CVE-2021-44228")?.watch_hit).toBe(0);
  });
});
