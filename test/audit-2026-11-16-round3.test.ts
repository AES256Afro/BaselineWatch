import { describe, expect, it } from "vitest";
import { msrcApi } from "../src/adapters/msrc.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { registrableName, whoseWord } from "../src/fix.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { alertStatusWord, recentAlerts, standingAlerts } from "../src/notify.ts";
import { choiceLabel } from "../src/pages/baselines.ts";
import { pathName } from "../src/pages/digest.ts";
import { withoutVerify } from "../src/fleet.ts";
import { renderToday } from "../src/pages/today.ts";
import { inboxOffset } from "../src/pages/triage.ts";
import { cpeGroups, refLabels } from "../src/pages/vulnerabilities.ts";
import { stigRuleIds } from "../src/register.ts";
import { vulnFilters } from "../src/routes/query.ts";
import { addSaved, listSaved, openSaved, savedCounts } from "../src/saved.ts";
import { countVulns, cweOf } from "../src/vulns.ts";
import { cookieFrom, fakeHttp, fixture, formPost, startTestApp } from "./helpers.ts";

/**
 * The third round of the 16 November audit: Patch Tuesday's paging, CSV and fleet filter, Today's
 * standing alerts, saved searches' counts, and the sweep's small cases.
 */

const at = "2026-11-16T12:00:00.000Z";
const now = new Date(at);
const look = { look: "register" as const, scheme: "system" as const, back: "/" };

function freshDb() {
  const db = openDatabase(":memory:");
  migrate(db);
  return db;
}
type Db = ReturnType<typeof freshDb>;

function addVuln(db: Db, cveId: string, firstSeen = at, over: { kev?: number; due?: string | null } = {}): void {
  db.prepare(
    `INSERT INTO vulns (cve_id, last_modified_at, vuln_status, description, cwes_json, cpes_json, vendors_json, products_json, kev, kev_due_date, watch_hit, first_seen_at, last_seen_at)
     VALUES (?, ?, 'Analyzed', 'A flaw.', '[]', '[]', '[]', '[]', ?, ?, 0, ?, ?)`,
  ).run(cveId, firstSeen, over.kev ?? 0, over.due ?? null, firstSeen, firstSeen);
  db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES (?, ?, 'new')").run(cveId, firstSeen);
}

describe("US3-1, FT3-2: Patch Tuesday's table", () => {
  const routes = { [`${msrcApi}/updates`]: { bytes: fixture("msrc/updates.json") }, [`${msrcApi}/cvrf/2026-Oct`]: { bytes: fixture("msrc/2026-Oct.json") } };
  const october = new Date("2026-10-21T22:00:00Z");

  it("says how many are shown, pages past 400, exports the filtered rows and narrows to the fleet's releases", async () => {
    const app = await startTestApp({ now: () => october });
    try {
      await ingestSource(app.db, app.dataDir, getSource(app.db, "msrc")!, { http: fakeHttp(routes), now: () => october });
      // 420 more of Microsoft's own, on a KB no fleet release takes.
      const insert = app.db.prepare("INSERT INTO msrc_vulns (cve_id, release_id, title, family, vendor, severity, fixes_json, released_at, seen_at) VALUES (?, '2026-Oct', ?, 'Filler Component', 'Microsoft', 'Important', ?, '2026-10-13T07:00:00Z', ?)");
      const fixes = JSON.stringify([{ kb: "9999999", url: "https://support.microsoft.com/help/9999999", label: null, products: ["Filler Product"], fixedBuild: null, restart: null }]);
      for (let i = 0; i < 420; i++) insert.run(`CVE-2026-9${String(i).padStart(5, "0")}`, `Filler ${i}`, fixes, october.toISOString());

      const first = await (await fetch(`${app.base}/vulnerabilities/microsoft`)).text();
      expect(first).toContain("400 shown of 435");
      expect(first).toContain("Page 1 of 2.");
      expect(first).toContain('href="/vulnerabilities/microsoft?page=2#cves">Next 35</a>');
      const second = await (await fetch(`${app.base}/vulnerabilities/microsoft?page=2`)).text();
      expect(second).toContain("401–435 shown of 435");
      expect(second).toContain('href="/vulnerabilities/microsoft#cves">Previous 400</a>');
      // A page past the end is the last page, not an empty table.
      expect(await (await fetch(`${app.base}/vulnerabilities/microsoft?page=99`)).text()).toContain("401–435 shown of 435");

      // The CSV is every filtered row, not one page.
      const csv = await fetch(`${app.base}/vulnerabilities/microsoft.csv?family=Filler%20Component`);
      expect(csv.headers.get("content-type")).toContain("text/csv");
      const lines = (await csv.text()).trim().split("\r\n");
      expect(lines[0]).toBe("cve,severity,cvss,component,title,exploited,disclosed,updates,update_urls,release,url");
      expect(lines).toHaveLength(421);
      expect(first).toContain('href="/vulnerabilities/microsoft.csv" download>CSV of these 435 CVEs</a>');

      // ?fleet=1: only what the fleet's Windows releases' updates fix; the filler KB is no fleet release's.
      const fleet = await (await fetch(`${app.base}/vulnerabilities/microsoft?fleet=1`)).text();
      expect(fleet).toContain("CVE-2026-100200");
      expect(fleet).not.toContain("CVE-2026-900000");
      expect(fleet).toContain('class="on" href="/vulnerabilities/microsoft#cves"');
      const fleetCsv = await (await fetch(`${app.base}/vulnerabilities/microsoft.csv?fleet=1`)).text();
      expect(fleetCsv).toContain("CVE-2026-100200");
      expect(fleetCsv).not.toContain("Filler");
    } finally {
      await app.close();
    }
  });
});

describe("QL3-1: Today's standing alerts", () => {
  it("drops a source's failure notice once the source has answered since, and says why one was not sent", () => {
    const db = freshDb();
    const alert = db.prepare("INSERT INTO alerts (kind, title, body, url, sent_at, status) VALUES (?, ?, NULL, ?, ?, ?)");
    alert.run("source", "NVD CVE API 2.0 has been failing for 107 h", "http://localhost:8790/sources#src-nvd-cves", "2026-10-26T10:55:08.500Z", "unconfigured");
    alert.run("kev", "CISA KEV: CVE-2026-1", "https://example.test/vulnerabilities/CVE-2026-1", "2026-10-26T11:00:00.000Z", "unconfigured");
    db.prepare("UPDATE sources SET last_status = 'error', failing_since = '2026-10-21T00:00:00Z', last_fetch_at = '2026-10-26T10:00:00Z' WHERE id = 'nvd-cves'").run();
    expect(standingAlerts(db, recentAlerts(db)).map((a) => a.kind)).toEqual(["kev", "source"]);
    db.prepare("UPDATE sources SET last_status = 'ok', failing_since = NULL, last_fetch_at = '2026-11-16T09:00:00Z' WHERE id = 'nvd-cves'").run();
    expect(standingAlerts(db, recentAlerts(db)).map((a) => a.kind)).toEqual(["kev"]);
    expect(alertStatusWord("unconfigured")).toBe("not sent: no notifier");
    expect(alertStatusWord("sent")).toBe("sent");

    const page = renderToday({ db, owner: true, open: false, now, hours: 24, look });
    expect(page).not.toContain("has been failing for 107 h");
    expect(page).toContain("kev · not sent: no notifier");
    db.close();
  });
});

describe("FT3-1: saved searches count what they hold and what is new", () => {
  it("counts through the table's own query, and opening one restarts what is new", () => {
    const db = freshDb();
    addVuln(db, "CVE-2026-1", "2026-11-10T00:00:00.000Z", { kev: 1 });
    addVuln(db, "CVE-2026-2", "2026-11-12T00:00:00.000Z", { kev: 1 });
    addVuln(db, "CVE-2026-3", "2026-11-12T00:00:00.000Z");
    addSaved(db, "KEV", "/vulnerabilities?kev=1", at);
    addSaved(db, "A search", "/search?q=x", at);
    const kev = listSaved(db).find((s) => s.name === "KEV")!;
    expect(kev.last_opened_at).toBeNull();
    expect(savedCounts(db, kev, now)).toEqual({ total: 2, fresh: 2 });
    expect(countVulns(db, vulnFilters({ kev: "1" }, now, true))).toBe(2);
    // Not a counted list: no figure.
    expect(savedCounts(db, listSaved(db).find((s) => s.name === "A search")!, now)).toBeNull();

    expect(openSaved(db, kev.id, "2026-11-11T00:00:00.000Z")).toBe("/vulnerabilities?kev=1");
    expect(savedCounts(db, listSaved(db).find((s) => s.name === "KEV")!, now)).toEqual({ total: 2, fresh: 1 });
    expect(openSaved(db, 9999, at)).toBeNull();

    const today = renderToday({ db, owner: true, open: false, now, hours: 24, look });
    expect(today).toContain('<a href="/saved/1/open">KEV</a> <span class="small">2 · <b>1 new</b> since last opened</span>');
    expect(renderToday({ db, owner: false, open: true, now, hours: 24, look })).not.toContain("/saved/1/open");
    db.close();
  });

  it("opens through /saved/<id>/open for the owner only", async () => {
    const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" }, now: () => now });
    try {
      addSaved(app.db, "KEV", "/vulnerabilities?kev=1", at);
      expect((await fetch(`${app.base}/saved/1/open`, { redirect: "manual" })).status).toBe(403);
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
      const opened = await fetch(`${app.base}/saved/1/open`, { headers: { cookie }, redirect: "manual" });
      expect(opened.status).toBe(303);
      expect(opened.headers.get("location")).toBe("/vulnerabilities?kev=1");
      expect(listSaved(app.db)[0]!.last_opened_at).toBe(at);
      const list = await (await fetch(`${app.base}/saved`, { headers: { cookie } })).text();
      expect(list).toContain('<a href="/saved/1/open"><b>KEV</b></a>');
    } finally {
      await app.close();
    }
  });
});

describe("the sweep's small cases", () => {
  it("B6-5: holds the inbox offset to the last page's start", () => {
    expect(inboxOffset(undefined, 100)).toBe(0);
    expect(inboxOffset(30, 100)).toBe(30);
    expect(inboxOffset(99, 100)).toBe(90);
    expect(inboxOffset(500, 61)).toBe(60);
    expect(inboxOffset(60, 60)).toBe(30);
    expect(inboxOffset(-5, 10)).toBe(0);
    expect(inboxOffset(40, 0)).toBe(0);
  });

  it("B6-6: reads a weakness id without its leading zeros", () => {
    expect(cweOf("CWE-079")).toBe("CWE-79");
    expect(cweOf("cwe-0787")).toBe("CWE-787");
    expect(cweOf("079")).toBe("CWE-79");
    expect(cweOf("NVD-CWE-noinfo")).toBe("NVD-CWE-noinfo");
  });

  it("B6-9: 'due this week' is seven days, today to today + 6", () => {
    const f = vulnFilters({ due: "7" }, now);
    expect([f.dueFrom, f.dueTo]).toEqual(["2026-11-16", "2026-11-22"]);
    const db = freshDb();
    addVuln(db, "CVE-2026-10", at, { kev: 1, due: "2026-11-22" });
    addVuln(db, "CVE-2026-11", at, { kev: 1, due: "2026-11-23" });
    expect(countVulns(db, f)).toBe(1);
    db.close();
  });

  it("B6-7: names the vendor's reference by its registrable domain, not any label", () => {
    expect(registrableName("support.citrix.com")).toBe("citrix");
    expect(registrableName("www.ncsc.gov.uk")).toBe("ncsc");
    expect(registrableName("example.com")).toBe("example");
    expect(whoseWord({ url: "x", host: "y", whose: "vendor" })).toBe("the vendor's");
    expect(whoseWord(null)).toBe("the first");
  });

  it("B6-11, C6-5: a CVE id is not a STIG rule id, and the ids come back with where they start", () => {
    expect(stigRuleIds("See CVE-2026-12345 and WN11-00-000160 (V-253286); CCI-000366.")).toEqual([
      { id: "WN11-00-000160", index: 23 },
      { id: "V-253286", index: 39 },
    ]);
  });

  it("US3-2, US3-3: references on one host carry their tail; CPEs group by vendor and product", () => {
    const labels = refLabels([
      { url: "https://git.kernel.org/stable/c/0123456789abcdef0123456789abcdef01234567" },
      { url: "https://git.kernel.org/stable/c/fedcba9876543210fedcba9876543210fedcba98" },
      { url: "https://github.com/owner/repo/commit/abcdef1234567890abcdef1234567890abcdef12" },
      { url: "https://www.vendor.example/advisories/VSA-2026-01" },
    ]);
    expect([...labels.values()]).toEqual(["git.kernel.org · 0123456789ab", "git.kernel.org · fedcba987654", "github.com", "vendor.example"]);
    const groups = cpeGroups(["cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", "cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*", "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"]);
    expect(groups.map((g) => [g.vendor, g.total, g.products.map((p) => `${p.product}:${p.cpes.length}`)])).toEqual([
      ["linux", 2, ["linux_kernel:2"]],
      ["acme", 1, ["widget:1"]],
    ]);
  });

  it("RD3-5, QL3-2, QL3-4: one date per choice, links by name, the fleet's to-do notes for the owner", () => {
    expect(choiceLabel({ label: "Windows 11 v24h2 2026-10-08", publishedAt: "2026-10-08T00:00:00Z" })).toBe("Windows 11 v24h2 2026-10-08");
    expect(choiceLabel({ label: "Microsoft Windows 11 V2R11", publishedAt: "2026-10-05T00:00:00Z" })).toBe("Microsoft Windows 11 V2R11 (2026-10-05)");
    expect(pathName("/standards/nist-sp-800-53/117")).toBe("the release");
    expect(pathName("/sources")).toBe("Sources");
    expect(pathName("/vulnerabilities/cve-2026-1")).toBe("CVE-2026-1");
    expect(withoutVerify("Security updates until about September 2028 by Apple's practice (verify)")).toBe("Security updates until about September 2028 by Apple's practice");
    expect(withoutVerify("the two before it (about September 2029, verify)")).toBe("the two before it (about September 2029)");
  });
});
