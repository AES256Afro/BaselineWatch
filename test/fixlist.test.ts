import type { DatabaseSync } from "node:sqlite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fixList, fixListCandidates, fixListHeadline } from "../src/fixlist.ts";
import { upsertMsrcVulns } from "../src/msrc.ts";
import type { VulnRow } from "../src/vulns.ts";
import { formPost, startTestApp, type TestApp } from "./helpers.ts";

/**
 * Today keyed by the remedy (M20). The thing under test is the inversion: one update is one row
 * however many CVEs it closes, and a reference that proves a fix exists without naming a version
 * is not counted as an update you can install.
 */

const now = new Date("2026-10-26T09:00:00Z");
const since = new Date(now.getTime() - 72 * 3_600_000).toISOString();

let app: TestApp;
let db: DatabaseSync;

/** A CVE row with the columns this module reads and sane defaults for the rest. */
function vuln(cveId: string, over: Partial<VulnRow> = {}): VulnRow {
  return {
    id: 0,
    cve_id: cveId,
    source_identifier: null,
    published_at: since,
    last_modified_at: since,
    vuln_status: null,
    description: null,
    cvss_version: null,
    cvss_score: 7.8,
    cvss_severity: "HIGH",
    cvss_vector: null,
    cvss_source: null,
    ssvc_json: null,
    cwes_json: null,
    cpes_json: null,
    vendors_json: null,
    products_json: null,
    references_json: null,
    kev: 0,
    kev_date_added: null,
    kev_due_date: null,
    kev_ransomware: null,
    epss: null,
    epss_percentile: null,
    epss_date: null,
    watch_hit: 0,
    watch_labels_json: null,
    first_seen_at: since,
    last_seen_at: since,
    packages_json: null,
    aliases_json: null,
    ...over,
  };
}

beforeAll(async () => {
  app = await startTestApp({ now: () => now });
  db = app.db;
  // Microsoft publishes one KB per build, and the same KB closes many CVEs.
  upsertMsrcVulns(
    db,
    ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"].map((cveId) => ({
      cveId,
      releaseId: "2026-Oct",
      title: `${cveId} Windows elevation of privilege`,
      family: "Windows",
      vendor: "Microsoft",
      severity: "Important",
      exploited: false,
      disclosed: false,
      exploitability: null,
      cvssScore: 7.8,
      cvssVector: null,
      description: null,
      fixes: [{ kb: "5071234", url: null, label: null, products: ["Windows 11 Version 25H2"], fixedBuild: "26200.3112", restart: true }],
      releasedAt: since,
      revisedAt: null,
    })),
    since,
  );
  // CISA's own words for a CVE with no patch, shared by two CVEs.
  const item = db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at, signals_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
  for (const cveId of ["CVE-2026-5511", "CVE-2026-5512"]) {
    item.run("cisa-kev", "kev", cveId, `${cveId}: SMB`, "https://cisa/1", since, since, JSON.stringify({ requiredAction: "Disable SMBv1 inbound at the edge.", dueDate: "2026-11-16" }));
  }
  // A vendor advisory on the Wire naming two CVEs is one read.
  item.run("ubuntu-usn", "article", "usn-1", "USN-7412-1: OpenSSL vulnerabilities", "https://ubuntu/usn", since, since, JSON.stringify({ cves: ["CVE-2026-7701", "CVE-2026-7702"] }));
});
afterAll(async () => {
  await app.close();
});

describe("the fix list", () => {
  it("makes one row of an update however many CVEs it closes, and counts the CVEs not the rows", () => {
    const list = fixList(db, ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"].map((c) => vuln(c)), since);
    expect(list.install).toHaveLength(1);
    const kb = list.install[0]!;
    expect(kb.verb).toBe("Install");
    expect(kb.what).toBe("KB5071234");
    expect(kb.where).toBe("Windows 11 Version 25H2");
    expect(kb.detail).toContain("fixed build 26200.3112");
    expect(kb.detail).toContain("needs a restart");
    expect(kb.url).toBe("https://support.microsoft.com/help/5071234");
    expect(kb.cves.map((c) => c.cveId)).toEqual(["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"]);
    expect(list.fixed).toBe(3);
    expect(fixListHeadline(list)).toBe("3 of this window's 3 CVEs have an update you can install");
  });

  it("takes a fixed package version as the remedy, one row per version", () => {
    const packages = JSON.stringify([{ ecosystem: "Ubuntu", name: "openssl", introduced: [], fixed: ["3.0.18-1ubuntu1.2"], lastAffected: [], advisory: "USN-7412-1" }]);
    const list = fixList(db, [vuln("CVE-2026-9001", { packages_json: packages }), vuln("CVE-2026-9002", { packages_json: packages })], since);
    expect(list.install).toHaveLength(1);
    expect(list.install[0]!.verb).toBe("Upgrade");
    expect(list.install[0]!.what).toBe("openssl 3.0.18-1ubuntu1.2");
    expect(list.install[0]!.detail).toBe("Package advisory USN-7412-1");
    expect(list.install[0]!.cves).toHaveLength(2);
  });

  it("takes a vendor advisory on the Wire as the remedy when nothing names a version", () => {
    const list = fixList(db, [vuln("CVE-2026-7701"), vuln("CVE-2026-7702")], since);
    expect(list.install).toHaveLength(1);
    expect(list.install[0]!.what).toBe("USN-7412-1: OpenSSL vulnerabilities");
    expect(list.install[0]!.url).toBe("https://ubuntu/usn");
    expect(list.install[0]!.cves).toHaveLength(2);
  });

  it("does not call a commit an update: a Patch reference is grouped by host and never counted as fixed", () => {
    // Thirty kernel commits are one line, not thirty rows, and not thirty fixes.
    const rows = Array.from({ length: 4 }, (_, i) =>
      vuln(`CVE-2026-20${i}0`, { references_json: JSON.stringify([{ url: `https://git.kernel.org/stable/c/abc${i}`, tags: ["Patch"] }]) }),
    );
    const list = fixList(db, rows, since);
    expect(list.install).toHaveLength(0);
    expect(list.fixed).toBe(0);
    expect(list.published).toHaveLength(1);
    expect(list.published[0]!.kind).toBe("upstream");
    expect(list.published[0]!.what).toBe("Patched upstream at git.kernel.org");
    expect(list.published[0]!.cves).toHaveLength(4);
    expect(fixListHeadline(list)).toBe("No update to install yet for any of this window's 4 CVEs");
  });

  it("keeps the vendor's own bulletin above a commit, and groups it by host too", () => {
    const list = fixList(
      db,
      [
        vuln("CVE-2026-3001", { references_json: JSON.stringify([{ url: "https://jira.atlassian.com/browse/BAM-1", tags: ["Vendor Advisory"] }]) }),
        vuln("CVE-2026-3002", { references_json: JSON.stringify([{ url: "https://jira.atlassian.com/browse/BAM-2", tags: ["Vendor Advisory"] }]) }),
        vuln("CVE-2026-3003", { references_json: JSON.stringify([{ url: "https://git.kernel.org/stable/c/zzz", tags: ["Patch"] }]) }),
      ],
      since,
    );
    expect(list.published.map((r) => r.kind)).toEqual(["advisory", "upstream"]);
    expect(list.published[0]!.verb).toBe("Read");
    expect(list.published[0]!.what).toBe("jira.atlassian.com advisory");
    expect(list.published[0]!.cves).toHaveLength(2);
    expect(list.fixed).toBe(0);
  });

  it("quotes CISA's required action as the one mitigation row, with the date it is owed", () => {
    const list = fixList(db, [vuln("CVE-2026-5511", { kev: 1, kev_due_date: "2026-11-16" }), vuln("CVE-2026-5512", { kev: 1, kev_due_date: "2026-11-16" })], since);
    expect(list.install).toHaveLength(0);
    expect(list.mitigate).toHaveLength(1);
    expect(list.mitigate[0]!.what).toBe("Disable SMBv1 inbound at the edge.");
    expect(list.mitigate[0]!.verb).toBeNull();
    expect(list.mitigate[0]!.dueDate).toBe("2026-11-16");
    expect(list.mitigate[0]!.kevCount).toBe(2);
  });

  it("says plainly when nothing is published, in one row rather than a silence", () => {
    const list = fixList(db, [vuln("CVE-2026-8840", { watch_hit: 1 }), vuln("CVE-2026-8841", { watch_hit: 1 })], since);
    expect(list.none).toHaveLength(1);
    expect(list.none[0]!.what).toBe("No patch, advisory or mitigation published");
    expect(list.none[0]!.detail).toContain("does not guess");
    expect(list.none[0]!.watchCount).toBe(2);
    expect(list.fixed).toBe(0);
  });

  it("leads with the date someone owes, then exploitation, then the size of the job", () => {
    const list = fixList(
      db,
      [
        vuln("CVE-2026-1001"),
        vuln("CVE-2026-5511", { kev: 1, kev_due_date: "2026-11-16" }),
        vuln("CVE-2026-9001", { packages_json: JSON.stringify([{ ecosystem: "Ubuntu", name: "openssl", introduced: [], fixed: ["1.2"], lastAffected: [], advisory: "USN-1" }]), kev: 1, kev_due_date: "2026-10-30" }),
      ],
      since,
    );
    expect(list.install.map((r) => r.what)).toEqual(["openssl 1.2", "KB5071234"]);
  });

  it("marks every CVE an update closes done in one press, and refuses anything that is not a CVE id", async () => {
    // The row ends in a verb, so it ends in a button: one update done is every CVE it clears
    // placed on the same board the CVE page writes to.
    db.prepare("INSERT INTO vulns (cve_id, last_modified_at, first_seen_at, last_seen_at) VALUES ('CVE-2026-1001', ?, ?, ?)").run(since, since, since);
    db.prepare("INSERT INTO vulns (cve_id, last_modified_at, first_seen_at, last_seen_at) VALUES ('CVE-2026-1002', ?, ?, ?)").run(since, since, since);
    const done = await formPost(app.base, "/today/done", { cves: "CVE-2026-1001,CVE-2026-1002", back: "/today?since=72" });
    expect(done.status).toBe(303);
    expect(done.headers.get("location")).toBe("/today?since=72");
    const states = db.prepare("SELECT v.cve_id, t.state FROM triage t JOIN vulns v ON v.id = t.subject_id WHERE t.subject_kind = 'vuln' ORDER BY v.cve_id").all() as { cve_id: string; state: string }[];
    expect(states).toEqual([
      { cve_id: "CVE-2026-1001", state: "done" },
      { cve_id: "CVE-2026-1002", state: "done" },
    ]);
    expect((await formPost(app.base, "/today/done", { cves: "not-a-cve" })).status).toBe(400);
  });

  it("asks the database only for CVEs that moved in the window and touch you", () => {
    db.prepare("INSERT INTO vulns (cve_id, last_modified_at, kev, watch_hit, first_seen_at, last_seen_at) VALUES ('CVE-2026-4001', ?, 1, 0, ?, ?)").run(since, since, since);
    db.prepare("INSERT INTO vulns (cve_id, last_modified_at, kev, watch_hit, first_seen_at, last_seen_at) VALUES ('CVE-2026-4002', ?, 0, 0, ?, ?)").run(since, since, since);
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-4001', ?, 'cvss')").run(since);
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-4002', ?, 'cvss')").run(since);
    const picked = fixListCandidates(db, since, []).map((r) => r.cve_id);
    expect(picked).toContain("CVE-2026-4001");
    expect(picked).not.toContain("CVE-2026-4002");
  });
});
