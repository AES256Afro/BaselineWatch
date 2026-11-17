import { request } from "node:http";
import { gunzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ParsedDocument } from "../src/adapters/types.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { fixContext, fixesFor, fixSummary, untaggedReferences } from "../src/fix.ts";
import { getSource } from "../src/ingest.ts";
import type { NormalizedRequirement } from "../src/oscal.ts";
import { atlasGroups } from "../src/pages/atlas.ts";
import { publisherListedRules, storeDocument } from "../src/register.ts";
import { cweOf, getVuln, listVulns, matchWatch, upsertVuln, type NormalizedVuln } from "../src/vulns.ts";
import { startTestApp, type TestApp } from "./helpers.ts";

/**
 * The second pass of the 16 November audit: each case is one the audit found on the live data,
 * written as the smallest input that shows it.
 */

const at = "2026-11-16T12:00:00.000Z";

function freshDb() {
  const db = openDatabase(":memory:");
  migrate(db);
  return db;
}

const base: NormalizedVuln = {
  cveId: "CVE-2026-0001",
  sourceIdentifier: "nvd@nist.gov",
  publishedAt: at,
  lastModifiedAt: at,
  vulnStatus: "Received",
  description: "A flaw.",
  cvss: null,
  ssvc: null,
  cwes: [],
  cpes: [],
  vendors: [],
  products: [],
  references: [],
  kev: null,
};

describe("the Fix line when NVD has not tagged its references", () => {
  it("names the vendor's reference rather than saying nothing is published", () => {
    const refs = [
      { url: "https://github.com/someone/notes", tags: [] },
      { url: "https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX695486", tags: [] },
    ];
    expect(untaggedReferences(refs, ["citrix"], "secure@citrix.com")).toEqual({ count: 2, lead: { url: refs[1]!.url, host: "support.citrix.com", whose: "vendor" } });
    // No vendor from the CPEs yet: the CNA's own mail domain picks it.
    expect(untaggedReferences(refs, [], "psirt@citrix.com").lead).toMatchObject({ host: "support.citrix.com", whose: "CNA" });
    // Neither: the first.
    expect(untaggedReferences(refs, [], "cve@mitre.org").lead).toMatchObject({ host: "github.com", whose: null });
    // A tagged reference is not untagged.
    expect(untaggedReferences([{ url: "https://example.test/x", tags: ["Third Party Advisory"] }], [], null)).toEqual({ count: 0, lead: null });

    const db = freshDb();
    upsertVuln(db, { ...base, cveId: "CVE-2025-12101", sourceIdentifier: "secure@citrix.com", references: [refs[1]!] }, at, []);
    const fix = fixesFor(db, fixContext(db), getVuln(db, "CVE-2025-12101")!);
    expect(fix.empty).toBe(true);
    expect(fixSummary(fix)).toBe("NVD has not tagged its 1 reference yet; the CNA's: support.citrix.com");
    upsertVuln(db, { ...base, cveId: "CVE-2026-0002", references: [] }, at, []);
    expect(fixSummary(fixesFor(db, fixContext(db), getVuln(db, "CVE-2026-0002")!))).toMatch(/^Nothing published yet/);
    db.close();
  });
});

describe("watch matching", () => {
  it("reads CISA's spelling and NVD's as the same vendor", () => {
    const entries = [
      { id: 1, kind: "product" as const, value: "Palo Alto Networks", label: null },
      { id: 2, kind: "product" as const, value: "trend micro:apex one", label: "Apex One" },
    ];
    expect(matchWatch({ cpes: ["cpe:2.3:o:paloaltonetworks:pan-os:11.1:*:*:*:*:*:*:*"], vendors: ["paloaltonetworks"], products: ["pan-os"], description: null }, entries)).toEqual(["Palo Alto Networks"]);
    expect(matchWatch({ cpes: ["cpe:2.3:a:trendmicro:apex_one:2019:*:*:*:*:*:*:*"], vendors: ["trendmicro"], products: ["apex_one"], description: null }, entries)).toEqual(["Apex One"]);
    expect(matchWatch({ cpes: ["cpe:2.3:a:paloalto:other:1:*:*:*:*:*:*:*"], vendors: ["paloalto"], products: ["other"], description: null }, entries)).toEqual([]);
  });
});

describe("the weakness index", () => {
  it("keeps vuln_cwes in step with cwes_json and filters by it", () => {
    const db = freshDb();
    upsertVuln(db, { ...base, cveId: "CVE-2026-1001", cwes: ["CWE-79", "CWE-80"] }, at, []);
    upsertVuln(db, { ...base, cveId: "CVE-2026-1002", cwes: ["CWE-787"] }, at, []);
    const pairs = () => (db.prepare("SELECT v.cve_id || ' ' || c.cwe AS p FROM vuln_cwes c JOIN vulns v ON v.id = c.vuln_id ORDER BY 1").all() as { p: string }[]).map((r) => r.p);
    expect(pairs()).toEqual(["CVE-2026-1001 CWE-79", "CVE-2026-1001 CWE-80", "CVE-2026-1002 CWE-787"]);
    expect(listVulns(db, { cwe: "CWE-79" }).rows.map((r) => r.cve_id)).toEqual(["CVE-2026-1001"]);
    upsertVuln(db, { ...base, cveId: "CVE-2026-1002", lastModifiedAt: "2026-11-16T13:00:00.000Z", cwes: ["CWE-79"] }, "2026-11-16T13:00:00.000Z", []);
    expect(pairs()).toEqual(["CVE-2026-1001 CWE-79", "CVE-2026-1001 CWE-80", "CVE-2026-1002 CWE-79"]);
    expect(listVulns(db, { cwe: "CWE-79" }).total).toBe(2);
    db.prepare("DELETE FROM vulns WHERE cve_id = 'CVE-2026-1001'").run();
    expect(pairs()).toEqual(["CVE-2026-1002 CWE-79"]);
    expect(cweOf("cwe79")).toBe("CWE-79");
    db.close();
  });
});

describe("DISA's revision history", () => {
  it("counts the rules that start an item, not the ones an item mentions", () => {
    const db = freshDb();
    const snapshot = db.prepare("INSERT INTO snapshots (source_id, document_key, sha256, bytes, media_type, blob_path, fetched_at) VALUES ('disa-stigs', 'stig:x', 'x', 1, 'application/zip', 'blobs/x', ?)").run(at);
    const req = (ref: string, label: string): NormalizedRequirement => ({ ref, parentRef: null, family: "CAT II", label, title: label, statement: null, guidance: null, params: [], related: [], sortKey: ref, status: "active", extra: {} });
    const parsed: ParsedDocument = {
      title: "Microsoft Windows 11 Security Technical Implementation Guide",
      versionLabel: "V2R11",
      publishedAt: at,
      rationale: { text: "Revision History, V2R11:\n- WN11-00-000040: Revised Check.\n- WN11-SO-000080: Removed rule due to overlap with WN11-SO-000075.\n- V-253286, WN11-00-000045: Revised Fix.", url: null },
      requirements: [req("v-253263", "WN11-00-000040"), req("v-253445", "WN11-SO-000075")],
    };
    const id = storeDocument(db, { source: getSource(db, "disa-stigs")!, target: { key: "stig:x", url: "https://example.test/x" }, parsed, snapshotId: Number(snapshot.lastInsertRowid), fetchedAt: at }).documentId;
    expect(publisherListedRules(db, id)).toEqual(["WN11-00-000040", "WN11-SO-000080", "V-253286", "WN11-00-000045"]);
    db.close();
  });
});

describe("the Atlas", () => {
  it("groups by publisher and sets the blocklists apart", () => {
    const db = freshDb();
    const row = (sourceId: string, name: string) => ({ sourceId, name, releases: [] });
    const groups = atlasGroups(db, [row("nist-sp-800-53", "NIST SP 800-53 (controls)"), row("disa-stigs", "DISA STIG library"), row("nist-mscp", "NIST macOS Security Compliance Project"), row("canary-ads", "Ad canaries (EasyList)")]);
    expect(groups.publishers.map(([p, rows]) => `${p} ${rows.length}`)).toEqual(["NIST 2", "DISA 1"]);
    expect(groups.blocklists.map((r) => r.sourceId)).toEqual(["canary-ads"]);
    db.close();
  });
});

/** A GET with the request's headers exactly as given, the body as bytes, and no decoding. */
function raw(url: string, headers: Record<string, string>, method = "GET"): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const req = request(url, { method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    req.end();
  });
}

describe("the app", () => {
  let app: TestApp;
  beforeAll(async () => {
    app = await startTestApp({ now: () => new Date(at) });
    for (let i = 0; i < 3; i++) upsertVuln(app.db, { ...base, cveId: `CVE-2026-200${i}`, cwes: ["CWE-79"], description: `Cross-site scripting number ${i}.` }, at, []);
    upsertVuln(app.db, { ...base, cveId: "CVE-2026-2100", cwes: ["CWE-787"], kev: { dateAdded: "2026-11-10", dueDate: "2026-11-20", requiredAction: "Apply updates.", name: "X" } }, at, []);
    upsertVuln(app.db, { ...base, cveId: "CVE-2026-2101", kev: { dateAdded: "2026-10-01", dueDate: "2026-10-20", requiredAction: "Apply updates.", name: "Y" } }, at, []);
  });
  afterAll(async () => {
    await app.close();
  });

  it("on News, says a CVE's references are untagged and marks a passed KEV due date", async () => {
    upsertVuln(app.db, { ...base, cveId: "CVE-2025-12101", sourceIdentifier: "secure@citrix.com", references: [{ url: "https://support.citrix.com/article/CTX695486", tags: [] }] }, at, []);
    const insert = app.db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, summary, published_at, fetched_at, signals_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    insert.run("nvd-cves", "vulnerability", "CVE-2025-12101", "CVE-2025-12101: a flaw", null, "A flaw.", at, at, JSON.stringify({ cves: ["CVE-2025-12101"] }));
    insert.run("cisa-kev", "kev", "CVE-2026-2101", "Y: a KEV entry", null, "Required action: Apply updates.", "2026-10-01T00:00:00.000Z", at, JSON.stringify({ kev: true, cves: ["CVE-2026-2101"], dueDate: "2026-10-20", requiredAction: "Apply updates." }));
    const page = await (await fetch(`${app.base}/?kind=vulnerability`)).text();
    expect(page).toContain("<b>Fix:</b> untagged references (1) · the CNA&#39;s: <a href=\"https://support.citrix.com/article/CTX695486\"");
    expect(page).not.toMatch(/CVE-2025-12101[\s\S]{0,800}Nothing published yet/);
    const kev = await (await fetch(`${app.base}/?kind=kev`)).text();
    expect(kev).toContain('<span class="chip kev overdue" title="CISA\'s due date has passed">KEV · due 2026-10-20 · overdue</span>');
  });

  it("sends a weakness id typed into search to the filtered table", async () => {
    const res = await fetch(`${app.base}/search?q=cwe-79`, { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/vulnerabilities?cwe=CWE-79");
  });

  it("heads a filtered table with its count and filter, and offers the weakness field and this week's KEV due dates", async () => {
    const page = await (await fetch(`${app.base}/vulnerabilities?cwe=CWE-79`)).text();
    expect(page).toContain('<h2 class="list-count" id="list">3 CVEs · CWE-79</h2>');
    expect(page).toContain('id="cwe" name="cwe" value="CWE-79"');
    expect(page).toContain("Filters (1 on)");
    const due = await (await fetch(`${app.base}/vulnerabilities?due=7`)).text();
    expect(due).toContain("1 CVE · Due this week (KEV)");
    expect(due).toContain("CVE-2026-2100");
    expect(due).not.toContain('href="/vulnerabilities/CVE-2026-2101"');
  });

  it("compresses a large text answer for a client that asks, and keeps the ETag and 304", async () => {
    const url = `${app.base}/vulnerabilities`;
    const zipped = await raw(url, { "accept-encoding": "gzip, deflate" });
    expect(zipped.status).toBe(200);
    expect(zipped.headers["content-encoding"]).toBe("gzip");
    expect(String(zipped.headers.vary)).toMatch(/Accept-Encoding/i);
    const html = gunzipSync(zipped.body).toString("utf8");
    expect(html).toContain("<h1>Vulnerabilities");
    expect(Number(zipped.headers["content-length"])).toBe(zipped.body.length);
    const plain = await raw(url, {});
    expect(plain.headers["content-encoding"]).toBeUndefined();
    expect(plain.body.toString("utf8")).toBe(html);
    const etag = String(zipped.headers.etag);
    expect(etag).toBe(String(plain.headers.etag));
    const again = await raw(url, { "accept-encoding": "gzip", "if-none-match": etag });
    expect(again.status).toBe(304);
    expect(again.body.length).toBe(0);
    const head = await raw(url, { "accept-encoding": "gzip" }, "HEAD");
    expect(head.headers["content-encoding"]).toBeUndefined();
    // A small answer goes as it is.
    const health = await raw(`${app.base}/health`, { "accept-encoding": "gzip" });
    expect(health.headers["content-encoding"]).toBeUndefined();
    // A streamed static file is compressed too.
    const css = await raw(`${app.base}/assets/app.css`, { "accept-encoding": "gzip" });
    expect(css.headers["content-encoding"]).toBe("gzip");
    expect(gunzipSync(css.body).toString("utf8")).toContain(".vf-narrow");
  });
});
