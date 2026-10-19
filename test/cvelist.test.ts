import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cvelistAdapter, normalizeCvelist, storeCvelistRecords, type CveRecord } from "../src/adapters/cvelist.ts";
import { storeNvdRecords, type NvdCve } from "../src/adapters/nvd.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { HttpError, type HttpGet } from "../src/http.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { getVuln, vulnChanges } from "../src/vulns.ts";
import { unzipAll } from "../src/zip.ts";
import { fakeHttp, fixture, startTestApp, type TestApp } from "./helpers.ts";

const at = new Date("2026-10-19T18:00:00Z");
const apiUrl = "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=30";
const delta1700 = "https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-10-19_1700Z/2026-10-19_delta_CVEs_at_1700Z.zip";
const delta1600 = "https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-10-19_1600Z/2026-10-19_delta_CVEs_at_1600Z.zip";

const deltaRecords = (): CveRecord[] => unzipAll(fixture("cvelist/delta.zip")).map((e) => JSON.parse(new TextDecoder().decode(e.bytes)) as CveRecord);
const record = (cveId: string): CveRecord => deltaRecords().find((r) => r.cveMetadata.cveId === cveId)!;

/** An NVD record the way the NVD adapter would store it, for the merge tests. */
function nvdRecord(id: string, overrides: Partial<NvdCve> = {}): { cve: NvdCve } {
  return {
    cve: {
      id,
      sourceIdentifier: "cve@mitre.org",
      published: "2026-10-19T08:31:40.984",
      lastModified: "2026-10-19T17:50:00.000",
      vulnStatus: "Analyzed",
      descriptions: [{ lang: "en", value: "NVD's own words about this flaw." }],
      metrics: { cvssMetricV31: [{ type: "Primary", source: "nvd@nist.gov", cvssData: { version: "3.1", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", baseScore: 9.8, baseSeverity: "CRITICAL" } }] },
      ...overrides,
    },
  };
}

describe("normalizeCvelist", () => {
  it("reads state, dates, descriptions, CNA CVSS (preferring v4.0), CWEs, affected and references from real records", () => {
    const n = normalizeCvelist(record("CVE-2026-104679"), at.toISOString());
    expect(n.cveId).toBe("CVE-2026-104679");
    expect(n.sourceIdentifier).toBe("cvelist-v5");
    expect(n.vulnStatus).toBe("Published");
    expect(n.publishedAt).toBe("2026-10-19T08:31:40.984Z");
    expect(n.lastModifiedAt).toBe("2026-10-19T08:31:40.984Z");
    expect(n.description).toMatch(/^VOCALOID6 Editor provided by Yamaha/);
    expect(n.cvss).toMatchObject({ version: "4.0", score: 6.9, severity: "MEDIUM", source: "jpcert" });
    expect(n.cwes).toEqual(["CWE-611"]);
    expect(n.vendors).toEqual(["yamaha corporation"]);
    expect(n.products).toEqual(["vocaloid6 editor"]);
    expect(n.references).toHaveLength(3);
    expect(n.kev).toBeNull();
  });

  it("copes with records that carry no metrics, and reads a rejection's reason", () => {
    const linux = normalizeCvelist(record("CVE-2026-100070"), at.toISOString());
    expect(linux.cvss).toBeNull();
    expect(linux.description).toMatch(/^In the Linux kernel/);
    const rejected = normalizeCvelist(record("CVE-2026-77225"), at.toISOString());
    expect(rejected.vulnStatus).toBe("Rejected");
    expect(rejected.description).toMatch(/rejected or withdrawn/);
    expect(rejected.lastModifiedAt).toBe("2026-10-19T15:18:04.916Z");
  });
});

describe("cvelist merge", () => {
  let db: ReturnType<typeof openDatabase>;
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
  });
  afterEach(() => db.close());

  it("inserts unseen CVEs without putting anything on the Wire", () => {
    const counts = storeCvelistRecords({ db, now: () => at }, deltaRecords());
    expect(counts).toEqual({ inserted: 6, updated: 0, skipped: 0 });
    expect((db.prepare("SELECT COUNT(*) AS n FROM vulns").get() as { n: number }).n).toBe(6);
    expect((db.prepare("SELECT COUNT(*) AS n FROM items").get() as { n: number }).n).toBe(0);
    expect(getVuln(db, "CVE-2026-104679")).toMatchObject({ cvss_score: 6.9, source_identifier: "cvelist-v5", vuln_status: "Published" });
  });

  it("lets a later NVD pull enrich its rows rather than duplicate them", () => {
    storeCvelistRecords({ db, now: () => at }, deltaRecords());
    const stored = storeNvdRecords({ db, now: () => at }, [nvdRecord("CVE-2026-104679")]);
    expect(stored).toMatchObject({ inserted: 0, updated: 1 });
    expect((db.prepare("SELECT COUNT(*) AS n FROM vulns WHERE cve_id = 'CVE-2026-104679'").get() as { n: number }).n).toBe(1);
    expect(getVuln(db, "CVE-2026-104679")).toMatchObject({ cvss_score: 9.8, cvss_source: "nvd@nist.gov", source_identifier: "cve@mitre.org", vuln_status: "Analyzed" });
  });

  it("never overwrites an NVD-enriched row", () => {
    storeNvdRecords({ db, now: () => at }, [nvdRecord("CVE-2026-104679")]);
    const counts = storeCvelistRecords({ db, now: () => at }, deltaRecords());
    expect(counts).toEqual({ inserted: 5, updated: 0, skipped: 1 });
    expect(getVuln(db, "CVE-2026-104679")).toMatchObject({ cvss_score: 9.8, description: "NVD's own words about this flaw.", vuln_status: "Analyzed" });
  });

  it("lends description, status and dates to an NVD row still awaiting analysis, and nothing more", () => {
    storeNvdRecords({ db, now: () => at }, [nvdRecord("CVE-2026-104679", { vulnStatus: "Awaiting Analysis", descriptions: [], metrics: {} })]);
    const counts = storeCvelistRecords({ db, now: () => at }, deltaRecords());
    expect(counts).toEqual({ inserted: 5, updated: 1, skipped: 0 });
    const row = getVuln(db, "CVE-2026-104679")!;
    expect(row.description).toMatch(/^VOCALOID6 Editor/);
    expect(row.vuln_status).toBe("Published");
    expect(row.source_identifier).toBe("cve@mitre.org"); // still NVD's row
    expect(row.cvss_score).toBeNull(); // the targeted update never touches scores
    expect(vulnChanges(db, "CVE-2026-104679").map((c) => c.field)).toContain("description");
  });

  it("re-upserting its own rows from the next delta records no spurious change", () => {
    storeCvelistRecords({ db, now: () => at }, deltaRecords());
    const again = storeCvelistRecords({ db, now: () => new Date(at.getTime() + 3_600_000) }, deltaRecords());
    expect(again).toEqual({ inserted: 0, updated: 0, skipped: 0 });
  });
});

describe("cvelist pull", () => {
  let db: ReturnType<typeof openDatabase>;
  let dataDir = "";
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    db.prepare("UPDATE sources SET enabled = 0 WHERE id = 'nvd-cves'").run();
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-cvelist-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("starts at the newest release, stores the cursor, and finds nothing new on the next run", async () => {
    const source = getSource(db, "cvelist-v5")!;
    const http = fakeHttp({ [apiUrl]: { bytes: fixture("cvelist/releases.json") }, [delta1700]: { bytes: fixture("cvelist/delta.zip") } });
    const result = await ingestSource(db, dataDir, source, { http, now: () => at, log: () => {} });
    expect(result.status).toBe("ok");
    expect(result).toMatchObject({ items: 6, inserted: 6 });
    expect(result.detail).toContain("first pull");
    expect(http.calls.map((c) => c.url)).toEqual([apiUrl, delta1700]); // never the 635 MB baseline, never an older delta
    const cursor = (db.prepare("SELECT value FROM app_settings WHERE key = 'cvelist.cursor'").get() as { value: string }).value;
    expect(cursor).toBe("2026-10-19T17:24:20Z");

    const again = await ingestSource(db, dataDir, getSource(db, "cvelist-v5")!, { http, now: () => at, log: () => {} });
    expect(again).toMatchObject({ status: "ok", items: 0, inserted: 0 });
    expect(again.detail).toContain("no release newer");
  });

  it("consumes every release newer than the cursor, oldest first", async () => {
    db.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES ('cvelist.cursor', '2026-10-19T16:00:00Z', ?)").run(at.toISOString());
    const http = fakeHttp({
      [apiUrl]: { bytes: fixture("cvelist/releases.json") },
      [delta1600]: { bytes: fixture("cvelist/delta.zip") },
      [delta1700]: { bytes: fixture("cvelist/delta.zip") },
    });
    const result = await ingestSource(db, dataDir, getSource(db, "cvelist-v5")!, { http, now: () => at, log: () => {} });
    expect(result).toMatchObject({ status: "ok", items: 12, inserted: 6, updated: 0 });
    expect(http.calls.map((c) => c.url)).toEqual([apiUrl, delta1600, delta1700]);
  });

  it("treats a GitHub rate limit as a skipped run, not a source failure", async () => {
    const http: HttpGet = async (url) => {
      throw new HttpError(url, 403);
    };
    const result = await ingestSource(db, dataDir, getSource(db, "cvelist-v5")!, { http, now: () => at, log: () => {} });
    expect(result.status).toBe("ok");
    expect(result.detail).toContain("rate limited");
    expect(cvelistAdapter.id).toBe("cvelist");
  });
});

describe("vulnerabilities page from a cvelist pull alone", () => {
  let app: TestApp;
  afterEach(async () => {
    await app?.close();
  });

  it("lists the delta's CVEs with the NVD source disabled", async () => {
    app = await startTestApp({ now: () => at });
    app.db.prepare("UPDATE sources SET enabled = 0 WHERE id = 'nvd-cves'").run();
    const http = fakeHttp({ [apiUrl]: { bytes: fixture("cvelist/releases.json") }, [delta1700]: { bytes: fixture("cvelist/delta.zip") } });
    await ingestSource(app.db, app.dataDir, getSource(app.db, "cvelist-v5")!, { http, now: () => at, log: () => {} });
    const page = await (await fetch(`${app.base}/vulnerabilities`)).text();
    expect(page).toContain("CVE-2026-104679");
    expect(page).toContain("CVE-2026-100070");
  });
});
