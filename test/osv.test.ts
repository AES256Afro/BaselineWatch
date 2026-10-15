import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { normalizeNvd } from "../src/adapters/nvd.ts";
import { normalizeOsv, osvAdapter, osvEcosystem, type OsvQueryResponse } from "../src/adapters/osv.ts";
import { scoreCvss3 } from "../src/cvss.ts";
import { migrate, openDatabase } from "../src/db.ts";
import type { HttpGet } from "../src/http.ts";
import { getSource } from "../src/ingest.ts";
import { advisoryKey, getVuln, loadWatchlist, parsePackageValue, upsertVuln, vulnChanges } from "../src/vulns.ts";
import { listWire } from "../src/wire.ts";
import { fixture } from "./helpers.ts";

const at = new Date("2026-10-15T12:00:00Z");
const query = (): OsvQueryResponse => JSON.parse(new TextDecoder().decode(fixture("osv/query-pyjwt.json"))) as OsvQueryResponse;

describe("CVSS 3.x scoring from a vector", () => {
  it("matches the specification's examples", () => {
    expect(scoreCvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toMatchObject({ version: "3.1", score: 9.8, severity: "CRITICAL" });
    expect(scoreCvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L")?.score).toBe(5.3);
    expect(scoreCvss3("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N")?.score).toBe(7.4);
    expect(scoreCvss3("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N")?.score).toBe(5.4);
    expect(scoreCvss3("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")).toMatchObject({ version: "3.0", score: 7.8, severity: "HIGH" });
    expect(scoreCvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")?.score).toBe(0);
    expect(scoreCvss3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBeNull();
    expect(scoreCvss3("AV:N/AC:L/Au:N/C:P/I:P/A:P")).toBeNull();
    expect(scoreCvss3("CVSS:3.1/AV:N/AC:L")).toBeNull();
  });
});

describe("package values and OSV records", () => {
  it("reads ecosystem:name the way people write it", () => {
    expect(parsePackageValue("npm:express")).toEqual({ ecosystem: "npm", name: "express" });
    expect(parsePackageValue("Maven:org.apache.logging.log4j:log4j-core")).toEqual({ ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core" });
    expect(parsePackageValue("Debian:12:openssl")).toEqual({ ecosystem: "Debian:12", name: "openssl" });
    expect(parsePackageValue("Ubuntu:24.04:LTS:openssl")).toEqual({ ecosystem: "Ubuntu:24.04:LTS", name: "openssl" });
    expect(parsePackageValue("express")).toBeNull();
    expect(parsePackageValue("npm:")).toBeNull();
    expect(osvEcosystem("pypi")).toBe("PyPI");
    expect(osvEcosystem("debian:12")).toBe("Debian:12");
    expect(osvEcosystem("Something New")).toBe("Something New");
  });

  it("normalises an OSV record with its score, packages and fixed versions", () => {
    const ghsa = query().vulns!.find((v) => v.id === "GHSA-2gx3-rcp4-g85q")!;
    const a = normalizeOsv(ghsa, at.toISOString());
    expect(a.aliases).toEqual(["CVE-2026-101917", "PYSEC-2026-4140"]);
    expect(advisoryKey(a)).toBe("CVE-2026-101917");
    expect(a.cvss).toMatchObject({ version: "3.1", score: 5.3, severity: "MEDIUM", source: "github-advisories" });
    expect(a.cwes).toEqual(["CWE-770"]);
    expect(a.publishedAt).toBe("2026-09-29T23:11:51.000Z");
    expect(a.packages).toEqual([{ ecosystem: "PyPI", name: "pyjwt", introduced: ["0"], fixed: ["2.14.0"], lastAffected: [], advisory: "GHSA-2gx3-rcp4-g85q" }]);
    expect(a.summary).toContain("PyJWKClient");
    expect(advisoryKey({ id: "GHSA-xxxx-yyyy-zzzz", aliases: [] })).toBe("GHSA-XXXX-YYYY-ZZZZ");
    expect(advisoryKey({ id: "PYSEC-2026-1", aliases: ["GHSA-aaaa-bbbb-cccc"] })).toBe("GHSA-AAAA-BBBB-CCCC");
    // Debian's and Ubuntu's trackers prefix the CVE and list no aliases: still the CVE's row.
    expect(advisoryKey({ id: "DEBIAN-CVE-2026-84782", aliases: [] })).toBe("CVE-2026-84782");
    expect(advisoryKey({ id: "UBUNTU-CVE-2026-1", aliases: ["USN-7000-1"] })).toBe("CVE-2026-1");
    expect(advisoryKey({ id: "DSA-5999-1", aliases: ["CVE-2026-2"] })).toBe("CVE-2026-2");
  });
});

describe("OSV pull", () => {
  let db: DatabaseSync;
  const http: HttpGet = async (url, options) => {
    expect(url).toBe("https://api.osv.dev/v1/query");
    expect(options?.method).toBe("POST");
    expect(JSON.parse(options?.body ?? "{}")).toEqual({ package: { name: "pyjwt", ecosystem: "PyPI" } });
    return { url, status: 200, notModified: false, bytes: fixture("osv/query-pyjwt.json"), etag: null, lastModified: null, contentType: "application/json" };
  };
  const ctx = (now: Date) => ({ db, dataDir: "", source: getSource(db, "osv")!, http, now: () => now, settings: { nvdApiKey: null, nvdBackfillDays: 7 }, log: () => undefined });
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
  });
  afterEach(() => db.close());

  it("does nothing without a package on the watchlist", async () => {
    const out = await osvAdapter.pull!(ctx(at));
    expect(out).toMatchObject({ items: 0, inserted: 0, updated: 0 });
    expect(out.detail).toContain("no package");
  });

  it("stores each advisory once under its CVE, marks the watch, and puts only fresh ones on the Wire", async () => {
    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('package', 'pypi:pyjwt', 'PyJWT', ?)").run(at.toISOString());
    expect(loadWatchlist(db).map((e) => e.kind)).toContain("package");
    const first = await osvAdapter.pull!(ctx(at));
    // Four records, but the GHSA and the PYSEC of CVE-2026-101917 are one advisory: three rows.
    expect(first).toMatchObject({ items: 3, inserted: 3, updated: 0 });
    expect(first.alerts ?? []).toHaveLength(0); // a first pull is a back catalogue

    const recent = getVuln(db, "CVE-2026-101917")!;
    expect(recent.source_identifier).toBe("github-advisories");
    expect(recent.cvss_score).toBe(5.3);
    expect(recent.watch_hit).toBe(1);
    expect(JSON.parse(recent.watch_labels_json!)).toEqual(["PyJWT"]);
    expect(JSON.parse(recent.aliases_json!)).toEqual(["GHSA-2GX3-RCP4-G85Q", "PYSEC-2026-4140"]);
    expect(JSON.parse(recent.packages_json!)).toEqual([{ ecosystem: "PyPI", name: "pyjwt", introduced: ["0"], fixed: ["2.14.0"], lastAffected: [], advisory: "GHSA-2gx3-rcp4-g85q" }]);
    expect(getVuln(db, "CVE-2022-29217")?.cvss_score).toBe(7.4);
    expect(getVuln(db, "CVE-2025-45768")?.source_identifier).toBe("osv.dev");

    // Published two weeks before the pull: on the Wire. The 2022 and 2025 ones: table only.
    const wire = listWire(db, { kind: "vulnerability" });
    expect(wire.map((i) => i.external_id)).toEqual(["CVE-2026-101917"]);
    expect(wire[0]?.title).toContain("PyPI:pyjwt");

    // The same answer again: nothing new, nothing changed, nothing announced.
    const second = await osvAdapter.pull!(ctx(new Date("2026-10-16T12:00:00Z")));
    expect(second).toMatchObject({ items: 3, inserted: 0, updated: 0 });
    expect(second.alerts ?? []).toHaveLength(0);
    expect(vulnChanges(db, "CVE-2026-101917").map((c) => c.field)).toEqual(["new"]);
  });

  it("keeps the packages when NVD later describes the same CVE, and attaches them to a CVE NVD already has", async () => {
    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('package', 'PyPI:pyjwt', NULL, ?)").run(at.toISOString());
    // NVD knew CVE-2022-29217 first, with its own CPEs and score.
    const nvd = normalizeNvd({
      id: "CVE-2022-29217",
      published: "2022-05-24T15:15:00.000",
      lastModified: "2022-06-03T13:00:00.000",
      vulnStatus: "Analyzed",
      descriptions: [{ lang: "en", value: "PyJWT key confusion through non-blocklisted public key formats." }],
      metrics: { cvssMetricV31: [{ type: "Primary", source: "nvd@nist.gov", cvssData: { version: "3.1", baseScore: 7.5, baseSeverity: "HIGH", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" } }] },
      configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:pyjwt_project:pyjwt:*:*:*:*:*:*:*:*" }] }] }],
    });
    upsertVuln(db, nvd, "2026-10-01T00:00:00.000Z", loadWatchlist(db));
    expect(getVuln(db, "CVE-2022-29217")?.watch_hit).toBe(0);

    await osvAdapter.pull!(ctx(at));
    const enriched = getVuln(db, "CVE-2022-29217")!;
    expect(enriched.cvss_score).toBe(7.5); // NVD's score and words stay
    expect(enriched.description).toContain("key confusion");
    expect(enriched.watch_hit).toBe(1);
    expect(JSON.parse(enriched.watch_labels_json!)).toEqual(["PyPI:pyjwt"]);
    expect(JSON.parse(enriched.packages_json!)[0]).toMatchObject({ ecosystem: "PyPI", name: "pyjwt", fixed: ["2.4.0"] });
    expect(vulnChanges(db, "CVE-2022-29217").map((c) => c.field)).toEqual(["packages", "new"]);

    // NVD touches the CVE again: the packages and the watch mark survive.
    upsertVuln(db, { ...nvd, lastModifiedAt: "2026-10-20T00:00:00.000Z", description: `${nvd.description} Updated.` }, "2026-10-20T00:00:00.000Z", loadWatchlist(db));
    const after = getVuln(db, "CVE-2022-29217")!;
    expect(after.description).toContain("Updated.");
    expect(JSON.parse(after.packages_json!)[0].name).toBe("pyjwt");
    expect(after.watch_hit).toBe(1);
  });
});
