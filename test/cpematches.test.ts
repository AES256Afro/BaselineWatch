import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { normalizeNvd, storeNvdRecords, type NvdResponse } from "../src/adapters/nvd.ts";
import { cpeMatchesOf, rangesFor, splitCpe } from "../src/cpematches.ts";
import { countRows, migrate, openDatabase } from "../src/db.ts";
import { applyAdvisory, getVuln } from "../src/vulns.ts";
import { fixture } from "./helpers.ts";

// CVE-2024-6387 (regreSSHion) as NVD served it on 2026-10-22: 41 configurations, 120 cpeMatch
// entries, bounds on both sides, and AND configurations whose "running on" side is not vulnerable.
const openssh = (): NvdResponse => JSON.parse(new TextDecoder().decode(fixture("nvd/cve-2024-6387.json"))) as NvdResponse;
const windowFixture = (): NvdResponse => JSON.parse(new TextDecoder().decode(fixture("nvd-window.json"))) as NvdResponse;
const at = new Date("2026-10-22T03:00:00Z");
const later = new Date("2026-10-23T03:00:00Z");

describe("splitCpe", () => {
  it("splits on the colons that are not escaped", () => {
    expect(splitCpe("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")).toEqual(["cpe", "2.3", "a", "openbsd", "openssh", "*", "*", "*", "*", "*", "*", "*", "*"]);
    expect(splitCpe("cpe:2.3:a:vendor:name\\:with\\:colons:1.0:*:*:*:*:*:*:*").slice(2, 6)).toEqual(["a", "vendor", "name\\:with\\:colons", "1.0"]);
  });
});

describe("cpeMatchesOf", () => {
  it("keeps every entry of a real record once, with its bounds and its vulnerable flag", () => {
    const matches = cpeMatchesOf(openssh().vulnerabilities![0]!.cve.configurations!);
    expect(matches).toHaveLength(120);
    expect(matches.filter((m) => !m.vulnerable)).toHaveLength(28);
    // Both bounds inclusive; one upper bound, exclusive; one exact version with an update field.
    expect(matches).toContainEqual({ criteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", part: "a", vendor: "openbsd", product: "openssh", version: "*", versionStart: "8.6", startInclusive: true, versionEnd: "9.8", endInclusive: true, vulnerable: true });
    expect(matches).toContainEqual({ criteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", part: "a", vendor: "openbsd", product: "openssh", version: "*", versionStart: null, startInclusive: null, versionEnd: "4.4", endInclusive: false, vulnerable: true });
    expect(matches).toContainEqual(expect.objectContaining({ criteria: "cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*", version: "8.5", versionStart: null, versionEnd: null, vulnerable: true }));
    expect(matches).toContainEqual(expect.objectContaining({ part: "o", vendor: "apple", product: "macos", versionStart: "14.0", startInclusive: true, versionEnd: "14.6", endInclusive: false }));
  });

  it("skips what is not a CPE 2.3 criterion, and a repeat of the same criterion with the same bounds", () => {
    const same = { vulnerable: true, criteria: "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*" };
    const other = { vulnerable: true, criteria: "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*", versionStartExcluding: "1", versionEndIncluding: "2" };
    const matches = cpeMatchesOf([{ nodes: [{ cpeMatch: [same, same, other, { vulnerable: true, criteria: "cpe:/a:x:y:1" }, { vulnerable: true }] }] }, { nodes: [{ cpeMatch: [same, { ...same, vulnerable: false }] }] }]);
    expect(matches.map((m) => [m.version, m.versionStart, m.startInclusive, m.versionEnd, m.endInclusive, m.vulnerable])).toEqual([
      ["1", null, null, null, null, true],
      ["*", "1", false, "2", true, true],
      ["1", null, null, null, null, false],
    ]);
  });

  it("rides on the normalised record, while cpes still lists only the vulnerable criteria", () => {
    const n = normalizeNvd(openssh().vulnerabilities![0]!.cve);
    expect(n.cpeMatches).toHaveLength(120);
    expect(n.cpes).toHaveLength(89);
    // The appliance an affected firmware runs on is the "running on" side of an AND: a row, not a criterion in cpes.
    expect(n.cpes).not.toContain("cpe:2.3:h:sonicwall:sma_6200:-:*:*:*:*:*:*:*");
    expect(n.cpeMatches).toContainEqual(expect.objectContaining({ criteria: "cpe:2.3:h:sonicwall:sma_6200:-:*:*:*:*:*:*:*", part: "h", vendor: "sonicwall", product: "sma_6200", version: "-", vulnerable: false }));
  });
});

describe("vuln_cpe_matches", () => {
  let db: ReturnType<typeof openDatabase>;
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
  });
  afterEach(() => db.close());

  it("writes one row per entry, replaces them whole on the next sighting, and leaves them alone when an advisory lands", () => {
    storeNvdRecords({ db, now: () => at }, openssh().vulnerabilities!);
    expect(countRows(db, "vuln_cpe_matches")).toBe(120);
    expect((db.prepare("SELECT COUNT(*) AS n FROM vuln_cpe_matches WHERE vulnerable = 0").get() as { n: number }).n).toBe(28);

    const rows = rangesFor(db, "OpenBSD", " openssh ");
    expect(rows).toHaveLength(5);
    expect(rows.every((r) => r.cveId === "CVE-2024-6387")).toBe(true);
    expect(rows).toContainEqual({ cveId: "CVE-2024-6387", criteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", part: "a", vendor: "openbsd", product: "openssh", version: "*", versionStart: "8.6", startInclusive: true, versionEnd: "9.8", endInclusive: true, vulnerable: true });
    expect(rows).toContainEqual(expect.objectContaining({ version: "*", versionStart: null, startInclusive: null, versionEnd: "4.4", endInclusive: false }));
    expect(rangesFor(db, "openbsd", "opensmtpd")).toEqual([]);

    // NVD serves the record again with one configuration: the rows it no longer carries go.
    const trimmed = openssh().vulnerabilities![0]!.cve;
    trimmed.lastModified = "2026-10-23T00:00:00.000";
    trimmed.configurations = trimmed.configurations!.slice(32, 33);
    storeNvdRecords({ db, now: () => later }, [{ cve: trimmed }]);
    expect(countRows(db, "vuln_cpe_matches")).toBe(5);
    expect(rangesFor(db, "apple", "macos")).toEqual([]);
    expect(rangesFor(db, "openbsd", "openssh")).toHaveLength(5);

    // A distribution's advisory on the same CVE says nothing about CPEs; the rows stay.
    applyAdvisory(
      db,
      {
        id: "DSA-5724-1",
        aliases: ["CVE-2024-6387"],
        summary: "openssh - security update",
        details: null,
        publishedAt: "2024-07-01T00:00:00.000Z",
        modifiedAt: "2024-07-02T00:00:00.000Z",
        cvss: null,
        cwes: [],
        references: [],
        packages: [{ ecosystem: "Debian:12", name: "openssh", introduced: ["0"], fixed: ["1:9.2p1-2+deb12u3"], lastAffected: [], advisory: "DSA-5724-1" }],
      },
      later.toISOString(),
      [],
    );
    expect(getVuln(db, "CVE-2024-6387")?.packages_json).toContain("deb12u3");
    expect(countRows(db, "vuln_cpe_matches")).toBe(5);
  });

  it("keeps the one-sided bounds the window fixture carries", () => {
    storeNvdRecords({ db, now: () => at }, windowFixture().vulnerabilities!);
    const openssl = rangesFor(db, "openssl", "openssl");
    expect(openssl.length).toBeGreaterThan(20);
    expect(openssl.filter((r) => r.versionEnd !== null)).toEqual([expect.objectContaining({ cveId: "CVE-2015-0204", version: "*", versionStart: null, startInclusive: null, versionEnd: "0.9.8zc", endInclusive: true })]);
    expect(rangesFor(db, "siemens", "6bk1602-0aa12-0tp0_firmware")).toEqual([expect.objectContaining({ cveId: "CVE-2021-44228", versionStart: null, versionEnd: "2.7.0", endInclusive: false, vulnerable: true })]);
  });
});
