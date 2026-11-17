import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import type { HttpGet } from "../src/http.ts";
import { windowsEdition } from "../src/eol.ts";
import { hasFixAbove, matchOs, matchPackages, matchWindows, osvBatchUrl, osvEcosystem, osvQueryUrl, packageBase, readReport, windowsProduct, type InventoryReport } from "../src/inventory.ts";
import { compareDebian } from "../src/versions.ts";

/**
 * The device reading's second pass (audit of 2026-11-16): a Windows report's edition picks the
 * endoflife.date cycle that is it, OSV's advisories are split into those with a fix published and
 * those without, Debian versions compare by Debian's rules, and a derivative's packages are asked
 * of OSV as its parent's.
 */

const now = new Date("2026-11-16T12:00:00Z");
const at = now.toISOString();
const base = { bw: 1 as const, browsers: [] as { name: string; version: string }[], packages: [] as { name: string; version: string }[], packageSource: null };

function windows(display: string, build: string, edition: string | null): InventoryReport {
  return { ...base, os: { family: "windows", name: "Windows", version: display, build, display, id: null, versionId: null, edition } };
}

describe("a Windows edition", () => {
  it("is kept from the report and maps to endoflife.date's cycle for it", () => {
    const report = readReport('{"bw":1,"os":{"family":"windows","name":"Windows 10 Enterprise LTSC 2021","version":"21H2","build":"10.0.19044.6456","display":"21H2","edition":"EnterpriseS"},"browsers":[],"packages":[],"package_source":""}');
    expect(report.os.edition).toBe("EnterpriseS");
    expect(windowsEdition("EnterpriseS")).toMatchObject({ suffix: "e-lts" });
    expect(windowsEdition("IoTEnterpriseS")).toMatchObject({ suffix: "iot-lts" });
    expect(windowsEdition("Professional")).toMatchObject({ suffix: "w" });
    expect(windowsEdition("CoreSingleLanguage")).toMatchObject({ suffix: "w" });
    expect(windowsEdition("Enterprise")).toMatchObject({ suffix: "e" });
    expect(windowsEdition("Education")).toMatchObject({ suffix: "e" });
    expect(windowsEdition("ServerRdsh")).toMatchObject({ suffix: "e" });
    expect(windowsEdition("ServerStandard")).toBe("server");
    expect(windowsEdition("Mystery")).toBeNull();

    const db = openDatabase(":memory:");
    migrate(db);
    const row = db.prepare("INSERT INTO eol_cycles (product, cycle, label, release_date, eol, support, latest, latest_release_date, lts, link, seen_at) VALUES ('windows', ?, NULL, NULL, ?, ?, NULL, NULL, ?, NULL, ?)");
    for (const [cycle, eol, lts] of [["10-21h2-e", "2024-06-11", 0], ["10-21h2-w", "2023-06-13", 0], ["10-21h2-e-lts", "2027-01-12", 1], ["10-21h2-iot-lts", "2032-01-13", 1], ["11-24h2-w", "2026-10-13", 0], ["11-24h2-e", "2027-10-12", 0], ["10-22h2", "2025-10-14", 0]] as const) row.run(cycle, eol, eol, lts, at);

    const ltsc = matchOs(db, windows("21H2", "10.0.19044.6456", "EnterpriseS"), now);
    expect(ltsc).toMatchObject({ state: "ok", text: "Windows 10 Version 21H2 Enterprise LTSC, the edition here (EnterpriseS), is in support until 2027-01-12." });
    expect(matchOs(db, windows("21H2", "10.0.19044.6456", "IoTEnterpriseS"), now).text).toContain("until 2032-01-13");
    const pro = matchOs(db, windows("24H2", "10.0.26100.9711", "Professional"), now);
    expect(pro).toMatchObject({ state: "bad", text: expect.stringContaining("Home and Pro, the edition here (Professional), ended on 2026-10-13") });
    expect(matchOs(db, windows("24H2", "10.0.26100.9711", "Enterprise"), now)).toMatchObject({ state: "ok", text: expect.stringContaining("until 2027-10-12") });
    // Windows 10 22H2 is one cycle for every edition.
    expect(matchOs(db, windows("22H2", "10.0.19045.6456", "Professional"), now)).toMatchObject({ state: "bad", text: expect.stringContaining("ended on 2025-10-14") });
    expect(matchOs(db, windows("24H2", "10.0.26100.9711", "ServerDatacenter"), now)).toMatchObject({ state: "na", text: expect.stringContaining("Windows Server edition") });
    // An edition the report does not carry, or one not known, keeps the reading across editions; no double space.
    const unknown = matchOs(db, windows("24H2", "10.0.26100.9711", null), now);
    expect(unknown).toMatchObject({ state: "warn", text: expect.stringContaining("Home and Pro; the others continue") });
    expect(unknown.quoted.every((q) => !q.includes("  "))).toBe(true);
    db.close();
  });

  it("agrees the verb with the count of exploited CVEs", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    db.prepare("INSERT INTO msrc_vulns (cve_id, title, severity, exploited, fixes_json, release_id, seen_at) VALUES ('CVE-2026-1', 't', 'Important', 1, ?, '2026-Nov', '2026-11-11'), ('CVE-2026-2', 't', 'Important', 0, ?, '2026-Nov', '2026-11-11')").run(
      JSON.stringify([{ kb: "5000001", products: ["Windows 11 Version 24H2"], fixedBuild: "10.0.26100.9800" }]),
      JSON.stringify([{ kb: "5000001", products: ["Windows 11 Version 24H2"], fixedBuild: "10.0.26100.9800" }]),
    );
    const finding = matchWindows(db, windows("24H2", "10.0.26100.9711", "Professional"));
    expect(finding.text).toContain("Microsoft says 1 of them is exploited");
    db.close();
  });
});

describe("a Windows 10 release older than DisplayVersion (bug sweep 3a)", () => {
  it("reads ReleaseId's four digits: LTSC 2019 is Windows 10 Version 1809, checked for updates and support", () => {
    expect(windowsProduct("1809", "10.0.17763.6000")).toBe("Windows 10 Version 1809");
    expect(windowsProduct("1607", "10.0.14393.7000")).toBe("Windows 10 Version 1607");
    expect(windowsProduct("Version 2", "10.0.17763.6000")).toBeNull();
    const db = openDatabase(":memory:");
    migrate(db);
    db.prepare("INSERT INTO msrc_vulns (cve_id, title, severity, exploited, fixes_json, release_id, seen_at) VALUES ('CVE-2026-3', 't', 'Important', 0, ?, '2026-Nov', '2026-11-11')").run(
      JSON.stringify([{ kb: "5000002", products: ["Windows 10 Version 1809"], fixedBuild: "10.0.17763.7000" }]),
    );
    expect(matchWindows(db, windows("1809", "10.0.17763.6000", "EnterpriseS")).state).not.toBe("na");
    const row = db.prepare("INSERT INTO eol_cycles (product, cycle, label, release_date, eol, support, latest, latest_release_date, lts, link, seen_at) VALUES ('windows', ?, NULL, NULL, ?, ?, NULL, NULL, 1, NULL, ?)");
    row.run("10-1809-e-lts", "2029-01-09", "2029-01-09", at);
    row.run("10-1607-e-lts", "2026-10-13", "2026-10-13", at);
    expect(matchOs(db, windows("1809", "10.0.17763.6000", "EnterpriseS"), now)).toMatchObject({ state: "ok", text: expect.stringContaining("Windows 10 Version 1809 Enterprise LTSC, the edition here (EnterpriseS), is in support until 2029-01-09") });
    expect(matchOs(db, windows("1607", "10.0.14393.7000", "EnterpriseS"), now)).toMatchObject({ state: "bad", text: expect.stringContaining("ended on 2026-10-13") });
    db.close();
  });
});

describe("Debian's version comparison", () => {
  it("follows deb-version: epoch, upstream, revision, tilde before everything", () => {
    const less: [string, string][] = [
      ["1.0~rc1", "1.0"],
      ["1.0", "1.0-1"],
      ["1.0", "1.0a"],
      ["1.0", "1.0+b1"],
      ["2.0", "1:0.9"],
      ["3.0.11-1~deb12u1", "3.0.11-1~deb12u2"],
      ["3.0.11-1~deb12u2", "3.0.11-1"],
      ["3.0.11-1~deb12u2", "3.0.17-1~deb12u3"],
      ["7.81.0-1ubuntu1.3", "7.81.0-1ubuntu1.20"],
      ["1.2.3", "1.10"],
      ["1.0-1", "1.0-1.1"],
    ];
    for (const [a, b] of less) {
      expect(compareDebian(a, b), `${a} < ${b}`).toBeLessThan(0);
      expect(compareDebian(b, a), `${b} > ${a}`).toBeGreaterThan(0);
    }
    expect(compareDebian("1.0-1", "1.0-1")).toBe(0);
    expect(compareDebian("01.0", "1.0")).toBe(0);
  });
});

describe("advisories with and without a fix", () => {
  const debian = (name: string, events: Record<string, string>[]) => [{ package: { name, ecosystem: "Debian:12" }, ranges: [{ type: "ECOSYSTEM", events }] }];

  it("reads a fixed event above the installed version as a fix, and none as no fix", () => {
    expect(hasFixAbove(debian("openssl", [{ introduced: "0" }, { fixed: "3.0.17-1~deb12u3" }]), "openssl", "Debian:12", "3.0.11-1~deb12u2")).toBe(true);
    expect(hasFixAbove(debian("openssl", [{ introduced: "0" }]), "openssl", "Debian:12", "3.0.11-1~deb12u2")).toBe(false);
    expect(hasFixAbove(debian("openssl", [{ introduced: "0" }, { fixed: "3.0.9-1" }]), "openssl", "Debian:12", "3.0.11-1~deb12u2")).toBe(false);
    // Another release's fix is not this one's.
    expect(hasFixAbove([{ package: { name: "openssl", ecosystem: "Debian:13" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "3.5.1-1" }] }] }], "openssl", "Debian:12", "3.0.11-1~deb12u2")).toBe(false);
    expect(hasFixAbove([{ package: { name: "curl", ecosystem: "Ubuntu:24.04:LTS" } , ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "8.5.0-2ubuntu10.6" }] }] }], "curl", "Ubuntu:24.04:LTS", "8.5.0-2ubuntu10.4")).toBe(true);
  });

  it("keeps a patched machine out of warn when the advisories left have no fix, and bounds the requests", async () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const packages = [{ name: "openssl", version: "3.0.17-1~deb12u3" }, { name: "glibc", version: "2.36-9+deb12u13" }, { name: "zlib1g", version: "1:1.2.13.dfsg-1" }];
    const records: Record<string, { id: string; affected: ReturnType<typeof debian> }[]> = {
      openssl: [{ id: "DEBIAN-CVE-2025-1", affected: debian("openssl", [{ introduced: "0" }]) }, { id: "DEBIAN-CVE-2025-2", affected: debian("openssl", [{ introduced: "0" }]) }],
      glibc: [{ id: "DEBIAN-CVE-2010-4756", affected: debian("glibc", [{ introduced: "0" }]) }],
    };
    let queries = 0;
    let inFlight = 0;
    let most = 0;
    const http = (fix: boolean): HttpGet => async (url, options) => {
      const body = JSON.parse(options?.body ?? "{}") as { queries?: { package: { name: string } }[]; package?: { name: string } };
      const reply = (value: unknown) => ({ url, status: 200, notModified: false, bytes: new TextEncoder().encode(JSON.stringify(value)), etag: null, lastModified: null, contentType: "application/json" });
      if (url === osvBatchUrl) return reply({ results: body.queries!.map((q) => ({ vulns: (records[q.package.name] ?? []).map((r) => ({ id: r.id })) })) });
      if (url === osvQueryUrl) {
        queries += 1;
        inFlight += 1;
        most = Math.max(most, inFlight);
        await Promise.resolve();
        inFlight -= 1;
        const list = (records[body.package!.name] ?? []).map((r) => (fix && r.id === "DEBIAN-CVE-2025-1" ? { ...r, affected: debian("openssl", [{ introduced: "0" }, { fixed: "3.0.18-1~deb12u1" }]) } : r));
        return reply({ vulns: list });
      }
      throw new Error(`no route for ${url}`);
    };
    const report: InventoryReport = { bw: 1, os: { family: "linux", name: "Debian GNU/Linux", version: "12", build: null, display: null, id: "debian", versionId: "12" }, browsers: [], packages, packageSource: "dpkg" };
    const patched = await matchPackages(db, http(false), report);
    expect(patched.state).toBe("ok");
    expect(patched.text).toBe("No installed version has an advisory with a fix published. 3 advisories on 2 packages have no fix published yet; the distribution has nothing to install for them.");
    expect(patched.refs.every((r) => r.note?.includes("no fix published"))).toBe(true);
    expect(queries).toBe(2);
    const behind = await matchPackages(db, http(true), report);
    expect(behind.state).toBe("warn");
    expect(behind.text).toMatch(/^1 package has advisories with a fixed version published above the one installed: openssl\. Update the distribution's packages\. 2 advisories on 2 packages have no fix published yet/);
    expect(behind.refs[0]).toMatchObject({ id: "DEBIAN-CVE-2025-1", note: "openssl 3.0.17-1~deb12u3" });
    expect(most).toBeLessThanOrEqual(6);
    db.close();
  });

  it("says one package, not one packages", async () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const finding = await matchPackages(db, (async () => { throw new Error("offline"); }) as HttpGet, { bw: 1, os: { family: "linux", name: "Debian", version: "12", build: null, display: null, id: "debian", versionId: "12" }, browsers: [], packages: [{ name: "x", version: "1" }], packageSource: "dpkg" });
    expect(finding.text).toContain("1 package was not judged");
    const other = await matchPackages(db, (async () => { throw new Error("offline"); }) as HttpGet, { bw: 1, os: { family: "linux", name: "Fedora", version: "40", build: null, display: null, id: "fedora", versionId: "40" }, browsers: [], packages: [{ name: "x", version: "1" }], packageSource: "rpm" });
    expect(other.text).toBe("OSV carries no advisories for Fedora 40, so 1 package cannot be judged here.");
    db.close();
  });
});

describe("a derivative's packages", () => {
  it("are asked of OSV as the parent release's", () => {
    expect(osvEcosystem("linuxmint", "22", "dpkg")).toBe("Ubuntu:24.04:LTS");
    expect(osvEcosystem("linuxmint", "21.3", "dpkg")).toBe("Ubuntu:22.04:LTS");
    expect(osvEcosystem("linuxmint", "6", "dpkg")).toBe("Debian:12");
    expect(osvEcosystem("pop", "22.04", "dpkg")).toBe("Ubuntu:22.04:LTS");
    expect(osvEcosystem("raspbian", "12", "dpkg")).toBe("Debian:12");
    expect(osvEcosystem("zorin", "17", "dpkg")).toBeNull();
    expect(osvEcosystem("kali", "2025.1", "dpkg", "debian")).toBeNull();
    expect(osvEcosystem("elementary", "24.04", "dpkg", "ubuntu debian")).toBe("Ubuntu:24.04:LTS");
    expect(packageBase("linuxmint", "22", null)).toEqual({ id: "ubuntu", versionId: "24.04", via: "Linux Mint 22" });
    expect(readReport('{"bw":1,"os":{"family":"linux","id":"elementary","version_id":"8","id_like":"ubuntu debian"},"packages":[]}').os.idLike).toBe("ubuntu debian");
  });
});

describe("an Ubuntu LTS past standard support", () => {
  it("names Ubuntu Pro instead of saying no more updates", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    db.prepare("INSERT INTO eol_cycles (product, cycle, label, release_date, eol, support, latest, latest_release_date, lts, link, seen_at) VALUES ('ubuntu', '20.04', 'Focal Fossa', NULL, '2025-05-31', '2022-10-01', NULL, NULL, 1, NULL, ?), ('ubuntu', '23.10', 'Mantic', NULL, '2024-07-12', '2024-07-12', NULL, NULL, 0, NULL, ?)").run(at, at);
    const lts = matchOs(db, { ...base, os: { family: "linux", name: "Ubuntu", version: "20.04", build: null, display: null, id: "ubuntu", versionId: "20.04" } }, now);
    expect(lts).toMatchObject({ state: "bad", text: "Standard support ended 2025-05-31: security updates continue only under Ubuntu Pro (ESM), for a machine attached to it; the ESM end date is not read here." });
    const interim = matchOs(db, { ...base, os: { family: "linux", name: "Ubuntu", version: "23.10", build: null, display: null, id: "ubuntu", versionId: "23.10" } }, now);
    expect(interim.text).toBe("Standard support ended 2024-07-12: no more security updates for this release.");
    db.close();
  });
});
