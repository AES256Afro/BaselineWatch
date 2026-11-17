import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { isPlatformKey, kevPlatformKeys, kevReading, microsoftServers, platformsOf, type KevReading, type PlatformKey } from "../src/platforms.ts";
import { kevPlatform, type PlatformId } from "../src/stigs.ts";
import { applyKev, getVuln, recomputePlatforms } from "../src/vulns.ts";

/**
 * CISA's vendor and product as the catalogue writes them, and what each is: the platforms the CVE
 * table gives the KEV-only row, and the STIG page that lists the entry. One reading
 * (src/platforms.ts kevReading) feeds both.
 */
const catalogue: [vendor: string | null, product: string | null, table: PlatformKey[], stig: PlatformId | null][] = [
  ["Microsoft", "Win32k", ["windows"], "windows"],
  ["Microsoft", "Windows", ["windows"], "windows"],
  ["Microsoft", "SMBv1 server", ["windows"], "windows"],
  ["Microsoft", "Internet Key Exchange (IKE) Service Extensions", ["windows"], "windows"],
  ["Microsoft", "Exchange Server", [], "applications"],
  ["Microsoft", "Exchange", [], "applications"],
  ["Microsoft", "Office", [], "applications"],
  ["Microsoft", ".NET Framework, SharePoint, Visual Studio", [], "applications"],
  ["Microsoft", "Edge", ["edge"], "browsers"],
  ["Microsoft", "Internet Explorer and Edge", ["edge"], "browsers"],
  ["Microsoft", "Internet Explorer", [], "browsers"],
  ["Microsoft", "MSHTML", [], "browsers"],
  ["Apple", "Multiple Products", ["apple"], "macos"],
  ["Apple", "macOS", ["apple"], "macos"],
  ["Apple", "iOS and iPadOS", ["apple"], "mobile"],
  ["Google", "Chromium V8", ["chrome"], "browsers"],
  ["Google", "Pixel", ["android"], "mobile"],
  ["Google", "Skia", [], null],
  ["Android", "Framework", ["android"], "mobile"],
  ["Samsung", "Mobile Devices", ["android"], "mobile"],
  ["Mozilla", "Firefox and Thunderbird", ["firefox"], "browsers"],
  ["Linux", "Kernel", ["linux"], "linux"],
  ["Red Hat", "Polkit", ["linux"], "linux"],
  ["Red Hat", "Libuser", ["linux"], "linux"],
  ["Red Hat", "Automatic Bug Reporting Tool", ["linux"], "linux"],
  ["Red Hat", "JBoss", [], "applications"],
  ["Oracle", "Solaris", [], "linux"],
  ["Oracle", "Solaris and Zettabyte File System (ZFS)", [], "linux"],
  ["Oracle", "WebLogic Server", [], "applications"],
  ["Cisco", "IOS and IOS XE Software", ["network"], "network"],
  ["F5", "BIG-IP", ["network"], "network"],
  ["Palo Alto Networks", "PAN-OS", ["network"], "network"],
  ["Check Point", "Quantum Security Gateways", ["network"], "network"],
  ["Pulse Secure", "Pulse Connect Secure", ["network"], "network"],
  ["Array Networks ", "ArrayOS AG", ["network"], "network"],
  ["Juniper", "Junos OS", ["network"], "network"],
  ["TP-Link", "Archer AX21", ["network"], "network"],
  ["DrayTek", "Multiple Vigor Routers", ["network"], "network"],
  ["Ubiquiti", "UniFi OS", ["network"], "network"],
  ["Hewlett Packard Enterprise (HPE)", "OneView", ["network"], "network"],
  ["Barracuda Networks", "Email Security Gateway (ESG) Appliance", ["network"], "network"],
  ["D-Link and TRENDnet", "Multiple Devices", ["network"], "network"],
  ["NETGEAR", "Multiple Routers", ["network"], "network"],
  ["Langflow", "Langflow", ["ai"], null],
  ["BerriAI", "LiteLLM", ["ai"], null],
  ["VMware", "ESXi", [], "virtualization"],
  ["Hewlett Packard (HP)", "OpenView Network Node Manager", [], null],
  ["Ahsay", "AhsayCBS", [], null],
  [null, null, [], null],
];

/** The STIG pages a table platform may be filed under: the same thing, grouped the pages' way. */
const pagesFor: Record<PlatformKey, (PlatformId | null)[]> = {
  windows: ["windows"],
  apple: ["macos", "mobile"],
  linux: ["linux"],
  android: ["mobile"],
  chrome: ["browsers"],
  firefox: ["browsers"],
  edge: ["browsers"],
  network: ["network"],
  ai: [null],
};

/** And the readings the table has no platform for: where the STIG pages may put them. */
const pagesOnlyFor: Record<Exclude<KevReading, PlatformKey>, PlatformId[]> = {
  "microsoft-browser": ["browsers"],
  "microsoft-application": ["applications"],
  unix: ["linux"],
  application: ["applications"],
};

describe("one reading of a KEV entry's vendor and product", () => {
  it("gives the CVE table and the STIG pages what a person would read", () => {
    for (const [vendor, product, table, stig] of catalogue) {
      expect(kevPlatformKeys(vendor, product), `${vendor} | ${product}`).toEqual(table);
      expect(kevPlatform(vendor, product), `${vendor} | ${product}`).toBe(stig);
    }
  });

  it("holds the table and the STIG pages together: neither files an entry the other leaves out", () => {
    for (const [vendor, product] of catalogue) {
      const reading = kevReading(vendor, product);
      const table = kevPlatformKeys(vendor, product);
      const stig = kevPlatform(vendor, product);
      const label = `${vendor} | ${product}: ${reading}`;
      if (reading === null) {
        expect(table, label).toEqual([]);
        // VMware is the one arm the STIG pages have and the reading does not.
        expect(stig === null || (stig === "virtualization" && /^vmware$/i.test(vendor ?? "")), label).toBe(true);
      } else if (isPlatformKey(reading)) {
        expect(table, label).toEqual([reading]);
        expect(pagesFor[reading], label).toContain(stig);
      } else {
        expect(table, label).toEqual([]);
        expect(pagesOnlyFor[reading], label).toContain(stig);
      }
    }
  });

  it("files a network vendor the same way by CISA's name as by NVD's", () => {
    const names: [cisa: string, nvd: string][] = [
      ["Palo Alto Networks", "paloaltonetworks"],
      ["Check Point", "checkpoint"],
      ["Pulse Secure", "pulsesecure"],
      ["Array Networks ", "arraynetworks"],
      ["Barracuda Networks", "barracuda"],
      ["Juniper Networks", "juniper"],
      ["D-Link", "d-link"],
      ["TP-Link", "tp-link"],
      ["DrayTek", "draytek"],
      ["Ubiquiti", "ubiquiti"],
      ["Hewlett Packard Enterprise (HPE)", "hpe"],
      ["Aruba", "aruba"],
    ];
    for (const [cisa, nvd] of names) {
      const byCpe = platformsOf({ cpes: [`cpe:2.3:o:${nvd}:firmware:*:*:*:*:*:*:*:*`], vendors: [], products: [], description: null });
      expect(byCpe, nvd).toEqual(["network"]);
      expect(kevPlatformKeys(cisa, "Firmware"), cisa).toEqual(byCpe);
      expect(kevPlatform(cisa, "Firmware"), cisa).toBe("network");
    }
  });

  it("does not take Windows' Internet Key Exchange for Exchange Server", () => {
    expect(microsoftServers.test("Internet Key Exchange (IKE) Service Extensions")).toBe(false);
    expect(microsoftServers.test("Exchange Server")).toBe(true);
    expect(microsoftServers.test("Exchange")).toBe(true);
    expect(microsoftServers.test("exchange server")).toBe(true);
  });

  it("re-reads the KEV-only rows a start after migration 0060, and leaves NVD's rows alone", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const at = "2026-11-16T10:00:00.000Z";
    applyKev(
      db,
      [
        { cveId: "CVE-2023-1389", dateAdded: "2023-05-01", dueDate: "2023-05-22", ransomware: false, description: "TP-Link Archer AX21 command injection.", vendor: "TP-Link", product: "Archer AX21" },
        { cveId: "CVE-2015-3245", dateAdded: "2022-03-25", dueDate: "2022-04-15", ransomware: false, description: "Red Hat libuser.", vendor: "Red Hat", product: "Libuser" },
        { cveId: "CVE-2024-38145", dateAdded: "2024-09-10", dueDate: "2024-10-01", ransomware: false, description: "IKE.", vendor: "Microsoft", product: "Internet Key Exchange (IKE) Service Extensions" },
      ],
      at,
    );
    // What the older reading stored for them, and an NVD row whose platforms are its own.
    db.prepare("UPDATE vulns SET platforms_json = '[]' WHERE vuln_status = 'KEV only'").run();
    db.prepare("UPDATE vulns SET source_identifier = 'secure@microsoft.com', vuln_status = 'Analyzed', platforms_json = '[\"windows\"]' WHERE cve_id = 'CVE-2024-38145'").run();
    applyKev(db, [{ cveId: "CVE-2024-0001", dateAdded: "2024-01-02", dueDate: null, ransomware: false, description: "x", vendor: "DrayTek", product: "Vigor Routers" }], at);
    db.prepare("UPDATE vulns SET platforms_json = '[]' WHERE cve_id = 'CVE-2024-0001'").run();

    db.exec(readFileSync(path.join(import.meta.dirname, "..", "src", "migrations", "0060_kev_platforms_again.sql"), "utf8"));
    expect(recomputePlatforms(db).sort()).toEqual(["CVE-2015-3245", "CVE-2023-1389", "CVE-2024-0001"]);
    expect(getVuln(db, "CVE-2023-1389")?.platforms_json).toBe('["network"]');
    expect(getVuln(db, "CVE-2015-3245")?.platforms_json).toBe('["linux"]');
    expect(getVuln(db, "CVE-2024-0001")?.platforms_json).toBe('["network"]');
    expect(getVuln(db, "CVE-2024-38145")?.platforms_json).toBe('["windows"]');
    const indexed = db.prepare("SELECT v.cve_id, p.platform FROM vuln_platforms p JOIN vulns v ON v.id = p.vuln_id ORDER BY v.cve_id").all();
    expect(indexed).toEqual([
      { cve_id: "CVE-2015-3245", platform: "linux" },
      { cve_id: "CVE-2023-1389", platform: "network" },
      { cve_id: "CVE-2024-0001", platform: "network" },
      { cve_id: "CVE-2024-38145", platform: "windows" },
    ]);
    db.close();
  });
});
