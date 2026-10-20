import { zipSync } from "fflate";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { cciListUrl } from "../src/adapters/cci.ts";
import type { DisaListingItem } from "../src/adapters/disa.ts";
import { nistCatalogAdapter } from "../src/adapters/oscal-nist.ts";
import { getSource, ingestDocumentTarget, ingestSource } from "../src/ingest.ts";
import { latestDocument } from "../src/register.ts";
import { compareControlRefs, controlLabel, directivePlatforms, kevPlatform, platformOf, productOf, stigRulesForControl, cciMap } from "../src/stigs.ts";
import { fakeHttp, fixture, startTestApp, type TestApp } from "./helpers.ts";

const text = (name: string) => new TextDecoder().decode(fixture(name));

describe("platforms", () => {
  it("files a STIG under the page a person would look for it on", () => {
    expect(platformOf("Microsoft Windows 11")).toBe("windows");
    expect(platformOf("Microsoft Windows Server 2025")).toBe("windows");
    expect(platformOf("Active Directory Domain")).toBe("windows");
    expect(platformOf("Microsoft Windows Defender Firewall with Advanced Security")).toBe("windows");
    expect(platformOf("Microsoft Edge")).toBe("browsers");
    expect(platformOf("Google Chrome")).toBe("browsers");
    expect(platformOf("Mozilla Firefox")).toBe("browsers");
    expect(platformOf("Apple macOS 26 (Tahoe)")).toBe("macos");
    expect(platformOf("Apple iOS/iPadOS 18")).toBe("mobile");
    expect(platformOf("Red Hat Enterprise Linux 9")).toBe("linux");
    expect(platformOf("Canonical Ubuntu 24.04 LTS")).toBe("linux");
    expect(platformOf("Oracle Linux 9")).toBe("linux");
    expect(platformOf("SUSE Linux Enterprise Server 15")).toBe("linux");
    expect(platformOf("Cisco IOS XE Router")).toBe("network");
    expect(platformOf("VMware vSphere 8.0")).toBe("virtualization");
    expect(platformOf("Application Security and Development")).toBe("applications");
    expect(platformOf("Microsoft Office 365 ProPlus")).toBe("applications");
  });

  it("reads CISA's vendor and product the way a person does", () => {
    expect(kevPlatform("Microsoft", "Windows")).toBe("windows");
    expect(kevPlatform("Microsoft", "Win32k")).toBe("windows");
    expect(kevPlatform("Microsoft", "SMBv1 server")).toBe("windows");
    expect(kevPlatform("Microsoft", "Edge")).toBe("browsers");
    expect(kevPlatform("Microsoft", "Internet Explorer")).toBe("browsers");
    expect(kevPlatform("Microsoft", "Exchange Server")).toBe("applications");
    expect(kevPlatform("Microsoft", "Office")).toBe("applications");
    expect(kevPlatform("Apple", "Multiple Products")).toBe("macos");
    expect(kevPlatform("Apple", "macOS")).toBe("macos");
    expect(kevPlatform("Apple", "iOS and iPadOS")).toBe("mobile");
    expect(kevPlatform("Linux", "Kernel")).toBe("linux");
    expect(kevPlatform("Red Hat", "Polkit")).toBe("linux");
    expect(kevPlatform("Red Hat", "JBoss")).toBe("applications");
    expect(kevPlatform("Cisco", "IOS and IOS XE Software")).toBe("network");
    expect(kevPlatform("F5", "BIG-IP")).toBe("network");
    expect(kevPlatform("Google", "Chromium V8")).toBe("browsers");
    expect(kevPlatform("Android", "Framework")).toBe("mobile");
    expect(kevPlatform("VMware", "ESXi")).toBe("virtualization");
    expect(kevPlatform("Ahsay", "AhsayCBS")).toBeNull();
    expect(kevPlatform(null, null)).toBeNull();
  });

  it("labels and sorts control refs the way the catalog prints them", () => {
    expect(controlLabel("ac-11")).toBe("AC-11");
    expect(controlLabel("ia-5.2")).toBe("IA-5(2)");
    expect(["si-2", "ac-11.1", "ac-2", "ac-11", "au-2"].sort(compareControlRefs)).toEqual(["ac-2", "ac-11", "ac-11.1", "au-2", "si-2"]);
    expect(productOf("Microsoft Windows Server 2025 Security Technical Implementation Guide", "stig:x")).toBe("Microsoft Windows Server 2025");
    expect(productOf(null, "stig:red-hat-enterprise-linux-9")).toBe("Red Hat Enterprise Linux 9");
    expect(directivePlatforms("Supplemental Direction ED 25-03: Core Dump and Hunt Instructions")).toEqual(["all"]);
  });
});

describe("STIG pages", () => {
  let app: TestApp;
  const at = new Date("2026-10-17T10:00:00Z");
  const listing = (): DisaListingItem[] => (JSON.parse(text("disa-listing.json")) as { returnValue: DisaListingItem[] }).returnValue;
  const linkFor = (re: RegExp) => listing().find((i) => re.test(i.FileName.split(String.fromCharCode(0x200b)).join("")))!.DownloadLink;
  let macDoc = 0;
  let ws25Doc = 0;
  let catalogDoc = 0;

  beforeAll(async () => {
    const macZip = zipSync({ "U_Apple_macOS_26_V1R4_Manual_STIG/U_Apple_macOS_26_V1R4_STIG_Manual-xccdf.xml": fixture("stig-macos.xccdf.xml") });
    const winZip = zipSync({ "U_MS_Windows_11_V2R11_Manual_STIG/U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml": fixture("stig-win11.xccdf.xml") });
    const ws25Zip = zipSync({ "U_MS_Windows_Server_2025_V1R4_Manual_STIG/U_MS_Windows_Server_2025_STIG_V1R4_Manual-xccdf.xml": fixture("stig.xccdf.xml") });
    const cciZip = zipSync({ "CCI_List.xml": fixture("cci/CCI_List.xml") });
    const routes: Record<string, { bytes: Uint8Array; contentType?: string }> = {
      [linkFor(/Apple macOS 26 \(Tahoe\) STIG - Ver/)]: { bytes: new Uint8Array(macZip) },
      [linkFor(/Microsoft Windows 11 STIG - Ver/)]: { bytes: new Uint8Array(winZip) },
      [linkFor(/Microsoft Windows Server 2025 STIG - Ver/)]: { bytes: new Uint8Array(ws25Zip) },
      [cciListUrl]: { bytes: new Uint8Array(cciZip) },
      "https://www.cisa.gov/news-events/directives/all": { bytes: fixture("cisa-directives/all-page0.html") },
      "https://www.cisa.gov/news-events/directives/all?page=1": { bytes: fixture("cisa-directives/all-page1.html") },
      "https://www.cisa.gov/news-events/directives/all?page=2": { bytes: fixture("cisa-directives/all-page2.html") },
    };
    app = await startTestApp({ now: () => at });
    const disa = getSource(app.db, "disa-stigs")!;
    routes[disa.url] = { bytes: fixture("disa-listing.json") };
    const http = fakeHttp(routes);
    for (const name of ["Apple macOS 26", "Microsoft Windows 11", "Microsoft Windows Server 2025"]) {
      app.db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('baseline', ?, NULL, ?)").run(name, at.toISOString());
    }
    expect((await ingestSource(app.db, app.dataDir, disa, { http, now: () => at })).status).toBe("ok");
    expect((await ingestSource(app.db, app.dataDir, getSource(app.db, "disa-cci")!, { http, now: () => at })).status).toBe("ok");
    expect((await ingestSource(app.db, app.dataDir, getSource(app.db, "cisa-directives")!, { http, now: () => at })).status).toBe("ok");
    // The SP 800-53 catalog fixture, so control links have a page to point at.
    const nist = getSource(app.db, "nist-sp-800-53")!;
    const nistHttp = fakeHttp({ [nistCatalogAdapter.history!(nist)[1]!.url]: { bytes: fixture("oscal-catalog-5.2.0.json") } });
    await ingestDocumentTarget(app.db, app.dataDir, nist, nistCatalogAdapter, nistCatalogAdapter.history!(nist)[1]!, { http: nistHttp, now: () => at });
    macDoc = latestDocument(app.db, "disa-stigs", "stig:apple-macos-26-tahoe")!.id;
    ws25Doc = latestDocument(app.db, "disa-stigs", "stig:microsoft-windows-server-2025")!.id;
    catalogDoc = latestDocument(app.db, "nist-sp-800-53", "catalog")!.id;
    // Two KEV entries, one per platform, as the KEV adapter stores them.
    const insert = app.db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, summary, published_at, fetched_at, signals_json) VALUES ('cisa-kev', 'kev', ?, ?, ?, NULL, ?, ?, ?)");
    insert.run("CVE-2026-81963", "Microsoft Windows: Microsoft Windows Link Following Vulnerability", "https://nvd.nist.gov/vuln/detail/CVE-2026-81963", "2026-09-08T00:00:00.000Z", at.toISOString(), JSON.stringify({ kev: true, vendor: "Microsoft", product: "Windows", dueDate: "2026-09-22" }));
    insert.run("CVE-2026-86950", "Apple Multiple Products: Apple Multiple Products Out-of-Bounds Write Vulnerability", "https://nvd.nist.gov/vuln/detail/CVE-2026-86950", "2026-09-29T00:00:00.000Z", at.toISOString(), JSON.stringify({ kev: true, vendor: "Apple", product: "Multiple Products", dueDate: "2026-10-13", ransomware: false }));
  });

  afterAll(async () => {
    await app.close();
  });

  it("lists the followed STIGs by platform with their CAT counts", async () => {
    const html = await (await fetch(`${app.base}/stigs`)).text();
    expect(html).toContain('<a href="/stigs/windows">Windows</a>');
    expect(html).toContain('<a href="/stigs/macos">macOS</a>');
    expect(html).toContain("Apple macOS 26 (Tahoe)");
    expect(html).toContain("Microsoft Windows 11");
    expect(html).toContain("V2R11");
    expect(html).toContain('CCI list</a>, version 2026-07-14 (<a href="/standards/disa-cci">19 identifiers</a>)');
    expect(html).not.toContain('<a href="/stigs/linux">Linux</a> <span class="count"');
    expect(html).toContain('aria-current="page">STIGs</a>');
    // Each platform's count and each CAT cell lead to the rules they count.
    expect(html).toContain('<a href="/stigs/windows">Windows</a> <span class="count"><a href="/stigs/windows">2 STIGs</a></span>');
    expect(html).toMatch(/<td class="n"><a href="\/stigs\/macos\?stig=stig%3A[^"&]+&amp;cat=1">\d+<\/a><\/td>/);
    expect(html).toContain('<li><a href="/stigs/linux">Linux</a><b><a href="/stigs/linux">0</a></b></li>');
    expect(html).toContain('<h2><a href="/watchlist">Follow another STIG</a></h2>');
  });

  it("draws one STIG's rules by CAT with check, fix and the controls each maps to", async () => {
    const html = await (await fetch(`${app.base}/stigs/macos`)).text();
    expect(html).toContain("<h1>macOS <span class=\"arrow\">STIGs</span></h1>");
    expect(html).toContain("APPL-26-005020");
    expect(html).toContain("The macOS system must enforce FileVault.");
    expect(html).toContain(`<a href="/standards/nist-sp-800-53/${catalogDoc}/sc-28">SC-28</a>`);
    expect(html).toContain(`<a href="/standards/nist-sp-800-53/${catalogDoc}/sc-28.1">SC-28(1)</a>`);
    expect(html).toContain("CCI-002476 not in the list");
    expect(html).toContain("<summary>Check</summary>");
    expect(html).toContain("<summary>Fix</summary>");
    expect(html).toContain("fdesetup status");
    // CAT I rules come first; the CAT filter keeps only one group; each group's heading is the filter for it.
    expect(html.indexOf("CAT I</a> <span")).toBeLessThan(html.indexOf("CAT II</a> <span"));
    expect(html).toMatch(/<h2><a href="\/stigs\/macos\?cat=1">CAT I<\/a> <span class="count"><a href="\/stigs\/macos\?cat=1">\d+<\/a><\/span><\/h2>/);
    expect(html).toContain('<a href="/standards/disa-stigs">1 STIG followed</a>');
    expect(html).toMatch(/<dt>Rules<\/dt><dd><a href="\/stigs\/macos">\d+<\/a>: <a href="\/stigs\/macos\?cat=1">\d+ CAT I<\/a>/);
    expect(html).toContain('<h3 class="small"><a href="/?kind=kev">Known exploited</a> <span class="count"><a href="/?kind=kev">1</a></span></h3>');
    expect(html).toMatch(/<h3 class="small"><a href="\/\?source=cisa-directives">Directives<\/a> <span class="count"><a href="\/\?source=cisa-directives">\d+<\/a><\/span><\/h3>/);
    const catOne = await (await fetch(`${app.base}/stigs/macos?cat=1`)).text();
    expect(catOne).toContain("APPL-26-002064"); // gatekeeper, high
    expect(catOne).not.toContain("APPL-26-000070"); // screen saver timeout, medium
    expect(catOne).toContain('href="/stigs/macos?cat=1"');
    // CISA's advice for the platform: Apple's KEV entry, not Microsoft's; the cross-cutting directive, not Cisco's.
    expect(html).toContain("CVE-2026-86950");
    expect(html).not.toContain("CVE-2026-81963");
    expect(html).toContain("BOD 26-04: Prioritizing Security Updates Based on Risk");
    expect(html).not.toContain("Cisco SD-WAN");
    expect(html).toContain("First version loaded");
  });

  it("switches STIG and platform, and answers 404 off the map", async () => {
    const windows = await (await fetch(`${app.base}/stigs/windows?stig=stig%3Amicrosoft-windows-11&cat=3`)).text();
    expect(windows).toContain("WN11-00-000085"); // the one CAT III rule in the fixture
    expect(windows).not.toContain("WN11-00-000031");
    expect(windows).toContain("CVE-2026-81963");
    expect(windows).not.toContain("CVE-2026-86950");
    expect(windows).toContain("ED 25-02: Mitigate Microsoft Exchange Vulnerability");
    expect(windows).toContain('<option value="stig:microsoft-windows-server-2025"');
    const network = await (await fetch(`${app.base}/stigs/network`)).text();
    expect(network).toContain("No Network devices STIG loaded.");
    expect(network).toContain("ED 26-03: Mitigate Vulnerabilities in Cisco SD-WAN Systems");
    expect((await fetch(`${app.base}/stigs/amiga`)).status).toBe(404);
  });

  it("joins both ways on the Register's pages", async () => {
    // A STIG rule's page names the controls it implements.
    const rule = await (await fetch(`${app.base}/standards/disa-stigs/${macDoc}/v-277166`)).text();
    expect(rule).toContain(`Maps to <a href="/standards/nist-sp-800-53/${catalogDoc}/sc-28">SC-28</a>`);
    expect(rule).toContain("via CCI-001199, CCI-002475, CCI-002476");
    // A control's page lists the followed rules whose CCIs index it.
    const control = await (await fetch(`${app.base}/standards/nist-sp-800-53/${catalogDoc}/si-2`)).text();
    expect(control).toContain("STIG rules that implement this control");
    expect(control).toContain(`<a href="/standards/disa-stigs/${ws25Doc}/v-277982"><b>WN25-00-000001</b></a>`);
    expect(control).toContain('<a href="/stigs/windows?stig=stig%3Amicrosoft-windows-server-2025">Microsoft Windows Server 2025</a>');
    const hits = stigRulesForControl(app.db, "si-2", cciMap(app.db));
    expect(hits).toHaveLength(1);
    expect(hits[0]!.rules.map((r) => r.label)).toEqual(["WN25-00-000001"]);
    const quiet = await (await fetch(`${app.base}/standards/nist-sp-800-53/${catalogDoc}/sa-24`)).text();
    expect(quiet).toContain("No followed STIG rule cites a CCI indexed to this control");
  });
});
