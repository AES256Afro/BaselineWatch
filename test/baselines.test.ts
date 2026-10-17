import { zipSync } from "fflate";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { cciListUrl } from "../src/adapters/cci.ts";
import { packageTarget, type DisaListingItem } from "../src/adapters/disa.ts";
import { gpoPackageKey } from "../src/adapters/disa-gpo.ts";
import { intunePackageKey } from "../src/adapters/disa-intune.ts";
import { branchCommitUrl, branchZipUrl } from "../src/adapters/mscp.ts";
import { nistBaselinesAdapter, nistCatalogAdapter } from "../src/adapters/oscal-nist.ts";
import { parseSctListing } from "../src/adapters/sct.ts";
import { buildProfile, defaultMscp, defaultSct, gpoPathFromFix, matchIntune, registryFromCheck, registryKey } from "../src/baselines.ts";
import { exportProfile } from "../src/exports.ts";
import { getSource, ingestDocumentTarget, ingestSource } from "../src/ingest.ts";
import { latestDocument } from "../src/register.ts";
import { fakeHttp, fixture, formPost, startTestApp, type TestApp } from "./helpers.ts";
import { mscpZip } from "./mscp.test.ts";

const text = (name: string) => new TextDecoder().decode(fixture(name));

describe("Windows rule parsing", () => {
  it("reads the registry values a check names and the Group Policy path a fix names", () => {
    const check = "If the following registry value does not exist or is not configured as specified, this is a finding: Registry Hive: HKEY_LOCAL_MACHINE Registry Path: \\SOFTWARE\\Policies\\Microsoft\\FVE\\ Value Name: UseAdvancedStartup Type: REG_DWORD Value: 0x00000001 (1) If one of the following registry values does not exist or is not configured as specified, this is a finding. Registry Hive: HKEY_LOCAL_MACHINE Registry Path: \\SOFTWARE\\Policies\\Microsoft\\FVE\\ Value Name: UseTPMPIN Type: REG_DWORD Value: 0x00000001 (1) Value Name: UseTPMKeyPIN Type: REG_DWORD Value: 0x00000001 (1)";
    const registry = registryFromCheck(check);
    expect(registry).toHaveLength(3);
    expect(registry[0]).toEqual({ hive: "HKEY_LOCAL_MACHINE", key: "SOFTWARE\\Policies\\Microsoft\\FVE", value: "UseAdvancedStartup", type: "REG_DWORD", data: "0x00000001 (1)" });
    expect(registry[2]!.value).toBe("UseTPMKeyPIN");
    expect(registryKey("HKEY_LOCAL_MACHINE", "\\SOFTWARE\\Policies\\Microsoft\\FVE\\", "UseTPMPIN")).toBe("hklm\\software\\policies\\microsoft\\fve\\usetpmpin");
    expect(registryKey("HKLM", "Software\\Policies\\Microsoft\\FVE", "UseTPMPIN")).toBe("hklm\\software\\policies\\microsoft\\fve\\usetpmpin");
    const fix = 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "Enable Structured Exception Handling Overwrite Protection (SEHOP)" to "Enabled".';
    expect(gpoPathFromFix(fix)).toEqual({ path: "Computer Configuration >> Administrative Templates >> MS Security Guide", setting: "Enable Structured Exception Handling Overwrite Protection (SEHOP)" });
    expect(gpoPathFromFix("Use Windows 11 Enterprise 64-bit version.")).toBeNull();
    expect(registryFromCheck(null)).toEqual([]);
  });

  it("matches a rule to DISA's settings-catalog definition by the policy's name", () => {
    const settings = [
      { label: "device_vendor_msft_policy_config_mssecurityguide_enablestructuredexceptionhandlingoverwriteprotection", statement: "1", extra: { policy: "DoD Windows 11 STIG v2r11 Settings Catalog" } },
      { label: "device_vendor_msft_policy_config_localpoliciessecurityoptions_accounts_renameadministratoraccount", statement: "X_Admin", extra: { policy: "DoD Windows 11 STIG v2r11 Settings Catalog" } },
      { label: "device_vendor_msft_policy_config_mssecurityguide_configuresmbv1server", statement: "0", extra: { policy: "p" } },
    ].map((s) => ({ ref: s.label, parentRef: null, family: null, label: s.label, title: s.label, statement: s.statement, guidance: null, params: [], related: [], sortKey: s.label, status: "active" as const, extra: s.extra }));
    expect(matchIntune({ gpoPath: { setting: "Enable Structured Exception Handling Overwrite Protection (SEHOP)" }, registry: [] }, settings)).toEqual([{ definitionId: settings[0]!.label, value: "1", policy: "DoD Windows 11 STIG v2r11 Settings Catalog" }]);
    expect(matchIntune({ gpoPath: { setting: "Accounts: Rename administrator account" }, registry: [] }, settings).map((s) => s.definitionId)).toEqual([settings[1]!.label]);
    expect(matchIntune({ gpoPath: { setting: "Configure SMBv1 Server" }, registry: [] }, settings).map((s) => s.value)).toEqual(["0"]);
    expect(matchIntune({ gpoPath: { setting: "Something else" }, registry: [] }, settings)).toEqual([]);
    expect(matchIntune({ gpoPath: null, registry: [{ hive: "HKEY_LOCAL_MACHINE", key: "x", value: "SMB1", type: null, data: null }] }, settings)).toEqual([]);
    const revised = { ...settings[0]!, label: "device_vendor_msft_policy_config_localpoliciessecurityoptions_interactivelogon_machineinactivitylimit_v2", statement: "900" };
    expect(matchIntune({ gpoPath: { setting: "Interactive logon: Machine inactivity limit" }, registry: [] }, [revised]).map((s) => s.value)).toEqual(["900"]);
  });
});

describe("the baseline builder", () => {
  let app: TestApp;
  const at = new Date("2026-10-17T10:00:00Z");
  const listing = (): DisaListingItem[] => (JSON.parse(text("disa-listing.json")) as { returnValue: DisaListingItem[] }).returnValue;
  const linkFor = (re: RegExp) => listing().find((i) => re.test(i.FileName.split(String.fromCharCode(0x200b)).join("")))!.DownloadLink;
  let win11Doc = 0;

  beforeAll(async () => {
    app = await startTestApp({ now: () => at });
    const sha = "cf656e844a4091868b2eeb8e6405f8f83952d08f";
    const disa = getSource(app.db, "disa-stigs")!;
    const routes: Record<string, { bytes?: Uint8Array; text?: string }> = {
      [disa.url]: { bytes: fixture("disa-listing.json") },
      [linkFor(/Microsoft Windows 11 STIG - Ver/)]: { bytes: new Uint8Array(zipSync({ "U_MS_Windows_11_V2R11_Manual_STIG/U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml": fixture("stig-win11.xccdf.xml") })) },
      [linkFor(/Apple macOS 26 \(Tahoe\) STIG - Ver/)]: { bytes: new Uint8Array(zipSync({ "U_Apple_macOS_26_V1R4_Manual_STIG/U_Apple_macOS_26_V1R4_STIG_Manual-xccdf.xml": fixture("stig-macos.xccdf.xml") })) },
      // The Server 2025 fixture, retitled, stands in for a Linux STIG.
      [linkFor(/Red Hat Enterprise Linux 9 STIG - Ver/)]: { bytes: new Uint8Array(zipSync({ "U_RHEL_9_V2R10_Manual_STIG/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml": new TextEncoder().encode(text("stig.xccdf.xml").replace("Microsoft Windows Server 2025 Security Technical Implementation Guide", "Red Hat Enterprise Linux 9 Security Technical Implementation Guide")) })) },
      [cciListUrl]: { bytes: new Uint8Array(zipSync({ "CCI_List.xml": fixture("cci/CCI_List.xml") })) },
      [packageTarget(listing(), intunePackageKey, /^Intune Policy - (.+)$/i)!.url]: { bytes: new Uint8Array(zipSync({ "Intune Policies/Settings Catalog/DoD Windows 11 STIG v2r11 Settings Catalog.json": fixture("disa-intune/DoD Windows 11 STIG v2r11 Settings Catalog.json") })) },
      [packageTarget(listing(), gpoPackageKey, /^Group Policy Objects \(GPOs\) - (.+)$/i)!.url]: { bytes: new Uint8Array(zipSync({ "Support Files/Checklist Files/DoD Windows 11 STIG v2r11.ckl": fixture("disa-gpo/DoD Windows 11 STIG v2r11.ckl") })) },
      [branchCommitUrl("tahoe")]: { text: JSON.stringify({ sha, html_url: "https://github.com/usnistgov/macos_security/commit/x", commit: { message: "Tahoe fixes", committer: { date: "2026-06-25T13:21:01Z" } } }) },
      [branchZipUrl(sha)]: { bytes: mscpZip(`macos_security-${sha}`) },
      "https://www.microsoft.com/en-us/download/details.aspx?id=55319": { bytes: fixture("sct-listing.html") },
    };
    // Serve the PolicyRules fixture for every baseline zip the SCT listing fixture names.
    for (const file of parseSctListing(text("sct-listing.html"))) {
      routes[file.url] = { bytes: new Uint8Array(zipSync({ "Windows 11 v25H2 Security Baseline/Documentation/MSFT-Win11-v25H2.PolicyRules": fixture("sct.PolicyRules") })) };
    }
    const http = fakeHttp(routes);
    for (const name of ["Microsoft Windows 11", "Apple macOS 26", "Red Hat Enterprise Linux 9", "mscp: tahoe"]) {
      app.db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('baseline', ?, NULL, ?)").run(name, at.toISOString());
    }
    for (const id of ["disa-stigs", "disa-cci", "disa-intune", "disa-gpo", "nist-mscp", "microsoft-sct"]) {
      const result = await ingestSource(app.db, app.dataDir, getSource(app.db, id)!, { http, now: () => at });
      expect(result.status, `${id}: ${result.error ?? result.detail}`).toBe("ok");
    }
    const nist = getSource(app.db, "nist-sp-800-53")!;
    const nistHttp = fakeHttp({ [nistCatalogAdapter.history!(nist)[1]!.url]: { bytes: fixture("oscal-catalog-5.2.0.json") } });
    await ingestDocumentTarget(app.db, app.dataDir, nist, nistCatalogAdapter, nistCatalogAdapter.history!(nist)[1]!, { http: nistHttp, now: () => at });
    // The moderate profile fixture stands in for the High baseline.
    const b = getSource(app.db, "nist-sp-800-53b")!;
    const high = { key: "profile:high", url: "https://example.test/high.json" };
    await ingestDocumentTarget(app.db, app.dataDir, b, nistBaselinesAdapter, high, { http: fakeHttp({ [high.url]: { bytes: fixture("oscal-profile-moderate-5.2.0.json") } }), now: () => at });
    win11Doc = latestDocument(app.db, "disa-stigs", "stig:microsoft-windows-11")!.id;
  });

  afterAll(async () => {
    await app.close();
  });

  it("builds the Windows profile: CAT I and II rules joined to Microsoft's settings, DISA's Intune definitions and checklist, and the High controls", () => {
    const profile = buildProfile(app.db, { platform: "windows" });
    expect(profile.components.stig).toMatchObject({ key: "stig:microsoft-windows-11", documentId: win11Doc, version: "V2R11" });
    expect(profile.components.sct?.key).toMatch(/^baseline:windows-11/);
    expect(profile.components.intune?.label).toBe("DoD Windows 11 STIG Settings Catalog");
    expect(profile.components.checklist?.label).toBe("DoD Windows 11 STIG");
    expect(profile.components.controls?.key).toBe("profile:high");
    expect(profile.components.cciVersion).toBe("2026-07-14");
    const stig = profile.items.filter((i) => i.kind === "stig");
    expect(stig.map((i) => i.label).sort()).toEqual(["WN11-00-000030", "WN11-00-000031", "WN11-00-000150", "WN11-00-000165", "WN11-CC-000190", "WN11-SO-000070"]); // the CAT III rule is out
    const sehop = stig.find((i) => i.label === "WN11-00-000150")!;
    expect(sehop.severity).toBe("CAT I");
    expect(sehop.registry[0]).toMatchObject({ hive: "HKEY_LOCAL_MACHINE", key: "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel", value: "DisableExceptionChainValidation", type: "REG_DWORD" });
    expect(sehop.gpoPath?.setting).toBe("Enable Structured Exception Handling Overwrite Protection (SEHOP)");
    expect(sehop.intune).toEqual([{ definitionId: "device_vendor_msft_policy_config_mssecurityguide_enablestructuredexceptionhandlingoverwriteprotection", value: "1", policy: "DoD Windows 11 STIG v2r11 Settings Catalog" }]);
    expect(sehop.checklist).toMatchObject({ status: "NotAFinding", label: "Covered by DISA's policy" });
    const smb = stig.find((i) => i.label === "WN11-00-000165")!;
    expect(smb.intune.map((s) => `${s.definitionId}=${s.value}`)).toEqual(["device_vendor_msft_policy_config_mssecurityguide_configuresmbv1server=0"]);
    expect(smb.controls).toEqual(["cm-7"]);
    const bitlocker = stig.find((i) => i.label === "WN11-00-000030")!;
    expect(bitlocker.checklist).toMatchObject({ status: "Not_Applicable", comment: "Outside scope of GPO configurations" });
    const sct = profile.items.filter((i) => i.kind === "sct");
    expect(sct.length).toBe(10); // the PolicyRules fixture's settings, less the one the AutoPlay rule names by registry path
    expect(stig.find((i) => i.label === "WN11-CC-000190")?.sctValue).toBe("REG_DWORD = 255");
    expect(sct[0]!.section).toMatch(/^Microsoft baseline: /);
    const controls = profile.items.filter((i) => i.kind === "control");
    expect(controls.length).toBeGreaterThan(200);
    expect(controls.find((c) => c.label === "SC-28(1)")?.implementedBy).toEqual(["WN11-00-000030"]); // BitLocker cites CCI-002475, indexed to SC-28(1); CCI-002476 is not in the fixture list
    const cm7 = controls.find((c) => c.controls[0] === "cm-7");
    expect(cm7?.implementedBy).toContain("WN11-00-000165");
    expect(profile.counts.included).toBe(profile.items.length);
    expect(profile.next).toEqual([]);
  });

  it("builds the macOS profile with mSCP joined by STIG id, and the Linux profile from the STIG alone", () => {
    const mac = buildProfile(app.db, { platform: "macos" });
    expect(mac.components.mscp?.key).toBe("mscp:tahoe");
    expect(defaultMscp("stig:apple-macos-15-sequoia", mac.choices.mscps)).toBeNull();
    const fv = mac.items.find((i) => i.label === "APPL-26-005020")!;
    expect(fv.mscp?.id).toBe("system_settings_filevault_enforce");
    expect(fv.mscp?.payloads).toEqual([{ domain: "com.apple.MCX", keys: { dontAllowFDEDisable: true } }]);
    expect(fv.controls).toEqual(["sc-28", "sc-28.1"]);
    const gatekeeper = mac.items.find((i) => i.label === "APPL-26-002064")!;
    expect(gatekeeper.mscp?.id).toBe("os_gatekeeper_enable");
    expect(gatekeeper.controls).toEqual(expect.arrayContaining(["cm-14", "cm-5", "si-3", "si-7.1"]));
    const adds = mac.items.filter((i) => i.kind === "mscp");
    expect(adds.map((i) => i.label).sort()).toEqual(["os_sip_enable", "pwpolicy_minimum_length_enforce"]); // no STIG id in the five-rule fixture; the supplemental is not a setting
    expect(adds.every((i) => i.section.startsWith("mSCP adds: "))).toBe(true);
    const linux = buildProfile(app.db, { platform: "linux" });
    expect(linux.components.stig?.key).toBe("stig:red-hat-enterprise-linux-9");
    expect(linux.components.sct).toBeNull();
    expect(linux.items.filter((i) => i.kind === "stig")).toHaveLength(3);
    expect(linux.items.find((i) => i.label === "WN25-00-000001")?.fix).toMatch(/^Configure the operating system to use/);
    expect(defaultSct("stig:microsoft-windows-server-2025", mac.choices.scts)).toBeNull();
  });

  it("drops what is unticked, keeps the drops through a redraw, and exports in every format and flavour", async () => {
    const base = app.base;
    const page = await (await fetch(`${base}/baselines/windows`)).text();
    expect(page).toContain("Windows <span class=\"arrow\">strictest published profile</span>");
    expect(page).toContain('name="keep" value="stig:v-253287" checked');
    expect(page).toContain("Intune: 1 definition");
    expect(page).toContain("DISA: Not applicable to the policy");
    expect(page).toContain("Microsoft's baseline adds");
    expect(page).toContain("SP 800-53 High baseline controls");
    expect(page).toContain('aria-current="page">Baselines</a>');

    // The form sends only what is kept; the SMBv1 rule and one control are unticked.
    const all = buildProfile(app.db, { platform: "windows" }).items.map((i) => i.id);
    const kept = all.filter((id) => id !== "stig:v-253287" && id !== "control:cm-7");
    const fields: Record<string, string> = { applied: "1", stig: `stig:microsoft-windows-11@${win11Doc}`, flavour: "intune" };
    const body = new URLSearchParams(fields);
    for (const id of kept) body.append("keep", id);
    const redrawn = await fetch(`${base}/baselines/windows`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: base, "sec-fetch-site": "same-origin" }, body: body.toString() });
    expect(redrawn.status).toBe(200);
    const html = await redrawn.text();
    expect(html).toContain('name="keep" value="stig:v-253287" >');
    expect(html).toContain('name="keep" value="stig:v-253284" checked');
    expect(html).toContain("(2 dropped)");
    expect(html).toContain('<option value="intune" selected>');

    // Exports answer to the same fields, and to a GET with drop= for scripts.
    body.set("format", "csv");
    const csv = await fetch(`${base}/baselines/windows/export`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: base, "sec-fetch-site": "same-origin" }, body: body.toString() });
    expect(csv.headers.get("content-type")).toMatch(/text\/csv/);
    expect(csv.headers.get("content-disposition")).toMatch(/baselinewatch-windows-microsoft-windows-11-v2r11-intune\.csv/);
    const csvText = await csv.text();
    expect(csvText.split("\r\n")[0]).toMatch(/^section,kind,id,severity,title,controls/);
    expect(csvText).not.toContain("WN11-00-000165");
    expect(csvText).toContain("WN11-00-000150");
    expect(csvText).toContain("device_vendor_msft_policy_config_mssecurityguide_enablestructuredexceptionhandlingoverwriteprotection = 1");
    const json = await (await fetch(`${base}/baselines/windows/export?format=json&flavour=intune&drop=stig:v-253287`)).json() as { items: { label: string; apply: { label: string; text: string }[] }[]; dropped: string[]; attribution: string[]; flavour: string };
    expect(json.flavour).toBe("intune");
    expect(json.dropped).toEqual(["stig:v-253287"]);
    expect(json.items.some((i) => i.label === "WN11-00-000165")).toBe(false);
    const sehop = json.items.find((i) => i.label === "WN11-00-000150")!;
    expect(sehop.apply.map((a) => a.label)).toEqual(expect.arrayContaining(["Settings catalog (DISA's policy)", "Group Policy path", "Registry", "DISA checklist"]));
    expect(json.attribution.join(" ")).toContain("No CIS Benchmark text is included");
    const md = await (await fetch(`${base}/baselines/macos/export?format=md&flavour=jamf`)).text();
    expect(md).toContain("# macOS strictest published profile: Apple macOS 26 (Tahoe) V1R4");
    expect(md).toContain("- mSCP rule: system_settings_filevault_enforce");
    expect(md).toContain('- Profile payload: com.apple.MCX: {"dontAllowFDEDisable":true}');
    expect(md).toContain("## Attribution");
    const printable = await fetch(`${base}/baselines/linux/export?format=html&flavour=linux`);
    expect(printable.headers.get("content-type")).toMatch(/text\/html/);
    const printableText = await printable.text();
    expect(printableText).toContain("<title>Linux strictest published profile: Red Hat Enterprise Linux 9 V2R10</title>");
    expect(printableText).toContain("<dt>Fix</dt>");
    expect(printableText).not.toMatch(/<script/i);
    const direct = exportProfile(buildProfile(app.db, { platform: "linux" }), "md", "linux", { baseUrl: "https://example.test", generatedAt: at.toISOString(), version: "0.20.0" });
    expect(direct.filename).toBe("baselinewatch-linux-red-hat-enterprise-linux-9-v2r10-linux.md");
    expect(direct.body).toContain("Configure the operating system to use");
    expect((await formPost(base, "/baselines/amiga", { applied: "1" })).status).toBe(404);
  });

  it("shows current versus next when a newer STIG version is loaded", async () => {
    // A V2R12 of Windows 11 with one rule raised to CAT I and one removed.
    const next = text("stig-win11.xccdf.xml").replace("WN11-00-000085", "WN11-00-000086").replace('<Group id="V-253272"', '<Group id="V-253273"').replace("Release: 11", "Release: 12").replace('severity="medium"', 'severity="high"');
    const disa = getSource(app.db, "disa-stigs")!;
    const adapter = (await import("../src/adapters/disa.ts")).disaAdapter;
    await ingestDocumentTarget(app.db, app.dataDir, disa, adapter, { key: "stig:microsoft-windows-11", url: "https://example.test/win11-v2r12.zip", versionLabel: "V2R12", publishedAt: "2026-12-01T00:00:00.000Z" }, {
      http: fakeHttp({ "https://example.test/win11-v2r12.zip": { bytes: new Uint8Array(zipSync({ "x/U_MS_Windows_11_STIG_V2R12_Manual-xccdf.xml": new TextEncoder().encode(next) })) } }),
      now: () => at,
    });
    const profile = buildProfile(app.db, { platform: "windows", stig: `stig:microsoft-windows-11@${win11Doc}` });
    expect(profile.components.stig?.version).toBe("V2R11");
    expect(profile.next).toHaveLength(1);
    const cmp = profile.next[0]!;
    expect(cmp.component).toBe("stig");
    expect(cmp.next.version).toBe("V2R12");
    expect(cmp.added.map((a) => a.label)).toEqual([]);
    expect(cmp.removed).toEqual([]);
    expect(cmp.changed.map((c) => `${c.label}: ${c.what}`)).toContain("WN11-00-000165: CAT II → CAT I");
    const html = await (await fetch(`${app.base}/baselines/windows?stig=stig%3Amicrosoft-windows-11%40${win11Doc}`)).text();
    expect(html).toContain("STIG: current versus next");
    expect(html).toContain("CAT II → CAT I");
    // Without a choice the builder starts from the newest version, which has nothing newer.
    expect(buildProfile(app.db, { platform: "windows" }).components.stig?.version).toBe("V2R12");
  });
});
