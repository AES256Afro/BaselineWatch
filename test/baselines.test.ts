import { zipSync } from "fflate";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildProfile, defaultMscp, defaultSct, gpoPathFromFix, matchIntune, registryFromCheck, registryKey, sectionOf } from "../src/baselines.ts";
import { exportProfile } from "../src/exports.ts";
import { getSource, ingestDocumentTarget } from "../src/ingest.ts";
import { loadBaselineFixtures } from "./baseline-fixtures.ts";
import { fakeHttp, fixture, formPost, startTestApp, type TestApp } from "./helpers.ts";

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
  let win11Doc = 0;

  beforeAll(async () => {
    app = await startTestApp({ now: () => at });
    ({ win11Doc } = await loadBaselineFixtures(app, at));
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
    // The first page is the CAT I section: the CAT II rules wait behind their own tab.
    const page = await (await fetch(`${base}/baselines/windows`)).text();
    expect(page).toContain("Windows <span class=\"arrow\">strictest published profile</span>");
    expect(page).toContain('name="shown" value="cat1"');
    expect(page).toContain('name="keep" value="stig:v-253284" checked');
    expect(page).not.toContain('name="keep" value="stig:v-253287"');
    expect(page).toContain("Intune: 1 definition");
    expect(page).toContain("DISA: Not applicable to the policy");
    expect(page).toContain('<button type="submit" name="section" value="cat2" class="" >STIG rules: CAT II <span class="count">2 of 2</span></button>');
    // The drawn section's heading is a plain link to itself, carrying the documents it was built from.
    expect(page).toMatch(/<h2><a href="\/baselines\/windows\?stig=stig%3Amicrosoft-windows-11%40\d+&amp;sct=[^"]+&amp;section=cat1">STIG rules: CAT I<\/a> <span class="count"><a href="[^"]+">\d+ kept<\/a><\/span><\/h2>/);
    expect(page).toContain('<h2><a href="/register">Built from</a></h2>');
    expect(page).toMatch(/<dt>Kept<\/dt><dd><a href="\/baselines\/windows\?[^"]+">\d+ of \d+<\/a>/);
    expect(page).toContain("Microsoft&#39;s baseline adds");
    expect(page).toContain("SP 800-53 High baseline controls");
    expect(page).toContain('aria-current="page"><b>Baselines</b>');
    const cat2 = await (await fetch(`${base}/baselines/windows?section=cat2`)).text();
    expect(cat2).toContain('name="shown" value="cat2"');
    expect(cat2).toContain('name="keep" value="stig:v-253287" checked');
    expect(cat2).not.toContain('name="keep" value="stig:v-253284"');

    // A form that sends every kept id (no `shown`) still works: the SMBv1 rule and one control are unticked.
    const all = buildProfile(app.db, { platform: "windows" }).items.map((i) => i.id);
    const kept = all.filter((id) => id !== "stig:v-253287" && id !== "control:cm-7");
    const fields: Record<string, string> = { applied: "1", stig: `stig:microsoft-windows-11@${win11Doc}`, flavour: "intune", section: "cat2" };
    const body = new URLSearchParams(fields);
    for (const id of kept) body.append("keep", id);
    const redrawn = await fetch(`${base}/baselines/windows`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: base, "sec-fetch-site": "same-origin" }, body: body.toString() });
    expect(redrawn.status).toBe(200);
    const html = await redrawn.text();
    expect(html).toContain('name="keep" value="stig:v-253287" >');
    expect(html).toContain('<input type="hidden" name="drop" value="control:cm-7">');
    expect(html).not.toContain('name="drop" value="stig:v-253284"');
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

  it("carries a drop made in one section through a redraw of another and into the export", async () => {
    const base = app.base;
    const all = buildProfile(app.db, { platform: "windows" }).items;
    const ids = (section: string) => all.filter((i) => sectionOf(i) === section).map((i) => i.id);
    const post = async (fields: Record<string, string>, keep: string[], drop: string[], path = "/baselines/windows") => {
      const body = new URLSearchParams(fields);
      for (const id of keep) body.append("keep", id);
      for (const id of drop) body.append("drop", id);
      const response = await fetch(`${base}${path}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: base, "sec-fetch-site": "same-origin" }, body: body.toString() });
      expect(response.status).toBe(200);
      return response;
    };
    const row = (html: string, id: string) => html.split('<li class="pitem').find((part) => part.includes(`value="${id}"`)) ?? "";

    // On the CAT II section, untick the SMBv1 rule and open the controls section: the drop rides along hidden.
    const controls = await (await post({ applied: "1", shown: "cat2", section: "controls" }, ids("cat2").filter((id) => id !== "stig:v-253287"), [])).text();
    expect(controls).toContain('name="shown" value="controls"');
    expect(controls).toContain('<input type="hidden" name="drop" value="stig:v-253287">');
    expect(controls).toContain("(1 dropped)");
    expect(controls).toContain('name="keep" value="control:cm-7" checked');
    expect(row(controls, "control:cm-7")).not.toContain("WN11-00-000165"); // the dropped rule no longer implements CM-7
    expect(controls).toContain('<button type="submit" name="section" value="cat2" class="" >STIG rules: CAT II <span class="count">1 of 2</span></button>');

    // On the controls section, untick CM-7 and go back to CAT II: both drops hold, each where it belongs.
    const cat2 = await (await post({ applied: "1", shown: "controls", section: "cat2" }, ids("controls").filter((id) => id !== "control:cm-7"), ["stig:v-253287"])).text();
    expect(cat2).toContain('name="shown" value="cat2"');
    expect(cat2).toContain('name="keep" value="stig:v-253287" >');
    expect(cat2).toContain('<input type="hidden" name="drop" value="control:cm-7">');
    expect(cat2).not.toContain('name="drop" value="stig:v-253287"'); // the shown section speaks through its checkboxes
    expect(cat2).toContain("(2 dropped)");

    // Rebuild redraws the same section with the same state.
    const rebuilt = await (await post({ applied: "1", shown: "cat2", action: "rebuild", flavour: "intune" }, ids("cat2").filter((id) => id !== "stig:v-253287"), ["control:cm-7"])).text();
    expect(rebuilt).toContain('name="shown" value="cat2"');
    expect(rebuilt).toContain('name="keep" value="stig:v-253287" >');
    expect(rebuilt).toContain("(2 dropped)");

    // An export from the CAT II section covers the whole profile: both drops reach it and the sections never drawn stay whole.
    const json = (await (await post({ applied: "1", shown: "cat2", format: "json", flavour: "intune" }, ids("cat2").filter((id) => id !== "stig:v-253287"), ["control:cm-7"], "/baselines/windows/export")).json()) as { dropped: string[]; items: { kind: string; label: string }[] };
    expect(json.dropped).toEqual(["stig:v-253287", "control:cm-7"]);
    expect(json.items.some((i) => i.label === "WN11-00-000165")).toBe(false);
    expect(json.items.some((i) => i.label === "CM-7")).toBe(false);
    expect(json.items.filter((i) => i.kind === "sct")).toHaveLength(10);
    expect(json.items.filter((i) => i.kind === "stig")).toHaveLength(5);

    // A carried drop for an id the profile no longer holds is forgotten.
    const stale = await (await post({ applied: "1", shown: "cat2", section: "cat1" }, ids("cat2"), ["stig:v-999999", "control:cm-7"])).text();
    expect(stale).toContain('<input type="hidden" name="drop" value="control:cm-7">');
    expect(stale).not.toContain("v-999999");
    expect(stale).toContain("(1 dropped)");

    // The GET export API is unchanged.
    const api = (await (await fetch(`${base}/baselines/windows/export?format=json&flavour=intune&drop=stig:v-253287&drop=control:cm-7`)).json()) as { dropped: string[] };
    expect(api.dropped).toEqual(["stig:v-253287", "control:cm-7"]);

    // The check and fix text is folded into each row only when asked for; the apply lines are always folded.
    const plain = await (await fetch(`${base}/baselines/windows?section=cat2`)).text();
    expect(plain).toContain("<details><summary>How to apply</summary><dl class=\"pitem-apply\">");
    expect(plain).not.toContain('<h4 class="small">Check</h4>');
    const withText = await (await fetch(`${base}/baselines/windows?section=cat2&text=1`)).text();
    expect(withText).toContain('name="text" value="1" checked');
    expect(withText).toContain("<summary>How to apply, check and fix</summary>");
    expect(withText).toContain('<h4 class="small">Check</h4>');
    const macos = await (await fetch(`${base}/baselines/macos?section=mscp`)).text();
    expect(macos).toMatch(/<h2><a href="\/baselines\/macos\?stig=[^"]+&amp;mscp=[^"]+&amp;section=mscp">mSCP adds<\/a> <span class="count"><a href="[^"]+">2 kept<\/a><\/span><\/h2>/);
    expect(macos).toContain('name="keep" value="mscp:');
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
