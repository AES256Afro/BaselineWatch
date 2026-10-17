import { zipSync } from "fflate";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { packageTarget, type DisaListingItem } from "../src/adapters/disa.ts";
import { disaGpoAdapter, gpoPackageKey, parseChecklist, parseGpoPackage } from "../src/adapters/disa-gpo.ts";
import { disaIntuneAdapter, intunePackageKey, normalizePolicy, parseIntunePackage, policyFamily, valueText } from "../src/adapters/disa-intune.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { listDocuments, loadRequirements } from "../src/register.ts";
import { unzipAll } from "../src/zip.ts";
import { fakeHttp, fixture } from "./helpers.ts";

const text = (name: string) => new TextDecoder().decode(fixture(name));
const listing = (): DisaListingItem[] => (JSON.parse(text("disa-listing.json")) as { returnValue: DisaListingItem[] }).returnValue;

describe("DISA Intune policy package", () => {
  it("turns a settings-catalog export into one requirement per setting with a readable value", () => {
    const { name, requirements } = normalizePolicy(text("disa-intune/DoD Windows 11 STIG v2r11 Settings Catalog.json"));
    expect(name).toBe("DoD Windows 11 STIG v2r11 Settings Catalog");
    expect(requirements).toHaveLength(13);
    const smb = requirements.find((r) => r.label === "device_vendor_msft_policy_config_mssecurityguide_configuresmbv1server")!;
    expect(smb.ref).toBe("dod-windows-11-stig-settings-catalog|device_vendor_msft_policy_config_mssecurityguide_configuresmbv1server");
    expect(smb.family).toBe("DoD Windows 11 STIG Settings Catalog");
    expect(smb.statement).toBe("0");
    expect(smb.extra).toMatchObject({ policy: "DoD Windows 11 STIG v2r11 Settings Catalog", policyVersion: "v2r11", platforms: "windows10", scope: "device", instance: "ChoiceSettingInstance" });
    const client = requirements.find((r) => r.label.endsWith("configuresmbv1clientdriver"))!;
    expect(client.statement).toBe("1; pol_secguide_smb1clientdriver = 4");
    expect(requirements.find((r) => r.label.endsWith("renameadministratoraccount"))!.statement).toBe("X_Admin");
    expect(requirements.find((r) => r.label.endsWith("systemdrivesminimumpinlength"))!.statement).toBe("1; minpinlength = 6");
    expect(requirements.find((r) => r.label.endsWith("minimumpasswordage"))!.statement).toBe("1");
    expect(policyFamily("DoD WinSvr 2025 MS STIG v1r4")).toEqual({ family: "DoD WinSvr 2025 MS STIG", version: "v1r4" });
    expect(valueText({ settingDefinitionId: "x", simpleSettingCollectionValue: [{ value: "a" }, { value: "b" }] })).toBe("a; b");
    expect(() => normalizePolicy("{}")).toThrow(/not a settings-catalog policy/);
  });

  it("names the package in the listing and reads every settings-catalog file in the zip", () => {
    const target = packageTarget(listing(), intunePackageKey, /^Intune Policy - (.+)$/i);
    expect(target).toMatchObject({ key: "intune:package", versionLabel: "October 2026", publishedAt: "2026-10-16T00:00:00.000Z" });
    expect(target!.url).toMatch(/U_Intune_Policy_Package_October_2026\.zip$/);
    const zip = zipSync({
      "Intune Policies/Settings Catalog/DoD Windows 11 STIG v2r11 Settings Catalog.json": fixture("disa-intune/DoD Windows 11 STIG v2r11 Settings Catalog.json"),
      "Intune Policies/Settings Catalog/Assignments/DoD Windows 11 STIG v2r11 Settings Catalog.json": new TextEncoder().encode("[]"),
      "Intune Policies/Device Configurations/DoD Microsoft Edge STIG 2vr5 - macOS.json": new TextEncoder().encode("{}"),
      "ReadMe.txt": new TextEncoder().encode("WARNING"),
    });
    const parsed = parseIntunePackage(unzipAll(new Uint8Array(zip)));
    expect(parsed.policies).toEqual(["DoD Windows 11 STIG v2r11 Settings Catalog"]);
    expect(parsed.requirements).toHaveLength(13);
    expect(() => parseIntunePackage(unzipAll(new Uint8Array(zipSync({ "ReadMe.txt": new Uint8Array([1]) }))))).toThrow(/no settings-catalog policy/);
  });
});

describe("DISA GPO package checklists", () => {
  it("reads each rule's verdict and DISA's comment", () => {
    const parsed = parseChecklist(text("disa-gpo/DoD Windows 11 STIG v2r11.ckl"));
    expect(parsed.stigId).toBe("Microsoft_Windows_11_STIG");
    expect(parsed.vulns).toHaveLength(7);
    const smb = parsed.vulns.find((v) => v.ruleVer === "WN11-00-000165")!;
    expect(smb).toMatchObject({ vulnNum: "V-253287", severity: "medium", status: "NotAFinding", comments: "GPO - DoD Windows 11 Computer STIG v2r11 Intune - DoD Windows 11 STIG v2r11 Settings Catalog" });
    expect(smb.ruleTitle).toBe("The Server Message Block (SMB) v1 protocol must be disabled on the SMB server.");
    const bitlocker = parsed.vulns.find((v) => v.ruleVer === "WN11-00-000030")!;
    expect(bitlocker).toMatchObject({ status: "Not_Applicable", comments: "Outside scope of GPO configurations" });
    const pkg = parseGpoPackage(unzipAll(new Uint8Array(zipSync({ "Support Files/Checklist Files/DoD Windows 11 STIG v2r11.ckl": fixture("disa-gpo/DoD Windows 11 STIG v2r11.ckl"), "ReadMe.txt": new Uint8Array([1]) }))));
    expect(pkg.checklists).toEqual(["DoD Windows 11 STIG v2r11"]);
    const row = pkg.requirements.find((r) => r.label === "WN11-00-000030")!;
    expect(row.ref).toBe("dod-windows-11-stig|v-253259");
    expect(row.family).toBe("DoD Windows 11 STIG");
    expect(row.statement).toBe("Not applicable to the policy. Outside scope of GPO configurations");
    expect(row.extra).toMatchObject({ checklist: "DoD Windows 11 STIG v2r11", checklistVersion: "v2r11", stigId: "Microsoft_Windows_11_STIG", status: "Not_Applicable", vulnNum: "V-253259" });
    expect(pkg.requirements.find((r) => r.label === "WN11-00-000165")!.statement).toMatch(/^Covered by DISA's policy\. GPO - DoD Windows 11 Computer STIG v2r11/);
  });
});

describe("DISA package adapters end to end", () => {
  let db: ReturnType<typeof openDatabase>;
  let dataDir = "";
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-disa-pkg-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("loads both packages through the listing and skips them while the listing's dates stand", async () => {
    const listingUrl = getSource(db, "disa-stigs")!.url;
    const intuneUrl = packageTarget(listing(), intunePackageKey, /^Intune Policy - (.+)$/i)!.url;
    const gpoUrl = packageTarget(listing(), gpoPackageKey, /^Group Policy Objects \(GPOs\) - (.+)$/i)!.url;
    const http = fakeHttp({
      [listingUrl]: { bytes: fixture("disa-listing.json") },
      [intuneUrl]: { bytes: new Uint8Array(zipSync({ "Intune Policies/Settings Catalog/DoD Windows 11 STIG v2r11 Settings Catalog.json": fixture("disa-intune/DoD Windows 11 STIG v2r11 Settings Catalog.json") })) },
      [gpoUrl]: { bytes: new Uint8Array(zipSync({ "Support Files/Checklist Files/DoD Windows 11 STIG v2r11.ckl": fixture("disa-gpo/DoD Windows 11 STIG v2r11.ckl") })) },
    });
    const at = new Date("2026-10-17T10:00:00Z");
    const intune = await ingestSource(db, dataDir, getSource(db, "disa-intune")!, { http, now: () => at });
    expect(intune.status).toBe("ok");
    expect(intune.detail).toContain("intune:package October 2026: first version, 13 requirements");
    const gpo = await ingestSource(db, dataDir, getSource(db, "disa-gpo")!, { http, now: () => at });
    expect(gpo.status).toBe("ok");
    expect(gpo.detail).toContain("gpo:checklists October 2026: first version, 7 requirements");
    expect(listDocuments(db, "disa-intune")[0]).toMatchObject({ version_label: "October 2026", published_at: "2026-10-16T00:00:00.000Z", title: "DISA STIG Intune Policy Package, October 2026" });
    expect(loadRequirements(db, listDocuments(db, "disa-gpo")[0]!.id).map((r) => r.label)).toContain("WN11-SO-000070");

    const calls = http.calls.length;
    expect((await ingestSource(db, dataDir, getSource(db, "disa-intune")!, { http, now: () => new Date("2026-10-18T10:00:00Z") })).status).toBe("unchanged");
    expect((await ingestSource(db, dataDir, getSource(db, "disa-gpo")!, { http, now: () => new Date("2026-10-18T10:00:00Z") })).status).toBe("unchanged");
    expect(http.calls.length).toBe(calls + 2); // one listing call each, no zips
    expect(disaIntuneAdapter.id).toBe("disa-intune");
    expect(disaGpoAdapter.id).toBe("disa-gpo");
  });
});
