import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { areaOf, buildTestPlan, exportPlan, loadTemplates, templatesDir } from "../src/testplans.ts";
import { loadBaselineFixtures } from "./baseline-fixtures.ts";
import { startTestApp, type TestApp } from "./helpers.ts";

describe("areas", () => {
  it("files a check by the words in its title, then its procedure", () => {
    expect(areaOf({ title: "Windows 11 systems must use a BitLocker PIN for pre-boot authentication.", check: null })).toBe("encryption");
    expect(areaOf({ title: "The macOS system must enforce FileVault.", check: null })).toBe("encryption");
    expect(areaOf({ title: "The machine inactivity limit must be set to 15 minutes, locking the system with the screen saver.", check: null })).toBe("authentication");
    expect(areaOf({ title: "The macOS system must enforce smart card authentication.", check: null })).toBe("authentication");
    expect(areaOf({ title: "The Server Message Block (SMB) v1 protocol must be disabled on the SMB server.", check: null })).toBe("network");
    expect(areaOf({ title: "Windows Server 2025 must install security-relevant software updates within 30 days.", check: null })).toBe("updates");
    expect(areaOf({ title: "The audit log must be configured to retain records.", check: null })).toBe("logging");
    expect(areaOf({ title: "Microsoft Edge must be configured to block pop-ups.", check: null })).toBe("browsers");
    expect(areaOf({ title: "The macOS system must be enrolled in MDM.", check: null })).toBe("mdm");
    expect(areaOf({ title: "Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.", check: null })).toBe("other");
    expect(areaOf({ title: "The system must be configured properly.", check: "Run cryptsetup luksDump on each volume." })).toBe("encryption");
  });

  it("reads the repository's templates and reports a broken one without failing", () => {
    const { templates, errors } = loadTemplates(templatesDir);
    expect(errors).toEqual([]);
    expect(templates.map((t) => t.id)).toEqual([
      "bitlocker-escrow",
      "collaboration-samsung-displays",
      "collaboration-teams-rooms",
      "conditional-access",
      "entra-join-hello-windows",
      "entra-sso-mobile",
      "filevault-escrow",
      "firewall-macos",
      "hardware-root-android",
      "hardware-root-ios",
      "hardware-root-linux",
      "hardware-root-macos",
      "hardware-root-windows",
      "ipados-shared-ipad",
      "luks-escrow",
      "macos-release-checks",
      "mdm-enrolment",
      "platform-sso-entra-macos",
      "smartcard-macos",
      "ssh-macos",
      "sso-intune-browsers",
      "sso-jamf-browsers",
      "sso-jamf-connect",
      "sso-kerberos-extension",
      "windows-feature-update",
    ]);
    const jamf = templates.find((t) => t.id === "sso-jamf-browsers")!;
    expect(jamf.platforms).toEqual(["macos"]);
    expect(jamf.area).toBe("authentication");
    expect(jamf.steps.length).toBeGreaterThanOrEqual(4);
    expect(jamf.steps[0]!.source?.url).toMatch(/^https:\/\/support\.apple\.com\//);
    expect(templates.every((t) => t.steps.every((s) => s.source === null || s.source.url.startsWith("https://")))).toBe(true);
    const dir = mkdtempSync(path.join(os.tmpdir(), "bw-templates-"));
    writeFileSync(path.join(dir, "good.yaml"), "id: good\ntitle: Good\nplatforms: [linux]\narea: network\nsteps:\n  - do: Check the firewall\n    expect: Active\n");
    writeFileSync(path.join(dir, "bad.yaml"), "title: No steps\n");
    writeFileSync(path.join(dir, "http.yaml"), "title: Insecure link\nsteps:\n  - do: x\n    source: { title: t, url: http://example.test }\n");
    const loaded = loadTemplates(dir);
    expect(loaded.templates.map((t) => t.id)).toEqual(["good", "http"]);
    expect(loaded.templates[1]!.steps[0]!.source).toBeNull();
    expect(loaded.templates[1]!.platforms).toEqual(["all"]);
    expect(loaded.errors).toEqual(["bad.yaml: no steps"]);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("test plans", () => {
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

  it("derives checks from the strict profile and files them with the templates by area", () => {
    const plan = buildTestPlan(app.db, { platform: "windows" });
    expect(plan.profile!.components.stig?.documentId).toBe(win11Doc);
    const derived = plan.items.filter((i) => i.source === "stig");
    expect(derived.map((i) => i.label).sort()).toEqual(["WN11-00-000030", "WN11-00-000031", "WN11-00-000150", "WN11-00-000165", "WN11-CC-000190", "WN11-SO-000070"]);
    expect(derived.find((i) => i.label === "WN11-00-000031")?.area).toBe("encryption");
    expect(derived.find((i) => i.label === "WN11-00-000165")?.area).toBe("network");
    expect(derived.find((i) => i.label === "WN11-SO-000070")?.area).toBe("authentication");
    expect(derived.find((i) => i.label === "WN11-00-000150")?.area).toBe("other");
    expect(derived.every((i) => i.procedure && i.url?.startsWith("/standards/disa-stigs/"))).toBe(true);
    const templates = plan.items.filter((i) => i.source === "template");
    expect(plan.templates.map((t) => t.id)).toEqual(["bitlocker-escrow", "conditional-access", "entra-join-hello-windows", "hardware-root-windows", "mdm-enrolment", "sso-intune-browsers", "windows-feature-update"]);
    expect(templates.find((i) => i.id === "template:bitlocker-escrow:1")).toMatchObject({ area: "encryption", url: "https://learn.microsoft.com/windows/client-management/mdm/bitlocker-csp" });
    expect(templates.find((i) => i.id === "template:sso-intune-browsers:3")?.title).toMatch(/Google Chrome/);
    // Derived checks come before template steps within an area; areas keep their order.
    const encryption = plan.items.filter((i) => i.area === "encryption");
    expect(encryption[0]!.source).toBe("stig");
    expect(encryption[encryption.length - 1]!.source).toBe("template");
    expect(plan.items.findIndex((i) => i.area === "authentication")).toBeLessThan(plan.items.findIndex((i) => i.area === "encryption"));
    expect(plan.counts.byArea.mdm).toBe(3);
    const without = buildTestPlan(app.db, { platform: "windows", templates: false });
    expect(without.items.every((i) => i.source !== "template")).toBe(true);
    const mac = buildTestPlan(app.db, { platform: "macos" });
    expect(mac.items.filter((i) => i.source === "mscp").map((i) => i.label).sort()).toEqual(["os_sip_enable", "pwpolicy_minimum_length_enforce"]);
    expect(mac.templates.map((t) => t.id)).toEqual(["conditional-access", "filevault-escrow", "hardware-root-macos", "macos-release-checks", "mdm-enrolment", "platform-sso-entra-macos", "smartcard-macos", "sso-jamf-browsers", "sso-jamf-connect", "sso-kerberos-extension"]);
    // The fixtures apply a smart card rule but no SSH or firewall rule, so those templates are left out, saying why.
    expect(mac.skippedTemplates.map((s) => `${s.template.id}: ${s.reason}`)).toEqual(["firewall-macos: no applied rule names firewall", "ssh-macos: no applied rule names ssh or sshd"]);
    expect(mac.items.find((i) => i.label === "APPL-26-005020")?.area).toBe("encryption");
  });

  it("draws the page, keeps unticked checks out through a redraw, and exports a checklist", async () => {
    const base = app.base;
    const html = await (await fetch(`${base}/baselines/windows/tests?section=encryption`)).text();
    expect(html).toContain("Windows <span class=\"arrow\">test plan</span>");
    expect(html).toContain('<h2>Disk encryption <span class="count">');
    expect(html).toContain('name="keep" value="test:stig:v-253260" checked');
    expect(html).toContain("owner's template");
    expect(html).toContain("BitLocker with TPM and PIN, recovery keys backed up to Microsoft Entra ID");
    expect(html).toContain('<a href="/baselines/windows">');

    const kept = buildTestPlan(app.db, { platform: "windows" }).items.map((i) => i.id).filter((id) => id !== "test:stig:v-253260" && !id.startsWith("template:mdm-enrolment"));
    // A form without `shown` (an older page or a script) drops everything it does not keep.
    const body = new URLSearchParams({ applied: "1", templates: "1", section: "encryption" });
    for (const id of kept) body.append("keep", id);
    const post = (p: string, b: URLSearchParams) => fetch(`${base}${p}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: base, "sec-fetch-site": "same-origin" }, body: b.toString() });
    const redrawn = await (await post("/baselines/windows/tests", body)).text();
    expect(redrawn).toContain('name="keep" value="test:stig:v-253260" >');
    expect(redrawn).toContain("4 dropped");

    body.set("format", "md");
    const md = await (await post("/baselines/windows/tests/export", body)).text();
    expect(md).toContain("# Windows test plan: Microsoft Windows 11 V2R11");
    expect(md).toContain("- [ ] **WN11-00-000030**");
    expect(md).not.toContain("- [ ] **WN11-00-000031**");
    expect(md).not.toContain("mdm-enrolment");
    expect(md).toContain("## Disk encryption");
    expect(md).toContain("- [ ] **sso-intune-browsers 3**");
    expect(md).toContain("## Attribution");
    const csv = await (await fetch(`${base}/baselines/macos/tests/export?format=csv&drop=template:conditional-access:1`)).text();
    expect(csv.split("\r\n")[0]).toBe("done,area,id,severity,title,source,procedure,expected,if not,our value,reference");
    expect(csv).toContain("APPL-26-005020");
    expect(csv).not.toContain("conditional-access 1,");
    expect(csv).toContain("conditional-access 2,");
    const json = await (await fetch(`${base}/baselines/linux/tests/export?format=json`)).json() as { title: string; items: { area: string; label: string }[]; counts: { template: number } };
    expect(json.title).toBe("Linux test plan: Red Hat Enterprise Linux 9 V2R10");
    expect(json.items.some((i) => i.label === "luks-escrow 1" && i.area === "Disk encryption")).toBe(true);
    expect(json.counts.template).toBe(15); // luks 3 + conditional access 3 + enrolment 3 + hardware root 6
    const printable = await fetch(`${base}/baselines/windows/tests/export?format=html&templates=0`);
    expect(printable.headers.get("content-disposition")).toMatch(/baselinewatch-windows-tests-microsoft-windows-11\.html/);
    const text = await printable.text();
    expect(text).toContain('<input type="checkbox">');
    expect(text).not.toContain("sso-intune-browsers");
    expect(text).not.toMatch(/<script/i);
    const direct = exportPlan(buildTestPlan(app.db, { platform: "linux", templates: false }), "csv", { baseUrl: "https://example.test", generatedAt: at.toISOString(), version: "0.21.0" });
    expect(String(direct.body).split("\r\n").length).toBe(3 + 2); // header, three rules, trailing newline
    expect((await fetch(`${base}/baselines/amiga/tests`)).status).toBe(404);
  });

  it("carries a drop made in one area through a redraw of another and into the export", async () => {
    const base = app.base;
    const all = buildTestPlan(app.db, { platform: "windows" }).items;
    const ids = (area: string) => all.filter((i) => i.area === area).map((i) => i.id);
    const post = async (fields: Record<string, string>, keep: string[], drop: string[], path = "/baselines/windows/tests") => {
      const body = new URLSearchParams(fields);
      for (const id of keep) body.append("keep", id);
      for (const id of drop) body.append("drop", id);
      const response = await fetch(`${base}${path}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: base, "sec-fetch-site": "same-origin" }, body: body.toString() });
      expect(response.status).toBe(200);
      return response;
    };
    const pin = "test:stig:v-253260"; // WN11-00-000031, BitLocker PIN: disk encryption
    const smb = "test:stig:v-253287"; // WN11-00-000165, SMBv1: network

    // On disk encryption, untick the BitLocker PIN check and open network: the drop rides along hidden.
    const network = await (await post({ applied: "1", templates: "1", shown: "encryption", section: "network" }, ids("encryption").filter((id) => id !== pin), [])).text();
    expect(network).toContain('name="shown" value="network"');
    expect(network).toContain(`<input type="hidden" name="drop" value="${pin}">`);
    expect(network).not.toContain(`name="keep" value="${pin}"`); // only the shown area's checkboxes are drawn
    expect(network).toContain(`name="keep" value="${smb}" checked`);
    expect(network).toContain("; 1 dropped");
    expect(network).toContain(`<button type="submit" name="section" value="encryption" class="" >Disk encryption <span class="count">${ids("encryption").length - 1} of ${ids("encryption").length}</span></button>`);

    // On network, untick SMBv1 and go back to disk encryption: both drops hold, each where it belongs.
    const encryption = await (await post({ applied: "1", templates: "1", shown: "network", section: "encryption" }, ids("network").filter((id) => id !== smb), [pin])).text();
    expect(encryption).toContain('name="shown" value="encryption"');
    expect(encryption).toContain(`name="keep" value="${pin}" >`);
    expect(encryption).toContain(`<input type="hidden" name="drop" value="${smb}">`);
    expect(encryption).not.toContain(`name="drop" value="${pin}"`); // the shown area speaks through its checkboxes
    expect(encryption).toContain("; 2 dropped");

    // Rebuild redraws the same area with the same state.
    const rebuilt = await (await post({ applied: "1", templates: "1", shown: "encryption", action: "rebuild" }, ids("encryption").filter((id) => id !== pin), [smb])).text();
    expect(rebuilt).toContain('name="shown" value="encryption"');
    expect(rebuilt).toContain(`name="keep" value="${pin}" >`);
    expect(rebuilt).toContain("; 2 dropped");

    // An export from the disk encryption area covers the whole plan: both drops reach it and the areas never drawn stay whole.
    const json = (await (await post({ applied: "1", templates: "1", shown: "encryption", format: "json" }, ids("encryption").filter((id) => id !== pin), [smb], "/baselines/windows/tests/export")).json()) as { counts: { dropped: number; template: number }; items: { id: string; area: string }[] };
    expect(json.counts.dropped).toBe(2);
    expect(json.items.map((i) => i.id)).toEqual(all.map((i) => i.id).filter((id) => id !== pin && id !== smb));
    expect(json.items.filter((i) => i.area === "MDM enrolment")).toHaveLength(ids("mdm").length);
    expect(json.counts.template).toBe(all.filter((i) => i.source === "template").length);

    // Unticking the owner's templates leaves their steps out; a carried template drop goes with them.
    const bare = await (await post({ applied: "1", shown: "encryption", section: "authentication" }, ids("encryption").filter((id) => id !== pin), [smb, "template:mdm-enrolment:1"])).text();
    expect(bare).toContain('name="templates" value="1" >');
    expect(bare).not.toContain("<span class=\"chip\">owner's template</span>");
    expect(bare).not.toContain("template:mdm-enrolment:1");
    expect(bare).toContain(`<input type="hidden" name="drop" value="${pin}">`);
    expect(bare).toContain("; 2 dropped");
    const bareExport = (await (await post({ applied: "1", shown: "encryption", format: "json" }, ids("encryption").filter((id) => id !== pin), [smb], "/baselines/windows/tests/export")).json()) as { counts: { template: number } };
    expect(bareExport.counts.template).toBe(0);

    // A carried drop for an id the plan no longer holds is forgotten.
    const stale = await (await post({ applied: "1", templates: "1", shown: "network", section: "other" }, ids("network"), ["test:stig:v-999999", pin])).text();
    expect(stale).toContain(`<input type="hidden" name="drop" value="${pin}">`);
    expect(stale).not.toContain("v-999999");
    expect(stale).toContain("; 1 dropped");

    // ?section= opens an area directly; one the plan has no checks in falls back to the first (the hardware root of trust leads now).
    const direct = await (await fetch(`${base}/baselines/windows/tests?section=network`)).text();
    expect(direct).toContain('name="shown" value="network"');
    expect(direct).toContain('<h2>Network <span class="count">');
    expect(direct).not.toContain('name="drop"');
    const fallback = await (await fetch(`${base}/baselines/windows/tests?section=nowhere`)).text();
    expect(fallback).toContain('name="shown" value="hardware"');

    // The GET export API is unchanged.
    const api = (await (await fetch(`${base}/baselines/windows/tests/export?format=json&drop=${pin}&drop=${smb}`)).json()) as { counts: { dropped: number } };
    expect(api.counts.dropped).toBe(2);
  });
});
