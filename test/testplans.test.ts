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
    expect(templates.map((t) => t.id)).toEqual(["bitlocker-escrow", "conditional-access", "filevault-escrow", "luks-escrow", "mdm-enrolment", "sso-intune-browsers", "sso-jamf-browsers"]);
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
    expect(plan.profile.components.stig?.documentId).toBe(win11Doc);
    const derived = plan.items.filter((i) => i.source === "stig");
    expect(derived.map((i) => i.label).sort()).toEqual(["WN11-00-000030", "WN11-00-000031", "WN11-00-000150", "WN11-00-000165", "WN11-CC-000190", "WN11-SO-000070"]);
    expect(derived.find((i) => i.label === "WN11-00-000031")?.area).toBe("encryption");
    expect(derived.find((i) => i.label === "WN11-00-000165")?.area).toBe("network");
    expect(derived.find((i) => i.label === "WN11-SO-000070")?.area).toBe("authentication");
    expect(derived.find((i) => i.label === "WN11-00-000150")?.area).toBe("other");
    expect(derived.every((i) => i.procedure && i.url?.startsWith("/standards/disa-stigs/"))).toBe(true);
    const templates = plan.items.filter((i) => i.source === "template");
    expect(plan.templates.map((t) => t.id)).toEqual(["bitlocker-escrow", "conditional-access", "mdm-enrolment", "sso-intune-browsers"]);
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
    expect(mac.templates.map((t) => t.id)).toEqual(["conditional-access", "filevault-escrow", "mdm-enrolment", "sso-jamf-browsers"]);
    expect(mac.items.find((i) => i.label === "APPL-26-005020")?.area).toBe("encryption");
  });

  it("draws the page, keeps unticked checks out through a redraw, and exports a checklist", async () => {
    const base = app.base;
    const html = await (await fetch(`${base}/baselines/windows/tests`)).text();
    expect(html).toContain("Windows <span class=\"arrow\">test plan</span>");
    expect(html).toContain("<b>Disk encryption</b>");
    expect(html).toContain('name="keep" value="test:stig:v-253260" checked');
    expect(html).toContain("owner's template");
    expect(html).toContain("BitLocker with TPM and PIN, recovery keys backed up to Microsoft Entra ID");
    expect(html).toContain('<a href="/baselines/windows">');

    const kept = buildTestPlan(app.db, { platform: "windows" }).items.map((i) => i.id).filter((id) => id !== "test:stig:v-253260" && !id.startsWith("template:mdm-enrolment"));
    const body = new URLSearchParams({ applied: "1", templates: "1" });
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
    expect(csv.split("\r\n")[0]).toBe("done,area,id,severity,title,source,procedure,expected,reference");
    expect(csv).toContain("APPL-26-005020");
    expect(csv).not.toContain("conditional-access 1,");
    expect(csv).toContain("conditional-access 2,");
    const json = await (await fetch(`${base}/baselines/linux/tests/export?format=json`)).json() as { title: string; items: { area: string; label: string }[]; counts: { template: number } };
    expect(json.title).toBe("Linux test plan: Red Hat Enterprise Linux 9 V2R10");
    expect(json.items.some((i) => i.label === "luks-escrow 1" && i.area === "Disk encryption")).toBe(true);
    expect(json.counts.template).toBe(9); // luks 3 + conditional access 3 + enrolment 3
    const printable = await fetch(`${base}/baselines/windows/tests/export?format=html&templates=0`);
    expect(printable.headers.get("content-disposition")).toMatch(/baselinewatch-windows-tests-microsoft-windows-11\.html/);
    const text = await printable.text();
    expect(text).toContain('<input type="checkbox">');
    expect(text).not.toContain("sso-intune-browsers");
    expect(text).not.toMatch(/<script/i);
    const direct = exportPlan(buildTestPlan(app.db, { platform: "linux", templates: false }), "csv", { baseUrl: "https://example.test", generatedAt: at.toISOString(), version: "0.21.0" });
    expect(direct.body.split("\r\n").length).toBe(3 + 2); // header, three rules, trailing newline
    expect((await fetch(`${base}/baselines/amiga/tests`)).status).toBe(404);
  });
});
