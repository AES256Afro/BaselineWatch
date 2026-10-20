import { unzipSync } from "fflate";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { pdfText } from "../src/pdf.ts";
import { buildTestPlan, exportPlan, releaseChoices, testedItems } from "../src/testplans.ts";
import { loadBaselineFixtures } from "./baseline-fixtures.ts";
import { startTestApp, type TestApp } from "./helpers.ts";

const at = new Date("2026-10-19T10:00:00Z");
const meta = { baseUrl: "https://example.test", generatedAt: at.toISOString(), version: "0.31.0" };

describe("platform engineering: the release and hardware under test", () => {
  let app: TestApp;

  beforeAll(async () => {
    app = await startTestApp({ now: () => at });
    await loadBaselineFixtures(app, at);
  });

  afterAll(async () => {
    await app.close();
  });

  it("leaves out the steps a release or a device cannot take, and says why", () => {
    // macOS 26 Tahoe on an Intel Mac without a T2 chip: no Secure Enclave, no boot policy.
    const intel = buildTestPlan(app.db, { platform: "macos", version: "26", hardware: "intel" });
    expect(intel.release?.label).toBe("macOS 26 Tahoe");
    expect(intel.hardware?.id).toBe("intel");
    // Left out for the hardware, and (separately) for naming no applied rule.
    expect(intel.skippedTemplates.map((s) => s.template.id)).toEqual(["firewall-macos", "hardware-root-macos", "ssh-macos"]);
    expect(intel.skippedTemplates.find((s) => s.template.id === "hardware-root-macos")!.reason).toMatch(/needs Apple silicon Mac .* or Intel Mac with the Apple T2/);
    const rosetta = intel.items.find((i) => i.id === "template:macos-release-checks:3")!;
    expect(rosetta.applicable).toEqual({ ok: false, reason: "applies to macOS >=27, not macOS 26 Tahoe" });
    expect(rosetta.included).toBe(false);
    const held = intel.items.find((i) => i.id === "template:macos-release-checks:2")!;
    expect(held.applicable.ok).toBe(true);

    // macOS 13 Ventura is too old for Platform SSO.
    const ventura = buildTestPlan(app.db, { platform: "macos", version: "13" });
    expect(ventura.skippedTemplates.map((s) => s.template.id)).toEqual(["firewall-macos", "platform-sso-entra-macos", "ssh-macos"]);

    // Windows 11 23H2: the 24H2 and 25H2 behaviours do not apply; the first step always does.
    const w23 = buildTestPlan(app.db, { platform: "windows", version: "23H2", hardware: "tpm-2" });
    const update = w23.items.filter((i) => i.id.startsWith("template:windows-feature-update:"));
    expect(update.map((i) => i.applicable.ok)).toEqual([true, false, false, false, false, false, false]);
    expect(update[4]!.applicable.reason).toBe("applies to Windows >=25H2, not Windows 11, version 23H2");
    expect(update[6]!.applicable.reason).toMatch(/needs Copilot\+ PC/);
    expect(w23.items.find((i) => i.id === "template:hardware-root-windows:5")!.applicable.reason).toMatch(/needs PC with Microsoft Pluton or Copilot\+ PC/);
    expect(w23.counts.inapplicable).toBe(7);
    // Nothing chosen: everything applies.
    const any = buildTestPlan(app.db, { platform: "windows" });
    expect(any.counts.inapplicable).toBe(0);
    expect(any.release).toBeNull();
  });

  it("starts a plan from the Register documents its release names, and still takes a choice", () => {
    // macOS 26 Tahoe names stig:apple-macos-26-tahoe and mscp:tahoe in data/platforms.yaml; both are loaded.
    const tahoe = buildTestPlan(app.db, { platform: "macos", version: "26" });
    expect(tahoe.profile?.components.stig?.key).toBe("stig:apple-macos-26-tahoe");
    expect(tahoe.profile?.components.mscp?.key).toBe("mscp:tahoe");
    // macOS 15 names the Sequoia STIG, which is not loaded: the first choice stands in, as before.
    const sequoia = buildTestPlan(app.db, { platform: "macos", version: "15" });
    expect(sequoia.profile?.components.stig?.key).toBe("stig:apple-macos-26-tahoe");
    // Windows 25H2 names the v25H2 Microsoft baseline.
    const w25 = buildTestPlan(app.db, { platform: "windows", version: "25H2" });
    expect(w25.profile?.components.sct?.key).toBe("baseline:windows-11-v25h2");
    // An explicit choice wins over the release's.
    const choice = tahoe.profile!.choices.stigs[0]!;
    const picked = buildTestPlan(app.db, { platform: "macos", version: "26", stig: `${choice.key}@${choice.documentId}` });
    expect(picked.profile?.components.stig?.documentId).toBe(choice.documentId);
    expect(releaseChoices(app.db, null)).toEqual({});
  });

  it("builds the iOS baseline and lists six platforms", async () => {
    const index = await (await fetch(`${app.base}/baselines`)).text();
    expect(index).toContain("6 platforms");
    expect(index).toContain('<a href="/baselines/ios">iOS</a>');
    expect(index).toContain('<a href="/baselines/android">Android</a>');
    // A card's state and figures lead to the STIG page, the Register source or the watchlist they come from.
    expect(index).toContain('<a href="/baselines/ios">iOS</a></b><a class="state ok" href="/stigs/mobile">1 STIG loaded</a>');
    expect(index).toContain('<a href="/baselines/android">Android</a></b><a class="state wait" href="/stigs/mobile">No STIG loaded</a>');
    expect(index).toContain('<a href="/watchlist">follow a STIG first</a>');
    expect(index).toMatch(/<a class="n" href="\/standards\/microsoft-sct">\d+ Microsoft baselines?<\/a>/);
    expect(index).toContain('<h2><a href="/platforms">Test plans</a></h2>');
    const builder = await (await fetch(`${app.base}/baselines/ios`)).text();
    expect(builder).toContain("Apple iOS/iPadOS 26 V1R2");
    expect(builder).toContain("AIOS-26-006500");
    expect(builder).toContain('<a href="/stigs/mobile">');
    expect(builder).toContain("mSCP branch");
    const android = await (await fetch(`${app.base}/baselines/android`)).text();
    expect(android).toContain("No Android STIG loaded");
  });

  it("tests only the areas chosen and lists the rest as not tested", () => {
    const plan = buildTestPlan(app.db, { platform: "macos", version: "27", hardware: "apple-silicon", areas: ["hardware"] });
    expect(plan.areasChosen).toEqual(["hardware"]);
    expect(testedItems(plan).every((i) => i.area === "hardware")).toBe(true);
    expect(plan.counts.included).toBe(testedItems(plan).length);
    expect(plan.counts.untested).toBeGreaterThan(0);
    expect(plan.counts.byArea.sso).toBe(0);
    const md = String(exportPlan(plan, "md", meta).body);
    expect(md).toMatch(/^# macOS test plan: Apple macOS 26 \(Tahoe\) V1R4 \+ .+ \(macOS 27 Golden Gate, Apple silicon Mac \(M1 and later\)\)$/m);
    expect(md).toContain("## Hardware root of trust and secure enclave");
    expect(md).not.toContain("## Platform SSO and identity");
    expect(md).toContain("## Not tested, and why");
    expect(md).toContain("Platform SSO and identity is not being tested this time");
    expect(md).toContain("- **Release:** macOS 27 Golden Gate (released 2026-09-14)");
    expect(md).toContain("- If it does not: Reduced or Permissive Security");
    const json = JSON.parse(String(exportPlan(plan, "json", meta).body)) as { release: { id: string }; hardware: { id: string }; areas: string[]; notTested: { why: string }[]; items: { fail: string | null }[] };
    expect(json.release.id).toBe("27");
    expect(json.hardware.id).toBe("apple-silicon");
    expect(json.areas).toEqual(["hardware"]);
    expect(json.notTested.some((n) => /not being tested/.test(n.why))).toBe(true);
    expect(json.items.some((i) => i.fail)).toBe(true);
    const csv = String(exportPlan(plan, "csv", meta).body);
    expect(csv.split("\r\n")[0]).toBe("done,area,id,severity,title,source,procedure,expected,if not,our value,reference");
  });

  it("builds the iOS plan from its STIG and the templates, and templates-only plans for Android and the meeting rooms", () => {
    const ios = buildTestPlan(app.db, { platform: "ios", version: "26", hardware: "iphone-a13" });
    // The iOS/iPadOS 26 STIG is loaded: its CAT I and II rules are derived checks beside the templates.
    expect(ios.profile?.components.stig?.key).toBe("stig:apple-ios-ipados-26");
    expect(ios.items.filter((i) => i.source === "stig").map((i) => i.label).sort()).toEqual(["AIOS-26-006500", "AIOS-26-006800", "AIOS-26-007500", "AIOS-26-011200", "AIOS-26-012500", "AIOS-26-013200"]);
    expect(ios.items.find((i) => i.label === "AIOS-26-013200")?.area).toBe("mdm");
    expect(ios.items.find((i) => i.label === "AIOS-26-006500")?.area).toBe("authentication");
    expect(ios.templates.map((t) => t.id)).toEqual(["conditional-access", "entra-sso-mobile", "hardware-root-ios", "mdm-enrolment", "sso-kerberos-extension"]);
    expect(ios.items.find((i) => i.id === "template:hardware-root-ios:5")!.applicable.ok).toBe(true);
    const ipad = buildTestPlan(app.db, { platform: "ipados", version: "26" });
    expect(ipad.profile?.components.stig?.key).toBe("stig:apple-ios-ipados-26");
    // Android has no STIG loaded in the fixtures: a profile with no STIG, templates only.
    const droid = buildTestPlan(app.db, { platform: "android", version: "17", hardware: "pixel" });
    expect(droid.profile?.components.stig).toBeNull();
    expect(droid.items.every((i) => i.source === "template")).toBe(true);
    const ios18 = buildTestPlan(app.db, { platform: "ios", version: "18" });
    expect(ios18.items.find((i) => i.id === "template:hardware-root-ios:5")!.applicable.reason).toBe("applies to iOS >=26, not iOS 18");
    const rooms = buildTestPlan(app.db, { platform: "collaboration", hardware: "samsung-signage" });
    expect(rooms.templates.map((t) => t.id)).toEqual(["collaboration-samsung-displays", "conditional-access", "mdm-enrolment"]);
    expect(rooms.skippedTemplates.map((s) => s.template.id)).toEqual(["collaboration-teams-rooms"]);
    expect(rooms.items.find((i) => i.id === "template:collaboration-samsung-displays:3")!.applicable.reason).toMatch(/needs Samsung interactive display/);
    const android = buildTestPlan(app.db, { platform: "android", version: "17", hardware: "pixel" });
    expect(android.items.find((i) => i.id === "template:hardware-root-android:2")!.applicable.reason).toMatch(/needs Samsung Galaxy with Knox/);
  });

  it("exports LaTeX, Word and PDF over HTTP, and draws the page with the selects", async () => {
    const base = app.base;
    const tex = await fetch(`${base}/baselines/macos/tests/export?format=tex&version=26&hardware=apple-silicon`);
    expect(tex.headers.get("content-type")).toMatch(/x-tex/);
    expect(tex.headers.get("content-disposition")).toMatch(/baselinewatch-macos-tests-26-apple-macos-26-tahoe\.tex/);
    const texBody = await tex.text();
    expect(texBody).toContain("\\section*{The release under test}");
    expect(texBody).toContain("macOS 26 Tahoe");

    const docx = await fetch(`${base}/baselines/ios/tests/export?format=docx&version=27`);
    expect(docx.headers.get("content-type")).toMatch(/wordprocessingml/);
    const parts = unzipSync(new Uint8Array(await docx.arrayBuffer()));
    expect(new TextDecoder().decode(parts["word/document.xml"]!)).toContain("iOS test plan: Apple iOS/iPadOS 26 V1R2 (iOS 27)");

    const pdf = await fetch(`${base}/baselines/windows/tests/export?format=pdf&version=26H2&hardware=copilot-plus`);
    expect(pdf.headers.get("content-type")).toMatch(/application\/pdf/);
    const text = await pdfText(new Uint8Array(await pdf.arrayBuffer()));
    // The title wraps across lines in the PDF; its parts are all there.
    expect(text).toContain("Windows test plan: Microsoft Windows 11 V2R11");
    expect(text).toContain("version 26H2, Copilot+ PC");
    expect(text).toContain("Recall & snapshots");
    expect(text).toContain("Page 1 of");

    const html = await (await fetch(`${base}/baselines/macos/tests?version=27&section=hardware`)).text();
    expect(html).toContain('<option value="27" selected>macOS 27 Golden Gate (current)</option>');
    expect(html).toContain('<option value="intel-t2"  disabled>Intel Mac with the Apple T2 Security Chip (2018 to 2020) (cannot run macOS 27 Golden Gate)</option>');
    expect(html).toContain('<option value="apple-silicon"  >Apple silicon Mac (M1 and later)</option>');
    expect(html).toContain('name="area" value="hardware" checked');
    expect(html).toContain('formaction="/baselines/macos/tests/export" name="format" value="pdf"');
    expect(html).toContain("Apple silicon only; Intel Macs stay on macOS 26 Tahoe.");

    const intel = await (await fetch(`${base}/baselines/macos/tests?version=26&hardware=intel&section=hardware`)).text();
    expect(intel).toContain("not applicable");
    expect(intel).toContain("Left out");
    expect(intel).toContain("needs Apple silicon Mac");

    const collab = await (await fetch(`${base}/baselines/collaboration/tests`)).text();
    expect(collab).toContain("Collaboration <span class=\"arrow\">test plan</span>");
    expect(collab).toContain("has no STIG checks in the Register yet");
    expect(collab).toContain("Samsung meeting-room displays and signage");
  });

  it("says what ends support soon on Today and the Platforms page, and links a plan as a URL", async () => {
    // The app's clock is 2026-10-19 in these tests: Windows 11 23H2 Enterprise ends 2026-11-10, 22 days out.
    const today = await (await fetch(`${app.base}/today`)).text();
    expect(today).toContain('<a class="tile warn" href="/platforms"><small>Support ending</small><b>1</b><span>Windows 11, version 23H2: Enterprise and Education 2026-11-10</span></a>');
    const platforms = await (await fetch(`${app.base}/platforms`)).text();
    expect(platforms).toContain("<b>Support ending within 90 days:</b>");
    expect(platforms).toContain('<span class="chip na">ends in 22 days</span> <span class="small">Enterprise and Education 2026-11-10</span>');
    const plan = await (await fetch(`${app.base}/baselines/macos/tests?version=27&hardware=apple-silicon&areas=1&area=hardware&area=sso`)).text();
    expect(plan).toContain('<a href="/baselines/macos/tests?version=27&amp;hardware=apple-silicon&amp;areas=1&amp;area=hardware&amp;area=sso">Link to this plan</a>');
    const whole = await (await fetch(`${app.base}/baselines/macos/tests`)).text();
    expect(whole).toContain('<a href="/baselines/macos/tests">Link to this plan</a>');
  });

  it("lists every platform, release and hardware family on the Platforms page", async () => {
    const html = await (await fetch(`${app.base}/platforms`)).text();
    expect(html).toContain("<h1>Platforms</h1>");
    // A platform's name and counts are permalinks to its section; the template count opens its test plan.
    expect(html).toMatch(/<b><a href="#macos">macOS<\/a><\/b><span class="small"><a href="#macos">\d+ releases<\/a> · <a href="#macos-hardware">\d+ hardware families<\/a> · <a href="\/baselines\/macos\/tests">\d+ templates<\/a><\/span>/);
    expect(html).toContain('<ul class="hw" id="macos-hardware">');
    expect(html).toContain('<h2><a href="/register">In the Register</a></h2>');
    expect(html).toContain("macOS 27 Golden Gate");
    expect(html).toContain("Windows 11, version 26H2");
    expect(html).toContain('href="/baselines/macos/tests?version=27"');
    expect(html).toContain('href="/baselines/collaboration/tests?version=samsung-display-2026"');
    expect(html).toContain("secure element");
    expect(html).toContain("support ended");
    // The Register holds the Tahoe STIG and the tahoe mSCP branch from the fixtures; Sequoia's are not loaded.
    expect(html).toMatch(/STIG V1R4<\/a>/);
    expect(html).toContain("mSCP ");
    expect(html).toContain("STIG not loaded");
    expect(html).toContain('<a href="/platforms"');
    expect(html).toContain(">Platforms</a>");
  });
});
