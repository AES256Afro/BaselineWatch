import { unzipSync } from "fflate";
import { XMLValidator } from "fast-xml-parser";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildProfile, sectionOf } from "../src/baselines.ts";
import { getDecision, loadDecisions, saveDecision } from "../src/decisions.ts";
import { pdfText } from "../src/pdf.ts";
import { renderDocx, renderLatex, renderPdf, reportStyle, reportStyles, type Block } from "../src/report.ts";
import { buildTestPlan, exportPlan, namesApplied } from "../src/testplans.ts";
import { loadBaselineFixtures } from "./baseline-fixtures.ts";
import { cookieFrom, formPost, startTestApp, type TestApp } from "./helpers.ts";

describe("baseline decisions", () => {
  let app: TestApp;
  const at = new Date("2026-10-19T10:00:00Z");
  let cookie = "";

  beforeAll(async () => {
    app = await startTestApp({ now: () => at, env: { BW_ADMIN_PASSWORD: "hunter2hunter2" } });
    await loadBaselineFixtures(app, at);
    cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
  });

  afterAll(async () => {
    await app.close();
  });

  it("stores, replaces and clears a decision", () => {
    const now = new Date("2026-10-19T11:00:00Z");
    expect(saveDecision(app.db, "linux", "stig:x", { decision: "modify", value: " 30 minutes ", reason: "Lab machines", owner: "Platform team" }, now)).toMatchObject({ value: "30 minutes", owner: "Platform team" });
    expect(saveDecision(app.db, "linux", "stig:x", { decision: "exclude", value: "ignored", reason: "No GUI" }, now)).toMatchObject({ decision: "exclude", value: null, reason: "No GUI", owner: null });
    expect(loadDecisions(app.db, "linux").size).toBe(1);
    expect(loadDecisions(app.db, "windows").size).toBe(0);
    // Apply as published with nothing to say is the default: the row goes.
    expect(saveDecision(app.db, "linux", "stig:x", { decision: "apply" }, now)).toBeNull();
    expect(getDecision(app.db, "linux", "stig:x")).toBeNull();
    expect(saveDecision(app.db, "linux", "stig:x", { decision: "apply", reason: "Checked by audit" }, now)?.decision).toBe("apply");
    saveDecision(app.db, "linux", "stig:x", { decision: "apply" }, now);
  });

  it("gates decisions behind sign-in, starts the builder from them, and keeps excluded rules out of the test plan", async () => {
    const mac = buildProfile(app.db, { platform: "macos" });
    const rules = mac.items.filter((i) => i.kind === "stig" && i.check);
    expect(rules.length).toBeGreaterThanOrEqual(2);
    const [excluded, modified] = [rules[0]!, rules[1]!];

    expect((await formPost(app.base, "/baselines/macos/decide", { item: excluded.id, decision: "exclude" })).status).toBe(403);
    const saved = await formPost(app.base, "/baselines/macos/decide", { item: excluded.id, decision: "exclude", reason: "Kiosk Macs have no users", owner: "Endpoint team" }, cookie);
    expect(saved.status).toBe(303);
    expect(saved.headers.get("location")).toBe(`/baselines/macos/decide?item=${encodeURIComponent(excluded.id)}&saved=1`);
    expect((await formPost(app.base, "/baselines/macos/decide", { item: modified.id, decision: "modify", value: "20 minutes", reason: "Shared lab" }, cookie)).status).toBe(303);
    expect((await formPost(app.base, "/baselines/macos/decide", { item: "stig:nope", decision: "exclude" }, cookie)).status).toBe(400);
    expect((await formPost(app.base, "/baselines/macos/decide", { item: excluded.id, decision: "maybe" }, cookie)).status).toBe(400);

    const after = buildProfile(app.db, { platform: "macos" });
    expect(after.items.find((i) => i.id === excluded.id)?.included).toBe(false);
    expect(after.items.find((i) => i.id === modified.id)?.decision?.value).toBe("20 minutes");
    expect(after.counts.decisions).toMatchObject({ modify: 1, exclude: 1 });
    // A form that carries its own drops overrides the stored decisions.
    expect(buildProfile(app.db, { platform: "macos", drop: [] }).items.find((i) => i.id === excluded.id)?.included).toBe(true);

    const decide = await (await fetch(`${app.base}/baselines/macos/decide?item=${encodeURIComponent(excluded.id)}&saved=1`, { headers: { cookie } })).text();
    expect(decide).toContain("Saved");
    expect(decide).toContain("Kiosk Macs have no users");
    expect(decide).toContain('value="exclude" checked');
    // The owner's board carries the whole decision; a visitor's does not carry the organisation's
    // reason or the name of whoever signed it. That a rule is modified or not applied, and the
    // value chosen instead, is the teaching value and stays public.
    const ownerBoard = await (await fetch(`${app.base}/baselines/macos/decisions`, { headers: { cookie } })).text();
    expect(ownerBoard).toContain("Kiosk Macs have no users");
    const board = await (await fetch(`${app.base}/baselines/macos/decisions`)).text();
    expect(board).not.toContain("Kiosk Macs have no users");
    expect(board).toContain("Not applying");
    expect(board).toContain("20 minutes");
    expect(board).not.toContain('name="decision"');
    // The same on the decide page and in the download.
    expect(await (await fetch(`${app.base}/baselines/macos/decide?item=${encodeURIComponent(excluded.id)}`)).text()).not.toContain("Kiosk Macs have no users");
    expect(await (await fetch(`${app.base}/baselines/macos/decisions.csv`)).text()).not.toContain("Kiosk Macs have no users");
    expect(await (await fetch(`${app.base}/baselines/macos/decisions.csv`, { headers: { cookie } })).text()).toContain("Kiosk Macs have no users");
    const builder = async (item: typeof excluded, headers: Record<string, string> = {}) => (await fetch(`${app.base}/baselines/macos?section=${sectionOf(item)}`, { headers })).text();
    expect(await builder(excluded)).toContain("Not applying");
    expect(await builder(modified)).toContain("Modified: 20 minutes");
    expect(await builder(excluded)).not.toContain("decide-unticked");
    expect(await builder(excluded, { cookie })).toContain("decide-unticked");
    expect((await fetch(`${app.base}/baselines/macos/decide?item=stig:nope`)).status).toBe(404);

    // A visitor's download keeps every column, including the two the organisation's own words
    // would have gone in: the shape does not change, so a script reading it does not break.
    const csv = await (await fetch(`${app.base}/baselines/macos/decisions.csv`)).text();
    expect(csv.split("\r\n")[0]).toBe("item,kind,severity,title,publisher recommends,decision,our value,reason,owner,decided,reference");
    expect(csv).toContain("Not applying");
    expect(csv).not.toContain("Kiosk Macs have no users");

    const plan = buildTestPlan(app.db, { platform: "macos" });
    expect(plan.items.some((i) => i.id === `test:${excluded.id}`)).toBe(false);
    expect(plan.notApplied.map((i) => i.id)).toEqual([`test:${excluded.id}`]);
    expect(plan.notApplied[0]!.applicable.reason).toBe("not applied: Kiosk Macs have no users");
    expect(plan.items.find((i) => i.id === `test:${modified.id}`)?.ourValue).toBe("20 minutes");
    const meta = { baseUrl: "https://example.test", generatedAt: at.toISOString(), version: "0.34.0" };
    const md = String(exportPlan(plan, "md", meta).body);
    expect(md).toContain("## Baseline decisions");
    expect(md).toContain("Kiosk Macs have no users");
    expect(md).toContain("Our value (modified): 20 minutes");
    expect(md).toContain("not applied: Kiosk Macs have no users");
    const page = await (await fetch(`${app.base}/baselines/macos/tests`)).text();
    expect(page).toContain("Rules not applied");
    expect(page).toContain('name="style"');
  });

  it("records every unticked item as not applying in one go", async () => {
    const mac = buildProfile(app.db, { platform: "macos" });
    const keep = mac.items.filter((i) => i.included).slice(1).map((i) => i.id);
    const dropped = mac.items.find((i) => i.included)!;
    const body = new URLSearchParams({ applied: "1", reason: "Out of scope for kiosks", owner: "Endpoint team" });
    for (const id of keep) body.append("keep", id);
    const res = await fetch(`${app.base}/baselines/macos/decide-unticked`, { method: "POST", redirect: "manual", headers: { cookie, "content-type": "application/x-www-form-urlencoded", origin: app.base, "sec-fetch-site": "same-origin" }, body: body.toString() });
    expect(res.status).toBe(303);
    // The item already marked not applying is not saved again; the newly unticked one is.
    expect(res.headers.get("location")).toBe("/baselines/macos/decisions?saved=1");
    expect(getDecision(app.db, "macos", dropped.id)).toMatchObject({ decision: "exclude", reason: "Out of scope for kiosks", owner: "Endpoint team" });
    expect(await (await fetch(`${app.base}${res.headers.get("location")}`)).text()).toContain("Saved 1 decision");
  });

  it("exports the report in every look as Word, PDF and LaTeX that open", async () => {
    // A visitor's copy keeps the decision and leaves out its reason and signer (the audit of 28 October).
    const visitor = unzipSync(new Uint8Array(await (await fetch(`${app.base}/baselines/macos/tests/export?format=docx`)).arrayBuffer()));
    expect(new TextDecoder().decode(visitor["word/document.xml"])).not.toContain("Kiosk Macs have no users");
    expect(await (await fetch(`${app.base}/baselines/macos/tests/export?format=json`)).text()).not.toContain("Endpoint team");
    for (const style of reportStyles) {
      const docx = await fetch(`${app.base}/baselines/macos/tests/export?format=docx&style=${style.id}`, { headers: { cookie } });
      expect(docx.status).toBe(200);
      const files = unzipSync(new Uint8Array(await docx.arrayBuffer()));
      for (const [name, bytes] of Object.entries(files)) expect(XMLValidator.validate(new TextDecoder().decode(bytes)), `${style.id} ${name}`).toBe(true);
      const doc = new TextDecoder().decode(files["word/document.xml"]);
      expect(doc).toContain("Kiosk Macs have no users");
      expect(doc.includes("<w:background"), style.id).toBe(style.colors.page !== null);
      expect(doc.includes('w:type="page"'), style.id).toBe(style.cover);
      expect(doc.includes(">1. "), style.id).toBe(style.numbered);
      const pdf = new Uint8Array(await (await fetch(`${app.base}/baselines/macos/tests/export?format=pdf&style=${style.id}`)).arrayBuffer());
      expect(new TextDecoder("latin1").decode(pdf.slice(0, 8))).toBe("%PDF-1.4");
      expect(await pdfText(pdf)).toContain("Baseline decisions");
      const tex = await (await fetch(`${app.base}/baselines/macos/tests/export?format=tex&style=${style.id}`)).text();
      expect(tex.includes("\\definecolor"), style.id).toBe(style.id !== "plain");
    }
    const html = await (await fetch(`${app.base}/baselines/macos/tests/export?format=html&style=console`)).text();
    expect(html).toContain('data-report="console"');
    expect(reportStyle("nope").id).toBe("plain");
  });
});

describe("report styles", () => {
  const sample: Block[] = [
    { type: "title", text: "Plan" },
    { type: "subtitle", text: "Summary" },
    { type: "h1", text: "First" },
    { type: "table", header: ["A", "B"], rows: [["1", "2"]] },
    { type: "code", text: "fdesetup status" },
    { type: "h1", text: "Second" },
  ];

  it("numbers the top-level headings, puts the cover on a page of its own and paints a dark page", async () => {
    const formal = reportStyle("formal");
    expect(renderLatex(sample, formal)).toContain("\\section*{\\color{heading}2. Second}");
    const bytes = renderPdf(sample, formal);
    expect(new TextDecoder("latin1").decode(bytes).match(/\/Type \/Page /g)?.length).toBe(2);
    expect(await pdfText(bytes)).toContain("1. First");
    const console = new TextDecoder("latin1").decode(renderPdf(sample, reportStyle("console")));
    expect(console).toContain("re f");
    expect(console).toContain("/BaseFont /Courier-Bold");
    expect(new TextDecoder("latin1").decode(renderPdf(sample, formal))).toContain("/BaseFont /Times-Bold");
    const docx = unzipSync(renderDocx(sample, reportStyle("console")));
    expect(Object.keys(docx)).toContain("word/settings.xml");
    expect(new TextDecoder().decode(docx["word/styles.xml"])).toContain('w:val="67E8F9"');
  });

  it("names the rule a template requires by id or a whole word of its title", () => {
    const item = (id: string, title: string, exclude = false) =>
      ({ id, kind: "mscp", label: id.replace(/^mscp:/, ""), title, decision: exclude ? { itemId: id, decision: "exclude", value: null, reason: null, owner: null, decidedAt: "" } : null }) as unknown as Parameters<typeof namesApplied>[1][number];
    expect(namesApplied("ssh", [item("mscp:os_sshd_fips_compliant", "Limit SSHD to FIPS Compliant Connections")])).toBe(true);
    expect(namesApplied("ssh", [item("mscp:os_sshd_fips_compliant", "Limit SSHD to FIPS Compliant Connections", true)])).toBe(false);
    expect(namesApplied("smart card", [item("mscp:auth_smartcard_enforce", "Enforce Smart Card Authentication")])).toBe(true);
    expect(namesApplied("ssh", [item("mscp:os_gatekeeper_enable", "Enable Gatekeeper")])).toBe(false);
  });
});
