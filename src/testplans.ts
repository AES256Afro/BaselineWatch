import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { parse as parseYaml } from "yaml";
import { buildProfile, isBuilderPlatform, type Profile, type ProfileItem, type ProfileOptions } from "./baselines.ts";
import { applicability, appliesToAll, findHardware, findRelease, fleetPlatformName, hardwareOf, isFleetPlatform, loadFleet, parseApplies, releasesOf, type Applicability, type Applies, type Fleet, type FleetPlatform, type Hardware, type Release } from "./fleet.ts";
import { escapeHtml } from "./html.ts";
import { renderDocx, renderLatex, renderPdf, type Block, type Inline } from "./report.ts";
import { productName } from "./version.ts";

/**
 * Test plans: what to test when a new OS release lands so the baseline still holds. Derived from
 * the STIG and mSCP check procedures of the strict profile, grouped by area, plus the owner's
 * templates kept as YAML under data/test-plans (the hardware root of trust, Platform SSO with
 * Entra ID, key escrow, enrolment, the meeting rooms), each step citing the publisher's document
 * it follows and saying what to do when it fails. A template, or one of its steps, can say which
 * releases and which hardware it applies to; the plan reads the fleet (data/platforms.yaml) and
 * leaves out what does not apply to the version and hardware chosen, saying why. The derived
 * items are the publishers' words; the templates are labelled as the owner's.
 */

export type Area = "hardware" | "sso" | "authentication" | "encryption" | "mdm" | "updates" | "network" | "browsers" | "logging" | "collaboration" | "other";

export const areas: { id: Area; label: string }[] = [
  { id: "hardware", label: "Hardware root of trust and secure enclave" },
  { id: "sso", label: "Platform SSO and identity" },
  { id: "authentication", label: "Authentication" },
  { id: "encryption", label: "Disk encryption" },
  { id: "mdm", label: "MDM enrolment" },
  { id: "updates", label: "Updates and release changes" },
  { id: "network", label: "Network" },
  { id: "browsers", label: "Browsers" },
  { id: "logging", label: "Logging and audit" },
  { id: "collaboration", label: "Collaboration and meeting rooms" },
  { id: "other", label: "Everything else" },
];

export function areaLabel(id: Area): string {
  return areas.find((a) => a.id === id)?.label ?? id;
}

export function isArea(value: unknown): value is Area {
  return typeof value === "string" && areas.some((a) => a.id === value);
}

const patterns: { area: Area; title: RegExp; body?: RegExp }[] = [
  { area: "mdm", title: /\bmdm\b|enrol|enroll|device management|managed by|management profile|supervis/i },
  { area: "hardware", title: /secure boot|verified boot|boot policy|bootloader|\buefi\b|firmware|\btpm\b|secure enclave|pluton|t2 chip|system integrity protection|\bsip\b|authenticated.root|activation lock|attestation|credential guard|device guard|\bhvci\b|memory integrity|virtualization.based|kernel dma|\bvbs\b|secure launch/i },
  { area: "sso", title: /\bsso\b|single sign|platform sso|\bentra\b|kerberos|jamf connect|\bokta\b|federat|conditional access|passkey|\bfido\b|webauthn|primary refresh token|\bprt\b|hello for business/i },
  { area: "encryption", title: /bitlocker|filevault|encrypt|\bluks\b|dm-crypt|cryptsetup|data at rest/i, body: /bitlocker|filevault|cryptsetup|\bluks\b/i },
  { area: "updates", title: /\bupdates?\b|\bpatch|wsus|softwareupdate|upgrade|end of life|end-of-life|unsupported|supported release|servicing level|current version|security-relevant software|feature update|release/i },
  { area: "browsers", title: /\bedge\b|chrome|chromium|firefox|safari|\bbrowser/i },
  { area: "collaboration", title: /teams rooms|zoom rooms|webex|meeting room|signage|magicinfo|room system|conference/i },
  { area: "authentication", title: /password|passphrase|passcode|\blogon\b|\blogin\b|lock(out|ed)|smart ?card|\bpiv\b|\bcac\b|ntlm|credential|biometric|touch ?id|face ?id|\bpam\b|\bsudo\b|session lock|screen ?saver|inactivity|multifactor|multi-factor|\bmfa\b|authenticat|account|administrator|guest|\bsu\b|apple watch|hot corner/i },
  { area: "logging", title: /\baudit|\blog(ging|s|ged)?\b|event log|syslog|rsyslog|journal|auditd|\basl\b|diagnostic|crash report|time ?stamp/i },
  { area: "network", title: /firewall|ipv6|ipv4|\bsmb|\bssh\b|sshd|\btls\b|\bssl\b|cipher|wireless|wi-?fi|bluetooth|bonjour|airdrop|remote desktop|\brdp\b|winrm|\bdns\b|\bntp\b|chrony|proxy|\bvpn\b|\bport\b|protocol|network|remote management|screen sharing|file sharing|internet sharing|file shares?\b|\bnfs\b|\bftp\b|\bhttp|llmnr|netbios|icloud|handoff|continuity|nearby/i },
];

/** The area a check belongs to, from its title first and its procedure second; "other" when none fits. */
export function areaOf(item: { title: string; check: string | null; label?: string }): Area {
  for (const p of patterns) if (p.title.test(item.title)) return p.area;
  for (const p of patterns) if (p.body && item.check && p.body.test(item.check)) return p.area;
  return "other";
}

/** The platforms a plan can be built for: the builder's three (STIG and mSCP checks plus templates) and four that are templates only. */
export type PlanPlatform = FleetPlatform;

export function isPlanPlatform(value: unknown): value is PlanPlatform {
  return isFleetPlatform(value);
}

export function planPlatformName(p: PlanPlatform): string {
  return fleetPlatformName(p);
}

export interface PlanItem {
  id: string;
  area: Area;
  label: string;
  title: string;
  severity: string | null;
  /** Where the procedure comes from: the STIG, mSCP, or the owner's template file. */
  source: "stig" | "mscp" | "template";
  /** The check procedure, verbatim. */
  procedure: string | null;
  /** What a pass looks like, when the source states it (mSCP's expected result, a template's expect). */
  expected: string | null;
  /** What to do when it does not pass, when the template says. */
  fail: string | null;
  /** A link into the Register, or the publisher's document for a template step. */
  url: string | null;
  sourceTitle: string | null;
  /** Whether the step applies to the chosen release and hardware, and why not. */
  applicable: Applicability;
  /** Whether the person kept it (an inapplicable item is never kept). */
  included: boolean;
}

export type TemplatePlatform = PlanPlatform | "all";
const templatePlatforms: TemplatePlatform[] = ["windows", "macos", "linux", "ios", "ipados", "android", "collaboration", "all"];

export interface TemplateStep {
  do: string;
  expect: string | null;
  fail: string | null;
  applies: Applies;
  source: { title: string; url: string } | null;
}

export interface Template {
  id: string;
  title: string;
  platforms: TemplatePlatform[];
  area: Area;
  notes: string | null;
  /** Which releases and hardware the whole template is for; a step may narrow it further. */
  applies: Applies;
  steps: TemplateStep[];
  file: string;
}

export const templatesDir = path.join(import.meta.dirname, "..", "data", "test-plans");

type Json = Record<string, unknown>;
const obj = (v: unknown): Json => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Json) : {});
const str = (v: unknown): string | null => (typeof v === "string" && v.trim() !== "" ? v.trim() : null);

/** Every template file, in name order; a file that will not parse is reported, not fatal. */
export function loadTemplates(dir: string = templatesDir): { templates: Template[]; errors: string[] } {
  const templates: Template[] = [];
  const errors: string[] = [];
  let files: string[] = [];
  try {
    files = readdirSync(dir).filter((f) => /\.ya?ml$/i.test(f)).sort();
  } catch {
    return { templates, errors };
  }
  for (const file of files) {
    try {
      const doc = obj(parseYaml(readFileSync(path.join(dir, file), "utf8")));
      const id = str(doc.id) ?? file.replace(/\.ya?ml$/i, "");
      const title = str(doc.title);
      if (!title) throw new Error("no title");
      const platforms = (Array.isArray(doc.platforms) ? doc.platforms : ["all"]).map((p) => String(p)).filter((p): p is TemplatePlatform => (templatePlatforms as string[]).includes(p));
      const area = isArea(doc.area) ? doc.area : "other";
      const steps: TemplateStep[] = (Array.isArray(doc.steps) ? doc.steps : []).map((s) => {
        const step = obj(s);
        const source = obj(step.source);
        const sourceTitle = str(source.title);
        const sourceUrl = str(source.url);
        const what = str(step.do);
        if (!what) throw new Error("a step has no 'do'");
        return {
          do: what,
          expect: str(step.expect),
          fail: str(step.fail),
          applies: step.applies === undefined ? appliesToAll : parseApplies(step.applies),
          source: sourceTitle && sourceUrl && /^https:\/\//.test(sourceUrl) ? { title: sourceTitle, url: sourceUrl } : null,
        };
      });
      if (steps.length === 0) throw new Error("no steps");
      templates.push({ id, title, platforms: platforms.length ? platforms : ["all"], area, notes: str(doc.notes), applies: doc.applies === undefined ? appliesToAll : parseApplies(doc.applies), steps, file });
    } catch (error) {
      errors.push(`${file}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return { templates, errors };
}

export interface PlanOptions extends Omit<ProfileOptions, "platform"> {
  platform: PlanPlatform;
  /** Whether the owner's templates join the derived items (default yes). */
  templates?: boolean;
  /** The release id from the fleet (26H2, 27, rhel-10); unset means every release. */
  version?: string | undefined;
  /** The hardware id from the fleet (apple-silicon, tpm-2); unset means every family. */
  hardware?: string | undefined;
  /** The areas to test; unset means all of them. */
  areas?: Area[] | undefined;
}

export interface TestPlan {
  platform: PlanPlatform;
  /** The strict profile the derived checks come from; null on a templates-only platform. */
  profile: Profile | null;
  options: PlanOptions;
  release: Release | null;
  hardware: Hardware | null;
  /** The fleet's releases and hardware for the platform, for the selects. */
  choices: { releases: Release[]; hardware: Hardware[] };
  /** The areas being tested; every area the plan has checks in, unless narrowed. */
  areasChosen: Area[];
  items: PlanItem[];
  templates: Template[];
  templateErrors: string[];
  fleetErrors: string[];
  /** Templates left out whole because they do not apply to the chosen release or hardware. */
  skippedTemplates: { template: Template; reason: string }[];
  counts: { included: number; dropped: number; inapplicable: number; untested: number; derived: number; template: number; byArea: Record<Area, number> };
}

function derived(item: ProfileItem, dropped: Set<string>): PlanItem | null {
  if (item.kind !== "stig" && item.kind !== "mscp") return null;
  if (!item.check) return null;
  const id = `test:${item.id}`;
  return {
    id,
    area: areaOf({ title: item.title, check: item.check, label: item.label }),
    label: item.label,
    title: item.title,
    severity: item.severity,
    source: item.kind === "mscp" ? "mscp" : "stig",
    procedure: item.check,
    expected: null,
    fail: null,
    url: item.url,
    sourceTitle: null,
    applicable: { ok: true, reason: null },
    included: !dropped.has(id),
  };
}

/** The plan: derived checks from the strict profile's STIG and mSCP items, then the owner's templates that apply, grouped by area. */
export function buildTestPlan(db: DatabaseSync, options: PlanOptions, templateDir: string = templatesDir, fleet: Fleet = loadFleet()): TestPlan {
  const { platform } = options;
  const profile = isBuilderPlatform(platform) ? buildProfile(db, { ...options, platform, drop: [] }) : null;
  const release = findRelease(fleet, platform, options.version);
  const hardware = findHardware(fleet, options.hardware);
  const dropped = new Set(options.drop ?? []);
  const items: PlanItem[] = [];
  if (profile) {
    for (const item of profile.items) {
      const d = derived(item, dropped);
      if (d) items.push(d);
    }
  }
  const loaded = options.templates === false ? { templates: [], errors: [] } : loadTemplates(templateDir);
  const forPlatform = loaded.templates.filter((t) => t.platforms.includes("all") || t.platforms.includes(platform));
  const skippedTemplates: TestPlan["skippedTemplates"] = [];
  const templates = forPlatform.filter((t) => {
    const a = applicability(fleet, t.applies, release, hardware);
    if (!a.ok) skippedTemplates.push({ template: t, reason: a.reason ?? "does not apply" });
    return a.ok;
  });
  for (const t of templates) {
    t.steps.forEach((step, i) => {
      const id = `template:${t.id}:${i + 1}`;
      const applicable = applicability(fleet, step.applies, release, hardware);
      items.push({
        id,
        area: t.area,
        label: `${t.id} ${i + 1}`,
        title: step.do,
        severity: null,
        source: "template",
        procedure: null,
        expected: step.expect,
        fail: step.fail,
        url: step.source?.url ?? null,
        sourceTitle: step.source ? `${step.source.title} (${t.title})` : t.title,
        applicable,
        included: applicable.ok && !dropped.has(id),
      });
    });
  }
  const order = new Map(areas.map((a, i) => [a.id, i]));
  items.sort((a, b) => order.get(a.area)! - order.get(b.area)! || (a.source === "template" ? 1 : 0) - (b.source === "template" ? 1 : 0) || a.label.localeCompare(b.label, "en", { numeric: true }));
  const present = areas.map((a) => a.id).filter((id) => items.some((i) => i.area === id));
  const areasChosen = options.areas ? present.filter((id) => options.areas!.includes(id)) : present;
  const tested = (i: PlanItem) => i.included && areasChosen.includes(i.area);
  const byArea = Object.fromEntries(areas.map((a) => [a.id, 0])) as Record<Area, number>;
  for (const i of items) if (tested(i)) byArea[i.area] += 1;
  return {
    platform,
    profile,
    options,
    release,
    hardware,
    choices: { releases: releasesOf(fleet, platform), hardware: hardwareOf(fleet, platform) },
    areasChosen,
    items,
    templates,
    templateErrors: loaded.errors,
    fleetErrors: fleet.errors,
    skippedTemplates,
    counts: {
      included: items.filter(tested).length,
      dropped: items.filter((i) => !i.included && i.applicable.ok).length,
      inapplicable: items.filter((i) => !i.applicable.ok).length,
      untested: items.filter((i) => i.included && !areasChosen.includes(i.area)).length,
      derived: items.filter((i) => i.source !== "template" && tested(i)).length,
      template: items.filter((i) => i.source === "template" && tested(i)).length,
      byArea,
    },
  };
}

/** The items the export carries: kept, applicable, and in an area being tested. */
export function testedItems(plan: TestPlan): PlanItem[] {
  return plan.items.filter((i) => i.included && plan.areasChosen.includes(i.area));
}

/**
 * The page draws one area at a time, so a phone loads one area's procedures rather than the
 * whole plan: the form carries the other areas' dropped ids as hidden fields, so a redraw or an
 * export from any area covers the plan.
 */
export interface PlanArea {
  id: Area;
  label: string;
  items: PlanItem[];
  kept: number;
  /** Whether the area is among those being tested. */
  tested: boolean;
}

/** The areas the plan has checks in, in page order, each with its kept count. */
export function planAreas(plan: TestPlan): PlanArea[] {
  return areas
    .map((a) => {
      const items = plan.items.filter((i) => i.area === a.id);
      return { id: a.id, label: a.label, items, kept: items.filter((i) => i.included).length, tested: plan.areasChosen.includes(a.id) };
    })
    .filter((a) => a.items.length);
}

export type PlanFormat = "html" | "md" | "csv" | "json" | "tex" | "docx" | "pdf";

export const planFormats: { id: PlanFormat; label: string }[] = [
  { id: "html", label: "Printable checklist" },
  { id: "md", label: "Markdown" },
  { id: "csv", label: "CSV" },
  { id: "json", label: "JSON" },
  { id: "tex", label: "LaTeX" },
  { id: "docx", label: "Word" },
  { id: "pdf", label: "PDF" },
];

export function isPlanFormat(v: unknown): v is PlanFormat {
  return planFormats.some((f) => f.id === v);
}

function planTitle(plan: TestPlan): string {
  const c = plan.profile?.components;
  const scope = [plan.release?.label, plan.hardware?.label].filter((s): s is string => !!s).join(", ");
  const from = c?.stig ? `: ${c.stig.label}${c.mscp ? ` + ${c.mscp.label}` : ""}` : "";
  return `${planPlatformName(plan.platform)} test plan${from}${scope ? ` (${scope})` : ""}`;
}

function planAttribution(plan: TestPlan): string[] {
  const c = plan.profile?.components;
  const out: string[] = [];
  if (c?.stig) out.push(`Check procedures: DISA, ${c.stig.label} (US Government work, public domain).`);
  if (c?.mscp) out.push(`macOS checks and expected results: NIST macOS Security Compliance Project, ${c.mscp.label}.`);
  if (plan.counts.template) out.push(`Template steps are the owner's, kept in this instance's data/test-plans; each cites the publisher's document it follows.`);
  if (plan.release || plan.hardware) out.push(`Release and hardware facts are the vendors', kept in this instance's data/platforms.yaml with the page each came from.`);
  out.push("No CIS Benchmark text is included. Nothing in this document was written by a model.");
  return out;
}

const absolute = (url: string | null, base: string): string | null => (url && url.startsWith("/") ? `${base}${url}` : url);

interface Facts {
  title: string;
  stem: string;
  summary: string;
  grouped: { area: (typeof areas)[number]; items: PlanItem[] }[];
  notTested: { label: string; title: string; why: string }[];
}

function facts(plan: TestPlan, meta: { generatedAt: string; version: string }): Facts {
  const kept = testedItems(plan);
  const stem = `baselinewatch-${plan.platform}-tests${plan.release ? `-${plan.release.id.toLowerCase().replace(/[^a-z0-9]+/g, "-")}` : ""}${plan.profile?.components.stig ? `-${plan.profile.components.stig.key.replace(/^stig:/, "")}` : ""}`;
  const notTested: Facts["notTested"] = [];
  for (const i of plan.items) {
    if (!i.applicable.ok) notTested.push({ label: i.label, title: i.title, why: i.applicable.reason ?? "does not apply" });
    else if (i.included && !plan.areasChosen.includes(i.area)) notTested.push({ label: i.label, title: i.title, why: `${areaLabel(i.area)} is not being tested this time` });
  }
  for (const s of plan.skippedTemplates) notTested.push({ label: s.template.id, title: s.template.title, why: s.reason });
  return {
    title: planTitle(plan),
    stem,
    summary: `Generated by ${productName} ${meta.version} at ${meta.generatedAt}. ${plan.counts.included} checks: ${plan.counts.derived} from the publishers' procedures, ${plan.counts.template} from the owner's templates.${plan.release ? ` Release: ${plan.release.label}${plan.release.supportEnds ? ` (support: ${plan.release.supportEnds})` : ""}.` : ""}${plan.hardware ? ` Hardware: ${plan.hardware.label}.` : ""}`,
    grouped: areas.map((a) => ({ area: a, items: kept.filter((i) => i.area === a.id) })).filter((g) => g.items.length),
    notTested,
  };
}

/** The plan as a document: the same blocks the LaTeX, Word and PDF renderers draw. */
export function planBlocks(plan: TestPlan, meta: { baseUrl: string; generatedAt: string; version: string }): Block[] {
  const f = facts(plan, meta);
  const blocks: Block[] = [{ type: "title", text: f.title }, { type: "subtitle", text: f.summary }];
  if (plan.release) {
    blocks.push({ type: "h1", text: "The release under test" });
    const rows: string[][] = [["Release", plan.release.label]];
    if (plan.release.released) rows.push(["Released", plan.release.released]);
    if (plan.release.supportEnds) rows.push(["Support", plan.release.supportEnds]);
    if (plan.hardware) rows.push(["Hardware", `${plan.hardware.label}${plan.hardware.note ? `. ${plan.hardware.note}` : ""}`]);
    if (plan.release.models) rows.push(["Models", plan.release.models]);
    if (plan.release.baselines.length) rows.push(["Baselines", plan.release.baselines.join("; ")]);
    blocks.push({ type: "table", header: ["Fact", "Value"], rows });
    for (const n of plan.release.notes) blocks.push({ type: "bullet", runs: [n] });
  }
  for (const g of f.grouped) {
    blocks.push({ type: "h1", text: `${g.area.label} (${g.items.length})` });
    for (const i of g.items) {
      const head: Inline[] = [{ text: i.label, bold: true }, ` ${i.title}`];
      if (i.severity) head.push(` (${i.severity})`);
      blocks.push({ type: "check", runs: head });
      if (i.procedure) blocks.push({ type: "code", text: i.procedure });
      if (i.expected) blocks.push({ type: "p", runs: [{ text: "Success looks like: ", bold: true }, i.expected] });
      if (i.fail) blocks.push({ type: "p", runs: [{ text: "If it does not: ", bold: true }, i.fail] });
      if (i.sourceTitle || i.url) blocks.push({ type: "p", runs: [{ text: "Source: ", bold: true }, `${i.sourceTitle ?? ""}${i.url ? ` ${absolute(i.url, meta.baseUrl)}` : ""}`.trim()] });
      blocks.push({ type: "p", runs: ["Result: ☐ Pass ☐ Fail ☐ N/A   Evidence: ________   Tester: ________   Date: ________"] });
    }
  }
  if (f.notTested.length) {
    blocks.push({ type: "h1", text: "Not tested, and why" });
    blocks.push({ type: "table", header: ["Check", "Why"], rows: f.notTested.map((n) => [`${n.label}: ${n.title}`, n.why]) });
  }
  blocks.push({ type: "h1", text: "Findings and exceptions" });
  blocks.push({ type: "table", header: ["#", "Check", "Finding", "Severity", "Remediation or acceptance", "Owner", "Due"], rows: [["1", "", "", "", "", "", ""], ["2", "", "", "", "", "", ""]] });
  blocks.push({ type: "h1", text: "Sign-off" });
  blocks.push({ type: "table", header: ["Role", "Name", "Signature", "Date"], rows: [["Prepared by", "", "", ""], ["Reviewed by", "", "", ""], ["Approved by", "", "", ""]] });
  blocks.push({ type: "h1", text: "Attribution" });
  for (const l of planAttribution(plan)) blocks.push({ type: "bullet", runs: [l] });
  return blocks;
}

/** The plan as a checklist or a report in one of the seven formats. */
export function exportPlan(plan: TestPlan, format: PlanFormat, meta: { baseUrl: string; generatedAt: string; version: string }): { body: string | Uint8Array; contentType: string; filename: string } {
  const f = facts(plan, meta);
  const kept = testedItems(plan);
  if (format === "tex") return { body: renderLatex(planBlocks(plan, meta)), contentType: "application/x-tex; charset=utf-8", filename: `${f.stem}.tex` };
  if (format === "docx") return { body: renderDocx(planBlocks(plan, meta)), contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", filename: `${f.stem}.docx` };
  if (format === "pdf") return { body: renderPdf(planBlocks(plan, meta)), contentType: "application/pdf", filename: `${f.stem}.pdf` };
  if (format === "json") {
    const body = JSON.stringify(
      {
        product: `${productName} ${meta.version}`,
        generatedAt: meta.generatedAt,
        title: f.title,
        platform: plan.platform,
        release: plan.release,
        hardware: plan.hardware,
        areas: plan.areasChosen,
        components: plan.profile?.components ?? null,
        counts: plan.counts,
        attribution: planAttribution(plan),
        items: kept.map((i) => ({ ...i, area: areaLabel(i.area), url: absolute(i.url, meta.baseUrl) })),
        notTested: f.notTested,
      },
      null,
      1,
    );
    return { body: `${body}\n`, contentType: "application/json; charset=utf-8", filename: `${f.stem}.json` };
  }
  if (format === "csv") {
    const cell = (v: unknown) => {
      const s = v === null || v === undefined ? "" : String(v);
      return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const rows = ["done,area,id,severity,title,source,procedure,expected,if not,reference"];
    for (const i of kept) rows.push(["", areaLabel(i.area), i.label, i.severity ?? "", i.title, i.source === "template" ? (i.sourceTitle ?? "template") : i.source.toUpperCase(), i.procedure ?? "", i.expected ?? "", i.fail ?? "", absolute(i.url, meta.baseUrl) ?? ""].map(cell).join(","));
    return { body: `${rows.join("\r\n")}\r\n`, contentType: "text/csv; charset=utf-8", filename: `${f.stem}.csv` };
  }
  if (format === "md") {
    const out: string[] = [`# ${f.title}`, "", f.summary, ""];
    if (plan.release) {
      out.push("## The release under test", "", `- **Release:** ${plan.release.label}${plan.release.released ? ` (released ${plan.release.released})` : ""}`);
      if (plan.release.supportEnds) out.push(`- **Support:** ${plan.release.supportEnds}`);
      if (plan.hardware) out.push(`- **Hardware:** ${plan.hardware.label}${plan.hardware.note ? `. ${plan.hardware.note}` : ""}`);
      if (plan.release.models) out.push(`- **Models:** ${plan.release.models}`);
      for (const b of plan.release.baselines) out.push(`- **Baseline:** ${b}`);
      for (const n of plan.release.notes) out.push(`- ${n}`);
      out.push("");
    }
    for (const g of f.grouped) {
      out.push(`## ${g.area.label} (${g.items.length})`, "");
      for (const i of g.items) {
        out.push(`- [ ] **${i.label}** ${i.title}${i.severity ? ` (${i.severity})` : ""}${i.sourceTitle ? ` — ${i.sourceTitle}` : ""}`);
        if (i.procedure) out.push("", "  ```", ...i.procedure.split("\n").map((l) => `  ${l}`), "  ```", "");
        if (i.expected) out.push(`  - Success looks like: ${i.expected}`);
        if (i.fail) out.push(`  - If it does not: ${i.fail}`);
        if (i.url) out.push(`  - Reference: ${absolute(i.url, meta.baseUrl)}`);
        out.push("  - Result: ☐ Pass ☐ Fail ☐ N/A · Evidence: ____ · Tester: ____ · Date: ____");
      }
      out.push("");
    }
    if (f.notTested.length) {
      out.push("## Not tested, and why", "");
      for (const n of f.notTested) out.push(`- **${n.label}** ${n.title}: ${n.why}.`);
      out.push("");
    }
    out.push("## Findings and exceptions", "", "| # | Check | Finding | Severity | Remediation or acceptance | Owner | Due |", "| --- | --- | --- | --- | --- | --- | --- |", "| 1 |  |  |  |  |  |  |", "");
    out.push("## Sign-off", "", "| Role | Name | Signature | Date |", "| --- | --- | --- | --- |", "| Prepared by |  |  |  |", "| Reviewed by |  |  |  |", "| Approved by |  |  |  |", "");
    out.push("## Attribution", "", ...planAttribution(plan).map((l) => `- ${l}`), "");
    return { body: out.join("\n"), contentType: "text/markdown; charset=utf-8", filename: `${f.stem}.md` };
  }
  const e = escapeHtml;
  const parts: string[] = [`<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${e(f.title)}</title><link rel="stylesheet" href="${e(meta.baseUrl)}/assets/app.css"></head><body><main class="wrap export">`];
  parts.push(`<h1>${e(f.title)}</h1><p>${e(f.summary)}</p>`);
  if (plan.release) {
    parts.push(`<section><h2>The release under test</h2><dl class="kv"><dt>Release</dt><dd>${e(plan.release.label)}${plan.release.released ? ` (released ${e(plan.release.released)})` : ""}</dd>${plan.release.supportEnds ? `<dt>Support</dt><dd>${e(plan.release.supportEnds)}</dd>` : ""}${plan.hardware ? `<dt>Hardware</dt><dd>${e(plan.hardware.label)}${plan.hardware.note ? `. ${e(plan.hardware.note)}` : ""}</dd>` : ""}${plan.release.models ? `<dt>Models</dt><dd>${e(plan.release.models)}</dd>` : ""}${plan.release.baselines.length ? `<dt>Baselines</dt><dd>${plan.release.baselines.map(e).join("; ")}</dd>` : ""}</dl>${plan.release.notes.length ? `<ul>${plan.release.notes.map((n) => `<li>${e(n)}</li>`).join("")}</ul>` : ""}</section>`);
  }
  for (const g of f.grouped) {
    parts.push(`<section><h2>${e(g.area.label)} <small>(${g.items.length})</small></h2><ol class="checklist">`);
    for (const i of g.items) {
      const ref = absolute(i.url, meta.baseUrl);
      parts.push(`<li class="export-item"><label><input type="checkbox"> <code>${e(i.label)}</code> ${e(i.title)}${i.severity ? ` <small>${e(i.severity)}</small>` : ""}</label>${i.sourceTitle ? `<div><small>${e(i.sourceTitle)}</small></div>` : ""}${i.procedure ? `<pre>${e(i.procedure)}</pre>` : ""}${i.expected ? `<div><b>Success looks like:</b> ${e(i.expected)}</div>` : ""}${i.fail ? `<div><b>If it does not:</b> ${e(i.fail)}</div>` : ""}${ref ? `<div><a href="${e(ref)}">${e(ref)}</a></div>` : ""}<div><small>Result: ☐ Pass ☐ Fail ☐ N/A · Evidence: ____ · Tester: ____ · Date: ____</small></div></li>`);
    }
    parts.push("</ol></section>");
  }
  if (f.notTested.length) parts.push(`<section><h2>Not tested, and why</h2><ul>${f.notTested.map((n) => `<li><code>${e(n.label)}</code> ${e(n.title)}: ${e(n.why)}.</li>`).join("")}</ul></section>`);
  parts.push(`<footer><h2>Attribution</h2><ul>${planAttribution(plan)
    .map((l) => `<li>${e(l)}</li>`)
    .join("")}</ul></footer></main></body></html>\n`);
  return { body: parts.join("\n"), contentType: "text/html; charset=utf-8", filename: `${f.stem}.html` };
}
