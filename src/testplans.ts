import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { parse as parseYaml } from "yaml";
import { buildProfile, type BuilderPlatform, type Profile, type ProfileItem, type ProfileOptions } from "./baselines.ts";
import { escapeHtml } from "./html.ts";
import { productName } from "./version.ts";

/**
 * Test plans: what to test when a new OS release lands so the baseline still holds. Derived from
 * the STIG and mSCP check procedures of the strict profile, grouped by area, plus the owner's
 * templates kept as YAML under data/test-plans (SSO with each browser, disk-encryption key escrow,
 * conditional access, enrolment), each step citing the publisher's document it comes from. The
 * derived items are the publishers' words; the templates are labelled as the owner's.
 */

export type Area = "authentication" | "browsers" | "encryption" | "logging" | "network" | "updates" | "mdm" | "other";

export const areas: { id: Area; label: string }[] = [
  { id: "authentication", label: "Authentication and SSO" },
  { id: "browsers", label: "Browsers" },
  { id: "encryption", label: "Disk encryption" },
  { id: "logging", label: "Logging and audit" },
  { id: "network", label: "Network" },
  { id: "updates", label: "Updates" },
  { id: "mdm", label: "MDM enrolment" },
  { id: "other", label: "Everything else" },
];

export function areaLabel(id: Area): string {
  return areas.find((a) => a.id === id)?.label ?? id;
}

const patterns: { area: Area; title: RegExp; body?: RegExp }[] = [
  { area: "mdm", title: /\bmdm\b|enrol|enroll|device management|managed by|management profile|supervis/i },
  { area: "encryption", title: /bitlocker|filevault|encrypt|\bluks\b|dm-crypt|cryptsetup|\btpm\b|secure enclave|data at rest/i, body: /bitlocker|filevault|cryptsetup|\bluks\b/i },
  { area: "updates", title: /\bupdates?\b|\bpatch|wsus|softwareupdate|upgrade|end of life|end-of-life|unsupported|supported release|servicing level|current version|security-relevant software/i },
  { area: "browsers", title: /\bedge\b|chrome|chromium|firefox|safari|\bbrowser/i },
  { area: "authentication", title: /password|passphrase|passcode|\blogon\b|\blogin\b|lock(out|ed)|smart ?card|\bpiv\b|\bcac\b|kerberos|ntlm|\bsso\b|single sign|credential|biometric|touch ?id|face ?id|\bpam\b|\bsudo\b|session lock|screen ?saver|inactivity|multifactor|multi-factor|\bmfa\b|authenticat|account|administrator|guest|\bsu\b|apple watch|hot corner/i },
  { area: "logging", title: /\baudit|\blog(ging|s|ged)?\b|event log|syslog|rsyslog|journal|auditd|\basl\b|diagnostic|crash report|time ?stamp/i },
  { area: "network", title: /firewall|ipv6|ipv4|\bsmb|\bssh\b|sshd|\btls\b|\bssl\b|cipher|wireless|wi-?fi|bluetooth|bonjour|airdrop|remote desktop|\brdp\b|winrm|\bdns\b|\bntp\b|chrony|proxy|\bvpn\b|\bport\b|protocol|network|remote management|screen sharing|file sharing|internet sharing|file shares?\b|\bnfs\b|\bftp\b|\bhttp|llmnr|netbios|icloud|handoff|continuity|nearby/i },
];

/** The area a check belongs to, from its title first and its procedure second; "other" when none fits. */
export function areaOf(item: { title: string; check: string | null; label?: string }): Area {
  for (const p of patterns) if (p.title.test(item.title)) return p.area;
  for (const p of patterns) if (p.body && item.check && p.body.test(item.check)) return p.area;
  return "other";
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
  /** What a pass looks like, when the source states it (mSCP's expected result). */
  expected: string | null;
  /** A link into the Register, or the publisher's document for a template step. */
  url: string | null;
  sourceTitle: string | null;
  included: boolean;
}

export interface Template {
  id: string;
  title: string;
  platforms: ("windows" | "macos" | "linux" | "all")[];
  area: Area;
  notes: string | null;
  steps: { do: string; expect: string | null; source: { title: string; url: string } | null }[];
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
      const platforms = (Array.isArray(doc.platforms) ? doc.platforms : ["all"]).map((p) => String(p)).filter((p): p is Template["platforms"][number] => ["windows", "macos", "linux", "all"].includes(p));
      const area = areas.some((a) => a.id === doc.area) ? (doc.area as Area) : "other";
      const steps = (Array.isArray(doc.steps) ? doc.steps : []).map((s) => {
        const step = obj(s);
        const source = obj(step.source);
        const sourceTitle = str(source.title);
        const sourceUrl = str(source.url);
        const what = str(step.do);
        if (!what) throw new Error("a step has no 'do'");
        return { do: what, expect: str(step.expect), source: sourceTitle && sourceUrl && /^https:\/\//.test(sourceUrl) ? { title: sourceTitle, url: sourceUrl } : null };
      });
      if (steps.length === 0) throw new Error("no steps");
      templates.push({ id, title, platforms: platforms.length ? platforms : ["all"], area, notes: str(doc.notes), steps, file });
    } catch (error) {
      errors.push(`${file}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return { templates, errors };
}

export interface PlanOptions extends ProfileOptions {
  /** Whether the owner's templates join the derived items (default yes). */
  templates?: boolean;
}

export interface TestPlan {
  platform: BuilderPlatform;
  profile: Profile;
  options: PlanOptions;
  items: PlanItem[];
  templates: Template[];
  templateErrors: string[];
  counts: { included: number; dropped: number; derived: number; template: number; byArea: Record<Area, number> };
}

function derived(item: ProfileItem, dropped: Set<string>): PlanItem | null {
  if (item.kind !== "stig" && item.kind !== "mscp") return null;
  if (!item.check) return null;
  const id = `test:${item.id}`;
  const expected = item.mscp && item.kind === "stig" ? null : null;
  return {
    id,
    area: areaOf({ title: item.title, check: item.check, label: item.label }),
    label: item.label,
    title: item.title,
    severity: item.severity,
    source: item.kind === "mscp" ? "mscp" : "stig",
    procedure: item.check,
    expected,
    url: item.url,
    sourceTitle: null,
    included: !dropped.has(id),
  };
}

/** The plan: derived checks from the strict profile's STIG and mSCP items, then the owner's templates, grouped by area. */
export function buildTestPlan(db: DatabaseSync, options: PlanOptions, templateDir: string = templatesDir): TestPlan {
  const profile = buildProfile(db, { ...options, drop: [] });
  const dropped = new Set(options.drop ?? []);
  const items: PlanItem[] = [];
  for (const item of profile.items) {
    const d = derived(item, dropped);
    if (d) items.push(d);
  }
  // mSCP states an expected result; carry it onto the derived item of the rule it joined.
  const byMscp = new Map<string, ProfileItem>();
  for (const item of profile.items) if (item.mscp) byMscp.set(item.id, item);
  const loaded = options.templates === false ? { templates: [], errors: [] } : loadTemplates(templateDir);
  const templates = loaded.templates.filter((t) => t.platforms.includes("all") || t.platforms.includes(options.platform));
  for (const t of templates) {
    t.steps.forEach((step, i) => {
      const id = `template:${t.id}:${i + 1}`;
      items.push({
        id,
        area: t.area,
        label: `${t.id} ${i + 1}`,
        title: step.do,
        severity: null,
        source: "template",
        procedure: null,
        expected: step.expect,
        url: step.source?.url ?? null,
        sourceTitle: step.source ? `${step.source.title} (${t.title})` : t.title,
        included: !dropped.has(id),
      });
    });
  }
  const order = new Map(areas.map((a, i) => [a.id, i]));
  items.sort((a, b) => order.get(a.area)! - order.get(b.area)! || (a.source === "template" ? 1 : 0) - (b.source === "template" ? 1 : 0) || a.label.localeCompare(b.label, "en", { numeric: true }));
  const byArea = Object.fromEntries(areas.map((a) => [a.id, 0])) as Record<Area, number>;
  for (const i of items) if (i.included) byArea[i.area] += 1;
  return {
    platform: options.platform,
    profile,
    options,
    items,
    templates,
    templateErrors: loaded.errors,
    counts: {
      included: items.filter((i) => i.included).length,
      dropped: items.filter((i) => !i.included).length,
      derived: items.filter((i) => i.source !== "template" && i.included).length,
      template: items.filter((i) => i.source === "template" && i.included).length,
      byArea,
    },
  };
}

export type PlanFormat = "html" | "md" | "csv" | "json";

export function isPlanFormat(v: unknown): v is PlanFormat {
  return v === "html" || v === "md" || v === "csv" || v === "json";
}

function planTitle(plan: TestPlan): string {
  const c = plan.profile.components;
  return `${plan.platform === "macos" ? "macOS" : plan.platform.charAt(0).toUpperCase() + plan.platform.slice(1)} test plan${c.stig ? `: ${c.stig.label}` : ""}${c.mscp ? ` + ${c.mscp.label}` : ""}`;
}

function planAttribution(plan: TestPlan): string[] {
  const c = plan.profile.components;
  const out: string[] = [];
  if (c.stig) out.push(`Check procedures: DISA, ${c.stig.label} (US Government work, public domain).`);
  if (c.mscp) out.push(`macOS checks and expected results: NIST macOS Security Compliance Project, ${c.mscp.label}.`);
  if (plan.counts.template) out.push(`Template steps are the owner's, kept in this instance's data/test-plans; each cites the publisher's document it follows.`);
  out.push("No CIS Benchmark text is included. Nothing in this document was written by a model.");
  return out;
}

/** The plan as a checklist in one of the four formats. */
export function exportPlan(plan: TestPlan, format: PlanFormat, meta: { baseUrl: string; generatedAt: string; version: string }): { body: string; contentType: string; filename: string } {
  const stem = `baselinewatch-${plan.platform}-tests${plan.profile.components.stig ? `-${plan.profile.components.stig.key.replace(/^stig:/, "")}` : ""}`;
  const kept = plan.items.filter((i) => i.included);
  const grouped = areas.map((a) => ({ area: a, items: kept.filter((i) => i.area === a.id) })).filter((g) => g.items.length);
  if (format === "json") {
    const body = JSON.stringify(
      {
        product: `${productName} ${meta.version}`,
        generatedAt: meta.generatedAt,
        title: planTitle(plan),
        platform: plan.platform,
        components: plan.profile.components,
        counts: plan.counts,
        attribution: planAttribution(plan),
        items: kept.map((i) => ({ ...i, area: areaLabel(i.area), url: i.url && i.url.startsWith("/") ? `${meta.baseUrl}${i.url}` : i.url })),
      },
      null,
      1,
    );
    return { body: `${body}\n`, contentType: "application/json; charset=utf-8", filename: `${stem}.json` };
  }
  if (format === "csv") {
    const cell = (v: unknown) => {
      const s = v === null || v === undefined ? "" : String(v);
      return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const rows = ["done,area,id,severity,title,source,procedure,expected,reference"];
    for (const i of kept) rows.push(["", areaLabel(i.area), i.label, i.severity ?? "", i.title, i.source === "template" ? (i.sourceTitle ?? "template") : i.source.toUpperCase(), i.procedure ?? "", i.expected ?? "", i.url && i.url.startsWith("/") ? `${meta.baseUrl}${i.url}` : (i.url ?? "")].map(cell).join(","));
    return { body: `${rows.join("\r\n")}\r\n`, contentType: "text/csv; charset=utf-8", filename: `${stem}.csv` };
  }
  if (format === "md") {
    const out: string[] = [`# ${planTitle(plan)}`, "", `Generated by ${productName} ${meta.version} at ${meta.generatedAt}. ${plan.counts.included} checks: ${plan.counts.derived} from the publishers' procedures, ${plan.counts.template} from the owner's templates.`, ""];
    for (const g of grouped) {
      out.push(`## ${g.area.label} (${g.items.length})`, "");
      for (const i of g.items) {
        out.push(`- [ ] **${i.label}** ${i.title}${i.severity ? ` (${i.severity})` : ""}${i.sourceTitle ? ` — ${i.sourceTitle}` : ""}`);
        if (i.procedure) out.push("", "  ```", ...i.procedure.split("\n").map((l) => `  ${l}`), "  ```", "");
        if (i.expected) out.push(`  - Expect: ${i.expected}`);
        if (i.url) out.push(`  - Reference: ${i.url.startsWith("/") ? `${meta.baseUrl}${i.url}` : i.url}`);
      }
      out.push("");
    }
    out.push("## Attribution", "", ...planAttribution(plan).map((l) => `- ${l}`), "");
    return { body: out.join("\n"), contentType: "text/markdown; charset=utf-8", filename: `${stem}.md` };
  }
  const e = escapeHtml;
  const parts: string[] = [`<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${e(planTitle(plan))}</title><link rel="stylesheet" href="${e(meta.baseUrl)}/assets/app.css"></head><body><main class="wrap export">`];
  parts.push(`<h1>${e(planTitle(plan))}</h1><p>Generated by ${e(productName)} ${e(meta.version)} at ${e(meta.generatedAt)}. ${plan.counts.included} checks: ${plan.counts.derived} from the publishers' procedures, ${plan.counts.template} from the owner's templates.</p>`);
  for (const g of grouped) {
    parts.push(`<section><h2>${e(g.area.label)} <small>(${g.items.length})</small></h2><ol class="checklist">`);
    for (const i of g.items) {
      parts.push(`<li class="export-item"><label><input type="checkbox"> <code>${e(i.label)}</code> ${e(i.title)}${i.severity ? ` <small>${e(i.severity)}</small>` : ""}</label>${i.sourceTitle ? `<div><small>${e(i.sourceTitle)}</small></div>` : ""}${i.procedure ? `<pre>${e(i.procedure)}</pre>` : ""}${i.expected ? `<div>Expect: ${e(i.expected)}</div>` : ""}${i.url ? `<div><a href="${e(i.url.startsWith("/") ? `${meta.baseUrl}${i.url}` : i.url)}">${e(i.url.startsWith("/") ? `${meta.baseUrl}${i.url}` : i.url)}</a></div>` : ""}</li>`);
    }
    parts.push("</ol></section>");
  }
  parts.push(`<footer><h2>Attribution</h2><ul>${planAttribution(plan)
    .map((l) => `<li>${e(l)}</li>`)
    .join("")}</ul></footer></main></body></html>\n`);
  return { body: parts.join("\n"), contentType: "text/html; charset=utf-8", filename: `${stem}.html` };
}
