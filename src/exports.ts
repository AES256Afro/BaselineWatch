import { escapeHtml } from "./html.ts";
import type { Profile, ProfileItem } from "./baselines.ts";
import { csvCell } from "./csv.ts";
import { controlLabel } from "./stigs.ts";
import { productName } from "./version.ts";

/**
 * The profile as a reader who is not the owner may carry it away. Microsoft's baseline values
 * are the owner's own copy, quoted on screen only (AGENTS.md), so a public export leaves out the
 * settings Microsoft adds and the value it names on each STIG rule.
 */
export function publicProfile(profile: Profile): Profile {
  if (!profile.components.sct && !profile.items.some((i) => i.kind === "sct" || i.sctValue !== null)) return profile;
  const items = profile.items.filter((i) => i.kind !== "sct").map((i) => (i.sctValue === null ? i : { ...i, sctValue: null }));
  return {
    ...profile,
    components: { ...profile.components, sct: null },
    items,
    counts: { ...profile.counts, included: items.filter((i) => i.included).length, dropped: items.filter((i) => !i.included).length },
  };
}

/**
 * The profile as a guide: printable HTML, Markdown, CSV or JSON, in an "apply with" flavour.
 * Every line is a quote or a derived field from the sources the page names; the attribution
 * travels with the export. CIS text never appears here, and Microsoft's values appear only as
 * the page quotes them.
 */

export type ExportFormat = "html" | "md" | "csv" | "json";
export type Flavour = "plain" | "jamf" | "intune" | "linux";

export const exportFormats: ExportFormat[] = ["html", "md", "csv", "json"];
export const flavours: { id: Flavour; label: string; blurb: string }[] = [
  { id: "plain", label: "Plain", blurb: "Every field: check, fix, controls, registry, payloads, Intune and DISA's checklist." },
  { id: "jamf", label: "Jamf", blurb: "The mSCP rule id and the configuration-profile payload domain and keys for each rule." },
  { id: "intune", label: "Intune", blurb: "The settings-catalog definition DISA uses, the Group Policy path, the registry value, and DISA's checklist verdict." },
  { id: "linux", label: "Linux", blurb: "The STIG fix procedure, verbatim, with the check." },
];

export function isExportFormat(v: unknown): v is ExportFormat {
  return typeof v === "string" && (exportFormats as string[]).includes(v);
}

export function isFlavour(v: unknown): v is Flavour {
  return typeof v === "string" && flavours.some((f) => f.id === v);
}

export interface ExportMeta {
  baseUrl: string;
  generatedAt: string;
  version: string;
}

/** Who the words belong to, for the foot of every export. */
export function attribution(profile: Profile): string[] {
  const c = profile.components;
  const lines: string[] = [];
  if (c.stig) lines.push(`STIG rules, check and fix text: DISA, ${c.stig.label} (US Government work, public domain).`);
  if (c.cciVersion) lines.push(`Rule-to-control mapping: DISA Control Correlation Identifier list ${c.cciVersion} (public domain).`);
  if (c.controls) lines.push(`Controls: NIST SP 800-53 Revision 5 and its High baseline, ${c.controls.version ?? ""} (public domain).`);
  if (c.mscp) lines.push(`macOS rules, payload keys and values: NIST macOS Security Compliance Project, ${c.mscp.label}.`);
  if (c.sct) lines.push(`Microsoft baseline values: Microsoft Security Compliance Toolkit, ${c.sct.label}, quoted from your own copy under Microsoft's licence; not redistributed.`);
  if (c.intune) lines.push(`Intune settings-catalog definitions and values: DISA STIG Intune Policy Package, ${c.intune.version ?? ""} (${c.intune.label}).`);
  if (c.checklist) lines.push(`Checklist verdicts: DISA STIG GPO Package, ${c.checklist.version ?? ""} (${c.checklist.label}).`);
  lines.push("No CIS Benchmark text is included. Nothing in this document was written by a model.");
  return lines;
}

const kindLabel: Record<ProfileItem["kind"], string> = { stig: "STIG rule", sct: "Microsoft baseline setting", mscp: "mSCP rule", control: "SP 800-53 control" };

function sections(profile: Profile): { section: string; items: ProfileItem[] }[] {
  const out: { section: string; items: ProfileItem[] }[] = [];
  for (const item of profile.items.filter((i) => i.included)) {
    const last = out[out.length - 1];
    if (last && last.section === item.section) last.items.push(item);
    else out.push({ section: item.section, items: [item] });
  }
  return out;
}

const regText = (r: ProfileItem["registry"][number]): string => `${r.hive}\\${r.key}\\${r.value}${r.type ? ` (${r.type})` : ""}${r.data ? ` = ${r.data}` : ""}`;
const payloadText = (item: ProfileItem): string => (item.mscp ? item.mscp.payloads.map((p) => `${p.domain}: ${JSON.stringify(p.keys)}`).join("; ") : "");
const intuneText = (item: ProfileItem): string => item.intune.map((s) => `${s.definitionId} = ${s.value}`).join("; ");
const checklistText = (item: ProfileItem): string => (item.checklist ? `${item.checklist.label}${item.checklist.comment ? `: ${item.checklist.comment}` : ""}` : "");
const controlsText = (item: ProfileItem): string => item.controls.map(controlLabel).join(", ");

/** The "apply with" lines for one item in a flavour, in words a person can act on. */
export function applyLines(item: ProfileItem, flavour: Flavour): { label: string; text: string }[] {
  const lines: { label: string; text: string }[] = [];
  const push = (label: string, text: string | null | undefined) => {
    if (text && text.trim() !== "") lines.push({ label, text: text.trim() });
  };
  if (item.kind === "control") {
    push("Implemented by", item.implementedBy.length ? item.implementedBy.join(", ") : "no technical rule in this profile; an organisational control");
    return lines;
  }
  if (flavour === "jamf" || flavour === "plain") {
    if (item.mscp) {
      push("mSCP rule", item.mscp.id);
      push("Profile payload", item.mscp.payloads.length ? payloadText(item) : "none; see the fix");
      if (item.mscp.ddm) push("Declarative management", JSON.stringify(item.mscp.ddm));
      if (item.mscp.odv) push("Organisation-defined values", JSON.stringify(item.mscp.odv));
    } else if (flavour === "jamf" && item.kind === "stig") push("mSCP rule", "none for this STIG id; apply by the fix text");
  }
  if (flavour === "intune" || flavour === "plain") {
    push("Settings catalog (DISA's policy)", item.intune.length ? intuneText(item) : item.kind === "stig" && (item.gpoPath || item.registry.length) ? "no matching definition in DISA's package" : null);
    push("Group Policy path", item.gpoPath ? `${item.gpoPath.path} >> "${item.gpoPath.setting}"` : null);
    push("Registry", item.registry.length ? item.registry.map(regText).join("; ") : null);
    push("DISA checklist", checklistText(item));
    push("Microsoft baseline value", item.sctValue);
  }
  if (flavour === "linux" || flavour === "plain") {
    push("Fix", item.fix);
  }
  if (flavour === "plain") push("Check", item.check);
  if (flavour === "linux" && !item.fix) push("Fix", "no fix text published for this item");
  return lines;
}

function fileStem(profile: Profile): string {
  const stig = profile.components.stig?.key.replace(/^stig:/, "") ?? profile.platform;
  return `baselinewatch-${profile.platform}-${stig}${profile.components.stig?.version ? `-${profile.components.stig.version}` : ""}`.toLowerCase().replace(/[^a-z0-9.-]+/g, "-");
}

export function exportProfile(profile: Profile, format: ExportFormat, flavour: Flavour, meta: ExportMeta): { body: string; contentType: string; filename: string } {
  const stem = `${fileStem(profile)}-${flavour}`;
  switch (format) {
    case "json":
      return { body: toJson(profile, flavour, meta), contentType: "application/json; charset=utf-8", filename: `${stem}.json` };
    case "csv":
      return { body: toCsv(profile, flavour), contentType: "text/csv; charset=utf-8", filename: `${stem}.csv` };
    case "md":
      return { body: toMarkdown(profile, flavour, meta), contentType: "text/markdown; charset=utf-8", filename: `${stem}.md` };
    case "html":
      return { body: toHtml(profile, flavour, meta), contentType: "text/html; charset=utf-8", filename: `${stem}.html` };
  }
}

function title(profile: Profile): string {
  const c = profile.components;
  return `${profile.platform === "macos" ? "macOS" : profile.platform.charAt(0).toUpperCase() + profile.platform.slice(1)} strictest published profile${c.stig ? `: ${c.stig.label}` : ""}`;
}

function componentsList(profile: Profile): string[] {
  const c = profile.components;
  const out: string[] = [];
  if (c.stig) out.push(`STIG: ${c.stig.label}${c.stig.publishedAt ? ` (${c.stig.publishedAt.slice(0, 10)})` : ""}`);
  if (c.sct) out.push(`Microsoft baseline: ${c.sct.label}`);
  if (c.mscp) out.push(`mSCP: ${c.mscp.label}`);
  if (c.controls) out.push(`Controls: ${c.controls.label}`);
  if (c.intune) out.push(`DISA Intune policy: ${c.intune.label} (${c.intune.version ?? ""})`);
  if (c.checklist) out.push(`DISA checklist: ${c.checklist.label} (${c.checklist.version ?? ""})`);
  return out;
}

function toJson(profile: Profile, flavour: Flavour, meta: ExportMeta): string {
  const items = profile.items
    .filter((i) => i.included)
    .map((i) => ({
      id: i.id,
      kind: i.kind,
      section: i.section,
      label: i.label,
      title: i.title,
      severity: i.severity,
      controls: i.controls.map(controlLabel),
      stigIds: i.stigIds,
      mscp: i.mscp,
      registry: i.registry,
      gpoPath: i.gpoPath,
      intune: i.intune,
      checklist: i.checklist,
      microsoftBaselineValue: i.sctValue,
      implementedBy: i.implementedBy,
      url: `${meta.baseUrl}${i.url}`,
      ...(flavour === "plain" || flavour === "linux" ? { check: i.check, fix: i.fix } : {}),
      apply: applyLines(i, flavour),
    }));
  return `${JSON.stringify(
    {
      product: `${productName} ${meta.version}`,
      generatedAt: meta.generatedAt,
      title: title(profile),
      platform: profile.platform,
      flavour,
      components: profile.components,
      counts: profile.counts,
      dropped: profile.items.filter((i) => !i.included).map((i) => i.id),
      attribution: attribution(profile),
      items,
    },
    null,
    1,
  )}\n`;
}

function toCsv(profile: Profile, flavour: Flavour): string {
  const withText = flavour === "plain" || flavour === "linux";
  const head = ["section", "kind", "id", "severity", "title", "controls", "stig_ids", "mscp_rule", "payloads", "registry", "gpo_path", "intune_definitions", "disa_checklist", "microsoft_value", "implemented_by", ...(withText ? ["fix", "check"] : []), "url"];
  const rows = [head.join(",")];
  for (const i of profile.items.filter((i) => i.included)) {
    rows.push(
      [
        i.section,
        kindLabel[i.kind],
        i.label,
        i.severity ?? "",
        i.title,
        controlsText(i),
        i.stigIds.join("; "),
        i.mscp?.id ?? "",
        payloadText(i),
        i.registry.map(regText).join("; "),
        i.gpoPath ? `${i.gpoPath.path} >> "${i.gpoPath.setting}"` : "",
        intuneText(i),
        checklistText(i),
        i.sctValue ?? "",
        i.implementedBy.join("; "),
        ...(withText ? [i.fix ?? "", i.check ?? ""] : []),
        i.url,
      ]
        .map(csvCell)
        .join(","),
    );
  }
  return `${rows.join("\r\n")}\r\n`;
}

function toMarkdown(profile: Profile, flavour: Flavour, meta: ExportMeta): string {
  const out: string[] = [`# ${title(profile)}`, "", `Flavour: ${flavours.find((f) => f.id === flavour)?.label ?? flavour}. Generated by ${productName} ${meta.version} at ${meta.generatedAt}. ${profile.counts.included} items kept, ${profile.counts.dropped} dropped.`, ""];
  for (const line of componentsList(profile)) out.push(`- ${line}`);
  out.push("");
  for (const { section, items } of sections(profile)) {
    out.push(`## ${section} (${items.length})`, "");
    for (const i of items) {
      out.push(`### ${i.label}: ${i.title}`, "");
      const facts: string[] = [];
      if (i.severity) facts.push(`Severity: ${i.severity}`);
      if (i.controls.length) facts.push(`Controls: ${controlsText(i)}`);
      if (i.kind !== "stig" && i.stigIds.length) facts.push(`STIG ids: ${i.stigIds.join(", ")}`);
      facts.push(`Source: ${meta.baseUrl}${i.url}`);
      for (const f of facts) out.push(`- ${f}`);
      for (const line of applyLines(i, flavour)) {
        if ((line.label === "Fix" || line.label === "Check") && line.text.includes("\n")) out.push(`- ${line.label}:`, "", "  ```", ...line.text.split("\n").map((l) => `  ${l}`), "  ```");
        else out.push(`- ${line.label}: ${line.text.replace(/\n/g, " ")}`);
      }
      out.push("");
    }
  }
  out.push("## Attribution", "");
  for (const line of attribution(profile)) out.push(`- ${line}`);
  out.push("");
  return out.join("\n");
}

function toHtml(profile: Profile, flavour: Flavour, meta: ExportMeta): string {
  const e = escapeHtml;
  const parts: string[] = [];
  parts.push(`<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${e(title(profile))}</title><link rel="stylesheet" href="${e(meta.baseUrl)}/assets/app.css"></head><body><main class="wrap export">`);
  parts.push(`<h1>${e(title(profile))}</h1><p>Flavour: ${e(flavours.find((f) => f.id === flavour)?.label ?? flavour)}. Generated by ${e(productName)} ${e(meta.version)} at ${e(meta.generatedAt)}. ${profile.counts.included} items kept, ${profile.counts.dropped} dropped.</p><ul>${componentsList(profile)
    .map((l) => `<li>${e(l)}</li>`)
    .join("")}</ul>`);
  for (const { section, items } of sections(profile)) {
    parts.push(`<section><h2>${e(section)} <small>(${items.length})</small></h2>`);
    for (const i of items) {
      parts.push(`<article class="export-item"><h3><code>${e(i.label)}</code> ${e(i.title)}${i.severity ? ` <small>${e(i.severity)}</small>` : ""}</h3><dl>`);
      if (i.controls.length) parts.push(`<dt>Controls</dt><dd>${e(controlsText(i))}</dd>`);
      if (i.kind !== "stig" && i.stigIds.length) parts.push(`<dt>STIG ids</dt><dd>${e(i.stigIds.join(", "))}</dd>`);
      for (const line of applyLines(i, flavour)) parts.push(`<dt>${e(line.label)}</dt><dd>${line.text.includes("\n") ? `<pre>${e(line.text)}</pre>` : e(line.text)}</dd>`);
      parts.push(`<dt>Source</dt><dd><a href="${e(meta.baseUrl)}${e(i.url)}">${e(meta.baseUrl)}${e(i.url)}</a></dd></dl></article>`);
    }
    parts.push("</section>");
  }
  parts.push(`<footer><h2>Attribution</h2><ul>${attribution(profile)
    .map((l) => `<li>${e(l)}</li>`)
    .join("")}</ul></footer></main></body></html>\n`);
  return parts.join("\n");
}
