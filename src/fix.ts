import { readFileSync } from "node:fs";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { parse as parseYaml } from "yaml";
import type { NormalizedRequirement } from "./oscal.ts";
import { loadRequirements } from "./register.ts";
import { followedStigs, type StigSummary } from "./stigs.ts";
import type { AffectedPackage, VulnRow } from "./vulns.ts";

/**
 * The Fix panel: the remediation already published for a CVE, quoted and linked. NVD's references
 * tagged Patch, Vendor Advisory or Mitigation; the vendor advisories the Wire holds for the CVE;
 * CISA KEV's required action and due date; the package advisories' fixed versions; and the STIG
 * rules that mitigate the class of flaw, from the owner's data/mitigations.yaml. When nothing is
 * published the panel says so rather than guessing.
 */

export interface FixReference {
  url: string;
  tags: string[];
}

export interface FixAdvisory {
  id: number;
  source: string;
  title: string;
  url: string | null;
  publishedAt: string | null;
}

export interface Mitigation {
  id: string;
  note: string;
  source: { title: string; url: string } | null;
  rules: { stig: StigSummary; rule: NormalizedRequirement }[];
}

export interface Fix {
  cveId: string;
  references: FixReference[];
  advisories: FixAdvisory[];
  kev: { requiredAction: string | null; dueDate: string | null; dateAdded: string | null; name: string | null } | null;
  packages: { ecosystem: string; name: string; fixed: string[]; advisory: string }[];
  mitigations: Mitigation[];
  /** True when none of the above holds anything. */
  empty: boolean;
}

export interface MitigationEntry {
  id: string;
  cves: string[];
  keywords: string[];
  ruleTitleContains: string;
  note: string;
  source: { title: string; url: string } | null;
}

export const mitigationsFile = path.join(import.meta.dirname, "..", "data", "mitigations.yaml");

type Json = Record<string, unknown>;
const obj = (v: unknown): Json => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Json) : {});
const str = (v: unknown): string | null => (typeof v === "string" && v.trim() !== "" ? v.trim() : null);
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => str(x)).filter((x): x is string => x !== null) : []);

/** The owner's mitigation entries; a file that will not read gives none. */
export function loadMitigations(file: string = mitigationsFile): MitigationEntry[] {
  let doc: unknown;
  try {
    doc = parseYaml(readFileSync(file, "utf8"));
  } catch {
    return [];
  }
  if (!Array.isArray(doc)) return [];
  const out: MitigationEntry[] = [];
  for (const raw of doc) {
    const e = obj(raw);
    const id = str(e.id);
    const phrase = str(e.rule_title_contains);
    const note = str(e.note);
    if (!id || !phrase || !note) continue;
    const source = obj(e.source);
    const sourceUrl = str(source.url);
    const sourceTitle = str(source.title);
    out.push({
      id,
      cves: strings(e.cves).map((c) => c.toUpperCase()),
      keywords: strings(e.keywords),
      ruleTitleContains: phrase,
      note,
      source: sourceTitle && sourceUrl && /^https:\/\//.test(sourceUrl) ? { title: sourceTitle, url: sourceUrl } : null,
    });
  }
  return out;
}

/** The rules of every followed STIG's latest version, loaded once for a page. */
export interface FixContext {
  entries: MitigationEntry[];
  stigs: { stig: StigSummary; rules: NormalizedRequirement[] }[];
}

export function fixContext(db: DatabaseSync, file: string = mitigationsFile): FixContext {
  const entries = loadMitigations(file);
  const stigs = entries.length ? followedStigs(db).map((stig) => ({ stig, rules: loadRequirements(db, stig.latest.id) })) : [];
  return { entries, stigs };
}

/** The entries that speak to a CVE, by id or by the words in its description and KEV name. */
export function matchingEntries(entries: MitigationEntry[], v: { cveId: string; description: string | null; kevName: string | null }): MitigationEntry[] {
  const text = `${v.description ?? ""}\n${v.kevName ?? ""}`.toLowerCase();
  return entries.filter((e) => e.cves.includes(v.cveId.toUpperCase()) || e.keywords.some((k) => text.includes(k.toLowerCase())));
}

function parseJson<T>(text: string | null, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

const fixTags = /^(patch|vendor advisory|mitigation)$/i;

/** The KEV item for a CVE, with the required action from its signals or, for an older item, its summary. */
export function kevFor(db: DatabaseSync, cveId: string): Fix["kev"] {
  const row = db.prepare("SELECT title, summary, published_at, signals_json FROM items WHERE source_id = 'cisa-kev' AND external_id = ?").get(cveId) as { title: string; summary: string | null; published_at: string | null; signals_json: string | null } | undefined;
  if (!row) return null;
  const s = parseJson<{ requiredAction?: string; dueDate?: string }>(row.signals_json, {});
  const fromSummary = /Required action:\s*(.+)$/s.exec(row.summary ?? "")?.[1]?.trim() ?? null;
  return { requiredAction: s.requiredAction ?? fromSummary, dueDate: s.dueDate ?? null, dateAdded: row.published_at ? row.published_at.slice(0, 10) : null, name: row.title.split(": ").slice(1).join(": ") || row.title };
}

/** Vendor advisory items on the Wire that name the CVE. */
export function advisoriesFor(db: DatabaseSync, cveId: string, limit = 8): FixAdvisory[] {
  return (
    db
      .prepare(
        `SELECT i.id, s.name AS source, i.title, i.url, i.published_at FROM items i JOIN sources s ON s.id = i.source_id
         WHERE s.group_name = 'vulnerabilities' AND i.kind = 'article' AND i.signals_json LIKE ? ORDER BY i.published_at DESC LIMIT ?`,
      )
      .all(`%"${cveId}"%`, limit) as { id: number; source: string; title: string; url: string | null; published_at: string | null }[]
  ).map((r) => ({ id: r.id, source: r.source, title: r.title, url: r.url, publishedAt: r.published_at }));
}

/** Everything published that fixes or mitigates a CVE, or an honest empty. */
export function fixesFor(db: DatabaseSync, ctx: FixContext, row: VulnRow): Fix {
  const references = parseJson<{ url: string; tags: string[] }[]>(row.references_json, []).filter((r) => r.tags.some((t) => fixTags.test(t)));
  const advisories = advisoriesFor(db, row.cve_id);
  const kev = row.kev === 1 || kevFor(db, row.cve_id) ? kevFor(db, row.cve_id) : null;
  const packages = parseJson<AffectedPackage[]>(row.packages_json, [])
    .filter((p) => p.fixed.length)
    .map((p) => ({ ecosystem: p.ecosystem, name: p.name, fixed: p.fixed, advisory: p.advisory }));
  const mitigations: Mitigation[] = [];
  for (const entry of matchingEntries(ctx.entries, { cveId: row.cve_id, description: row.description, kevName: kev?.name ?? null })) {
    const phrase = entry.ruleTitleContains.toLowerCase();
    const rules: Mitigation["rules"] = [];
    for (const { stig, rules: all } of ctx.stigs) for (const rule of all) if (rule.title.toLowerCase().includes(phrase)) rules.push({ stig, rule });
    if (rules.length) mitigations.push({ id: entry.id, note: entry.note, source: entry.source, rules });
  }
  return { cveId: row.cve_id, references, advisories, kev, packages, mitigations, empty: references.length === 0 && advisories.length === 0 && !kev?.requiredAction && packages.length === 0 && mitigations.length === 0 };
}

/** A one-line account of the fix for a list, from the same facts. */
export function fixSummary(fix: Fix): string {
  const parts: string[] = [];
  if (fix.kev?.requiredAction) parts.push(`CISA: ${fix.kev.requiredAction.length > 120 ? `${fix.kev.requiredAction.slice(0, 119)}…` : fix.kev.requiredAction}${fix.kev.dueDate ? ` (due ${fix.kev.dueDate})` : ""}`);
  if (fix.references.length) parts.push(`${fix.references.length} patch or advisory reference${fix.references.length === 1 ? "" : "s"} on NVD`);
  if (fix.advisories.length) parts.push(`vendor advisory: ${fix.advisories[0]!.source}`);
  if (fix.packages.length) parts.push(`fixed in ${fix.packages[0]!.name} ${fix.packages[0]!.fixed[0]}`);
  if (fix.mitigations.length) parts.push(`STIG: ${fix.mitigations[0]!.rules[0]!.rule.label}`);
  return parts.length ? parts.join(" · ") : "Nothing published yet: no patch, advisory or mitigation reference, no vendor advisory on the Wire, no KEV action.";
}
