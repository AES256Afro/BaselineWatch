import { readFileSync, statSync } from "node:fs";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { parse as parseYaml } from "yaml";
import { exploitsFor, type ExploitRow } from "./exploits.ts";
import { msrcFor, type MsrcVuln } from "./msrc.ts";
import type { NormalizedRequirement } from "./oscal.ts";
import { loadRequirements } from "./register.ts";
import { followedStigs, type StigSummary } from "./stigs.ts";
import type { AffectedPackage, VulnRow } from "./vulns.ts";
import { parseJson } from "./json.ts";

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
  kev: { requiredAction: string | null; dueDate: string | null; dateAdded: string | null; name: string | null; notes?: { url: string; label: string | null }[] } | null;
  packages: { ecosystem: string; name: string; fixed: string[]; advisory: string }[];
  mitigations: Mitigation[];
  /** What the public exploit indexes hold for this CVE (src/exploits.ts): not a fix, but the reason to want one today. */
  exploits: ExploitRow[];
  /** Microsoft's Security Update Guide row (src/msrc.ts): the KB per product, and Microsoft's word on exploitation. */
  microsoft: MsrcVuln | null;
  /** True when none of the above holds anything. */
  empty: boolean;
  /**
   * NVD's references it has not tagged yet (no Patch, Advisory or any other tag): often the vendor's
   * own bulletin, waiting for NVD's analysis. Not counted as a fix, but never hidden behind "nothing
   * published". `lead` is the one on the vendor's or the CNA's domain when one is, else the first.
   */
  untagged: { count: number; lead: { url: string; host: string; whose: "vendor" | "CNA" | null } | null };
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

/** The owner's mitigation entries; a file that will not read gives none, and a file that will not parse says why in the log. */
export function loadMitigations(file: string = mitigationsFile): MitigationEntry[] {
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    return [];
  }
  let doc: unknown;
  try {
    doc = parseYaml(text);
  } catch (error) {
    // One typo would otherwise make every mitigation vanish from every CVE page without a word.
    console.error(`[fix] ${path.basename(file)} does not parse, so no mitigation is shown: ${error instanceof Error ? error.message : String(error)}`);
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

/**
 * Built once and kept until the mitigations file or the STIGs change. News, Today, a CVE's page
 * and the API each asked for it on every request, and it is every followed STIG's rules parsed
 * from JSON — eleven milliseconds a time for data that moves only at ingest. The key is the
 * file's modification time and the STIG documents' newest id and count, so an edit to the YAML
 * shows on the next request (as it did) and a new STIG release on the first after it is stored.
 */
const fixContexts = new WeakMap<DatabaseSync, { key: string; value: FixContext }>();

export function fixContext(db: DatabaseSync, file: string = mitigationsFile): FixContext {
  let mtime = -1;
  try {
    mtime = statSync(file).mtimeMs;
  } catch {
    // No file is no entries; loadMitigations says the same.
  }
  const stigDocs = db.prepare("SELECT MAX(id) AS top, COUNT(*) AS n FROM documents WHERE source_id = 'disa-stigs'").get() as { top: number | null; n: number };
  const key = `${file}|${mtime}|${stigDocs.top ?? 0}|${stigDocs.n}`;
  const cached = fixContexts.get(db);
  if (cached?.key === key) return cached.value;
  const entries = loadMitigations(file);
  const stigs = entries.length ? followedStigs(db).map((stig) => ({ stig, rules: loadRequirements(db, stig.latest.id) })) : [];
  const value = { entries, stigs };
  fixContexts.set(db, { key, value });
  return value;
}

/** The entries that speak to a CVE, by id or by the words in its description and KEV name. */
export function matchingEntries(entries: MitigationEntry[], v: { cveId: string; description: string | null; kevName: string | null }): MitigationEntry[] {
  const text = `${v.description ?? ""}\n${v.kevName ?? ""}`.toLowerCase();
  return entries.filter((e) => e.cves.includes(v.cveId.toUpperCase()) || e.keywords.some((k) => text.includes(k.toLowerCase())));
}

/** The NVD reference tags that mean "this is how you fix it". Shared with src/fixlist.ts. */
export const fixTags = /^(patch|vendor advisory|mitigation)$/i;

/** The KEV item for a CVE, with the required action from its signals or, for an older item, its summary. */
export function kevFor(db: DatabaseSync, cveId: string): Fix["kev"] {
  const row = db.prepare("SELECT title, summary, published_at, signals_json FROM items WHERE source_id = 'cisa-kev' AND external_id = ?").get(cveId) as { title: string; summary: string | null; published_at: string | null; signals_json: string | null } | undefined;
  if (!row) return null;
  const s = parseJson<{ requiredAction?: string; dueDate?: string; notes?: string }>(row.signals_json, {});
  // CISA's notes field holds the addresses the required action refers to ("see URL in Notes"),
  // separated by " ; ". Only web addresses are kept.
  // Most parts are a bare address; some carry a label ("BOD 26-04: https://..."), kept as the text.
  // Every address is kept, wherever it sits: a part may hold several, or one in parentheses
  // ("Reference CISA's ED 21-04 (https://...)"). A label is the text right before "Label: https",
  // never a cut-off phrase.
  const notes = (s.notes ?? "")
    .split(/\s*;\s*/)
    .flatMap((part) =>
      [...part.matchAll(/https?:\/\/[^\s<>"]+/gi)].map((m) => {
        // A closing bracket is the address's own only when it opened one ("...-(cve-2020-14472)").
        let url = m[0].replace(/[.,;:]+$/, "");
        while (url.endsWith(")") && (url.match(/\(/g) ?? []).length < (url.match(/\)/g) ?? []).length) url = url.slice(0, -1).replace(/[.,;:]+$/, "");
        const labelled = /^([^():]{2,60}):\s*$/.exec(part.slice(0, m.index));
        return { url, label: labelled ? labelled[1]!.trim() : null };
      }),
    )
    .slice(0, 8);
  const fromSummary = /Required action:\s*(.+)$/s.exec(row.summary ?? "")?.[1]?.trim() ?? null;
  return { requiredAction: s.requiredAction ?? fromSummary, dueDate: s.dueDate ?? null, dateAdded: row.published_at ? row.published_at.slice(0, 10) : null, name: row.title.split(": ").slice(1).join(": ") || row.title, notes };
}

/** Vendor advisory items on the Wire that name the CVE. */
function advisoriesFor(db: DatabaseSync, cveId: string, limit = 8): FixAdvisory[] {
  return (
    db
      .prepare(
        `SELECT i.id, s.name AS source, i.title, i.url, i.published_at FROM items i JOIN sources s ON s.id = i.source_id
         WHERE s.group_name = 'vulnerabilities' AND i.kind = 'article' AND i.signals_json LIKE ? ORDER BY i.published_at DESC LIMIT ?`,
      )
      .all(`%"${cveId}"%`, limit) as { id: number; source: string; title: string; url: string | null; published_at: string | null }[]
  ).map((r) => ({ id: r.id, source: r.source, title: r.title, url: r.url, publishedAt: r.published_at }));
}

const hostOf = (url: string): string | null => {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
};
/**
 * The second levels under a two-letter country code that are read as a public suffix of two labels
 * ("co.uk", "com.au", "ne.jp"). A hand-kept list (src/curated.ts): nothing else is guessed.
 */
export const twoLevelSuffixes: readonly string[] = ["co", "com", "org", "net", "gov", "ac", "edu", "or", "ne", "go"];

/**
 * The domain a host is registered under: "citrix.com" from "support.citrix.com", "bbc.co.uk"
 * from "www.bbc.co.uk" (a two-letter country code under one of `twoLevelSuffixes`).
 */
export function registrableDomain(host: string): string {
  const labels = host.toLowerCase().split(".").filter(Boolean);
  const twoLevel = labels.length >= 3 && labels.at(-1)!.length === 2 && twoLevelSuffixes.includes(labels.at(-2)!);
  return labels.slice(twoLevel ? -3 : -2).join(".");
}

/** The name a host is registered under: "citrix" from "support.citrix.com", "bbc" from "www.bbc.co.uk". */
export function registrableName(host: string): string {
  return registrableDomain(host).split(".")[0] ?? "";
}
/**
 * Hosts that serve what their users publish, not what the domain's owner says. A hand-kept list
 * (src/curated.ts): a reference there is never named as the vendor's.
 */
export const userContentHosts: readonly string[] = ["github.io", "sites.google.com", "raw.githubusercontent.com", "gist.github.com", "gitlab.io", "pages.dev", "blogspot.com"];
export function userContentHost(host: string): boolean {
  const h = host.toLowerCase();
  if (/(^|\.)[a-z0-9-]*usercontent\.com$/.test(h)) return true;
  return userContentHosts.some((u) => h === u || h.endsWith(`.${u}`));
}
const letters = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]/g, "");

/**
 * Words a company adds to its name that its domain leaves out ("QNAP Systems Inc." → qnap.com). A
 * hand-kept list (src/curated.ts): a vendor's first word stands for the name only when every word
 * after it is one of these, so "Justice AV Solutions" is not read as justice.gov.
 */
export const corporateSuffixes: readonly string[] = ["inc", "llc", "ltd", "gmbh", "corp", "corporation", "co", "company", "systems", "technologies", "kk"];

/** The names a vendor's domain may carry: the whole name, and its first word when the rest is a corporate suffix. */
export function vendorDomainNames(vendor: string): string[] {
  const words = vendor.trim().split(/\s+/).filter(Boolean);
  const out = [letters(vendor)];
  if (words.length > 1 && words.slice(1).every((w) => corporateSuffixes.includes(letters(w)))) out.push(letters(words[0]!));
  return out;
}

/**
 * The untagged references and the one to name: on a domain registered under the vendor's name
 * (from the CPEs), else on the CNA's own mail domain (`psirt@citrix.com`), else the first.
 */
export function untaggedReferences(refs: FixReference[], vendors: string[], sourceIdentifier: string | null): Fix["untagged"] {
  const bare = refs.filter((r) => r.tags.length === 0 && /^https?:\/\//i.test(r.url));
  if (!bare.length) return { count: 0, lead: null };
  const withHost = bare.map((r) => ({ url: r.url, host: hostOf(r.url) })).filter((r): r is { url: string; host: string } => r.host !== null);
  if (!withHost.length) return { count: bare.length, lead: null };
  // The whole name, and its first word when the rest is a company suffix: CISA and the CNAs write
  // "QNAP Systems Inc." for qnap.com, but "Justice AV Solutions" is not justice.gov.
  const names = [...new Set(vendors.flatMap(vendorDomainNames))].filter((v) => v.length >= 3);
  // The registrable domain's own name equals the vendor's (citrix.com, apache.org). A prefix matched
  // googleusercontent.com for Google and githubusercontent.com for GitHub, and a host where anyone
  // publishes (x.github.io, sites.google.com) is nobody's advisory however its domain reads.
  const byVendor = withHost.find((r) => {
    if (userContentHost(r.host)) return false;
    const name = letters(registrableName(r.host));
    return names.some((v) => name === v);
  });
  if (byVendor) return { count: bare.length, lead: { ...byVendor, whose: "vendor" } };
  const cnaDomain = /@([a-z0-9.-]+)$/i.exec(sourceIdentifier ?? "")?.[1]?.toLowerCase();
  const byCna = cnaDomain ? withHost.find((r) => registrableDomain(r.host) === registrableDomain(cnaDomain)) : undefined;
  if (byCna) return { count: bare.length, lead: { ...byCna, whose: "CNA" } };
  return { count: bare.length, lead: { ...withHost[0]!, whose: null } };
}

/** Everything published that fixes or mitigates a CVE, or an honest empty. */
export function fixesFor(db: DatabaseSync, ctx: FixContext, row: VulnRow): Fix {
  const allRefs = parseJson<{ url: string; tags?: string[] }[]>(row.references_json, []).map((r) => ({ url: r.url, tags: Array.isArray(r.tags) ? r.tags : [] }));
  const references = allRefs.filter((r) => r.tags.some((t) => fixTags.test(t)));
  const untagged = untaggedReferences(allRefs, parseJson<string[]>(row.vendors_json, []), row.source_identifier);
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
  // The panel is still "empty" of fixes when only exploits are known: that is the honest, and worse, state.
  const exploits = exploitsFor(db, row.cve_id);
  const microsoft = msrcFor(db, row.cve_id);
  return { cveId: row.cve_id, references, advisories, kev, packages, mitigations, exploits, microsoft, empty: references.length === 0 && advisories.length === 0 && !kev?.requiredAction && packages.length === 0 && mitigations.length === 0 && !microsoft?.fixes.length, untagged };
}

/** A one-line account of the fix for a list, from the same facts. */
export function fixSummary(fix: Fix): string {
  const parts: string[] = [];
  if (fix.microsoft?.fixes.length) {
    const named = fix.microsoft.fixes.slice(0, 3).map((f) => `${f.kb ? `KB${f.kb}` : (f.label ?? "update")}${f.products.length ? ` (${f.products.slice(0, 2).join(", ")}${f.products.length > 2 ? ", …" : ""})` : ""}`);
    parts.push(`Microsoft: ${named.join("; ")}${fix.microsoft.fixes.length > 3 ? "; …" : ""}`);
  }
  if (fix.kev?.requiredAction) parts.push(`CISA: ${fix.kev.requiredAction.length > 120 ? `${fix.kev.requiredAction.slice(0, 119)}…` : fix.kev.requiredAction}${fix.kev.dueDate ? ` (due ${fix.kev.dueDate})` : ""}`);
  if (fix.references.length) parts.push(`${fix.references.length} patch or advisory reference${fix.references.length === 1 ? "" : "s"} on NVD`);
  if (fix.advisories.length) parts.push(`vendor advisory: ${fix.advisories[0]!.source}`);
  if (fix.packages.length) parts.push(`fixed in ${fix.packages[0]!.name} ${fix.packages[0]!.fixed[0]}`);
  if (fix.mitigations.length) parts.push(`STIG: ${fix.mitigations[0]!.rules[0]!.rule.label}`);
  // The fix leads; the exploits, which are the reason to hurry and not a fix, follow it, labelled.
  const exploits = fix.exploits.length ? `Public exploits: ${fix.exploits.length}${fix.exploits.some((e) => e.verified === 1) ? " (verified)" : ""}` : null;
  const lead = parts.length ? parts.join(" · ") : fix.untagged.count ? untaggedSentence(fix.untagged) : "Nothing published yet: no patch, advisory or mitigation reference, no vendor advisory in the News, no KEV action.";
  return exploits ? `${lead}${parts.length ? " · " : " "}${exploits}` : lead;
}

/** Whose the named untagged reference is, as the sentence says it: "the vendor's", "the CNA's" or "the first". */
export function whoseWord(lead: Fix["untagged"]["lead"]): string {
  return lead?.whose === "vendor" ? "the vendor's" : lead?.whose === "CNA" ? "the CNA's" : "the first";
}

/** "NVD has not tagged its 3 references yet; the vendor's: support.citrix.com". */
function untaggedSentence(u: Fix["untagged"]): string {
  const n = u.count === 1 ? "its 1 reference" : `its ${u.count.toLocaleString("en-US")} references`;
  if (!u.lead) return `NVD has not tagged ${n} yet.`;
  return `NVD has not tagged ${n} yet; ${whoseWord(u.lead)}: ${u.lead.host}`;
}
