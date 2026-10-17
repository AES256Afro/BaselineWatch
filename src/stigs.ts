import type { DatabaseSync } from "node:sqlite";
import type { NormalizedRequirement } from "./oscal.ts";
import { latestDocument, loadRequirements, type DocumentRow } from "./register.ts";

/**
 * The STIG pages: the operating systems and products the Register follows, their rules by
 * severity, the join to NIST SP 800-53 through DISA's CCIs, and what CISA says about each
 * platform (KEV entries by vendor and product, directives by what their titles name). Everything
 * here is read from rows the adapters stored; nothing is generated.
 */

export type PlatformId = "windows" | "linux" | "macos" | "mobile" | "network" | "browsers" | "virtualization" | "applications";

export interface Platform {
  id: PlatformId;
  label: string;
  /** What DISA calls the group, for the index page. */
  blurb: string;
}

export const platforms: Platform[] = [
  { id: "windows", label: "Windows", blurb: "Windows 11, Windows Server and Active Directory." },
  { id: "linux", label: "Linux", blurb: "Red Hat Enterprise Linux, Ubuntu, Oracle Linux, SUSE and the other UNIX-like systems." },
  { id: "macos", label: "macOS", blurb: "Apple macOS by release." },
  { id: "mobile", label: "Mobile", blurb: "iOS, iPadOS, Android and the MDM servers that manage them." },
  { id: "browsers", label: "Browsers", blurb: "Microsoft Edge, Google Chrome and Mozilla Firefox." },
  { id: "network", label: "Network devices", blurb: "Routers, switches, firewalls and VPNs." },
  { id: "virtualization", label: "Virtualisation", blurb: "VMware vSphere and the hypervisors." },
  { id: "applications", label: "Applications", blurb: "Application security and development, office suites, databases and servers." },
];

export function isPlatformId(value: unknown): value is PlatformId {
  return typeof value === "string" && platforms.some((p) => p.id === value);
}

export function platformLabel(id: PlatformId | "all"): string {
  return id === "all" ? "every platform" : (platforms.find((p) => p.id === id)?.label ?? id);
}

/** Which page a STIG belongs on, from its product name; order matters (Edge before Windows, Defender Firewall before network). */
export function platformOf(name: string): PlatformId {
  const n = name.toLowerCase();
  if (/\b(edge|chrome|firefox|browser)\b/.test(n) && !/edge device/.test(n)) return "browsers";
  if (/\bmac\s?os\b|\bmacos\b/.test(n)) return "macos";
  if (/windows|active directory/.test(n)) return "windows";
  if (/cisco|juniper|router|switch|firewall|network|\bf5\b|palo alto|fortinet|fortigate|arista|\bvpn\b|wireless|sd-wan|ivanti|citrix/.test(n)) return "network";
  if (/\bios\b|ipados|android|visionos|watchos|\bmdm\b|mobile|smartphone/.test(n)) return "mobile";
  if (/linux|ubuntu|red hat|rhel|sles|suse|debian|nixos|toss|solaris|aix|unix|almalinux/.test(n)) return "linux";
  if (/vmware|vsphere|esxi|hyper-v|virtuali[sz]ation/.test(n)) return "virtualization";
  return "applications";
}

const microsoftBrowsers = /\b(edge|internet explorer|mshtml|scripting engine|silverlight)\b/i;
const microsoftOffice = /\b(office|word|excel|powerpoint|outlook|publisher|project|visio|access|wordpad|visual basic|vba|mscomctl)\b/i;
const microsoftServers = /exchange|sharepoint|sql server|configuration manager|partner center|power pages|skype|lync|dynamics|azure|forefront|open management|\bomi\b|\.net|visual studio|internet information|\biis\b/i;

/**
 * The platform a KEV entry's vendor and product belong to, so a platform page can show CISA's
 * known-exploited entries for it. Vendors CISA names in several ways ("Apple | Multiple Products",
 * "Linux | Kernel", "Red Hat | Polkit") are read as a person would; null when none fits.
 */
export function kevPlatform(vendor: string | null | undefined, product: string | null | undefined): PlatformId | null {
  const v = (vendor ?? "").trim().toLowerCase();
  const p = (product ?? "").trim();
  if (!v) return null;
  if (v === "microsoft") {
    if (microsoftBrowsers.test(p)) return "browsers";
    if (microsoftServers.test(p)) return "applications";
    if (microsoftOffice.test(p)) return "applications";
    return "windows";
  }
  if (v === "apple") {
    if (/mac|os x|multiple products/i.test(p)) return "macos";
    return "mobile";
  }
  if (v === "linux" || v === "canonical" || v === "ubuntu" || v === "debian" || v === "suse") return "linux";
  if (v === "red hat") return /linux|kernel|polkit|libuser|bug reporting|enterprise linux/i.test(p) ? "linux" : "applications";
  if (v === "oracle") return /linux|solaris/i.test(p) ? "linux" : "applications";
  if (v === "google") {
    if (/chrom/i.test(p)) return "browsers";
    if (/android|pixel/i.test(p)) return "mobile";
    return null;
  }
  if (v === "android" || v === "samsung") return "mobile";
  if (v === "mozilla") return "browsers";
  if (/^(cisco|f5|fortinet|palo alto networks|juniper|juniper networks|ivanti|citrix|sonicwall|zyxel|d-link|netgear|mikrotik|arista|check point|pulse secure|barracuda|sophos|watchguard|array networks)$/.test(v)) return "network";
  if (v === "vmware") return "virtualization";
  return null;
}

/** The platforms a directive's title names; "all" for the cross-cutting ones (asset visibility, update deadlines, cloud services). */
export function directivePlatforms(title: string): (PlatformId | "all")[] {
  const t = title.toLowerCase();
  const out = new Set<PlatformId | "all">();
  if (/cisco|f5\b|ivanti|fortinet|palo alto|citrix|edge device|network infrastructure|management interface|sd-wan|\bvpn\b|router|firewall|pulse|sonicwall/.test(t)) out.add("network");
  if (/microsoft|windows|exchange|sharepoint|active directory|solarwinds|kaspersky/.test(t)) out.add("windows");
  if (/apple|macos|\bios\b/.test(t)) out.add("macos");
  if (/linux|red hat|ubuntu|debian|log4j/.test(t)) out.add("linux");
  if (/chrome|firefox|browser|internet explorer/.test(t)) out.add("browsers");
  if (/vmware|vsphere|esxi/.test(t)) out.add("virtualization");
  if (out.size === 0) out.add("all");
  return [...out];
}

export interface CciMap {
  /** CCI id, upper case, to the Register's control refs (ac-11, ia-5.2). */
  controls: Map<string, string[]>;
  /** Control ref to the CCIs that index it, for the reverse view. */
  ccis: Map<string, string[]>;
  documentId: number | null;
  version: string | null;
}

/** The latest CCI list the Register holds, as two maps. Empty maps when the list has not loaded. */
export function cciMap(db: DatabaseSync): CciMap {
  const doc = latestDocument(db, "disa-cci", "cci");
  const controls = new Map<string, string[]>();
  const ccis = new Map<string, string[]>();
  if (!doc) return { controls, ccis, documentId: null, version: null };
  const rows = db.prepare("SELECT label, related_json FROM requirements WHERE document_id = ?").all(doc.id) as { label: string | null; related_json: string | null }[];
  for (const r of rows) {
    if (!r.label) continue;
    let related: string[] = [];
    try {
      related = r.related_json ? (JSON.parse(r.related_json) as string[]) : [];
    } catch {
      related = [];
    }
    controls.set(r.label.toUpperCase(), related);
    for (const c of related) ccis.set(c, [...(ccis.get(c) ?? []), r.label.toUpperCase()]);
  }
  return { controls, ccis, documentId: doc.id, version: doc.version_label };
}

/** The controls a STIG rule maps to, through its CCIs, sorted the way the catalog sorts. */
export function controlsFor(rule: Pick<NormalizedRequirement, "related">, map: CciMap): string[] {
  const out = new Set<string>();
  for (const cci of rule.related) for (const c of map.controls.get(cci.toUpperCase()) ?? []) out.add(c);
  return [...out].sort(compareControlRefs);
}

/** ac-2 before ac-2.1 before ac-11 before au-2. */
export function compareControlRefs(a: string, b: string): number {
  const parse = (ref: string) => {
    const m = /^([a-z]{2})-(\d+)(?:\.(\d+))?/.exec(ref);
    return m ? { family: m[1]!, n: Number(m[2]), e: m[3] ? Number(m[3]) : 0 } : { family: ref, n: 0, e: 0 };
  };
  const x = parse(a);
  const y = parse(b);
  return x.family.localeCompare(y.family) || x.n - y.n || x.e - y.e || a.localeCompare(b);
}

/** The printed label of a control ref: ac-11 → AC-11, ia-5.2 → IA-5(2). */
export function controlLabel(ref: string): string {
  const m = /^([a-z]{2})-(\d+)(?:\.(\d+))?$/.exec(ref);
  if (!m) return ref.toUpperCase();
  return `${m[1]!.toUpperCase()}-${m[2]}${m[3] ? `(${m[3]})` : ""}`;
}

export type Cat = "CAT I" | "CAT II" | "CAT III";
export const cats: Cat[] = ["CAT I", "CAT II", "CAT III"];

export interface StigSummary {
  key: string;
  /** "Microsoft Windows Server 2025", from the benchmark title. */
  product: string;
  platform: PlatformId;
  latest: DocumentRow;
  previous: DocumentRow | null;
  counts: Record<Cat, number> & { other: number };
}

/** "Microsoft Windows Server 2025 Security Technical Implementation Guide" → the product. */
export function productOf(title: string | null, key: string): string {
  const fromTitle = (title ?? "").replace(/\s*Security Technical Implementation Guide.*$/i, "").replace(/\s*\(STIG\)\s*$/i, "").trim();
  if (fromTitle) return fromTitle;
  return key
    .replace(/^stig:/, "")
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/** Every STIG the Register holds, latest version first per key, with its rule counts by CAT. */
export function followedStigs(db: DatabaseSync): StigSummary[] {
  const keys = db.prepare("SELECT DISTINCT document_key FROM documents WHERE source_id = 'disa-stigs' ORDER BY document_key").all() as { document_key: string }[];
  const out: StigSummary[] = [];
  for (const { document_key } of keys) {
    const latest = latestDocument(db, "disa-stigs", document_key);
    if (!latest) continue;
    const previous = latest.previous_document_id ? ((db.prepare("SELECT * FROM documents WHERE id = ?").get(latest.previous_document_id) as unknown as DocumentRow | undefined) ?? null) : null;
    const counts: StigSummary["counts"] = { "CAT I": 0, "CAT II": 0, "CAT III": 0, other: 0 };
    for (const r of db.prepare("SELECT family, COUNT(*) AS n FROM requirements WHERE document_id = ? GROUP BY family").all(latest.id) as { family: string | null; n: number }[]) {
      if (r.family === "CAT I" || r.family === "CAT II" || r.family === "CAT III") counts[r.family] = r.n;
      else counts.other += r.n;
    }
    const product = productOf(latest.title, document_key);
    out.push({ key: document_key, product, platform: platformOf(`${product} ${document_key}`), latest, previous, counts });
  }
  return out.sort((a, b) => a.product.localeCompare(b.product));
}

export function stigsFor(db: DatabaseSync, platform: PlatformId): StigSummary[] {
  return followedStigs(db).filter((s) => s.platform === platform);
}

/** The platforms that have at least one STIG loaded, in display order, with their STIGs. */
export function platformsWithStigs(db: DatabaseSync): { platform: Platform; stigs: StigSummary[] }[] {
  const all = followedStigs(db);
  return platforms.map((platform) => ({ platform, stigs: all.filter((s) => s.platform === platform.id) })).filter((g) => g.stigs.length > 0);
}

export interface RuleHit {
  stig: StigSummary;
  rules: NormalizedRequirement[];
}

/** The rules, across the followed STIGs' latest versions, whose CCIs index a control: the Register's reverse view. */
export function stigRulesForControl(db: DatabaseSync, controlRef: string, map: CciMap): RuleHit[] {
  const wanted = new Set(map.ccis.get(controlRef.toLowerCase()) ?? []);
  if (wanted.size === 0) return [];
  const hits: RuleHit[] = [];
  for (const stig of followedStigs(db)) {
    const rules = loadRequirements(db, stig.latest.id).filter((r) => r.related.some((cci) => wanted.has(cci.toUpperCase())));
    if (rules.length) hits.push({ stig, rules });
  }
  return hits;
}

/** The latest SP 800-53 catalog, for linking a control ref to its page. */
export function controlPageBase(db: DatabaseSync): string | null {
  const doc = latestDocument(db, "nist-sp-800-53", "catalog");
  return doc ? `/standards/nist-sp-800-53/${doc.id}` : null;
}

export interface KevEntry {
  id: number;
  cve: string;
  title: string;
  url: string | null;
  publishedAt: string | null;
  dueDate: string | null;
  ransomware: boolean;
  vendor: string | null;
  product: string | null;
}

function parseJson<T>(text: string | null, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

/** CISA's KEV entries whose vendor and product belong to a platform, newest first. */
export function kevForPlatform(db: DatabaseSync, platform: PlatformId, limit = 12): { entries: KevEntry[]; total: number } {
  const rows = db
    .prepare("SELECT id, external_id, title, url, published_at, signals_json FROM items WHERE kind = 'kev' ORDER BY published_at DESC, id DESC")
    .all() as { id: number; external_id: string; title: string; url: string | null; published_at: string | null; signals_json: string | null }[];
  const entries: KevEntry[] = [];
  let total = 0;
  for (const r of rows) {
    const s = parseJson<{ vendor?: string; product?: string; dueDate?: string; ransomware?: boolean }>(r.signals_json, {});
    if (kevPlatform(s.vendor, s.product) !== platform) continue;
    total += 1;
    if (entries.length < limit) {
      entries.push({ id: r.id, cve: r.external_id, title: r.title, url: r.url, publishedAt: r.published_at, dueDate: s.dueDate ?? null, ransomware: s.ransomware === true, vendor: s.vendor ?? null, product: s.product ?? null });
    }
  }
  return { entries, total };
}

export interface DirectiveEntry {
  id: number;
  title: string;
  url: string | null;
  publishedAt: string | null;
  kind: string;
  code: string | null;
  supplemental: boolean;
  platforms: string[];
}

/** The CISA directives that name a platform, or every platform, newest first. */
export function directivesForPlatform(db: DatabaseSync, platform: PlatformId, limit = 12): DirectiveEntry[] {
  const rows = db
    .prepare("SELECT id, title, url, published_at, signals_json FROM items WHERE source_id = 'cisa-directives' ORDER BY published_at DESC, id DESC")
    .all() as { id: number; title: string; url: string | null; published_at: string | null; signals_json: string | null }[];
  const out: DirectiveEntry[] = [];
  for (const r of rows) {
    const s = parseJson<{ directive?: string | null; directiveKind?: string; supplemental?: boolean; platforms?: string[] }>(r.signals_json, {});
    const tags = s.platforms ?? [];
    if (!tags.includes(platform) && !tags.includes("all")) continue;
    out.push({ id: r.id, title: r.title, url: r.url, publishedAt: r.published_at, kind: s.directiveKind ?? "other", code: s.directive ?? null, supplemental: s.supplemental === true, platforms: tags });
    if (out.length >= limit) break;
  }
  return out;
}

/** Rules of a STIG version grouped by CAT, each group in STIG-id order. */
export function rulesByCat(rules: NormalizedRequirement[]): Record<Cat | "other", NormalizedRequirement[]> {
  const out: Record<Cat | "other", NormalizedRequirement[]> = { "CAT I": [], "CAT II": [], "CAT III": [], other: [] };
  for (const r of rules) {
    if (r.family === "CAT I" || r.family === "CAT II" || r.family === "CAT III") out[r.family].push(r);
    else out.other.push(r);
  }
  for (const list of Object.values(out)) list.sort((a, b) => a.sortKey.localeCompare(b.sortKey));
  return out;
}
