import type { DatabaseSync } from "node:sqlite";
import { ecosystemCovers, hasRelease } from "./ecosystems.ts";
import { isMicrosoftApplicationCpe, isPlatformKey, kevReading, platformChoices, platformKeysOf, platformName, platformsOf, platformsOfCpes, platformsOfDescription, platformsOfNames, type PlatformChoice } from "./platforms.ts";
import { parseJson } from "./json.ts";
import { csvLine } from "./csv.ts";
import { epssPercent } from "./words.ts";
import { ftsQuery } from "./wire.ts";

/** A CVE in the shape BaselineWatch keeps, whatever it came from. */
export interface NormalizedVuln {
  cveId: string;
  sourceIdentifier: string | null;
  publishedAt: string | null;
  lastModifiedAt: string;
  vulnStatus: string | null;
  description: string | null;
  cvss: { version: string; score: number; severity: string | null; vector: string | null; source: string | null } | null;
  ssvc: Record<string, string> | null;
  cwes: string[];
  cpes: string[];
  vendors: string[];
  products: string[];
  references: { url: string; tags: string[] }[];
  kev: { dateAdded: string | null; dueDate: string | null; requiredAction: string | null; name: string | null } | null;
  /** Affected packages, from an advisory source; undefined when the source (NVD) says nothing about packages. */
  packages?: AffectedPackage[];
}

/** A package an advisory names as affected, with the versions that introduced and fixed the flaw. */
export interface AffectedPackage {
  ecosystem: string;
  name: string;
  introduced: string[];
  fixed: string[];
  lastAffected: string[];
  /** The advisory that named it: GHSA-..., PYSEC-..., DSA-... */
  advisory: string;
}

/** A package advisory in the shape BaselineWatch keeps, from OSV.dev or the GitHub Advisory Database. */
export interface NormalizedAdvisory {
  id: string;
  aliases: string[];
  summary: string | null;
  details: string | null;
  publishedAt: string | null;
  modifiedAt: string;
  cvss: NormalizedVuln["cvss"];
  cwes: string[];
  references: { url: string; tags: string[] }[];
  packages: AffectedPackage[];
}

export interface VulnRow {
  id: number;
  cve_id: string;
  source_identifier: string | null;
  published_at: string | null;
  last_modified_at: string;
  vuln_status: string | null;
  description: string | null;
  cvss_version: string | null;
  cvss_score: number | null;
  cvss_severity: string | null;
  cvss_vector: string | null;
  cvss_source: string | null;
  ssvc_json: string | null;
  cwes_json: string | null;
  cpes_json: string | null;
  vendors_json: string | null;
  products_json: string | null;
  references_json: string | null;
  kev: number;
  kev_date_added: string | null;
  kev_due_date: string | null;
  kev_ransomware: number | null;
  /** CISA's own vendor and product for a KEV entry, lower-cased (migration 0073); NVD never writes them. */
  kev_vendor: string | null;
  kev_product: string | null;
  epss: number | null;
  epss_percentile: number | null;
  epss_date: string | null;
  watch_hit: number;
  watch_labels_json: string | null;
  first_seen_at: string;
  last_seen_at: string;
  packages_json: string | null;
  aliases_json: string | null;
  /** The platforms src/platforms.ts places it on, as a JSON array of ids; vuln_platforms mirrors it. */
  platforms_json: string | null;
  /** Kept by triggers from the exploits table (migration 0045). */
  has_exploit: number;
}

export interface VulnChange {
  field: "new" | "cvss" | "description" | "cpes" | "references" | "cwes" | "status" | "kev" | "epss" | "packages";
  before: string | null;
  after: string | null;
}

export interface WatchEntry {
  id: number;
  kind: "product" | "baseline" | "family" | "keyword" | "package" | "platform";
  value: string;
  label: string | null;
}

/**
 * A watchlist package value, `ecosystem:name`. Maven names carry their own colon
 * (`Maven:org.apache.logging.log4j:log4j-core`), so the split is at the first colon, except for
 * distributions, whose release sits between (`Debian:12:openssl`), which split at the last.
 */
export function parsePackageValue(value: string): { ecosystem: string; name: string } | null {
  const trimmed = value.trim();
  const first = trimmed.indexOf(":");
  if (first <= 0 || first === trimmed.length - 1) return null;
  const head = trimmed.slice(0, first);
  if (hasRelease(head)) {
    const last = trimmed.lastIndexOf(":");
    return { ecosystem: trimmed.slice(0, last), name: trimmed.slice(last + 1) };
  }
  return { ecosystem: head, name: trimmed.slice(first + 1) };
}

/** Whether an affected package is the one a watchlist entry names; an entry without a release matches every release. */
function packageMatches(entry: { ecosystem: string; name: string }, pkg: { ecosystem: string; name: string }): boolean {
  return pkg.name.toLowerCase() === entry.name.toLowerCase() && ecosystemCovers(entry.ecosystem, pkg.ecosystem);
}

export function loadWatchlist(db: DatabaseSync): WatchEntry[] {
  return db.prepare("SELECT id, kind, value, label FROM watchlist ORDER BY kind, value").all() as unknown as WatchEntry[];
}

/**
 * The labels of every watchlist entry a vulnerability matches. A product entry is a CPE prefix
 * (`cpe:2.3:o:fortinet:fortios`), a `vendor:product` pair, or one vendor or product name; a
 * keyword entry is matched against the description.
 */
export function matchWatch(
  v: Parameters<typeof matchWatchDetailed>[0],
  entries: WatchEntry[],
): string[] {
  return matchWatchDetailed(v, entries).map((h) => h.label);
}

/** A platform entry's label defaults to the platform's name, so a chip reads "Apple". */
export function watchLabel(entry: Pick<WatchEntry, "kind" | "value" | "label">): string {
  const own = entry.label?.trim();
  if (own) return own;
  const value = entry.value.trim().toLowerCase();
  return entry.kind === "platform" && isPlatformKey(value) ? platformName(value) : entry.value;
}

/** A vendor or product name with case, spaces and punctuation removed ("Palo Alto Networks" → "paloaltonetworks"). */
export const squash = (s: string): string =>
  s
    .toLowerCase()
    // A CPE escapes its punctuation (`notepad\+\+`): the backslashes go first, then everything but
    // letters, digits, + and #, which tell "notepad++" from "notepad" and "8+ gen 1" from "8 gen 1".
    .replace(/\\(.)/g, "$1")
    .replace(/[^\p{L}\p{N}+#]/gu, "");

/**
 * Whether CISA's vendor and product make a pair worth watching: "multiple products" (Apple,
 * Microsoft) names no product, so only the vendor is offered and matched.
 */
export function kevPairUsable(vendor: string | null | undefined, product: string | null | undefined): boolean {
  return !!vendor?.trim() && !!product?.trim() && !/^multiple\b/i.test(product.trim());
}

/** What a CVE's platforms are read from: NVD's CPEs and names, CISA's vendor and product, the words. */
export interface PlatformInput {
  cpes: readonly string[];
  vendors: readonly string[];
  products: readonly string[];
  description: string | null;
  kevVendor?: string | null | undefined;
  kevProduct?: string | null | undefined;
}

/**
 * The platforms a CVE is placed on: the one reading every writer of platforms_json uses
 * (upsertVuln, applyKev, recomputePlatforms, the CVE list's rewording) and every watch match
 * reads, so no entry point leaves a row where another would put it. In order:
 * 1. The CPEs name a platform (or, with none named, NVD's vendor and product names do): that.
 * 2. The CPEs exist but name none, and one is a Microsoft application CPE (Exchange, SharePoint,
 *    Office): no platform. NVD read it as Microsoft software that is not Windows, and CISA's
 *    words are not asked; "Microsoft | Exchange Server" once read as Windows that way.
 * 3. Otherwise CISA's reading (kevReading), when CISA names the CVE and its words read as
 *    anything: a platform, or none for an application. A Microsoft entry whose product is empty,
 *    the vendor's name or "Multiple Products" reads as nothing and falls through.
 * 4. Otherwise, for a row with no CPEs and no vendor but CISA's own, the description's words
 *    ("Microsoft Windows"): a KEV-only row and NVD's unanalysed record of it read alike.
 */
export function rowPlatforms(v: PlatformInput): string[] {
  const byCpe = platformsOfCpes(v.cpes);
  if (byCpe.length) return byCpe;
  const byName = platformsOfNames(v.vendors, v.products);
  if (byName.length) return byName;
  if (v.cpes.some(isMicrosoftApplicationCpe)) return [];
  const kevVendor = v.kevVendor?.trim() ? v.kevVendor.trim().toLowerCase() : null;
  const reading = kevVendor ? kevReading(kevVendor, v.kevProduct) : null;
  if (reading !== null) return isPlatformKey(reading) ? [reading] : [];
  const ownVendors = v.vendors.every((x) => kevVendor !== null && squash(x) === squash(kevVendor));
  return v.cpes.length === 0 && ownVendors ? platformsOfDescription(v.description) : [];
}

/**
 * A stored row as matchWatchDetailed reads it: its own platforms (or, when none are stored yet, the
 * reading rowPlatforms would store, CISA's names included) and CISA's vendor and product, so every
 * re-read of a row agrees with the platform view and with upsertVuln's first reading.
 */
export function storedWatchInput(
  r: Pick<VulnRow, "cpes_json" | "vendors_json" | "products_json" | "description" | "packages_json" | "platforms_json" | "kev_vendor" | "kev_product">,
  packages?: AffectedPackage[],
): Parameters<typeof matchWatchDetailed>[0] {
  const v = {
    cpes: parseJson<string[]>(r.cpes_json, []),
    vendors: parseJson<string[]>(r.vendors_json, []),
    products: parseJson<string[]>(r.products_json, []),
    description: r.description,
  };
  return {
    ...v,
    packages: packages ?? parseJson<AffectedPackage[]>(r.packages_json, []),
    platforms: r.platforms_json !== null ? parseJson<string[]>(r.platforms_json, []) : rowPlatforms({ ...v, kevVendor: r.kev_vendor, kevProduct: r.kev_product }),
    kevVendor: r.kev_vendor,
    kevProduct: r.kev_product,
  };
}

/** The colon between a pair's vendor and product, not one of a "::" inside a name. */
const lonePairColon = /(?<!:):(?!:)/;

/** The entries a vulnerability matches, with their kinds, so a platform match can be told from a product one. */
export function matchWatchDetailed(
  v: {
    cpes: string[];
    vendors: string[];
    products: string[];
    description: string | null;
    packages?: { ecosystem: string; name: string }[];
    platforms?: string[];
    kevVendor?: string | null;
    kevProduct?: string | null;
  },
  entries: WatchEntry[],
): { label: string; kind: WatchEntry["kind"] }[] {
  const hits: { label: string; kind: WatchEntry["kind"] }[] = [];
  // The row's own platforms when it has them, so a watch on a platform agrees with the platform view;
  // else the reading that would be stored (rowPlatforms), CISA's words included.
  const platforms: string[] = entries.some((e) => e.kind === "platform") ? (v.platforms ?? rowPlatforms(v)) : [];
  // Names compared with spaces and punctuation removed: CISA writes "Palo Alto Networks" and
  // "Trend Micro", NVD's CPEs "palo_alto_networks", "paloaltonetworks" and "trendmicro".
  const vendors = new Set(v.vendors.map(squash));
  const products = new Set(v.products.map(squash));
  const pairs = new Set(v.cpes.map((c) => c.split(":").slice(3, 5).map(squash).join(":")));
  // CISA's vendor and product, kept in their own columns (migration 0073), make a pair too: the one
  // watchCandidates offers on a KEV entry's page. NVD's record replaces vendors and products with
  // CPE values and never spells CISA's pairs ("microsoft:windows"), so the pair is read from the
  // columns NVD does not write, and a watch made before NVD arrived still matches after.
  if (kevPairUsable(v.kevVendor, v.kevProduct)) pairs.add(`${squash(v.kevVendor!)}:${squash(v.kevProduct!)}`);
  if (v.kevVendor?.trim()) vendors.add(squash(v.kevVendor));
  const description = (v.description ?? "").toLowerCase();
  const packages = v.packages ?? [];
  for (const entry of entries) {
    const value = entry.value.trim().toLowerCase();
    if (value === "") continue;
    const label = watchLabel(entry);
    let hit = false;
    if (entry.kind === "product") {
      if (value.startsWith("cpe:2.3:")) hit = v.cpes.some((c) => c.toLowerCase().startsWith(value));
      // A pair is split on a lone colon: CISA's Perl entry "spreadsheet::parseexcel" is a name.
      else if (lonePairColon.test(value)) hit = pairs.has(value.split(lonePairColon).slice(0, 2).map(squash).join(":"));
      else hit = squash(value) !== "" && (vendors.has(squash(value)) || products.has(squash(value)));
    } else if (entry.kind === "keyword") {
      hit = description.includes(value);
    } else if (entry.kind === "package") {
      const wanted = parsePackageValue(entry.value);
      hit = wanted !== null && packages.some((p) => packageMatches(wanted, p));
    } else if (entry.kind === "platform") {
      hit = platforms.includes(value);
    }
    if (hit) hits.push({ label, kind: entry.kind });
  }
  return hits;
}

/**
 * EPSS kept to FIRST's own precision (five places). Rounding to two read 18,151 of 22,232 scores
 * as 0.00%, tied the sort, and called a 0.4% CVE and a 0.004% one the same.
 */
function epssPlaces(n: number): number {
  return Math.round(n * 100000) / 100000;
}

/**
 * A score with its vector, as a change row shows it. Metrics left "Not Defined" (`/E:X`) are dropped:
 * NVD spells every one of them out in some CVSS 4.0 vectors and omits them in others, and 330 of 497
 * stored CVSS changes were that spelling alone ("9.2 → 9.2").
 */
function cvssText(v: { version: string; score: number; vector: string | null } | null): string | null {
  if (!v) return null;
  const vector = v.vector?.replace(/\/[A-Za-z]+:X(?=\/|$)/g, "") ?? null;
  return `${v.score.toFixed(1)} (v${v.version}${vector ? `, ${vector}` : ""})`;
}

function setDiff(before: string[], after: string[]): { added: string[]; removed: string[] } {
  const b = new Set(before);
  const a = new Set(after);
  return { added: after.filter((x) => !b.has(x)), removed: before.filter((x) => !a.has(x)) };
}

function summariseSet(name: string, diff: { added: string[]; removed: string[] }, total: number): string {
  const parts: string[] = [];
  if (diff.added.length) parts.push(`+${diff.added.length}`);
  if (diff.removed.length) parts.push(`-${diff.removed.length}`);
  return `${parts.join(" ")} ${name} (now ${total})`;
}

export interface UpsertResult {
  isNew: boolean;
  /**
   * This sighting is the first full record of the CVE here (no row yet, or only the CVE list's) or
   * the one at which it first scores critical: what "new critical" means for isNotable. The CVE list
   * often lands a record seconds before NVD's, and NVD often scores a CVE days after publishing it.
   */
  fresh: boolean;
  changes: VulnChange[];
  watchLabels: string[];
  /** The labels among them that came from platform entries ("Apple"), for the alert's wording. */
  watchPlatforms: string[];
  row: VulnRow;
}

/** Stores one normalised CVE, recording what changed since it was last seen. */
export function upsertVuln(db: DatabaseSync, n: NormalizedVuln, observedAt: string, watch: WatchEntry[]): UpsertResult {
  const existing = db.prepare("SELECT * FROM vulns WHERE cve_id = ?").get(n.cveId) as unknown as VulnRow | undefined;
  // A source that says nothing about packages (NVD) must not lose the ones an advisory attached.
  const packages = n.packages ?? parseJson<AffectedPackage[]>(existing?.packages_json ?? null, []);
  // CISA's names: the row's own, or, for a KEV CVE NVD reaches first, the catalogue item's.
  const kevNames = existing?.kev_vendor ? { vendor: existing.kev_vendor, product: existing.kev_product } : n.kev || existing?.kev === 1 ? kevNamesFromItems(db, n.cveId) : null;
  const platforms = rowPlatforms({ ...n, kevVendor: kevNames?.vendor, kevProduct: kevNames?.product });
  const hits = matchWatchDetailed({ ...n, packages, platforms, kevVendor: kevNames?.vendor ?? null, kevProduct: kevNames?.product ?? null }, watch);
  const watchLabels = hits.map((h) => h.label);
  const watchPlatforms = hits.filter((h) => h.kind === "platform").map((h) => h.label);
  const changes: VulnChange[] = [];
  // A row the KEV catalogue made before NVD sent one: NVD filling it in is not a change to report,
  // the catalogue's own item was the news.
  // Known by the column the catalogue sets and no other source writes: cvelist may already have
  // replaced the status before NVD's record arrives.
  const placeholder = existing?.source_identifier === kevSourceIdentifier;

  if (placeholder) {
    // nothing: the first full record of a CVE already in the table
  } else if (!existing) {
    const summary = [n.cvss ? `CVSS ${n.cvss.score.toFixed(1)}` : "unscored", n.kev ? "in KEV" : null, n.vendors.length ? n.vendors.slice(0, 3).join(", ") : null]
      .filter(Boolean)
      .join(" · ");
    changes.push({ field: "new", before: null, after: summary });
  } else {
    const beforeCvss = existing.cvss_score !== null ? cvssText({ version: existing.cvss_version ?? "", score: existing.cvss_score, vector: existing.cvss_vector }) : null;
    const afterCvss = cvssText(n.cvss);
    if (beforeCvss !== afterCvss) changes.push({ field: "cvss", before: beforeCvss, after: afterCvss });
    if ((existing.description ?? null) !== (n.description ?? null)) changes.push({ field: "description", before: existing.description, after: n.description });
    if ((existing.vuln_status ?? null) !== (n.vulnStatus ?? null)) changes.push({ field: "status", before: existing.vuln_status, after: n.vulnStatus });
    const cpeDiff = setDiff(parseJson<string[]>(existing.cpes_json, []), n.cpes);
    if (cpeDiff.added.length || cpeDiff.removed.length) {
      changes.push({ field: "cpes", before: null, after: summariseSet("CPE criteria", cpeDiff, n.cpes.length) });
    }
    const refDiff = setDiff(parseJson<{ url: string }[]>(existing.references_json, []).map((r) => r.url), n.references.map((r) => r.url));
    if (refDiff.added.length || refDiff.removed.length) {
      changes.push({ field: "references", before: null, after: summariseSet("references", refDiff, n.references.length) });
    }
    const cweDiff = setDiff(parseJson<string[]>(existing.cwes_json, []), n.cwes);
    if (cweDiff.added.length || cweDiff.removed.length) {
      changes.push({ field: "cwes", before: parseJson<string[]>(existing.cwes_json, []).join(", ") || null, after: n.cwes.join(", ") || null });
    }
    if (existing.kev === 0 && n.kev) changes.push({ field: "kev", before: null, after: `added to CISA KEV${n.kev.dueDate ? `, due ${n.kev.dueDate}` : ""}` });
  }

  const kevDateAdded = n.kev?.dateAdded ?? existing?.kev_date_added ?? null;
  const kevDueDate = n.kev?.dueDate ?? existing?.kev_due_date ?? null;
  const kev = n.kev || existing?.kev === 1 ? 1 : 0;

  db.prepare(
    `INSERT INTO vulns (cve_id, source_identifier, published_at, last_modified_at, vuln_status, description,
        cvss_version, cvss_score, cvss_severity, cvss_vector, cvss_source, ssvc_json, cwes_json, cpes_json, vendors_json, products_json,
        references_json, kev, kev_date_added, kev_due_date, watch_hit, watch_labels_json, platforms_json, first_seen_at, last_seen_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (cve_id) DO UPDATE SET
        source_identifier = excluded.source_identifier, published_at = excluded.published_at, last_modified_at = excluded.last_modified_at,
        vuln_status = excluded.vuln_status, description = excluded.description, cvss_version = excluded.cvss_version, cvss_score = excluded.cvss_score,
        cvss_severity = excluded.cvss_severity, cvss_vector = excluded.cvss_vector, cvss_source = excluded.cvss_source, ssvc_json = excluded.ssvc_json,
        cwes_json = excluded.cwes_json, cpes_json = excluded.cpes_json, vendors_json = excluded.vendors_json, products_json = excluded.products_json,
        references_json = excluded.references_json, kev = excluded.kev, kev_date_added = excluded.kev_date_added, kev_due_date = excluded.kev_due_date,
        watch_hit = excluded.watch_hit, watch_labels_json = excluded.watch_labels_json, platforms_json = excluded.platforms_json,
        last_seen_at = excluded.last_seen_at`,
  ).run(
    n.cveId,
    n.sourceIdentifier,
    n.publishedAt,
    n.lastModifiedAt,
    n.vulnStatus,
    n.description,
    n.cvss?.version ?? null,
    n.cvss?.score ?? null,
    n.cvss?.severity ?? null,
    n.cvss?.vector ?? null,
    n.cvss?.source ?? null,
    n.ssvc ? JSON.stringify(n.ssvc) : null,
    JSON.stringify(n.cwes),
    JSON.stringify(n.cpes),
    JSON.stringify(n.vendors),
    JSON.stringify(n.products),
    JSON.stringify(n.references),
    kev,
    kevDateAdded,
    kevDueDate,
    watchLabels.length ? 1 : 0,
    watchLabels.length ? JSON.stringify(watchLabels) : null,
    JSON.stringify(platforms),
    existing?.first_seen_at ?? observedAt,
    observedAt,
  );

  const insertChange = db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, nvd_modified_at, field, before_text, after_text) VALUES (?, ?, ?, ?, ?, ?)");
  for (const c of changes) insertChange.run(n.cveId, observedAt, n.lastModifiedAt, c.field, c.before, c.after);
  if (kev === 1 && (existing?.kev_ransomware ?? null) === null) fillKevRansomware(db, n.cveId);
  if (kevNames && !existing?.kev_vendor && kevNames.vendor) db.prepare("UPDATE vulns SET kev_vendor = ?, kev_product = ? WHERE cve_id = ?").run(kevNames.vendor, kevNames.product, n.cveId);

  const row = db.prepare("SELECT * FROM vulns WHERE cve_id = ?").get(n.cveId) as unknown as VulnRow;
  // A KEV placeholder's first NVD record is the catalogue's CVE filled in, not a fresh critical.
  const fresh = !existing || (!placeholder && (existing.source_identifier === cvelistSourceIdentifier || ((existing.cvss_score ?? 0) < 9 && (n.cvss?.score ?? 0) >= 9)));
  return { isNew: !existing, fresh, changes, watchLabels, watchPlatforms, row };
}

/** A CVE id, bare or with a distribution's prefix (DEBIAN-CVE-2026-1234, UBUNTU-CVE-2026-1234). */
const cvePattern = /^(?:[A-Z]+-)?(CVE-\d{4}-\d{4,})$/i;

/** The row an advisory lands on: its CVE when it has one, else the GHSA id among its ids, else its own id. */
export function advisoryKey(a: { id: string; aliases: string[] }): string {
  const ids = [a.id, ...a.aliases];
  for (const id of ids) {
    const cve = cvePattern.exec(id)?.[1];
    if (cve) return cve.toUpperCase();
  }
  return (ids.find((x) => /^GHSA-/i.test(x)) ?? a.id).toUpperCase();
}

function packageKey(p: { ecosystem: string; name: string }): string {
  return `${p.ecosystem}:${p.name}`.toLowerCase();
}

/** Affected packages from two sightings, merged by package with their version lists united. */
function mergePackages(before: AffectedPackage[], after: AffectedPackage[]): AffectedPackage[] {
  const out = new Map<string, AffectedPackage>();
  for (const p of [...before, ...after]) {
    const key = packageKey(p);
    const seen = out.get(key);
    if (!seen) {
      out.set(key, { ...p, introduced: [...p.introduced], fixed: [...p.fixed], lastAffected: [...p.lastAffected] });
      continue;
    }
    seen.introduced = [...new Set([...seen.introduced, ...p.introduced])];
    seen.fixed = [...new Set([...seen.fixed, ...p.fixed])];
    seen.lastAffected = [...new Set([...seen.lastAffected, ...p.lastAffected])];
    if (!seen.advisory && p.advisory) seen.advisory = p.advisory;
  }
  return [...out.values()].sort((x, y) => packageKey(x).localeCompare(packageKey(y)));
}

function packagesText(packages: AffectedPackage[]): string {
  return packages
    .slice(0, 6)
    .map((p) => `${p.ecosystem}:${p.name}${p.fixed.length ? ` (fixed in ${p.fixed.slice(0, 3).join(", ")})` : ""}`)
    .join("; ");
}

/**
 * Stores what a package advisory says, on the CVE it names when NVD has that CVE (then only the
 * packages, the advisory ids and the watch marks change) or as a row of its own otherwise, so a
 * GHSA that NVD has not analysed yet still shows. Records a `packages` change when the affected
 * set moves.
 */
export function applyAdvisory(db: DatabaseSync, a: NormalizedAdvisory, observedAt: string, watch: WatchEntry[]): UpsertResult & { key: string } {
  const key = advisoryKey(a);
  const existing = db.prepare("SELECT * FROM vulns WHERE cve_id = ?").get(key) as unknown as VulnRow | undefined;
  const aliases = [...new Set([a.id, ...a.aliases].map((x) => x.toUpperCase()).filter((x) => x !== key))].sort();
  const ownRow = existing === undefined || existing.source_identifier === "osv.dev" || existing.source_identifier === "github-advisories";
  const before = parseJson<AffectedPackage[]>(existing?.packages_json ?? null, []);
  const packages = mergePackages(before, a.packages);
  const changes: VulnChange[] = [];
  let result: UpsertResult;

  if (ownRow) {
    const description = [a.summary, a.details].filter((t): t is string => !!t && t.trim() !== "").join("\n\n").replace(/[ \t]+/g, " ").trim().slice(0, 2000) || null;
    result = upsertVuln(
      db,
      {
        cveId: key,
        sourceIdentifier: /^GHSA-/i.test(a.id) ? "github-advisories" : "osv.dev",
        publishedAt: a.publishedAt,
        lastModifiedAt: a.modifiedAt,
        vulnStatus: "Advisory",
        description,
        cvss: a.cvss,
        ssvc: null,
        cwes: a.cwes,
        cpes: [],
        vendors: [],
        products: [],
        references: a.references,
        kev: null,
        packages,
      },
      observedAt,
      watch,
    );
    changes.push(...result.changes);
  } else {
    // The row's stored platforms and CISA's names, as upsertVuln reads them: without them a KEV-only
    // Windows row lost its platform watch when a GHSA alias arrived, though still on the Windows card.
    const hits = matchWatchDetailed(storedWatchInput(existing, packages), watch);
    const watchLabels = hits.map((h) => h.label);
    const watchPlatforms = hits.filter((h) => h.kind === "platform").map((h) => h.label);
    result = { isNew: false, fresh: false, changes: [], watchLabels, watchPlatforms, row: existing };
  }

  const beforeKeys = new Set(before.map(packageKey));
  const added = packages.filter((p) => !beforeKeys.has(packageKey(p)));
  const fixedMoved = packages.some((p) => {
    const was = before.find((b) => packageKey(b) === packageKey(p));
    return was !== undefined && p.fixed.some((f) => !was.fixed.includes(f));
  });
  if (!result.isNew && (added.length || fixedMoved)) {
    const change: VulnChange = { field: "packages", before: before.length ? packagesText(before) : null, after: packagesText(packages) };
    changes.push(change);
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, nvd_modified_at, field, before_text, after_text) VALUES (?, ?, ?, ?, ?, ?)").run(key, observedAt, a.modifiedAt, change.field, change.before, change.after);
  }

  db.prepare("UPDATE vulns SET packages_json = ?, aliases_json = ?, watch_hit = ?, watch_labels_json = ?, last_seen_at = ? WHERE cve_id = ?").run(
    packages.length ? JSON.stringify(packages) : null,
    aliases.length ? JSON.stringify(aliases) : null,
    result.watchLabels.length ? 1 : 0,
    result.watchLabels.length ? JSON.stringify(result.watchLabels) : null,
    observedAt,
    key,
  );
  const row = db.prepare("SELECT * FROM vulns WHERE cve_id = ?").get(key) as unknown as VulnRow;
  return { key, isNew: result.isNew, fresh: result.fresh, changes, watchLabels: result.watchLabels, watchPlatforms: result.watchPlatforms, row };
}

/**
 * KEV entries already stored as items whose CVE has no row: the catalogue is parsed only when its
 * bytes change, so on the first start after an upgrade the rows applyKev now makes would wait for
 * CISA's next addition. Read from the items this instance holds; nothing is fetched.
 */
export function backfillKevRows(db: DatabaseSync, observedAt: string): number {
  fillKevRansomware(db);
  const rows = db
    .prepare("SELECT i.external_id AS cveId, i.published_at, i.summary, i.title, i.signals_json FROM items i WHERE i.kind = 'kev' AND NOT EXISTS (SELECT 1 FROM vulns v WHERE v.cve_id = i.external_id)")
    .all() as { cveId: string; published_at: string | null; summary: string | null; title: string; signals_json: string | null }[];
  if (rows.length === 0) return 0;
  applyKev(
    db,
    rows.map((r) => {
      const s = parseJson<{ dueDate?: string; ransomware?: boolean; vendor?: string; product?: string }>(r.signals_json, {});
      return { cveId: r.cveId, dateAdded: r.published_at?.slice(0, 10) ?? null, dueDate: s.dueDate ?? null, ransomware: s.ransomware === true, description: r.summary ?? r.title, vendor: s.vendor ?? null, product: s.product ?? null };
    }),
    observedAt,
  );
  return rows.length;
}

/**
 * CISA's ransomware mark on a KEV row that lacks it, read from the catalogue entry this instance
 * already holds as an item. NVD's record says a CVE is in KEV but not whether ransomware crews use
 * it, and the catalogue is parsed only when its bytes change, so a row NVD made after the last
 * parse stayed NULL (37 on the public instance, 2026-11-16) and out of the ransomware filter.
 * With `cveId`, the one row an NVD upsert just wrote; without, every such row.
 */
export function fillKevRansomware(db: DatabaseSync, cveId?: string): number {
  return Number(
    db
      .prepare(
        `UPDATE vulns SET kev_ransomware = (
           SELECT CASE WHEN json_extract(i.signals_json, '$.ransomware') = 1 THEN 1 ELSE 0 END
             FROM items i WHERE i.source_id = 'cisa-kev' AND i.external_id = vulns.cve_id AND i.kind = 'kev' AND json_valid(i.signals_json) LIMIT 1)
         WHERE kev = 1 AND kev_ransomware IS NULL ${cveId ? "AND cve_id = ?" : ""}
           AND EXISTS (SELECT 1 FROM items i WHERE i.source_id = 'cisa-kev' AND i.external_id = vulns.cve_id AND i.kind = 'kev' AND json_valid(i.signals_json))`,
      )
      .run(...(cveId ? [cveId] : [])).changes,
  );
}

/** CISA's vendor and product for a CVE, lower-cased, from the catalogue item this instance holds. */
function kevNamesFromItems(db: DatabaseSync, cveId: string): { vendor: string | null; product: string | null } | null {
  const row = db
    .prepare(
      `SELECT nullif(lower(trim(json_extract(signals_json, '$.vendor'))), '') AS vendor, nullif(lower(trim(json_extract(signals_json, '$.product'))), '') AS product
         FROM items WHERE source_id = 'cisa-kev' AND kind = 'kev' AND external_id = ? AND json_valid(signals_json) LIMIT 1`,
    )
    .get(cveId) as { vendor: string | null; product: string | null } | undefined;
  return row?.vendor ? row : null;
}

/** The status of a row the KEV catalogue made because NVD had not sent the CVE; NVD's first record replaces it. */
const kevOnlyStatus = "KEV only";
/** The source_identifier of such a row; NVD's record replaces it with the CNA's. */
export const kevSourceIdentifier = "CISA KEV";

/** The source_identifier of a row the CVE list made and NVD has not filled in yet. */
export const cvelistSourceIdentifier = "cvelist-v5";

/**
 * Flags a CVE as in CISA's KEV from the KEV catalog, for CVEs NVD has not marked yet. An entry
 * whose CVE has no row gets one from the catalogue's own words, so "every KEV entry is in the
 * table" is true: before this, 1,639 of 1,780 on the public instance had no row and their links 404'd.
 */
export function applyKev(
  db: DatabaseSync,
  entries: { cveId: string; dateAdded: string | null; dueDate: string | null; ransomware: boolean; description?: string | null; vendor?: string | null; product?: string | null }[],
  observedAt: string,
): number {
  const select = db.prepare("SELECT kev, kev_vendor, kev_product FROM vulns WHERE cve_id = ?");
  const insert = db.prepare(
    `INSERT INTO vulns (cve_id, source_identifier, published_at, last_modified_at, vuln_status, description, cwes_json, cpes_json, vendors_json, products_json,
        references_json, kev, kev_date_added, kev_due_date, kev_ransomware, kev_vendor, kev_product, watch_hit, watch_labels_json, platforms_json, first_seen_at, last_seen_at)
     VALUES (?, ?, ?, ?, ?, ?, '[]', '[]', ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  // A catalogue row is matched against the watchlist and given its platforms as it is made, as an
  // NVD row is: otherwise a watched product's exploited CVE stayed out of "your stack" until the
  // watchlist was next edited, and out of the platform views until the next restart.
  const watch = loadWatchlist(db);
  const update = db.prepare(
    "UPDATE vulns SET kev = 1, kev_date_added = COALESCE(kev_date_added, ?), kev_due_date = COALESCE(?, kev_due_date), kev_ransomware = ?, kev_vendor = COALESCE(?, kev_vendor), kev_product = COALESCE(?, kev_product) WHERE cve_id = ?",
  );
  // Every row the catalogue reaches is read again (rowPlatforms) once CISA's names are written, and
  // its platforms cleared when the reading differs: recomputePlatforms below fills them, and the
  // trigger of migration 0047 keeps vuln_platforms in step.
  const reread = db.prepare("SELECT cpes_json, vendors_json, products_json, description, kev_vendor, kev_product, platforms_json FROM vulns WHERE cve_id = ?");
  const unplace = db.prepare("UPDATE vulns SET platforms_json = NULL WHERE cve_id = ?");
  // Rows whose CISA vendor or product was just written: matched against the watchlist again after.
  const renamed: string[] = [];
  // Rows with no platform when the catalogue reached them: placed again from CISA's names after.
  const replaced: string[] = [];
  const change = db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, nvd_modified_at, field, before_text, after_text) VALUES (?, ?, NULL, 'kev', NULL, ?)");
  let flagged = 0;
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const e of entries) {
      const row = select.get(e.cveId) as { kev: number; kev_vendor: string | null; kev_product: string | null } | undefined;
      const kevVendor = e.vendor?.trim() ? e.vendor.trim().toLowerCase() : null;
      const kevProduct = e.product?.trim() ? e.product.trim().toLowerCase() : null;
      if (!row) {
        if (!cveIdPattern.test(e.cveId)) continue;
        // No publication date is known until the CVE list or NVD says it; the catalogue's date
        // added is when it changed, not when the CVE was published.
        const added = e.dateAdded ? `${e.dateAdded}T00:00:00.000Z` : observedAt;
        const vendors = kevVendor ? [kevVendor] : [];
        const products = kevProduct ? [kevProduct] : [];
        const platforms = rowPlatforms({ cpes: [], vendors, products, description: e.description ?? null, kevVendor, kevProduct });
        const hits = matchWatchDetailed({ cpes: [], vendors, products, description: e.description ?? null, platforms, kevVendor, kevProduct }, watch).map((h) => h.label);
        insert.run(
          e.cveId,
          kevSourceIdentifier,
          null,
          added,
          kevOnlyStatus,
          e.description ?? null,
          JSON.stringify(vendors),
          JSON.stringify(products),
          JSON.stringify([{ url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${e.cveId}`, tags: ["CISA KEV"] }]),
          e.dateAdded,
          e.dueDate,
          e.ransomware ? 1 : 0,
          kevVendor,
          kevProduct,
          hits.length ? 1 : 0,
          hits.length ? JSON.stringify(hits) : null,
          JSON.stringify(platforms),
          observedAt,
          observedAt,
        );
        // A recent addition is movement Today should see; the catalogue's back-catalogue is not.
        if (e.dateAdded && Date.parse(observedAt) - Date.parse(added) <= 7 * 24 * 60 * 60 * 1000) change.run(e.cveId, observedAt, `added to CISA KEV${e.dueDate ? `, due ${e.dueDate}` : ""}`);
        continue;
      }
      update.run(e.dateAdded, e.dueDate, e.ransomware ? 1 : 0, kevVendor, kevProduct, e.cveId);
      const now = reread.get(e.cveId) as { cpes_json: string | null; vendors_json: string | null; products_json: string | null; description: string | null; kev_vendor: string | null; kev_product: string | null; platforms_json: string | null };
      const reading = JSON.stringify(
        rowPlatforms({
          cpes: parseJson<string[]>(now.cpes_json, []),
          vendors: parseJson<string[]>(now.vendors_json, []),
          products: parseJson<string[]>(now.products_json, []),
          description: now.description,
          kevVendor: now.kev_vendor,
          kevProduct: now.kev_product,
        }),
      );
      if (now.platforms_json !== reading) {
        unplace.run(e.cveId);
        replaced.push(e.cveId);
      }
      if ((kevVendor !== null && kevVendor !== row.kev_vendor) || (kevProduct !== null && kevProduct !== row.kev_product)) renamed.push(e.cveId);
      if (row.kev === 0) {
        change.run(e.cveId, observedAt, `added to CISA KEV${e.dueDate ? `, due ${e.dueDate}` : ""}`);
        flagged += 1;
      }
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
  const placed = replaced.length ? recomputePlatforms(db) : [];
  const again = [...new Set([...renamed, ...placed])];
  if (again.length && watch.length) recomputeWatchHits(db, again);
  return flagged;
}

export interface EpssScore {
  cveId: string;
  epss: number;
  percentile: number;
}

/** Below this a score must fall before a rise past epssNotable is news again. */
const epssRearm = 0.4;

/**
 * Joins a day's EPSS scores onto the CVEs BaselineWatch knows. A jump of 0.1 or more on a KEV or
 * watched CVE is a change; so is any live CVE crossing 50%, which isNotable puts on the News (the
 * table's own words promise "EPSS over 50%" there, and before this no score ever put one there).
 */
export function applyEpss(db: DatabaseSync, scores: Iterable<EpssScore>, scoreDate: string, observedAt: string): { updated: number; changes: number } {
  const known = new Map<string, { epss: number | null; notable: boolean; kev: boolean; published: string | null; crossedAt: string | null }>();
  for (const r of db.prepare("SELECT cve_id, epss, kev, watch_hit, published_at, epss_crossed_at FROM vulns").all() as { cve_id: string; epss: number | null; kev: number; watch_hit: number; published_at: string | null; epss_crossed_at: string | null }[]) {
    known.set(r.cve_id, { epss: r.epss, notable: r.kev === 1 || r.watch_hit === 1, kev: r.kev === 1, published: r.published_at, crossedAt: r.epss_crossed_at });
  }
  // A first score is a crossing only for a CVE published lately that CISA does not list: the first
  // EPSS file on a new instance scores every KEV and backfilled CVE at once, and every backfilled
  // CVE was first seen lately. A later score crosses when it reaches 50% from below while the CVE
  // is armed: epss_crossed_at (migration 0063) is set whenever a score is at or over 50% and
  // cleared only when one falls below 40%. So a gradual rise (35%, 45%, 55%) is news once, and a
  // score that hovers around 50% is not news every time it dips and returns.
  const update = db.prepare("UPDATE vulns SET epss = ?, epss_percentile = ?, epss_date = ?, epss_crossed_at = ? WHERE cve_id = ?");
  const change = db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, nvd_modified_at, field, before_text, after_text) VALUES (?, ?, NULL, 'epss', ?, ?)");
  const crossed: { cveId: string; change: VulnChange }[] = [];
  let updated = 0;
  let changes = 0;
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const s of scores) {
      const current = known.get(s.cveId);
      if (!current) continue;
      const after = epssPlaces(s.epss);
      const crossedAt = after >= epssNotable ? (current.crossedAt ?? observedAt) : after < epssRearm ? null : current.crossedAt;
      update.run(after, epssPlaces(s.percentile), scoreDate, crossedAt, s.cveId);
      updated += 1;
      const armed = current.crossedAt === null;
      const crossing = after >= epssNotable && armed && (current.epss !== null ? current.epss < epssNotable : !current.kev && publishedWithin(current.published, observedAt, recentDays));
      if (crossing || (current.notable && current.epss !== null && Math.abs(current.epss - s.epss) >= 0.1)) {
        const before = current.epss !== null ? epssPercent(current.epss) : null;
        change.run(s.cveId, observedAt, before, epssPercent(after));
        changes += 1;
        if (crossing) crossed.push({ cveId: s.cveId, change: { field: "epss", before, after: `EPSS ${epssPercent(after)}` } });
      }
    }
    for (const c of crossed) {
      const row = db.prepare("SELECT * FROM vulns WHERE cve_id = ?").get(c.cveId) as unknown as VulnRow;
      if (isNotable(row, false, observedAt)) recordVulnItem(db, row, [c.change], observedAt, observedAt);
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
  return { updated, changes };
}

/**
 * Fills platforms_json for every row that lacks it: rows that predate migration 0032, an upsert
 * that could not read a platform, and the KEV-only rows a migration cleared so they are read
 * again with a newer rule (0058, 0059, 0060). Called at every start, the way the Register
 * relinks; costs one query when nothing is missing. Returns the CVE ids it filled, so the caller
 * can match just those against the watchlist again.
 */
export function recomputePlatforms(db: DatabaseSync, limit = 100_000): string[] {
  const rows = db
    .prepare("SELECT cve_id, cpes_json, vendors_json, products_json, description, kev_vendor, kev_product FROM vulns WHERE platforms_json IS NULL LIMIT ?")
    .all(limit) as { cve_id: string; cpes_json: string | null; vendors_json: string | null; products_json: string | null; description: string | null; kev_vendor: string | null; kev_product: string | null }[];
  if (rows.length === 0) return [];
  const update = db.prepare("UPDATE vulns SET platforms_json = ? WHERE cve_id = ?");
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const row of rows) {
      const platforms = rowPlatforms({
        cpes: parseJson<string[]>(row.cpes_json, []),
        vendors: parseJson<string[]>(row.vendors_json, []),
        products: parseJson<string[]>(row.products_json, []),
        description: row.description,
        kevVendor: row.kev_vendor,
        kevProduct: row.kev_product,
      });
      update.run(JSON.stringify(platforms), row.cve_id);
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
  return rows.map((r) => r.cve_id);
}

/** Re-reads every CVE against the watchlist, or only the ones named (a source that changed their words). */
export function recomputeWatchHits(db: DatabaseSync, only?: readonly string[]): number {
  const entries = loadWatchlist(db);
  const columns = "cve_id, cpes_json, vendors_json, products_json, description, watch_hit, watch_labels_json, packages_json, platforms_json, kev_vendor, kev_product";
  const rows = (
    only === undefined
      ? db.prepare(`SELECT ${columns} FROM vulns`).all()
      : Array.from({ length: Math.ceil(only.length / 500) }, (_, i) => only.slice(i * 500, i * 500 + 500)).flatMap((ids) =>
          db.prepare(`SELECT ${columns} FROM vulns WHERE cve_id IN (${ids.map(() => "?").join(", ")})`).all(...ids),
        )
  ) as {
    platforms_json: string | null;
    cve_id: string;
    cpes_json: string | null;
    vendors_json: string | null;
    products_json: string | null;
    description: string | null;
    watch_hit: number;
    watch_labels_json: string | null;
    packages_json: string | null;
    kev_vendor: string | null;
    kev_product: string | null;
  }[];
  const update = db.prepare("UPDATE vulns SET watch_hit = ?, watch_labels_json = ? WHERE cve_id = ?");
  let changed = 0;
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const r of rows) {
      const labels = matchWatch(storedWatchInput(r), entries);
      const json = labels.length ? JSON.stringify(labels) : null;
      const hit = labels.length ? 1 : 0;
      if (hit !== r.watch_hit || json !== r.watch_labels_json) {
        update.run(hit, json, r.cve_id);
        changed += 1;
      }
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
  return changed;
}

export interface VulnFilters {
  /** Only CVEs their assigner has withdrawn. Without it the table leaves them out: a rejected id is not a vulnerability. */
  rejected?: boolean;
  watch?: boolean;
  kev?: boolean;
  /** Only KEV entries CISA marks as known to be used in ransomware campaigns. */
  ransomware?: boolean;
  /** One weakness, as NVD writes it: "CWE-787". */
  cwe?: string | undefined;
  /** Only CVEs with at least one row in the exploits table (src/exploits.ts). */
  exploit?: boolean;
  /** Only KEV entries whose CISA due date falls in this inclusive range (YYYY-MM-DD): "Due this week" is today to today + 6, seven days. */
  dueFrom?: string | undefined;
  dueTo?: string | undefined;
  /** One of src/platforms.ts' ids: the CVEs whose CPEs, vendors, products or description put them on that platform. */
  platform?: PlatformChoice | undefined;
  /** The most dangerous: exploited (KEV, or SSVC says active), a public exploit, or likely to be (EPSS ≥ 50%). */
  danger?: boolean;
  minCvss?: number | undefined;
  /** One CVSS severity as NVD words it, or "unscored" for a CVE without one, the way the Today page bands them. */
  severity?: "critical" | "high" | "medium" | "low" | "unscored" | undefined;
  minEpss?: number | undefined;
  /** An exclusive upper bound, so EPSS bands tile the range without overlapping. */
  maxEpss?: number | undefined;
  /** Only CVEs that have no EPSS score yet. */
  noEpss?: boolean;
  changedSince?: string | undefined;
  /** Only CVEs first seen since this instant: the list the "New, 24 h" figure is counted from. */
  newSince?: string | undefined;
  /** The windows above in hours, for the links and chips that carry them (24 when unset). */
  changedHours?: number | undefined;
  newHours?: number | undefined;
  /**
   * Only CVEs published or really changed since this instant: Today's window (`movedInWindowSql`),
   * which leaves out a record NVD merely re-touched. Today's figures link here, so the list they
   * open has the count they show.
   */
  movedSince?: string | undefined;
  movedHours?: number | undefined;
  /** Only CVEs the watchlist marked with this label: the figure beside a watchlist entry is counted this way. */
  label?: string | undefined;
  q?: string | undefined;
  sort?: "risk" | "modified" | "published" | "cvss" | "epss";
  offset?: number;
  limit?: number;
}

/** A weakness id as NVD writes it, whatever case it was typed in: "cwe-787" reads as "CWE-787"; anything else is no filter. */
export function cweOf(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const s = v.trim().toUpperCase();
  if (s === "" || s.length > 20) return undefined;
  const id = /^CWE-?(\d{1,5})$/.exec(s);
  // Leading zeros go: "CWE-079" is NVD's CWE-79, and the filter compares strings.
  if (id) return `CWE-${Number(id[1])}`;
  if (/^\d{1,5}$/.test(s)) return `CWE-${Number(s)}`;
  // NVD's two placeholders for a weakness it could not name.
  return s === "NVD-CWE-OTHER" ? "NVD-CWE-Other" : s === "NVD-CWE-NOINFO" ? "NVD-CWE-noinfo" : undefined;
}

/**
 * KEV entries that are the owner's and past CISA's due date: on the watchlist or triaged "affects
 * us" (on the CVE, or on its KEV item), and not since marked done (or, on the CVE, not ours: a
 * KEV item marked not ours may be one of the backlog cleared in bulk before the product was
 * watched, so it does not hide a watched CVE). CISA's date binds
 * federal agencies; for everyone else it is the clock the catalogue sets. `today` is YYYY-MM-DD;
 * a date is past once the day after it begins. Returns the count and the oldest few.
 */
export function overdueKev(db: DatabaseSync, today: string, limit = 5): { total: number; cves: { cveId: string; dueDate: string }[] } {
  const where = `v.kev = 1 AND v.kev_due_date IS NOT NULL AND v.kev_due_date < ? AND ${liveSql}
    AND (v.watch_hit = 1
      OR EXISTS (SELECT 1 FROM triage t WHERE t.subject_kind = 'vuln' AND t.subject_id = v.id AND t.state = 'affects')
      OR EXISTS (SELECT 1 FROM triage t JOIN items i ON i.id = t.subject_id WHERE t.subject_kind = 'item' AND t.state = 'affects' AND i.kind IN ('kev', 'vulnerability') AND i.external_id = v.cve_id))
    AND NOT EXISTS (SELECT 1 FROM triage t WHERE t.subject_kind = 'vuln' AND t.subject_id = v.id AND t.state IN ('done', 'dismissed'))
    AND NOT EXISTS (SELECT 1 FROM triage t JOIN items i ON i.id = t.subject_id WHERE t.subject_kind = 'item' AND t.state = 'done' AND i.kind IN ('kev', 'vulnerability') AND i.external_id = v.cve_id)`;
  const total = (db.prepare(`SELECT COUNT(*) AS n FROM vulns v WHERE ${where}`).get(today) as { n: number }).n;
  const cves = total
    ? (db.prepare(`SELECT v.cve_id AS cveId, v.kev_due_date AS dueDate FROM vulns v WHERE ${where} ORDER BY v.kev_due_date, v.cve_id LIMIT ?`).all(today, limit) as { cveId: string; dueDate: string }[])
    : [];
  return { total, cves };
}

/** The "most dangerous" line: being exploited, an exploit anyone can run, or a forecast that one will be. Takes no parameters. */
export const dangerSql = "(v.kev = 1 OR v.has_exploit = 1 OR COALESCE(v.epss, 0) >= 0.5 OR json_extract(v.ssvc_json, '$.exploitation') = 'active')";

/**
 * A platform and the dangerous line as SQL over `vulns v`, for a list that is not the table's own
 * (Today's fix list): the same clauses `vulnQuery` writes, so "Windows" means one thing everywhere.
 */
export function scopeSql(scope: { platform?: PlatformChoice | undefined; danger?: boolean | undefined }): { sql: string; params: string[] } {
  const clauses: string[] = [];
  const params: string[] = [];
  if (scope.platform) {
    const keys = platformKeysOf(scope.platform);
    clauses.push(`v.id IN (SELECT vuln_id FROM vuln_platforms WHERE platform IN (${keys.map(() => "?").join(", ")}))`);
    params.push(...keys);
  }
  if (scope.danger) clauses.push(dangerSql);
  return { sql: clauses.map((c) => ` AND ${c}`).join(""), params };
}

/**
 * What is affecting each platform, for the cards the Vulnerabilities page opens on: how many CVEs,
 * how many exploited, how many with a public exploit, how many first seen since `since` (the
 * table's `new` filter, so the figure and the list it opens agree), and the
 * worst of them by the table's own risk order. Plus the same figures for the dangerous line
 * across every platform. Six small indexed queries; no watchlist in it, so it reads the same to
 * everyone.
 */
export interface PlatformFigures {
  id: PlatformChoice | "danger";
  label: string;
  blurb: string;
  total: number;
  kev: number;
  exploit: number;
  recent: number;
  worst: Pick<VulnRow, "cve_id" | "cvss_score" | "kev" | "description" | "vendors_json" | "products_json"> | null;
  /** The worst CVE's product that put it on this platform ("microsoft windows 11 24h2"), as words. */
  worstProduct: string | null;
}

/**
 * The product a CVE is on a platform for: the first CPE criterion that places it there, as words,
 * not the first vendor NVD happens to list (a NetApp firmware on the Linux card read as though
 * NetApp were the Linux flaw). Falls back to the first vendor and product.
 */
export function productOnPlatform(row: { cpes_json?: string | null; vendors_json: string | null; products_json: string | null }, keys: readonly string[] | null): string | null {
  const words = (vendor: string, product: string) => [...new Set([vendor, product].filter((w) => w))].join(" ").replace(/_/g, " ");
  if (keys) {
    for (const cpe of parseJson<string[]>(row.cpes_json ?? null, [])) {
      const placed = platformsOf({ cpes: [cpe], vendors: [], products: [], description: null });
      if (!placed.some((p) => keys.includes(p))) continue;
      const parts = cpe.split(":");
      return words(parts[3] ?? "", parts[4] ?? "");
    }
  }
  const vendor = parseJson<string[]>(row.vendors_json, [])[0] ?? "";
  const product = parseJson<string[]>(row.products_json, [])[0] ?? "";
  return vendor || product ? words(vendor, product) : null;
}

/**
 * Kept until the data moves: about 75 ms to count across 46,000 CVEs, on the page everyone opens.
 * The key is the newest change, exploit and EPSS day and the CVE count — each moves when an ingest
 * changes anything these figures read — and the window's start to the hour.
 */
const figureCache = new WeakMap<DatabaseSync, { key: string; value: PlatformFigures[] }>();

export function platformFigures(db: DatabaseSync, since: string): PlatformFigures[] {
  const marks = db
    .prepare(
      `SELECT (SELECT MAX(rowid) FROM vuln_changes) AS changed, (SELECT MAX(rowid) FROM exploits) AS exploits,
              (SELECT MAX(rowid) FROM vulns) AS vulns, (SELECT value FROM app_settings WHERE key = 'epss.date') AS epss`,
    )
    .get() as { changed: number | null; exploits: number | null; vulns: number | null; epss: string | null };
  const key = `${marks.changed}|${marks.exploits}|${marks.vulns}|${marks.epss}|${since.slice(0, 13)}`;
  const cached = figureCache.get(db);
  if (cached?.key === key) return cached.value;
  const value = countPlatformFigures(db, since);
  figureCache.set(db, { key, value });
  return value;
}

function countPlatformFigures(db: DatabaseSync, since: string): PlatformFigures[] {
  const figures = (where: string, params: string[]) =>
    db
      .prepare(
        `SELECT COUNT(*) AS total, COALESCE(SUM(v.kev), 0) AS kev, COALESCE(SUM(v.has_exploit), 0) AS exploit,
                COALESCE(SUM(CASE WHEN v.cve_id IN (SELECT cve_id FROM vuln_changes WHERE observed_at >= ? AND field = 'new') THEN 1 ELSE 0 END), 0) AS recent
           FROM vulns v WHERE ${liveSql} AND (${where})`,
      )
      .get(since, ...params) as { total: number; kev: number; exploit: number; recent: number };
  const worst = (where: string, params: string[], keys: readonly string[] | null) => {
    const row = db.prepare(`SELECT v.cve_id, v.cvss_score, v.kev, v.description, v.vendors_json, v.products_json, v.cpes_json FROM vulns v WHERE ${liveSql} AND (${where}) ORDER BY ${sortSql.risk} LIMIT 1`).get(...params) as
      | (NonNullable<PlatformFigures["worst"]> & { cpes_json: string | null })
      | undefined;
    if (!row) return { worst: null, worstProduct: null };
    const { cpes_json, ...rest } = row;
    return { worst: rest, worstProduct: productOnPlatform({ ...rest, cpes_json }, keys) };
  };
  const out: PlatformFigures[] = platformChoices.map((c) => {
    const where = `v.id IN (SELECT vuln_id FROM vuln_platforms WHERE platform IN (${c.keys.map(() => "?").join(", ")}))`;
    return { id: c.id, label: c.label, blurb: c.blurb, ...figures(where, c.keys), ...worst(where, c.keys, c.keys) };
  });
  out.push({ id: "danger", label: "Most dangerous", blurb: "Exploited, exploit public, or likely (EPSS ≥ 50%)", ...figures(dangerSql, []), ...worst(dangerSql, [], null) });
  return out;
}

function vulnQuery(filters: VulnFilters): { where: string; params: (string | number)[] } {
  const clauses: string[] = [];
  const params: (string | number)[] = [];
  clauses.push(filters.rejected ? "v.vuln_status = 'Rejected'" : liveSql);
  if (filters.watch) clauses.push("v.watch_hit = 1");
  if (filters.platform) {
    // vuln_platforms (migration 0047) is platforms_json one row a pair, indexed; "browsers" is three ids.
    const keys = platformKeysOf(filters.platform);
    clauses.push(`v.id IN (SELECT vuln_id FROM vuln_platforms WHERE platform IN (${keys.map(() => "?").join(", ")}))`);
    params.push(...keys);
  }
  if (filters.kev) clauses.push("v.kev = 1");
  if (filters.ransomware) clauses.push("v.kev_ransomware = 1");
  if (filters.cwe) {
    // vuln_cwes (migration 0070) is cwes_json one row a pair, kept by triggers and indexed by weakness;
    // reading cwes_json with json_each parsed every row's JSON, 465 ms cold.
    clauses.push("v.id IN (SELECT vuln_id FROM vuln_cwes WHERE cwe = ?)");
    params.push(filters.cwe);
  }
  if (filters.exploit) clauses.push("v.has_exploit = 1");
  if (filters.dueFrom && filters.dueTo) {
    clauses.push("v.kev = 1 AND v.kev_due_date >= ? AND v.kev_due_date <= ?");
    params.push(filters.dueFrom, filters.dueTo);
  }
  if (filters.danger) clauses.push(dangerSql);
  if (filters.minCvss !== undefined) {
    clauses.push("v.cvss_score >= ?");
    params.push(filters.minCvss);
  }
  if (filters.severity === "unscored") clauses.push("(v.cvss_severity IS NULL OR LOWER(v.cvss_severity) NOT IN ('critical', 'high', 'medium', 'low'))");
  else if (filters.severity) {
    clauses.push("LOWER(v.cvss_severity) = ?");
    params.push(filters.severity);
  }
  if (filters.minEpss !== undefined) {
    clauses.push("v.epss >= ?");
    params.push(filters.minEpss);
  }
  if (filters.maxEpss !== undefined) {
    clauses.push("v.epss < ?");
    params.push(filters.maxEpss);
  }
  if (filters.noEpss) clauses.push("v.epss IS NULL");
  if (filters.changedSince) {
    clauses.push("v.cve_id IN (SELECT cve_id FROM vuln_changes WHERE observed_at >= ?)");
    params.push(filters.changedSince);
  }
  if (filters.movedSince) {
    clauses.push(movedInWindowSql);
    params.push(filters.movedSince, filters.movedSince);
  }
  if (filters.newSince) {
    clauses.push("v.cve_id IN (SELECT cve_id FROM vuln_changes WHERE observed_at >= ? AND field = 'new')");
    params.push(filters.newSince);
  }
  if (filters.label) {
    clauses.push("v.watch_labels_json IS NOT NULL AND EXISTS (SELECT 1 FROM json_each(v.watch_labels_json) WHERE json_each.value = ?)");
    params.push(filters.label);
  }
  if (filters.q) {
    // The same reader the News search uses (wire.ts): two copies of this could come to disagree
    // about what counts as FTS syntax, and only one of them would be the safe one.
    const query = ftsQuery(filters.q);
    if (query) {
      clauses.push("v.id IN (SELECT rowid FROM vulns_fts WHERE vulns_fts MATCH ?)");
      params.push(query);
    }
  }
  return { where: clauses.length ? `WHERE ${clauses.join(" AND ")}` : "", params };
}

/**
 * How the table is ordered. "risk" is the default, and it exists because the old default was not
 * one: ordering twenty-nine thousand CVEs by when NVD last touched them put a page of unscored,
 * zero-EPSS, single-vendor records at the top — the least useful list the data can produce, on
 * the page a practitioner opens first. The Wire is already "for what matters" (AGENTS.md); this
 * is the same rule applied to the table, which still holds every CVE.
 *
 * The order is the order a person would read it in: what is known to be exploited, then what is
 * likely to be, then how bad it is if it is, then how fresh. KEV first because CISA says it is
 * being used; a public exploit next because the work is done for the attacker; then EPSS, which
 * is a probability and not a severity; then CVSS; then recency to break the remaining ties.
 */
const sortSql: Record<NonNullable<VulnFilters["sort"]>, string> = {
  // Each written to match an index in 0045_risk_order_index.sql term for term, so a deep page is a walk, not a sort.
  risk: `v.kev DESC,
         v.has_exploit DESC,
         COALESCE(v.epss, 0) DESC,
         COALESCE(v.cvss_score, 0) DESC,
         v.last_modified_at DESC`,
  modified: "v.last_modified_at DESC",
  published: "v.published_at DESC",
  cvss: "(v.cvss_score IS NULL), v.cvss_score DESC, v.last_modified_at DESC",
  epss: "(v.epss IS NULL), v.epss DESC, v.last_modified_at DESC",
};

/** The deepest offset the table, its CSV and the API page to; the MCP tool uses the same. */
export const maxOffset = 10_000;

/** How many CVEs the table holds under these filters: the COUNT listVulns runs, without the page. */
export function countVulns(db: DatabaseSync, filters: VulnFilters = {}): number {
  const { where, params } = vulnQuery(filters);
  return (db.prepare(`SELECT COUNT(*) AS n FROM vulns v ${where}`).get(...params) as { n: number }).n;
}

/** A page of the table. A page is two hundred rows at most; the CSV export asks for more with `maxLimit`. */
export function listVulns(db: DatabaseSync, filters: VulnFilters = {}, options: { maxLimit?: number } = {}): { rows: VulnRow[]; total: number } {
  const { where, params } = vulnQuery(filters);
  const limit = Math.min(Math.max(filters.limit ?? 50, 1), options.maxLimit ?? 200);
  const offset = Math.max(filters.offset ?? 0, 0);
  const total = countVulns(db, filters);
  // Past the end there is nothing to sort: asking SQLite for page 18,000 of a 900-row list sorted
  // the whole set to answer with none, half a second each for anyone who asked.
  if (offset >= total) return { rows: [], total };
  const rows = db
    .prepare(`SELECT v.* FROM vulns v ${where} ORDER BY ${sortSql[filters.sort ?? "risk"]} LIMIT ? OFFSET ?`)
    .all(...params, limit, offset) as unknown as VulnRow[];
  return { rows, total };
}

export function getVuln(db: DatabaseSync, cveId: string): VulnRow | null {
  return (db.prepare("SELECT * FROM vulns WHERE cve_id = ?").get(cveId.toUpperCase()) as unknown as VulnRow | undefined) ?? null;
}

export interface VulnChangeRow {
  id: number;
  cve_id: string;
  observed_at: string;
  nvd_modified_at: string | null;
  field: VulnChange["field"];
  before_text: string | null;
  after_text: string | null;
}

export function vulnChanges(db: DatabaseSync, cveId: string, limit = 50): VulnChangeRow[] {
  return db.prepare("SELECT * FROM vuln_changes WHERE cve_id = ? ORDER BY observed_at DESC, id DESC LIMIT ?").all(cveId, limit) as unknown as VulnChangeRow[];
}

export function vulnStats(db: DatabaseSync, sinceIso: string): { total: number; kev: number; exploit: number; watch: number; changedSince: number; newSince: number } {
  const n = (sql: string, ...params: string[]) => (db.prepare(sql).get(...params) as { n: number }).n;
  const row = db
    .prepare(`SELECT COUNT(*) AS total, COALESCE(SUM(kev = 1), 0) AS kev, COALESCE(SUM(has_exploit = 1), 0) AS exploit, COALESCE(SUM(watch_hit = 1), 0) AS watch FROM vulns v WHERE ${liveSql}`)
    .get() as { total: number; kev: number; exploit: number; watch: number };
  const tallies = { total: row.total, kev: row.kev, exploit: row.exploit, watch: row.watch };
  return {
    // One pass over the covering index (migration 0054); has_exploit is kept equal to the exploits
    // table by triggers (0045), so it counts the same CVEs the DISTINCT over exploits did.
    ...tallies,
    // Any change observed in the window, first sightings included: the same set ?changed=1 lists and the Today tile counts.
    changedSince: n(`SELECT COUNT(DISTINCT c.cve_id) AS n FROM vuln_changes c JOIN vulns v ON v.cve_id = c.cve_id WHERE c.observed_at >= ? AND ${liveSql}`, sinceIso),
    newSince: n(`SELECT COUNT(*) AS n FROM vuln_changes c JOIN vulns v ON v.cve_id = c.cve_id WHERE c.observed_at >= ? AND c.field = 'new' AND ${liveSql}`, sinceIso),
  };
}

/** How long after publication a CVE that scores critical is still news. */
export const recentDays = 30;

/** An EPSS score at or over this puts a CVE on the News: "EPSS over 50%". */
export const epssNotable = 0.5;

/** Whether `published` falls no more than `days` days before `observedAt`; false when it is not known. */
export function publishedWithin(published: string | null, observedAt: string, days: number): boolean {
  return published !== null && Date.parse(observedAt) - Date.parse(published) <= days * 24 * 60 * 60 * 1000;
}

/** A CVSS change in the words the News, the alerts and the digest use: "CVSS 7.5 → 9.8". */
export function cvssChangeText(c: VulnChange): string {
  return `CVSS ${c.before ?? "unscored"} → ${c.after ?? "unscored"}`;
}

/**
 * Whether a CVE belongs on the Wire rather than only in the Vulnerabilities table. "New critical"
 * means published in the last thirty days and `fresh` (UpsertResult.fresh): its first full record
 * here, or the sighting that made it critical; NVD re-touching a 2015 CVE is not news.
 */
export function isNotable(row: VulnRow, fresh: boolean, observedAt: string): boolean {
  // A withdrawn id is news to nobody, whatever scores it still carries.
  if (row.vuln_status === "Rejected") return false;
  if (row.kev === 1 || row.watch_hit === 1) return true;
  if (fresh && publishedWithin(row.published_at, observedAt, recentDays) && (row.cvss_score ?? 0) >= 9) return true;
  if ((row.epss ?? 0) >= epssNotable) return true;
  const ssvc = parseJson<Record<string, string>>(row.ssvc_json, {});
  return ssvc.exploitation === "active";
}

/**
 * The same two judgements as SQL, for queries that read a page of CVEs rather than one. Both
 * assume the query aliases `vulns` as `v`. test/vulns.test.ts holds them to isNotable.
 *
 * `movedInWindowSql` is the one worth reading twice. A `vuln_changes` row with field 'new' means
 * *this instance* saw the CVE for the first time, which is not the same thing as the CVE being
 * new: on a backfill it is thousands of CVEs from years ago, all of them landing in one window.
 * So "moved" means NVD published it inside the window, or something about it other than its
 * arrival here changed. Takes the window start twice.
 */
export const movedInWindowSql = "(v.published_at >= ? OR v.cve_id IN (SELECT cve_id FROM vuln_changes WHERE observed_at >= ? AND field <> 'new'))";

/** isNotable's arms that can be read from columns alone. Takes no parameters. */
export const notableSql = `(COALESCE(v.vuln_status, '') <> 'Rejected' AND (v.kev = 1 OR v.watch_hit = 1 OR COALESCE(v.epss, 0) >= ${epssNotable} OR json_extract(v.ssvc_json, '$.exploitation') = 'active'))`;

/** A CVE id as MITRE assigns them: four digits of year, four or more of sequence. One pattern for every route. */
export const cveIdPattern = /^CVE-\d{4}-\d{4,}$/i;

/**
 * A CVE its assigner has not withdrawn. NVD keeps rejected ids with status "Rejected" (6,787 of
 * the local table); they were listed, counted and ranked as live, one with "1 public exploit".
 */
export const liveSql = "COALESCE(v.vuln_status, '') <> 'Rejected'";

/**
 * notableSql plus isNotable's remaining arm — a critical that is new rather than merely re-touched
 * — read against the window instead of against a `fresh` flag the database does not keep: published
 * in the window, or scored critical in the window within thirty days of publication. Takes the
 * window start twice, after movedInWindowSql's two.
 */
export const notableInWindowSql = `(${liveSql} AND (v.kev = 1 OR v.watch_hit = 1 OR COALESCE(v.epss, 0) >= ${epssNotable} OR json_extract(v.ssvc_json, '$.exploitation') = 'active' OR (COALESCE(v.cvss_score, 0) >= 9 AND (v.published_at >= ? OR EXISTS (SELECT 1 FROM vuln_changes c WHERE c.cve_id = v.cve_id AND c.field = 'cvss' AND c.observed_at >= ? AND (c.before_text IS NULL OR CAST(c.before_text AS REAL) < 9) AND julianday(c.observed_at) - julianday(v.published_at) <= ${recentDays})))))`;

/**
 * Puts or refreshes a notable CVE on the Wire, resurfacing it as unread when something changed.
 * `datedAt` dates the item when the change did not come from NVD's record (an EPSS crossing is
 * news the day it is scored, not the day NVD last touched the CVE, which may be weeks back).
 */
export function recordVulnItem(db: DatabaseSync, row: VulnRow, changes: VulnChange[], observedAt: string, datedAt?: string): void {
  const vendors = parseJson<string[]>(row.vendors_json, []);
  const products = parseJson<string[]>(row.products_json, []);
  const packages = parseJson<AffectedPackage[]>(row.packages_json, []);
  const who = [...new Set([...vendors.slice(0, 2), ...products.slice(0, 2)])].join(", ") || packages.slice(0, 2).map((p) => `${p.ecosystem}:${p.name}`).join(", ");
  const title = `${row.cve_id}${who ? ` · ${who}` : ""}${row.cvss_score !== null ? ` · CVSS ${row.cvss_score.toFixed(1)}` : ""}`;
  const changeSummary = changes
    .filter((c) => c.field !== "new")
    .map((c) => (c.field === "cvss" ? cvssChangeText(c) : (c.after ?? c.field)))
    .join("; ");
  const summary = changeSummary ? `${changeSummary}. ${row.description ?? ""}`.slice(0, 600) : (row.description ?? "").slice(0, 600);
  const signals = {
    cves: [row.cve_id],
    cvss: row.cvss_score,
    severity: row.cvss_severity,
    epss: row.epss,
    kev: row.kev === 1,
    ...(row.kev_due_date ? { dueDate: row.kev_due_date } : {}),
    vendors: vendors.slice(0, 5),
    products: products.slice(0, 5),
    changes: changes.map((c) => c.field),
    ...(row.watch_labels_json ? { watch: parseJson<string[]>(row.watch_labels_json, []) } : {}),
  };
  const existing = db.prepare("SELECT id FROM items WHERE source_id = 'nvd-cves' AND external_id = ?").get(row.cve_id) as { id: number } | undefined;
  const publishedAt = datedAt ?? (changes.some((c) => c.field === "new") ? (row.published_at ?? row.last_modified_at) : row.last_modified_at);
  if (!existing) {
    db.prepare(
      `INSERT INTO items (source_id, kind, external_id, title, url, canonical_url, summary, published_at, fetched_at, signals_json)
       VALUES ('nvd-cves', 'vulnerability', ?, ?, ?, NULL, ?, ?, ?, ?)`,
    ).run(row.cve_id, title, `https://nvd.nist.gov/vuln/detail/${row.cve_id}`, summary, publishedAt, observedAt, JSON.stringify(signals));
  } else {
    const resurfaced = changes.length > 0 ? 1 : 0;
    db.prepare(`UPDATE items SET title = ?, summary = ?, published_at = ?, signals_json = ?, read = CASE WHEN ? THEN 0 ELSE read END, surfaced_at = CASE WHEN ? THEN ? ELSE surfaced_at END WHERE id = ?`).run(
      title,
      summary,
      publishedAt,
      JSON.stringify(signals),
      resurfaced,
      resurfaced,
      observedAt,
      existing.id,
    );
  }
}

/**
 * The table as a CSV, under the same filters the page is showing.
 *
 * Every comparable tool lets a practitioner carry a filtered CVE list away — into a ticket, a
 * spreadsheet, a meeting — and this one could export a baseline, a test plan and the triage board
 * but not the table its own name is about. The rows are the ones on screen in the order on screen,
 * so "the worst two hundred this morning" is one click rather than a copy and paste.
 *
 * Numbers are written as numbers (a CVSS of 9.8, an EPSS as its decimal) rather than as the page
 * formats them, because the point of a CSV is that something else will do arithmetic on it.
 */
export function vulnsCsv(db: DatabaseSync, filters: VulnFilters, baseUrl: string, owner = false): string {
  const { rows } = listVulns(db, { ...filters, limit: Math.min(filters.limit ?? 1000, 5000) }, { maxLimit: 5000 });
  const exploited = new Set(
    rows.length
      ? (db.prepare(`SELECT DISTINCT cve_id FROM exploits WHERE cve_id IN (${rows.map(() => "?").join(", ")})`).all(...rows.map((r) => r.cve_id)) as { cve_id: string }[]).map((r) => r.cve_id)
      : [],
  );
  const lines = ["cve,published,modified,cvss,severity,epss,epss percentile,kev,kev due,public exploit,vendors,products,watchlist labels,description,link"];
  for (const v of rows) {
    lines.push(
      csvLine([
        v.cve_id,
        v.published_at?.slice(0, 10) ?? "",
        v.last_modified_at.slice(0, 10),
        v.cvss_score ?? "",
        v.cvss_severity ?? "",
        v.epss ?? "",
        v.epss_percentile ?? "",
        v.kev ? "yes" : "no",
        v.kev_due_date ?? "",
        exploited.has(v.cve_id) ? "yes" : "no",
        parseJson<string[]>(v.vendors_json, []).join("; "),
        parseJson<string[]>(v.products_json, []).join("; "),
        owner ? parseJson<string[]>(v.watch_labels_json, []).join("; ") : "",
        v.description ?? "",
        `${baseUrl}/vulnerabilities/${v.cve_id}`,
      ]),
    );
  }
  return `${lines.join("\r\n")}\r\n`;
}
