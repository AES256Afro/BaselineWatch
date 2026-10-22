import type { DatabaseSync } from "node:sqlite";
import { isPlatformKey, platformName, platformsOf, type PlatformKey } from "./platforms.ts";
import { parseJson } from "./json.ts";
import { replaceCpeMatches, type CpeMatch } from "./cpematches.ts";

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
  /** NVD's CPE match criteria with their version ranges; undefined when the source (an advisory) says nothing about them, so the rows the last NVD record wrote stay. */
  cpeMatches?: CpeMatch[];
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
  epss: number | null;
  epss_percentile: number | null;
  epss_date: string | null;
  watch_hit: number;
  watch_labels_json: string | null;
  first_seen_at: string;
  last_seen_at: string;
  packages_json: string | null;
  aliases_json: string | null;
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

/** Ecosystems whose OSV name carries a release after a colon (Debian:12, Ubuntu:24.04:LTS, Alpine:v3.20). */
const releaseEcosystems = new Set(["debian", "ubuntu", "alpine", "rocky linux", "almalinux", "mageia", "opensuse", "suse", "red hat", "chainguard", "wolfi", "photon os", "openeuler"]);

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
  if (releaseEcosystems.has(head.toLowerCase())) {
    const last = trimmed.lastIndexOf(":");
    return { ecosystem: trimmed.slice(0, last), name: trimmed.slice(last + 1) };
  }
  return { ecosystem: head, name: trimmed.slice(first + 1) };
}

/** Whether an affected package is the one a watchlist entry names; an entry without a release matches every release. */
function packageMatches(entry: { ecosystem: string; name: string }, pkg: { ecosystem: string; name: string }): boolean {
  if (pkg.name.toLowerCase() !== entry.name.toLowerCase()) return false;
  const want = entry.ecosystem.toLowerCase();
  const have = pkg.ecosystem.toLowerCase();
  return have === want || (!want.includes(":") && have.split(":")[0] === want);
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
  v: { cpes: string[]; vendors: string[]; products: string[]; description: string | null; packages?: { ecosystem: string; name: string }[] },
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

/** The entries a vulnerability matches, with their kinds, so a platform match can be told from a product one. */
export function matchWatchDetailed(
  v: { cpes: string[]; vendors: string[]; products: string[]; description: string | null; packages?: { ecosystem: string; name: string }[] },
  entries: WatchEntry[],
): { label: string; kind: WatchEntry["kind"] }[] {
  const hits: { label: string; kind: WatchEntry["kind"] }[] = [];
  const platforms: string[] = entries.some((e) => e.kind === "platform") ? platformsOf(v) : [];
  const vendors = new Set(v.vendors.map((x) => x.toLowerCase()));
  const products = new Set(v.products.map((x) => x.toLowerCase()));
  const pairs = new Set(v.cpes.map((c) => c.split(":").slice(3, 5).join(":").toLowerCase()));
  const description = (v.description ?? "").toLowerCase();
  const packages = v.packages ?? [];
  for (const entry of entries) {
    const value = entry.value.trim().toLowerCase();
    if (value === "") continue;
    const label = watchLabel(entry);
    let hit = false;
    if (entry.kind === "product") {
      if (value.startsWith("cpe:2.3:")) hit = v.cpes.some((c) => c.toLowerCase().startsWith(value));
      else if (value.includes(":")) hit = pairs.has(value);
      else hit = vendors.has(value) || products.has(value);
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

function round(n: number): number {
  return Math.round(n * 100) / 100;
}

function cvssText(v: { version: string; score: number; vector: string | null } | null): string | null {
  if (!v) return null;
  return `${v.score.toFixed(1)} (v${v.version}${v.vector ? `, ${v.vector}` : ""})`;
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
  const hits = matchWatchDetailed({ ...n, packages }, watch);
  const watchLabels = hits.map((h) => h.label);
  const watchPlatforms = hits.filter((h) => h.kind === "platform").map((h) => h.label);
  const changes: VulnChange[] = [];

  if (!existing) {
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
    JSON.stringify(platformsOf({ cpes: n.cpes, vendors: n.vendors, products: n.products, description: n.description })),
    existing?.first_seen_at ?? observedAt,
    observedAt,
  );
  if (n.cpeMatches !== undefined) replaceCpeMatches(db, n.cveId, n.cpeMatches);

  const insertChange = db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, nvd_modified_at, field, before_text, after_text) VALUES (?, ?, ?, ?, ?, ?)");
  for (const c of changes) insertChange.run(n.cveId, observedAt, n.lastModifiedAt, c.field, c.before, c.after);

  const row = db.prepare("SELECT * FROM vulns WHERE cve_id = ?").get(n.cveId) as unknown as VulnRow;
  return { isNew: !existing, changes, watchLabels, watchPlatforms, row };
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
    const watchLabels = matchWatch(
      { cpes: parseJson<string[]>(existing.cpes_json, []), vendors: parseJson<string[]>(existing.vendors_json, []), products: parseJson<string[]>(existing.products_json, []), description: existing.description, packages },
      watch,
    );
    result = { isNew: false, changes: [], watchLabels, watchPlatforms: [], row: existing };
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
  return { key, isNew: result.isNew, changes, watchLabels: result.watchLabels, watchPlatforms: result.watchPlatforms, row };
}

/** Flags a CVE as in CISA's KEV from the KEV catalog, for CVEs NVD has not marked yet. */
export function applyKev(db: DatabaseSync, entries: { cveId: string; dateAdded: string | null; dueDate: string | null; ransomware: boolean }[], observedAt: string): number {
  const select = db.prepare("SELECT kev FROM vulns WHERE cve_id = ?");
  const update = db.prepare("UPDATE vulns SET kev = 1, kev_date_added = COALESCE(kev_date_added, ?), kev_due_date = COALESCE(?, kev_due_date), kev_ransomware = ? WHERE cve_id = ?");
  const change = db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, nvd_modified_at, field, before_text, after_text) VALUES (?, ?, NULL, 'kev', NULL, ?)");
  let flagged = 0;
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const e of entries) {
      const row = select.get(e.cveId) as { kev: number } | undefined;
      if (!row) continue;
      update.run(e.dateAdded, e.dueDate, e.ransomware ? 1 : 0, e.cveId);
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
  return flagged;
}

export interface EpssScore {
  cveId: string;
  epss: number;
  percentile: number;
}

/** Joins a day's EPSS scores onto the CVEs BaselineWatch knows; a jump of 0.1 or more on a KEV or watched CVE is a change. */
export function applyEpss(db: DatabaseSync, scores: Iterable<EpssScore>, scoreDate: string, observedAt: string): { updated: number; changes: number } {
  const known = new Map<string, { epss: number | null; notable: boolean }>();
  for (const r of db.prepare("SELECT cve_id, epss, kev, watch_hit FROM vulns").all() as { cve_id: string; epss: number | null; kev: number; watch_hit: number }[]) {
    known.set(r.cve_id, { epss: r.epss, notable: r.kev === 1 || r.watch_hit === 1 });
  }
  const update = db.prepare("UPDATE vulns SET epss = ?, epss_percentile = ?, epss_date = ? WHERE cve_id = ?");
  const change = db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, nvd_modified_at, field, before_text, after_text) VALUES (?, ?, NULL, 'epss', ?, ?)");
  let updated = 0;
  let changes = 0;
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const s of scores) {
      const current = known.get(s.cveId);
      if (!current) continue;
      update.run(round(s.epss), round(s.percentile), scoreDate, s.cveId);
      updated += 1;
      if (current.notable && current.epss !== null && Math.abs(current.epss - s.epss) >= 0.1) {
        change.run(s.cveId, observedAt, current.epss.toFixed(2), s.epss.toFixed(2));
        changes += 1;
      }
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
  return { updated, changes };
}

/** Re-evaluates every CVE against the watchlist after it changes. */
/**
 * Fills platforms_json for rows that predate migration 0032 (or an upsert that could not read a
 * platform). Called once at start while any row is missing it, the way the Register relinks.
 */
export function recomputePlatforms(db: DatabaseSync, limit = 100_000): number {
  const rows = db
    .prepare("SELECT cve_id, cpes_json, vendors_json, products_json, description FROM vulns WHERE platforms_json IS NULL LIMIT ?")
    .all(limit) as { cve_id: string; cpes_json: string | null; vendors_json: string | null; products_json: string | null; description: string | null }[];
  if (rows.length === 0) return 0;
  const update = db.prepare("UPDATE vulns SET platforms_json = ? WHERE cve_id = ?");
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const row of rows) {
      const platforms = platformsOf({
        cpes: parseJson<string[]>(row.cpes_json, []),
        vendors: parseJson<string[]>(row.vendors_json, []),
        products: parseJson<string[]>(row.products_json, []),
        description: row.description,
      });
      update.run(JSON.stringify(platforms), row.cve_id);
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
  return rows.length;
}

export function recomputeWatchHits(db: DatabaseSync): number {
  const entries = loadWatchlist(db);
  const rows = db.prepare("SELECT cve_id, cpes_json, vendors_json, products_json, description, watch_hit, watch_labels_json, packages_json FROM vulns").all() as {
    cve_id: string;
    cpes_json: string | null;
    vendors_json: string | null;
    products_json: string | null;
    description: string | null;
    watch_hit: number;
    watch_labels_json: string | null;
    packages_json: string | null;
  }[];
  const update = db.prepare("UPDATE vulns SET watch_hit = ?, watch_labels_json = ? WHERE cve_id = ?");
  let changed = 0;
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const r of rows) {
      const labels = matchWatch(
        {
          cpes: parseJson<string[]>(r.cpes_json, []),
          vendors: parseJson<string[]>(r.vendors_json, []),
          products: parseJson<string[]>(r.products_json, []),
          description: r.description,
          packages: parseJson<AffectedPackage[]>(r.packages_json, []),
        },
        entries,
      );
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
  watch?: boolean;
  kev?: boolean;
  /** Only CVEs with at least one row in the exploits table (src/exploits.ts). */
  exploit?: boolean;
  /** One of src/platforms.ts' ids: the CVEs whose CPEs, vendors, products or description put them on that platform. */
  platform?: PlatformKey | undefined;
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
  /** Only CVEs the watchlist marked with this label: the figure beside a watchlist entry is counted this way. */
  label?: string | undefined;
  q?: string | undefined;
  sort?: "modified" | "published" | "cvss" | "epss";
  offset?: number;
  limit?: number;
}

function vulnQuery(filters: VulnFilters): { where: string; params: (string | number)[] } {
  const clauses: string[] = [];
  const params: (string | number)[] = [];
  if (filters.watch) clauses.push("v.watch_hit = 1");
  if (filters.platform) {
    // The column holds a JSON array of platform ids, so one quoted id matches exactly one platform.
    clauses.push("v.platforms_json LIKE ?");
    params.push(`%"${filters.platform}"%`);
  }
  if (filters.kev) clauses.push("v.kev = 1");
  if (filters.exploit) clauses.push("EXISTS (SELECT 1 FROM exploits e WHERE e.cve_id = v.cve_id)");
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
  if (filters.newSince) {
    clauses.push("v.cve_id IN (SELECT cve_id FROM vuln_changes WHERE observed_at >= ? AND field = 'new')");
    params.push(filters.newSince);
  }
  if (filters.label) {
    clauses.push("v.watch_labels_json IS NOT NULL AND EXISTS (SELECT 1 FROM json_each(v.watch_labels_json) WHERE json_each.value = ?)");
    params.push(filters.label);
  }
  if (filters.q) {
    const words = filters.q
      .split(/\s+/)
      .map((w) => w.replace(/["\p{Cc}]/gu, "").trim())
      .filter(Boolean);
    if (words.length) {
      clauses.push("v.id IN (SELECT rowid FROM vulns_fts WHERE vulns_fts MATCH ?)");
      params.push(words.map((w) => `"${w}"`).join(" "));
    }
  }
  return { where: clauses.length ? `WHERE ${clauses.join(" AND ")}` : "", params };
}

const sortSql: Record<NonNullable<VulnFilters["sort"]>, string> = {
  modified: "v.last_modified_at DESC",
  published: "v.published_at DESC",
  cvss: "v.cvss_score DESC NULLS LAST, v.last_modified_at DESC",
  epss: "v.epss DESC NULLS LAST, v.last_modified_at DESC",
};

export function listVulns(db: DatabaseSync, filters: VulnFilters = {}): { rows: VulnRow[]; total: number } {
  const { where, params } = vulnQuery(filters);
  const limit = Math.min(Math.max(filters.limit ?? 50, 1), 200);
  const offset = Math.max(filters.offset ?? 0, 0);
  const total = (db.prepare(`SELECT COUNT(*) AS n FROM vulns v ${where}`).get(...params) as { n: number }).n;
  const rows = db
    .prepare(`SELECT v.* FROM vulns v ${where} ORDER BY ${sortSql[filters.sort ?? "modified"]} LIMIT ? OFFSET ?`)
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
  return {
    total: n("SELECT COUNT(*) AS n FROM vulns"),
    kev: n("SELECT COUNT(*) AS n FROM vulns WHERE kev = 1"),
    exploit: n("SELECT COUNT(DISTINCT cve_id) AS n FROM exploits WHERE cve_id IN (SELECT cve_id FROM vulns)"),
    watch: n("SELECT COUNT(*) AS n FROM vulns WHERE watch_hit = 1"),
    // Any change observed in the window, first sightings included: the same set ?changed=1 lists and the Today tile counts.
    changedSince: n("SELECT COUNT(DISTINCT cve_id) AS n FROM vuln_changes WHERE observed_at >= ?", sinceIso),
    newSince: n("SELECT COUNT(*) AS n FROM vuln_changes WHERE observed_at >= ? AND field = 'new'", sinceIso),
  };
}

const recentDays = 30;

/**
 * Whether a CVE belongs on the Wire rather than only in the Vulnerabilities table. "New critical"
 * means published in the last thirty days; NVD re-touching a 2015 CVE is not news.
 */
export function isNotable(row: VulnRow, isNew: boolean, observedAt: string): boolean {
  if (row.kev === 1 || row.watch_hit === 1) return true;
  const publishedRecently = row.published_at !== null && new Date(observedAt).getTime() - new Date(row.published_at).getTime() <= recentDays * 24 * 60 * 60 * 1000;
  if (isNew && publishedRecently && (row.cvss_score ?? 0) >= 9) return true;
  if ((row.epss ?? 0) >= 0.5) return true;
  const ssvc = parseJson<Record<string, string>>(row.ssvc_json, {});
  return ssvc.exploitation === "active";
}

/** Puts or refreshes a notable CVE on the Wire, resurfacing it as unread when something changed. */
export function recordVulnItem(db: DatabaseSync, row: VulnRow, changes: VulnChange[], observedAt: string): void {
  const vendors = parseJson<string[]>(row.vendors_json, []);
  const products = parseJson<string[]>(row.products_json, []);
  const packages = parseJson<AffectedPackage[]>(row.packages_json, []);
  const who = [...new Set([...vendors.slice(0, 2), ...products.slice(0, 2)])].join(", ") || packages.slice(0, 2).map((p) => `${p.ecosystem}:${p.name}`).join(", ");
  const title = `${row.cve_id}${who ? ` · ${who}` : ""}${row.cvss_score !== null ? ` · CVSS ${row.cvss_score.toFixed(1)}` : ""}`;
  const changeSummary = changes
    .filter((c) => c.field !== "new")
    .map((c) => (c.field === "cvss" ? `CVSS ${c.before ?? "unscored"} → ${c.after ?? "unscored"}` : (c.after ?? c.field)))
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
  const publishedAt = changes.some((c) => c.field === "new") ? (row.published_at ?? row.last_modified_at) : row.last_modified_at;
  if (!existing) {
    db.prepare(
      `INSERT INTO items (source_id, kind, external_id, title, url, canonical_url, summary, published_at, fetched_at, signals_json)
       VALUES ('nvd-cves', 'vulnerability', ?, ?, ?, NULL, ?, ?, ?, ?)`,
    ).run(row.cve_id, title, `https://nvd.nist.gov/vuln/detail/${row.cve_id}`, summary, publishedAt, observedAt, JSON.stringify(signals));
  } else {
    db.prepare(`UPDATE items SET title = ?, summary = ?, published_at = ?, signals_json = ?, read = CASE WHEN ? THEN 0 ELSE read END WHERE id = ?`).run(
      title,
      summary,
      publishedAt,
      JSON.stringify(signals),
      changes.length > 0 ? 1 : 0,
      existing.id,
    );
  }
}
