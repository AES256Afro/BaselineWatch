import type { DatabaseSync } from "node:sqlite";

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
}

export interface VulnChange {
  field: "new" | "cvss" | "description" | "cpes" | "references" | "cwes" | "status" | "kev" | "epss";
  before: string | null;
  after: string | null;
}

export interface WatchEntry {
  id: number;
  kind: "product" | "baseline" | "family" | "keyword";
  value: string;
  label: string | null;
}

export function loadWatchlist(db: DatabaseSync): WatchEntry[] {
  return db.prepare("SELECT id, kind, value, label FROM watchlist ORDER BY kind, value").all() as unknown as WatchEntry[];
}

function parseJson<T>(text: string | null, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

/**
 * The labels of every watchlist entry a vulnerability matches. A product entry is a CPE prefix
 * (`cpe:2.3:o:fortinet:fortios`), a `vendor:product` pair, or one vendor or product name; a
 * keyword entry is matched against the description.
 */
export function matchWatch(
  v: { cpes: string[]; vendors: string[]; products: string[]; description: string | null },
  entries: WatchEntry[],
): string[] {
  const hits: string[] = [];
  const vendors = new Set(v.vendors.map((x) => x.toLowerCase()));
  const products = new Set(v.products.map((x) => x.toLowerCase()));
  const pairs = new Set(v.cpes.map((c) => c.split(":").slice(3, 5).join(":").toLowerCase()));
  const description = (v.description ?? "").toLowerCase();
  for (const entry of entries) {
    const value = entry.value.trim().toLowerCase();
    if (value === "") continue;
    const label = entry.label?.trim() || entry.value;
    let hit = false;
    if (entry.kind === "product") {
      if (value.startsWith("cpe:2.3:")) hit = v.cpes.some((c) => c.toLowerCase().startsWith(value));
      else if (value.includes(":")) hit = pairs.has(value);
      else hit = vendors.has(value) || products.has(value);
    } else if (entry.kind === "keyword") {
      hit = description.includes(value);
    }
    if (hit) hits.push(label);
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
  row: VulnRow;
}

/** Stores one normalised CVE, recording what changed since it was last seen. */
export function upsertVuln(db: DatabaseSync, n: NormalizedVuln, observedAt: string, watch: WatchEntry[]): UpsertResult {
  const existing = db.prepare("SELECT * FROM vulns WHERE cve_id = ?").get(n.cveId) as unknown as VulnRow | undefined;
  const watchLabels = matchWatch(n, watch);
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
        references_json, kev, kev_date_added, kev_due_date, watch_hit, watch_labels_json, first_seen_at, last_seen_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (cve_id) DO UPDATE SET
        source_identifier = excluded.source_identifier, published_at = excluded.published_at, last_modified_at = excluded.last_modified_at,
        vuln_status = excluded.vuln_status, description = excluded.description, cvss_version = excluded.cvss_version, cvss_score = excluded.cvss_score,
        cvss_severity = excluded.cvss_severity, cvss_vector = excluded.cvss_vector, cvss_source = excluded.cvss_source, ssvc_json = excluded.ssvc_json,
        cwes_json = excluded.cwes_json, cpes_json = excluded.cpes_json, vendors_json = excluded.vendors_json, products_json = excluded.products_json,
        references_json = excluded.references_json, kev = excluded.kev, kev_date_added = excluded.kev_date_added, kev_due_date = excluded.kev_due_date,
        watch_hit = excluded.watch_hit, watch_labels_json = excluded.watch_labels_json, last_seen_at = excluded.last_seen_at`,
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
    existing?.first_seen_at ?? observedAt,
    observedAt,
  );

  const insertChange = db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, nvd_modified_at, field, before_text, after_text) VALUES (?, ?, ?, ?, ?, ?)");
  for (const c of changes) insertChange.run(n.cveId, observedAt, n.lastModifiedAt, c.field, c.before, c.after);

  const row = db.prepare("SELECT * FROM vulns WHERE cve_id = ?").get(n.cveId) as unknown as VulnRow;
  return { isNew: !existing, changes, watchLabels, row };
}

/** Flags a CVE as in CISA's KEV from the KEV catalog, for CVEs NVD has not marked yet. */
export function applyKev(db: DatabaseSync, entries: { cveId: string; dateAdded: string | null; dueDate: string | null; ransomware: boolean }[], observedAt: string): number {
  const select = db.prepare("SELECT kev FROM vulns WHERE cve_id = ?");
  const update = db.prepare("UPDATE vulns SET kev = 1, kev_date_added = COALESCE(kev_date_added, ?), kev_due_date = COALESCE(?, kev_due_date), kev_ransomware = ? WHERE cve_id = ?");
  const change = db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, nvd_modified_at, field, before_text, after_text) VALUES (?, ?, NULL, 'kev', NULL, ?)");
  let flagged = 0;
  db.exec("BEGIN");
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
  db.exec("BEGIN");
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
export function recomputeWatchHits(db: DatabaseSync): number {
  const entries = loadWatchlist(db);
  const rows = db.prepare("SELECT cve_id, cpes_json, vendors_json, products_json, description, watch_hit, watch_labels_json FROM vulns").all() as {
    cve_id: string;
    cpes_json: string | null;
    vendors_json: string | null;
    products_json: string | null;
    description: string | null;
    watch_hit: number;
    watch_labels_json: string | null;
  }[];
  const update = db.prepare("UPDATE vulns SET watch_hit = ?, watch_labels_json = ? WHERE cve_id = ?");
  let changed = 0;
  db.exec("BEGIN");
  try {
    for (const r of rows) {
      const labels = matchWatch(
        { cpes: parseJson<string[]>(r.cpes_json, []), vendors: parseJson<string[]>(r.vendors_json, []), products: parseJson<string[]>(r.products_json, []), description: r.description },
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
  minCvss?: number | undefined;
  minEpss?: number | undefined;
  changedSince?: string | undefined;
  q?: string | undefined;
  sort?: "modified" | "published" | "cvss" | "epss";
  offset?: number;
  limit?: number;
}

function vulnQuery(filters: VulnFilters): { where: string; params: (string | number)[] } {
  const clauses: string[] = [];
  const params: (string | number)[] = [];
  if (filters.watch) clauses.push("v.watch_hit = 1");
  if (filters.kev) clauses.push("v.kev = 1");
  if (filters.minCvss !== undefined) {
    clauses.push("v.cvss_score >= ?");
    params.push(filters.minCvss);
  }
  if (filters.minEpss !== undefined) {
    clauses.push("v.epss >= ?");
    params.push(filters.minEpss);
  }
  if (filters.changedSince) {
    clauses.push("v.cve_id IN (SELECT cve_id FROM vuln_changes WHERE observed_at >= ?)");
    params.push(filters.changedSince);
  }
  if (filters.q) {
    const words = filters.q
      .split(/\s+/)
      .map((w) => w.replace(/"/g, "").trim())
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

export function vulnStats(db: DatabaseSync, sinceIso: string): { total: number; kev: number; watch: number; changedSince: number; newSince: number } {
  const n = (sql: string, ...params: string[]) => (db.prepare(sql).get(...params) as { n: number }).n;
  return {
    total: n("SELECT COUNT(*) AS n FROM vulns"),
    kev: n("SELECT COUNT(*) AS n FROM vulns WHERE kev = 1"),
    watch: n("SELECT COUNT(*) AS n FROM vulns WHERE watch_hit = 1"),
    changedSince: n("SELECT COUNT(DISTINCT cve_id) AS n FROM vuln_changes WHERE observed_at >= ? AND field <> 'new'", sinceIso),
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
  const who = [...new Set([...vendors.slice(0, 2), ...products.slice(0, 2)])].join(", ");
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
