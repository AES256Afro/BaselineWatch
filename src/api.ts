import type { DatabaseSync } from "node:sqlite";
import { latestDigest } from "./digest.ts";
import { fixContext, fixesFor, fixSummary } from "./fix.ts";
import { listDocuments, withheldReleaseSummary } from "./register.ts";
import { listTriage, type TriageState } from "./triage.ts";
import { getVuln, listVulns, vulnChanges, type VulnFilters } from "./vulns.ts";
import { listWire, type WireFilters } from "./wire.ts";
import { parseJson } from "./json.ts";

/**
 * The read-only JSON API, for BoxPilot's agents, dashboards and scripts. Same read gating as
 * the pages. Every list takes `limit` (max 200) and most take `since` (ISO 8601). A
 * licence-restricted source (`sources.restricted`) is listed with its versions and counts and
 * flagged `restricted`; its entries' names and text are never returned, to anyone, so its
 * changes are left out of the change list.
 */
export interface ApiQuery {
  [key: string]: unknown;
}

/**
 * Sources whose text is the owner's own licensed copy (AGENTS.md: CIS and Microsoft content is
 * quoted on screen and never redistributed or exposed through the API). The API and the MCP
 * tools list their versions but never their requirement text or diffs.
 */
const licensedSources: readonly string[] = ["cis-benchmarks", "microsoft-sct"];
export const isLicensedSource = (sourceId: string): boolean => licensedSources.includes(sourceId);

/**
 * A licensed source's release entry names the settings that moved — for Microsoft's baselines, the
 * registry paths and policy names. The page may show them; the API and the feeds say they are withheld.
 */
export const publicSummary = (item: { kind: string; source_id: string; summary: string | null }): string | null =>
  item.kind === "release" && isLicensedSource(item.source_id) ? withheldReleaseSummary : item.summary;

const str = (v: unknown, max = 200): string | undefined => (typeof v === "string" && v.trim() !== "" ? v.trim().slice(0, max) : undefined);
const limitOf = (v: unknown, fallback = 50): number => {
  const n = Number(str(v));
  return Number.isInteger(n) && n > 0 ? Math.min(n, 200) : fallback;
};
const sinceOf = (v: unknown): string | undefined => {
  const s = str(v, 40);
  if (!s) return undefined;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
};
/** A page offset SQLite can bind: a whole number, capped; anything else starts at the top. */
const offsetOf = (v: unknown): number => {
  const n = Number(str(v));
  return Number.isSafeInteger(n) && n >= 0 ? Math.min(n, 1_000_000) : 0;
};

export function apiItems(db: DatabaseSync, q: ApiQuery, baseUrl: string) {
  const kind = str(q.kind);
  const filters: WireFilters = {
    source: str(q.source),
    kind: kind === "article" || kind === "kev" || kind === "vulnerability" || kind === "release" ? kind : undefined,
    q: str(q.q),
    unread: str(q.unread) === "1",
    since: sinceOf(q.since),
    limit: limitOf(q.limit),
  };
  return listWire(db, filters).map((i) => ({
      id: i.id,
      source: i.source_id,
      sourceName: i.source_name,
      kind: i.kind,
      externalId: i.external_id,
      title: i.title,
      url: i.url && i.url.startsWith("/") ? `${baseUrl}${i.url}` : i.url,
      summary: publicSummary(i),
      publishedAt: i.published_at,
      fetchedAt: i.fetched_at,
      signals: parseJson<Record<string, unknown>>(i.signals_json, {}),
      read: i.read === 1,
      starred: i.starred === 1,
    }));
}

export function apiVulns(db: DatabaseSync, q: ApiQuery) {
  const sort = str(q.sort);
  const minCvss = Number(str(q.min_cvss));
  const minEpss = Number(str(q.min_epss));
  const filters: VulnFilters = {
    watch: str(q.watch) === "1",
    kev: str(q.kev) === "1",
    minCvss: Number.isFinite(minCvss) ? minCvss : undefined,
    minEpss: Number.isFinite(minEpss) ? minEpss : undefined,
    changedSince: sinceOf(q.since),
    q: str(q.q),
    sort: sort === "published" || sort === "cvss" || sort === "epss" ? sort : "modified",
    limit: limitOf(q.limit),
    offset: offsetOf(q.offset),
  };
  const { rows, total } = listVulns(db, filters);
  return { total, vulns: rows.map(vulnJson) };
}

function vulnJson(v: NonNullable<ReturnType<typeof getVuln>>) {
  return {
    cve: v.cve_id,
    published: v.published_at,
    modified: v.last_modified_at,
    status: v.vuln_status,
    description: v.description,
    cvss: v.cvss_score === null ? null : { version: v.cvss_version, score: v.cvss_score, severity: v.cvss_severity, vector: v.cvss_vector, source: v.cvss_source },
    epss: v.epss === null ? null : { score: v.epss, percentile: v.epss_percentile, date: v.epss_date },
    kev: v.kev === 1 ? { dateAdded: v.kev_date_added, dueDate: v.kev_due_date, ransomware: v.kev_ransomware === 1 } : null,
    ssvc: parseJson<Record<string, string>>(v.ssvc_json, {}),
    cwes: parseJson<string[]>(v.cwes_json, []),
    vendors: parseJson<string[]>(v.vendors_json, []),
    products: parseJson<string[]>(v.products_json, []),
    watch: parseJson<string[]>(v.watch_labels_json, []),
  };
}

export function apiVuln(db: DatabaseSync, cveId: string) {
  const v = getVuln(db, cveId);
  if (!v) return null;
  const fix = fixesFor(db, fixContext(db), v);
  return {
    ...vulnJson(v),
    cpes: parseJson<string[]>(v.cpes_json, []),
    references: parseJson<{ url: string; tags: string[] }[]>(v.references_json, []),
    history: vulnChanges(db, v.cve_id).map((c) => ({ at: c.observed_at, field: c.field, before: c.before_text, after: c.after_text })),
    // The Fix panel's facts: what has been published, or an empty with the summary saying so.
    fix: {
      summary: fixSummary(fix),
      published: !fix.empty,
      references: fix.references,
      advisories: fix.advisories.map((a) => ({ source: a.source, title: a.title, url: a.url, published: a.publishedAt })),
      kev: fix.kev,
      packages: fix.packages,
      // The public exploit indexes and Microsoft's update (N5): the same rows the panel draws.
      exploits: fix.exploits.map((e) => ({ source: e.source_id, ref: e.ref, title: e.title, url: e.url, published: e.published_at, verified: e.verified === 1 })),
      microsoft: fix.microsoft
        ? { release: fix.microsoft.release_id, severity: fix.microsoft.severity, exploited: fix.microsoft.exploited === 1, disclosed: fix.microsoft.disclosed === 1, exploitability: fix.microsoft.exploitability, fixes: fix.microsoft.fixes }
        : null,
      mitigations: fix.mitigations.map((m) => ({ id: m.id, note: m.note, source: m.source, rules: m.rules.map((r) => ({ stig: r.stig.product, label: r.rule.label, title: r.rule.title, severity: r.rule.family })) })),
    },
  };
}

export function apiStandards(db: DatabaseSync, baseUrl: string) {
  const sources = db.prepare("SELECT id, name, url, licence, restricted, last_fetch_at, last_status FROM sources WHERE group_name = 'standards' AND kind <> 'article' ORDER BY name").all() as {
    id: string;
    name: string;
    url: string;
    licence: string | null;
    restricted: number;
    last_fetch_at: string | null;
    last_status: string | null;
  }[];
  return sources.map((s) => ({
    id: s.id,
    name: s.name,
    publisherUrl: s.url,
    licence: s.licence,
    // Versions and counts only: the entries of a restricted source are shown to the instance's owner on its pages and nowhere else.
    restricted: s.restricted === 1,
    lastFetch: s.last_fetch_at,
    lastStatus: s.last_status,
    versions: listDocuments(db, s.id).map((d) => ({
      id: d.id,
      key: d.document_key,
      version: d.version_label,
      published: d.published_at,
      requirements: d.requirement_count,
      previous: d.previous_document_id,
      url: `${baseUrl}/standards/${s.id}/${d.id}`,
    })),
  }));
}

export function apiChanges(db: DatabaseSync, q: ApiQuery, baseUrl: string) {
  const since = sinceOf(q.since);
  const source = str(q.source);
  // A change row is a ref with its text: nothing of a restricted source's, nor of the owner's licensed copies, leaves through here.
  const clauses: string[] = ["s.restricted = 0", `c.source_id NOT IN (${licensedSources.map(() => "?").join(", ")})`];
  const params: (string | number)[] = [...licensedSources];
  if (since) {
    clauses.push("d.published_at >= ?");
    params.push(since);
  }
  if (source) {
    clauses.push("c.source_id = ?");
    params.push(source);
  }
  const rows = db
    .prepare(
      `SELECT c.id, c.source_id, c.document_key, c.to_document_id, c.ref, c.kind, c.field, c.before_text, c.after_text, d.version_label, d.published_at,
              COALESCE(r.label, p.label) AS label, COALESCE(r.title, p.title) AS title,
              (SELECT e.text FROM explanations e WHERE e.change_id = c.id AND e.kind = 'publisher' LIMIT 1) AS note
       FROM changes c JOIN documents d ON d.id = c.to_document_id JOIN sources s ON s.id = c.source_id
       LEFT JOIN requirements r ON r.document_id = c.to_document_id AND r.ref = c.ref
       LEFT JOIN requirements p ON p.document_id = c.from_document_id AND p.ref = c.ref
       WHERE ${clauses.join(" AND ")}
       ORDER BY d.published_at DESC, c.ref, c.field LIMIT ?`,
    )
    .all(...params, limitOf(q.limit, 100)) as {
    id: number;
    source_id: string;
    document_key: string;
    to_document_id: number;
    ref: string;
    kind: string;
    field: string | null;
    before_text: string | null;
    after_text: string | null;
    version_label: string | null;
    published_at: string | null;
    label: string | null;
    title: string | null;
    note: string | null;
  }[];
  return rows.map((c) => ({
    id: c.id,
    source: c.source_id,
    document: c.document_key,
    version: c.version_label,
    published: c.published_at,
    ref: c.ref,
    label: c.label,
    title: c.title,
    kind: c.kind,
    field: c.field,
    before: c.before_text,
    after: c.after_text,
    publisherNote: c.note,
    url: `${baseUrl}/standards/${c.source_id}/${c.to_document_id}/${c.ref}`,
  }));
}

export function apiTriage(db: DatabaseSync, q: ApiQuery, baseUrl: string) {
  const state = str(q.state);
  const valid: TriageState[] = ["new", "reviewing", "affects", "done", "dismissed"];
  // Never as the owner: a restricted source's requirement on the board is named on the page only.
  return listTriage(db, { state: valid.includes(state as TriageState) ? (state as TriageState) : undefined, limit: limitOf(q.limit, 200), owner: false }).map((c) => {
    // A triaged control of a licensed standard is named by its label alone; its title is the publisher's text.
    const row = c as unknown as Record<string, unknown>;
    const licensed = c.subject_kind === "control" && isLicensedSource(String(row.doc_source ?? ""));
    return {
    kind: c.subject_kind,
    id: c.subject_id,
    key: c.subject_key || null,
    state: c.state,
    title: licensed ? `${String(row.req_label ?? c.subject_key.toUpperCase())} (${String(row.doc_standard ?? row.doc_source)}; the text is on the page)` : c.title,
    url: c.url.startsWith("/") ? `${baseUrl}${c.url}` : c.url,
    note: c.note,
    due: c.due_at,
    updated: c.updated_at,
    };
  });
}

export function apiDigest(db: DatabaseSync) {
  const d = latestDigest(db);
  return d ? { period: d.period, coversFrom: d.covers_from, coversTo: d.covers_to, generatedAt: d.generated_at, text: d.text } : null;
}
