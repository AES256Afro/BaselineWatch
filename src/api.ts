import type { DatabaseSync } from "node:sqlite";
import { digestTextFor, latestDigest } from "./digest.ts";
import { fixContext, fixesFor, fixSummary } from "./fix.ts";
import { listDocuments, withheldReleaseSummary } from "./register.ts";
import { listTriage, type TriageState } from "./triage.ts";
import { getVuln, listVulns, vulnChanges, type VulnFilters } from "./vulns.ts";
import { listWire, type WireFilters } from "./wire.ts";
import { vulnFilters } from "./routes/query.ts";
import { parseJson } from "./json.ts";
import { csvLine } from "./csv.ts";

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

/** An item's signals without the watchlist's labels, which are the owner's. */
function withoutWatch(signals: Record<string, unknown>): Record<string, unknown> {
  const rest = { ...signals };
  delete rest.watch;
  return rest;
}

/** The News as JSON. The read and starred marks, and the owner-only sources, are in it for the owner alone. */
export function apiItems(db: DatabaseSync, q: ApiQuery, baseUrl: string, owner = false) {
  const kind = str(q.kind);
  const filters: WireFilters = {
    source: str(q.source),
    kind: kind === "article" || kind === "kev" || kind === "vulnerability" || kind === "release" ? kind : undefined,
    q: str(q.q),
    unread: owner && str(q.unread) === "1",
    since: sinceOf(q.since),
    limit: limitOf(q.limit),
  };
  return listWire(db, filters, { owner }).map((i) => ({
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
      signals: owner ? parseJson<Record<string, unknown>>(i.signals_json, {}) : withoutWatch(parseJson<Record<string, unknown>>(i.signals_json, {})),
      ...(owner ? { read: i.read === 1, starred: i.starred === 1 } : {}),
    }));
}

/**
 * The CVE list, through the same reader the Vulnerabilities page uses, so the API can express
 * every filter the page can — severity, platform, a watchlist label, having a public exploit, an
 * EPSS band, the "new" and "changed" windows in hours — and the two cannot come to disagree about
 * what a filter means. `limit` and `since` are this reader's own: a page scrolls, an agent asks.
 */
export function apiVulns(db: DatabaseSync, q: ApiQuery, now: Date = new Date(), owner = false) {
  const page = vulnFilters(q as Record<string, unknown>, now, owner);
  const filters: VulnFilters = {
    ...page,
    // `since` has meant "changed since" on this endpoint since it existed; `changed` (hours) is
    // the page's way of saying it, and an explicit one wins.
    ...(page.changedSince === undefined ? { changedSince: sinceOf(q.since) } : {}),
    limit: limitOf(q.limit),
  };
  const { rows, total } = listVulns(db, filters);
  return { total, vulns: rows.map((v) => vulnJson(v, owner)) };
}

/** One CVE as JSON. The watchlist's labels are the owner's and travel only to them. */
function vulnJson(v: NonNullable<ReturnType<typeof getVuln>>, owner = false) {
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
    ...(owner ? { watch: parseJson<string[]>(v.watch_labels_json, []) } : {}),
    platforms: parseJson<string[]>(v.platforms_json, []),
  };
}

export function apiVuln(db: DatabaseSync, cveId: string, owner = false) {
  const v = getVuln(db, cveId);
  if (!v) return null;
  const fix = fixesFor(db, fixContext(db), v);
  return {
    ...vulnJson(v, owner),
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

/** One change row as the API and the release's CSV name it. */
interface ChangeRow {
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
}

/**
 * The change rows that may leave this instance: never a restricted source's, nor the owner's
 * licensed copies'. Every reader of changes outside a page goes through here, so the rule is one line.
 */
function exportableChanges(db: DatabaseSync, filters: { since?: string | undefined; source?: string | undefined; documentId?: number | undefined }, limit: number | null): ChangeRow[] {
  const clauses: string[] = ["s.restricted = 0", `c.source_id NOT IN (${licensedSources.map(() => "?").join(", ")})`];
  const params: (string | number)[] = [...licensedSources];
  if (filters.since) {
    clauses.push("d.published_at >= ?");
    params.push(filters.since);
  }
  if (filters.source) {
    clauses.push("c.source_id = ?");
    params.push(filters.source);
  }
  if (filters.documentId !== undefined) {
    clauses.push("c.to_document_id = ?");
    params.push(filters.documentId);
  }
  return db
    .prepare(
      `SELECT c.id, c.source_id, c.document_key, c.to_document_id, c.ref, c.kind, c.field, c.before_text, c.after_text, d.version_label, d.published_at,
              COALESCE(r.label, p.label) AS label, COALESCE(r.title, p.title) AS title,
              (SELECT e.text FROM explanations e WHERE e.change_id = c.id AND e.kind = 'publisher' LIMIT 1) AS note
       FROM changes c JOIN documents d ON d.id = c.to_document_id JOIN sources s ON s.id = c.source_id
       LEFT JOIN requirements r ON r.document_id = c.to_document_id AND r.ref = c.ref
       LEFT JOIN requirements p ON p.document_id = c.from_document_id AND p.ref = c.ref
       WHERE ${clauses.join(" AND ")}
       ORDER BY d.published_at DESC, c.ref, c.field${limit === null ? "" : " LIMIT ?"}`,
    )
    .all(...params, ...(limit === null ? [] : [limit])) as unknown as ChangeRow[];
}

/**
 * A request the API answers with a refusal rather than an empty list: an error carrying its
 * status, which the app's error handler sends as that status.
 */
export class ApiRefusal extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiRefusal";
    this.status = status;
  }
}

/**
 * The change list. With `document`, every row of that one release, not the first page of it. A
 * release the API does not serve — no such id, or a licensed or restricted source's — is one
 * answer, 404, rather than an empty list that reads as "nothing changed"; a 403 for the licensed
 * ones alone would say which ids exist.
 */
export function apiChanges(db: DatabaseSync, q: ApiQuery, baseUrl: string) {
  const document = Number(str(q.document, 12));
  const documentId = Number.isInteger(document) && document > 0 ? document : undefined;
  if (documentId !== undefined) {
    const source = db.prepare("SELECT s.id, s.restricted FROM documents d JOIN sources s ON s.id = d.source_id WHERE d.id = ?").get(documentId) as { id: string; restricted: number } | undefined;
    if (!source || !changesExportable(source)) throw new ApiRefusal(404, "No release with that id is served through the API.");
  }
  const rows = exportableChanges(db, { since: sinceOf(q.since), source: str(q.source), documentId }, documentId === undefined ? limitOf(q.limit, 100) : null);
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

/** Whether a source's changes may leave as a file: not restricted by its licence, and not the owner's licensed copy. */
export function changesExportable(source: { id: string; restricted: number | boolean }): boolean {
  return !source.restricted && !isLicensedSource(source.id);
}

/**
 * One release's changes as CSV: every field-level row, its before and after, and the publisher's
 * note where there is one. Null for a source whose text may not leave (`changesExportable`).
 */
export function releaseChangesCsv(db: DatabaseSync, source: { id: string; restricted: number | boolean }, documentId: number, baseUrl: string): string | null {
  if (!changesExportable(source)) return null;
  const rows = exportableChanges(db, { source: source.id, documentId }, null);
  const lines = ["source,document,version,published,ref,label,title,kind,field,before,after,publisher_note,url"];
  for (const c of rows) {
    lines.push(csvLine([c.source_id, c.document_key, c.version_label ?? "", c.published_at?.slice(0, 10) ?? "", c.ref, c.label ?? "", c.title ?? "", c.kind, c.field ?? "", c.before_text ?? "", c.after_text ?? "", c.note ?? "", `${baseUrl}/standards/${c.source_id}/${c.to_document_id}/${c.ref}`]));
  }
  return `${lines.join("\n")}\n`;
}

export function apiTriage(db: DatabaseSync, q: ApiQuery, baseUrl: string, owner = false) {
  const state = str(q.state);
  const valid: TriageState[] = ["new", "reviewing", "affects", "done", "dismissed"];
  // The owner's notes follow who is asking; a restricted source's requirement is never named
  // here, not even for the owner, because the API is how content would be redistributed.
  return listTriage(db, { state: valid.includes(state as TriageState) ? (state as TriageState) : undefined, limit: limitOf(q.limit, 200), notes: owner, restrictedLabels: false }).map((c) => {
    // A triaged control of a licensed standard is named by its standard and version alone: its key,
    // label and address carry the publisher's words (for Microsoft's baselines, the registry path and
    // the policy name), which the API never repeats.
    const row = c as unknown as Record<string, unknown>;
    const licensed = c.subject_kind === "control" && isLicensedSource(String(row.doc_source ?? ""));
    const url = licensed ? `/standards/${String(row.doc_source)}/${c.subject_id}` : c.url;
    return {
    kind: c.subject_kind,
    id: c.subject_id,
    key: licensed ? null : c.subject_key || null,
    state: c.state,
    title: licensed ? `A setting in ${String(row.doc_standard ?? row.doc_source)}${row.doc_version ? ` ${String(row.doc_version)}` : ""} (named on the page)` : c.title,
    url: url.startsWith("/") ? `${baseUrl}${url}` : url,
    note: c.note,
    due: c.due_at,
    updated: c.updated_at,
    };
  });
}

/**
 * The latest digest, as this caller may read it. `owner` is not a courtesy: the owner's half names
 * their devices, their domains' certificates and their watchlist's products, and this endpoint is
 * gated for reading, not for the owner.
 */
export function apiDigest(db: DatabaseSync, owner = false) {
  const d = latestDigest(db);
  return d ? { period: d.period, coversFrom: d.covers_from, coversTo: d.covers_to, generatedAt: d.generated_at, text: digestTextFor(d, owner), ...(owner ? {} : { note: "The owner's own network, devices, domains and stack are left out of this half." }) } : null;
}
