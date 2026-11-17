import type { DatabaseSync } from "node:sqlite";
import type { ItemKind } from "./adapters/types.ts";
import { html, type Html } from "./html.ts";
import { newsQuery, platformKeysOf, type PlatformChoice } from "./platforms.ts";
import { aiHeadlineQuery, aiItemSql } from "./topics.ts";
import { dangerSql, liveSql } from "./vulns.ts";

/**
 * The News timeline's queries: the filters a reader can set, the page of items they select with
 * cursor paging and FTS5 search, and the read and star marks.
 */
export interface WireFilters {
  source?: string | undefined;
  /** A source group: news, vulnerabilities or standards. */
  group?: "news" | "vulnerabilities" | "standards" | undefined;
  kind?: ItemKind | undefined;
  q?: string | undefined;
  unread?: boolean;
  /** Only the items the owner starred. */
  starred?: boolean;
  /** Cursor: the id of the last item shown; the page continues below it in the list's own order (date, then id). */
  before?: number | undefined;
  /** Only items published (or, undated, fetched) at or after this instant. */
  since?: string | undefined;
  /** Only stories about this platform: one that names its CVEs, or one whose headline or summary names it. */
  platform?: PlatformChoice | undefined;
  /** Only stories about the most dangerous: a KEV addition, or a story naming an exploited or likely-exploited CVE. */
  danger?: boolean | undefined;
  /** Only the AI stories (src/topics.ts). */
  topic?: "ai" | undefined;
  /** Leave the AI stories out: a reader's choice, kept in a cookie, or `ai=hide` on a link. Ignored when `topic` asks for them. */
  hideAi?: boolean | undefined;
  limit?: number;
}

export interface WireItem {
  id: number;
  source_id: string;
  source_name: string;
  kind: ItemKind;
  external_id: string;
  title: string;
  url: string | null;
  canonical_url: string | null;
  summary: string | null;
  published_at: string | null;
  fetched_at: string;
  signals_json: string | null;
  read: number;
  starred: number;
  /** The cached lead image's blob hash and type, when one arrived with the item. */
  image_blob: string | null;
  image_type: string | null;
}

/**
 * The KEV mark, with CISA's due date and "overdue" once that date has passed: one helper for the
 * News, the triage board, the CVE table and Today's desk, so a past date reads the same on all of
 * them. A date is past once the day after it begins, as overdueKev reads it.
 */
export function kevChip(due: string | null | undefined, now: Date | string): Html {
  const today = typeof now === "string" ? now.slice(0, 10) : now.toISOString().slice(0, 10);
  const date = due ? due.slice(0, 10) : null;
  const overdue = date !== null && date < today;
  return html`<span class="chip kev${overdue ? " overdue" : ""}"${overdue ? html` title="CISA's due date has passed"` : ""}>KEV${date ? html` · due ${date}${overdue ? " · overdue" : ""}` : ""}</span>`;
}

/** Turns free text into an FTS5 query that cannot be mistaken for FTS syntax: every word quoted, all required. */
export function ftsQuery(text: string): string | null {
  // Quotes would end a phrase early and a control character (a NUL from a crafted query) is an FTS5 syntax error.
  const words = text
    .split(/\s+/)
    .map((w) => w.replace(/["\p{Cc}]/gu, "").trim())
    .filter((w) => w.length > 0);
  if (words.length === 0) return null;
  return words.map((w) => `"${w}"`).join(" ");
}

interface Built {
  where: string;
  params: (string | number)[];
}

/**
 * Sources whose items are the owner's own facts, not news: crt.sh's items name the certificates
 * logged for the owner's domains. They reach the owner's News and nobody else's — not a visitor's
 * page, the feeds, the API or the MCP tools — as the digest has kept them since 0.53.0.
 */
export const ownerOnlySources: readonly string[] = ["crtsh"];

function build(filters: WireFilters, options: { copies?: boolean; owner?: boolean } = {}): Built {
  const clauses: string[] = [];
  const params: (string | number)[] = [];
  if (!options.owner) {
    clauses.push(`i.source_id NOT IN (${ownerOnlySources.map(() => "?").join(", ")})`);
    params.push(...ownerOnlySources);
  }
  // Hide later copies of the same link (the same story from two feeds), unless every copy is wanted.
  if (!options.copies) clauses.push("(i.canonical_url IS NULL OR i.id = (SELECT MIN(d.id) FROM items d WHERE d.canonical_url = i.canonical_url))");
  if (filters.source) {
    clauses.push("i.source_id = ?");
    params.push(filters.source);
  }
  if (filters.group) {
    clauses.push("i.source_id IN (SELECT id FROM sources WHERE group_name = ?)");
    params.push(filters.group);
  }
  if (filters.kind) {
    clauses.push("i.kind = ?");
    params.push(filters.kind);
  }
  if (filters.unread) clauses.push("i.read = 0");
  if (filters.starred) clauses.push("i.starred = 1");
  if (filters.q) {
    const query = ftsQuery(filters.q);
    if (query) {
      clauses.push("i.id IN (SELECT rowid FROM items_fts WHERE items_fts MATCH ?)");
      params.push(query);
    }
  }
  // A story is about the CVEs it is (a KEV or CVE item) and the CVEs its signals name. Each set
  // of CVEs below is written uncorrelated, so SQLite builds it once for the query rather than
  // once a story: correlated, Linux's 7,700 CVEs made the page take two and a half seconds.
  const namesCveIn = (set: string): string =>
    `((i.kind IN ('kev', 'vulnerability') AND i.external_id IN ${set})
      OR EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(i.signals_json) THEN i.signals_json ELSE '{}' END, '$.cves') c WHERE c.value IN ${set}))`;
  if (filters.platform) {
    const keys = platformKeysOf(filters.platform);
    const set = `(SELECT v.cve_id FROM vuln_platforms p JOIN vulns v ON v.id = p.vuln_id WHERE p.platform IN (${keys.map(() => "?").join(", ")}))`;
    // Headlines only: a long post that mentions Windows once in passing is not a Windows story.
    clauses.push(`(i.id IN (SELECT rowid FROM items_fts WHERE items_fts MATCH ?) OR ${namesCveIn(set)})`);
    params.push(`title : (${newsQuery(filters.platform)})`, ...keys, ...keys);
  }
  if (filters.topic === "ai") {
    clauses.push(aiItemSql);
    params.push(aiHeadlineQuery);
  } else if (filters.hideAi) {
    clauses.push(`NOT ${aiItemSql}`);
    params.push(aiHeadlineQuery);
  }
  if (filters.danger) clauses.push(`(i.kind = 'kev' OR ${namesCveIn(`(SELECT v.cve_id FROM vulns v WHERE ${liveSql} AND ${dangerSql})`)})`);
  if (filters.since) {
    clauses.push("COALESCE(i.published_at, i.fetched_at) >= ?");
    params.push(filters.since);
  }
  if (filters.before) {
    // The list is ordered by date then id, so the cursor compares on both: an older item with a
    // higher id (a CVE whose published date is years back) is neither repeated nor skipped. A
    // cursor whose item is gone (a republished release) starts the list over rather than dead-ending.
    clauses.push("((COALESCE(i.published_at, i.fetched_at), i.id) < (SELECT COALESCE(b.published_at, b.fetched_at), b.id FROM items b WHERE b.id = ?) OR NOT EXISTS (SELECT 1 FROM items b WHERE b.id = ?))");
    params.push(filters.before, filters.before);
  }
  return { where: clauses.length ? `WHERE ${clauses.join(" AND ")}` : "", params };
}

/**
 * The page's items; with `copies`, later copies of one address come too, for a page that names the
 * other sources. Without `owner`, the owner-only sources are left out.
 */
export function listWire(db: DatabaseSync, filters: WireFilters = {}, options: { copies?: boolean; owner?: boolean } = {}): WireItem[] {
  const { where, params } = build(filters, options);
  const limit = Math.min(Math.max(filters.limit ?? 50, 1), 200);
  return db
    .prepare(
      `SELECT i.*, s.name AS source_name FROM items i JOIN sources s ON s.id = i.source_id
       ${where}
       ORDER BY COALESCE(i.published_at, i.fetched_at) DESC, i.id DESC
       LIMIT ?`,
    )
    .all(...params, limit) as unknown as WireItem[];
}

/** What makes two articles one story: the same address once canonical, or the same headline (a short one proves nothing). */
export function storyKeys(item: Pick<WireItem, "kind" | "canonical_url" | "title">): string[] {
  if (item.kind !== "article") return [];
  const keys: string[] = [];
  if (item.canonical_url) keys.push(`u:${item.canonical_url}`);
  const headline = item.title.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim().slice(0, 80);
  if (headline.length >= 24) keys.push(`t:${headline}`);
  return keys;
}

type Foldable = Pick<WireItem, "id" | "source_id" | "kind" | "canonical_url" | "title">;

/**
 * One story from several sources is one card: the first by date, the others named on it. Rows come
 * newest first, as the page lists them, and fold only among themselves.
 */
export function foldStories<T extends Foldable>(rows: T[]): { items: T[]; alsoOn: Map<number, T[]> } {
  const alsoOn = new Map<number, T[]>();
  const firstByKey = new Map<string, T>();
  const items: T[] = [];
  for (const item of rows) {
    const keys = storyKeys(item);
    const first = keys.map((k) => firstByKey.get(k)).find((f) => f !== undefined && f.source_id !== item.source_id);
    if (first) {
      alsoOn.set(first.id, [...(alsoOn.get(first.id) ?? []), item]);
      continue;
    }
    for (const k of keys) if (!firstByKey.has(k)) firstByKey.set(k, item);
    items.push(item);
  }
  return { items, alsoOn };
}

/**
 * How many stories the News page draws under these filters: every copy that matches, folded by
 * story among the matching rows alone, as the page lists them (hiding copies among all items
 * would count a story whose first copy the filters leave out as none). With `arrivedSince`, only the stories whose card was fetched since then.
 */
export function countStories(db: DatabaseSync, filters: WireFilters = {}, options: { owner?: boolean } = {}, arrivedSince?: string): { total: number; fresh: number } {
  const { where, params } = build({ ...filters, before: undefined }, { copies: true, owner: options.owner === true });
  const rows = db
    .prepare(`SELECT i.id, i.source_id, i.kind, i.canonical_url, i.title, i.fetched_at FROM items i ${where} ORDER BY COALESCE(i.published_at, i.fetched_at) DESC, i.id DESC`)
    .all(...params) as unknown as (Foldable & { fetched_at: string })[];
  const { items } = foldStories(rows);
  return { total: items.length, fresh: arrivedSince ? items.filter((i) => i.fetched_at >= arrivedSince).length : items.length };
}

export function markAllRead(db: DatabaseSync, filters: WireFilters = {}, upto?: number, drawnAt?: string): number {
  // Every copy of a story is marked, so the unread count (which counts them all) can reach zero.
  // Only up to the newest the page showed: what arrived after it loaded has not been seen, and a
  // KEV entry marked read would leave the triage inbox unread by anyone.
  const { where, params } = build({ ...filters, before: undefined }, { copies: true, owner: true });
  // And an older item that came back unread after the page was drawn (its CVE changed) was not
  // seen either: it keeps its id, so only the time it resurfaced tells.
  const bound = upto !== undefined && Number.isInteger(upto) && upto > 0 ? " AND id <= ?" : "";
  const drawn = drawnAt && !Number.isNaN(Date.parse(drawnAt)) ? " AND (surfaced_at IS NULL OR surfaced_at <= ?)" : "";
  const result = db
    .prepare(`UPDATE items SET read = 1 WHERE id IN (SELECT i.id FROM items i ${where})${bound}${drawn}`)
    .run(...params, ...(bound ? [upto!] : []), ...(drawn ? [drawnAt!] : []));
  return Number(result.changes);
}

export interface SourceCount {
  source_id: string;
  name: string;
  group_name: string;
  total: number;
  unread: number;
}

export function sourceCounts(db: DatabaseSync): SourceCount[] {
  return db
    .prepare(
      `SELECT s.id AS source_id, s.name, s.group_name, COUNT(i.id) AS total, SUM(CASE WHEN i.read = 0 THEN 1 ELSE 0 END) AS unread
       FROM sources s LEFT JOIN items i ON i.source_id = s.id
       WHERE s.enabled = 1
       GROUP BY s.id ORDER BY s.group_name, s.name`,
    )
    .all() as unknown as SourceCount[];
}

export function setRead(db: DatabaseSync, id: number, read: boolean): boolean {
  return Number(db.prepare("UPDATE items SET read = ? WHERE id = ?").run(read ? 1 : 0, id).changes) === 1;
}

export function setStarred(db: DatabaseSync, id: number, starred: boolean): boolean {
  return Number(db.prepare("UPDATE items SET starred = ? WHERE id = ?").run(starred ? 1 : 0, id).changes) === 1;
}
