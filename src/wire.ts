import type { DatabaseSync } from "node:sqlite";
import type { ItemKind } from "./adapters/types.ts";

export interface WireFilters {
  source?: string | undefined;
  /** A source group: news, vulnerabilities or standards. */
  group?: "news" | "vulnerabilities" | "standards" | undefined;
  kind?: ItemKind | undefined;
  q?: string | undefined;
  unread?: boolean;
  /** Cursor: the id of the last item shown; the page continues below it in the list's own order (date, then id). */
  before?: number | undefined;
  /** Only items published (or, undated, fetched) at or after this instant. */
  since?: string | undefined;
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

function build(filters: WireFilters, options: { copies?: boolean } = {}): Built {
  const clauses: string[] = [];
  const params: (string | number)[] = [];
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
  if (filters.q) {
    const query = ftsQuery(filters.q);
    if (query) {
      clauses.push("i.id IN (SELECT rowid FROM items_fts WHERE items_fts MATCH ?)");
      params.push(query);
    }
  }
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

export function listWire(db: DatabaseSync, filters: WireFilters = {}): WireItem[] {
  const { where, params } = build(filters);
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

export function markAllRead(db: DatabaseSync, filters: WireFilters = {}): number {
  // Every copy of a story is marked, so the unread count (which counts them all) can reach zero.
  const { where, params } = build({ ...filters, before: undefined }, { copies: true });
  const result = db.prepare(`UPDATE items SET read = 1 WHERE id IN (SELECT i.id FROM items i ${where})`).run(...params);
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
