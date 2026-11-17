import type { DatabaseSync } from "node:sqlite";
import { vulnFilters, wireFilters } from "./routes/query.ts";
import { countVulns } from "./vulns.ts";
import { countStories } from "./wire.ts";

/**
 * Saved searches (N6): the owner names a filtered list once — a table filter, a News filter, a
 * search, a Patch Tuesday component — and it waits on the desk and on Today. A saved search is
 * a path on this site with its query string, nothing more; the page it names does the work.
 */

export interface SavedSearch {
  id: number;
  name: string;
  path: string;
  created_at: string;
  /** When the owner last opened it through /saved/<id>/open (migration 0072); null before the first time. */
  last_opened_at: string | null;
}

/** The pages whose lists are worth saving: each takes filters in its query string. */
const savablePages = ["/", "/vulnerabilities", "/vulnerabilities/microsoft", "/search", "/controls", "/register"];

/** A path on this site, one of the list pages, with a query string; anything else is not a search. */
export function savablePath(value: unknown): string | null {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("\\") || value.length > 500) return null;
  const at = value.indexOf("?");
  const page = at < 0 ? value : value.slice(0, at);
  const query = at < 0 ? "" : value.slice(at + 1);
  if (!savablePages.includes(page) || !query || /[\r\n<>"']/.test(value)) return null;
  return value;
}

export function listSaved(db: DatabaseSync): SavedSearch[] {
  return db.prepare("SELECT * FROM saved_searches ORDER BY name").all() as unknown as SavedSearch[];
}

export function addSaved(db: DatabaseSync, name: string, path: string, at: string): boolean {
  return Number(db.prepare("INSERT OR IGNORE INTO saved_searches (name, path, created_at) VALUES (?, ?, ?)").run(name.trim().slice(0, 60), path, at).changes) > 0;
}

export function deleteSaved(db: DatabaseSync, id: number): boolean {
  return Number(db.prepare("DELETE FROM saved_searches WHERE id = ?").run(id).changes) > 0;
}

/** The pages' way of telling the Save form what they are showing: the path with its query, when it has one. */
export function isSaved(db: DatabaseSync, path: string): boolean {
  return db.prepare("SELECT 1 FROM saved_searches WHERE path = ?").get(path) !== undefined;
}

/** Opening a saved search: the time is kept so the next count of what is new starts there. Its path, or null for no such search. */
export function openSaved(db: DatabaseSync, id: number, at: string): string | null {
  const row = db.prepare("SELECT path FROM saved_searches WHERE id = ?").get(id) as { path: string } | undefined;
  if (!row) return null;
  db.prepare("UPDATE saved_searches SET last_opened_at = ? WHERE id = ?").run(at, id);
  return row.path;
}

/**
 * What a saved list holds now and how much of it is new since it was last opened, counted with one
 * COUNT through the same query builder the page uses: the Vulnerabilities table's filters (vulnQuery)
 * and the News's (wire.ts' build). "New" is a CVE first seen, or a story fetched, after the last
 * opening. Pages that are not a counted list (a search, the controls, Patch Tuesday, the register)
 * give null and show no figure. The owner's lists, counted as the owner sees them.
 */
export function savedCounts(db: DatabaseSync, s: SavedSearch, now: Date): { total: number; fresh: number } | null {
  const at = s.path.indexOf("?");
  const page = at < 0 ? s.path : s.path.slice(0, at);
  const query = Object.fromEntries(new URLSearchParams(at < 0 ? "" : s.path.slice(at + 1)));
  const since = s.last_opened_at ?? undefined;
  if (page === "/vulnerabilities") {
    const filters = { ...vulnFilters(query, now, true), offset: 0 };
    const total = countVulns(db, filters);
    if (!since) return { total, fresh: total };
    // The later of the list's own window and the last opening, so a 24-hour list never counts more than it holds.
    const newSince = filters.newSince && filters.newSince > since ? filters.newSince : since;
    return { total, fresh: countVulns(db, { ...filters, newSince }) };
  }
  if (page === "/") {
    const filters = { ...wireFilters(query, true), before: undefined };
    // Counted the way the page lists: every matching copy, folded by story among those rows.
    return countStories(db, filters, { owner: true }, since);
  }
  return null;
}
