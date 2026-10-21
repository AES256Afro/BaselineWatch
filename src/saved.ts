import type { DatabaseSync } from "node:sqlite";

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
