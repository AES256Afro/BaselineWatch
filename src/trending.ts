import type { DatabaseSync } from "node:sqlite";
import { parseJson } from "./json.ts";

/**
 * Which CVEs the News is talking about (N6): the CVE ids the articles and advisories name,
 * counted by distinct source over a window. A CVE two or more sources mention in a week is
 * being talked about, whatever its score; the table marks it and Today lists the top of them.
 * Read from the items this instance already holds, never from anywhere else.
 */

interface MentionRow {
  id: number;
  source_id: string;
  source_name: string;
  group_name: string;
  title: string;
  url: string | null;
  published_at: string | null;
  cves: string[];
}

/** Every article since `since` that names a CVE, with the ids it names; one scan, shared by the functions below. */
function mentionsSince(db: DatabaseSync, since: string): MentionRow[] {
  const rows = db
    .prepare(
      `SELECT i.id, i.source_id, s.name AS source_name, s.group_name, i.title, i.url, i.published_at, i.signals_json
       FROM items i JOIN sources s ON s.id = i.source_id
       WHERE i.kind = 'article' AND COALESCE(i.published_at, i.fetched_at) >= ? AND i.signals_json LIKE '%"cves"%'
       ORDER BY COALESCE(i.published_at, i.fetched_at) DESC`,
    )
    .all(since) as { id: number; source_id: string; source_name: string; group_name: string; title: string; url: string | null; published_at: string | null; signals_json: string | null }[];
  return rows.map((r) => ({ ...r, cves: parseJson<{ cves?: unknown }>(r.signals_json, {}).cves as string[] })).filter((r) => Array.isArray(r.cves) && r.cves.length > 0);
}

export interface Mention {
  /** Distinct sources naming the CVE in the window. */
  sources: number;
  items: number;
}

/** For a page of CVE rows: how many sources named each in the window. */
export function cveMentions(db: DatabaseSync, cveIds: string[], since: string): Map<string, Mention> {
  const out = new Map<string, Mention>();
  if (cveIds.length === 0) return out;
  const wanted = new Set(cveIds.map((c) => c.toUpperCase()));
  const seen = new Map<string, Set<string>>();
  for (const row of mentionsSince(db, since)) {
    for (const cve of row.cves) {
      if (!wanted.has(cve)) continue;
      const sources = seen.get(cve) ?? new Set<string>();
      sources.add(row.source_id);
      seen.set(cve, sources);
      const m = out.get(cve) ?? { sources: 0, items: 0 };
      m.items += 1;
      m.sources = sources.size;
      out.set(cve, m);
    }
  }
  return out;
}

export interface Trending {
  cveId: string;
  sources: number;
  items: number;
  /** The newest headline that named it. */
  headline: string;
  url: string | null;
  /** Whether the CVE is in this instance's table yet, so a link can be drawn or withheld. */
  known: boolean;
}

/** The CVEs two or more sources named in the window, most sources first, then most items. */
export function trendingCves(db: DatabaseSync, since: string, limit = 10): Trending[] {
  const tally = new Map<string, { sources: Set<string>; items: number; headline: string; url: string | null }>();
  for (const row of mentionsSince(db, since)) {
    for (const cve of row.cves) {
      const t = tally.get(cve) ?? { sources: new Set<string>(), items: 0, headline: row.title, url: row.url };
      t.sources.add(row.source_id);
      t.items += 1;
      tally.set(cve, t);
    }
  }
  const top = [...tally.entries()]
    .filter(([, t]) => t.sources.size >= 2)
    .sort((a, b) => b[1].sources.size - a[1].sources.size || b[1].items - a[1].items || a[0].localeCompare(b[0]))
    .slice(0, limit);
  if (top.length === 0) return [];
  const known = new Set((db.prepare(`SELECT cve_id FROM vulns WHERE cve_id IN (${top.map(() => "?").join(", ")})`).all(...top.map(([c]) => c)) as { cve_id: string }[]).map((r) => r.cve_id));
  return top.map(([cveId, t]) => ({ cveId, sources: t.sources.size, items: t.items, headline: t.headline, url: t.url, known: known.has(cveId) }));
}

export interface NewsMention {
  id: number;
  source_id: string;
  source_name: string;
  title: string;
  url: string | null;
  published_at: string | null;
}

/** The news items (not the vendor advisories, which the Fix panel lists) that name one CVE, newest first. */
export function newsFor(db: DatabaseSync, cveId: string, limit = 10): NewsMention[] {
  return (
    db
      .prepare(
        `SELECT i.id, i.source_id, s.name AS source_name, i.title, i.url, i.published_at FROM items i JOIN sources s ON s.id = i.source_id
         WHERE s.group_name = 'news' AND i.kind = 'article' AND i.signals_json LIKE ? ORDER BY COALESCE(i.published_at, i.fetched_at) DESC LIMIT ?`,
      )
      .all(`%"${cveId.toUpperCase()}"%`, limit) as unknown as NewsMention[]
  );
}
