import type { DatabaseSync } from "node:sqlite";
import { adapterFor, feedAdapter } from "./adapters/index.ts";
import type { SourceRow } from "./adapters/types.ts";
import { HttpError, type HttpGet } from "./http.ts";
import { parseJson } from "./json.ts";
import { logSourceChange } from "./newsource.ts";

/**
 * Repairs proposed, not hunted (M20.3). A source that fails first tries the other addresses it
 * declared for the same document (`sources.fallback_urls`, used at once and reported — see
 * ingestSource); a feed that still fails is looked into the way a person would, once a day while
 * it fails: did its address move permanently, does the publisher's page link a feed, does the
 * site answer at one of the usual feed addresses. Each candidate is probed and parsed by the
 * adapter that reads the source, and one that holds entries is kept as a proposed repair the owner
 * can use with a click. Nothing changes a source's address without that click.
 *
 * Every request here goes to the source's own site and through the public-only path, because the
 * candidates come out of a page rather than from the publisher the owner chose.
 */

export interface Repair {
  id: number;
  source_id: string;
  url: string;
  how: string;
  items: number;
  sample: string | null;
  found_at: string;
}

/** A source looks for a repair at most this often while it fails. */
export const repairEveryHours = 24;

/**
 * Failures that say the address is right and the server is refusing or unwell: a 403, a 429, a
 * 5xx. Looking for a new address then only adds requests to a host already asking for fewer.
 */
export function addressLooksRight(error: string | null): boolean {
  return /HTTP (403|429|5\d\d)\b/.test(error ?? "");
}

/** The usual places a site keeps its feed, tried on the source's own origin. */
export const usualFeedPaths = ["/feed/", "/feed.xml", "/rss.xml", "/atom.xml", "/index.xml", "/rss/"] as const;

/** The other addresses a source declared for the same document, in the order to try them. */
export function fallbacksOf(source: Pick<SourceRow, "fallback_urls">): string[] {
  const list = parseJson<unknown>(source.fallback_urls ?? null, []);
  return Array.isArray(list) ? list.filter((u): u is string => typeof u === "string" && /^https?:\/\//.test(u)) : [];
}

export function proposedRepairs(db: DatabaseSync, sourceId: string): Repair[] {
  return db.prepare("SELECT * FROM source_repairs WHERE source_id = ? ORDER BY items DESC, id").all(sourceId) as unknown as Repair[];
}

/** Every proposal, by source: what the Sources page and Today draw from. */
export function repairsBySource(db: DatabaseSync): Map<string, Repair[]> {
  const out = new Map<string, Repair[]>();
  for (const r of db.prepare("SELECT * FROM source_repairs ORDER BY items DESC, id").all() as unknown as Repair[]) {
    out.set(r.source_id, [...(out.get(r.source_id) ?? []), r]);
  }
  return out;
}

const attr = (tag: string, name: string): string | null => {
  const m = new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i").exec(tag);
  return m ? (m[1] ?? m[2] ?? m[3] ?? "") : null;
};

/** The feeds a page announces with `<link rel="alternate" type="application/rss+xml">` (or Atom), as absolute URLs. */
export function alternateFeeds(page: string, base: string): string[] {
  const out: string[] = [];
  for (const tag of page.match(/<link\b[^>]*>/gi) ?? []) {
    const rel = (attr(tag, "rel") ?? "").toLowerCase().split(/\s+/);
    const type = (attr(tag, "type") ?? "").toLowerCase();
    const href = attr(tag, "href");
    if (!rel.includes("alternate") || !/application\/(rss|atom|rdf)\+xml/.test(type) || !href) continue;
    try {
      const url = new URL(href.replace(/&amp;/g, "&"), base);
      if (url.protocol === "https:" || url.protocol === "http:") out.push(url.toString());
    } catch {
      // not a URL: skipped
    }
  }
  return [...new Set(out)];
}

/** The same site: the same host, or one a subdomain of the other, once a leading `www.` is dropped. */
export function sameSite(a: string, b: string): boolean {
  try {
    const x = new URL(a).hostname.replace(/^www\./, "");
    const y = new URL(b).hostname.replace(/^www\./, "");
    return x === y || x.endsWith(`.${y}`) || y.endsWith(`.${x}`);
  } catch {
    return false;
  }
}

/**
 * Looks for a repair to a failing feed and keeps what it finds. Returns how many it proposed;
 * zero when the source is not a feed, was looked into within the day, or nothing answered.
 */
export async function findRepairs(db: DatabaseSync, source: SourceRow, http: HttpGet, now: Date): Promise<number> {
  // The generic feed adapter only: Reddit and Hacker News build their own requests from the source.
  const adapter = adapterFor(source);
  if (adapter !== feedAdapter || !adapter.parse || addressLooksRight(source.last_error)) return 0;
  const last = source.repair_checked_at ? Date.parse(source.repair_checked_at) : NaN;
  if (Number.isFinite(last) && now.getTime() - last < repairEveryHours * 3_600_000) return 0;
  db.prepare("UPDATE sources SET repair_checked_at = ? WHERE id = ?").run(now.toISOString(), source.id);

  let origin: string;
  try {
    origin = new URL(source.url).origin;
  } catch {
    return 0;
  }
  const get = (url: string, redirect: "follow" | "manual" = "follow") =>
    http(url, { publicOnly: true, redirect, timeoutMs: 20_000, maxBytes: 5 * 1024 * 1024, headers: { accept: "text/html, application/xhtml+xml, application/rss+xml, application/atom+xml, */*;q=0.5" } });

  const candidates = new Map<string, string>();
  const consider = (url: string, how: string) => {
    if (url !== source.url && !candidates.has(url) && sameSite(url, source.url)) candidates.set(url, how);
  };
  // Did the address move for good? A 301 or 308 says where to.
  try {
    await get(source.url, "manual");
  } catch (error) {
    const location = error instanceof HttpError && (error.status === 301 || error.status === 308) ? error.headers.location : undefined;
    if (location) {
      try {
        consider(new URL(location, source.url).toString(), "the old address now moves here permanently");
      } catch {
        // an unreadable Location: nothing to propose
      }
    }
  }
  // The feeds the failing address and the site's home page announce.
  for (const page of [source.url, `${origin}/`]) {
    try {
      const text = new TextDecoder("utf-8").decode((await get(page)).bytes);
      for (const href of alternateFeeds(text, page)) consider(href, `linked from ${page}`);
    } catch {
      // the page did not answer: nothing found there
    }
  }
  for (const p of usualFeedPaths) consider(`${origin}${p}`, "a usual feed address on the same site");

  let found = 0;
  for (const [url, how] of [...candidates].slice(0, 10)) {
    // Another source already reading it is a duplicate, not a repair.
    if (db.prepare("SELECT 1 FROM sources WHERE url = ?").get(url)) continue;
    try {
      const response = await get(url);
      const items = adapter.parse(response.bytes, { ...source, url }, now).items;
      if (items.length === 0) continue;
      db.prepare(
        `INSERT INTO source_repairs (source_id, url, how, items, sample, found_at) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (source_id, url) DO UPDATE SET how = excluded.how, items = excluded.items, sample = excluded.sample, found_at = excluded.found_at`,
      ).run(source.id, url, how, items.length, items[0]!.title.slice(0, 200), now.toISOString());
      found += 1;
    } catch {
      // did not answer, or not with a feed: not a repair
    }
  }
  return found;
}

/** A source that answered again needs no repair, from its own address or a fallback. */
export function clearRepairs(db: DatabaseSync, sourceId: string): void {
  db.prepare("DELETE FROM source_repairs WHERE source_id = ?").run(sourceId);
  db.prepare("UPDATE sources SET repair_checked_at = NULL WHERE id = ? AND repair_checked_at IS NOT NULL").run(sourceId);
}

/** Points the source at the address it was failing over to, or at a proposed repair; logged. */
function moveSource(db: DatabaseSync, source: SourceRow, url: string, fallbacks: string[] | null, at: string): void {
  db.prepare(
    `UPDATE sources SET url = ?, fallback_urls = ?, etag = NULL, last_modified = NULL, answered_from = NULL, primary_error = NULL, repair_checked_at = NULL WHERE id = ?`,
  ).run(url, fallbacks && fallbacks.length ? JSON.stringify(fallbacks) : null, source.id);
  db.prepare("DELETE FROM source_repairs WHERE source_id = ?").run(source.id);
  logSourceChange(db, source.id, at, "address", source.url, url);
}

/** The owner's "Use it": the proposed address becomes the source's own. Null when there is no such proposal. */
export function useRepair(db: DatabaseSync, source: SourceRow, repairId: number, at: string): Repair | null {
  const repair = (db.prepare("SELECT * FROM source_repairs WHERE id = ? AND source_id = ?").get(repairId, source.id) as unknown as Repair | undefined) ?? null;
  if (!repair) return null;
  moveSource(db, source, repair.url, fallbacksOf(source), at);
  return repair;
}

/** The fallback that has been answering becomes the address; the rest stay fallbacks. Null when none is answering. */
export function adoptFallback(db: DatabaseSync, source: SourceRow, at: string): string | null {
  const url = source.answered_from;
  if (!url) return null;
  moveSource(db, source, url, fallbacksOf(source).filter((u) => u !== url), at);
  return url;
}
