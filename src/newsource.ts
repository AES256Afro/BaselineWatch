import type { DatabaseSync } from "node:sqlite";
import { feedAdapter } from "./adapters/feed.ts";
import type { SourceRow } from "./adapters/types.ts";
import type { HttpGet } from "./http.ts";

/**
 * A source the owner adds on the running instance (M20.2): a feed's address, probed before it is
 * saved — one request through the public-only path, parsed by the adapter that will read it, the
 * first entries shown — so a source no longer needs a migration written in a coding session. The
 * generic feed adapter reads any RSS, RSS 1.0 or Atom document, so a row is all a feed needs.
 *
 * Every change the owner makes to a source is logged here with what it was before.
 */

export type SourceAction = "added" | "address" | "enabled" | "disabled";

export interface SourceLogEntry {
  source_id: string;
  name: string | null;
  at: string;
  action: SourceAction;
  before: string | null;
  after: string | null;
}

export function logSourceChange(db: DatabaseSync, sourceId: string, at: string, action: SourceAction, before: string | null, after: string | null): void {
  db.prepare("INSERT INTO source_log (source_id, at, action, before, after) VALUES (?, ?, ?, ?, ?)").run(sourceId, at, action, before, after);
}

/** The newest changes first, with the source's current name when it still exists. */
export function sourceLog(db: DatabaseSync, limit = 30): SourceLogEntry[] {
  return db
    .prepare("SELECT l.source_id, s.name, l.at, l.action, l.before, l.after FROM source_log l LEFT JOIN sources s ON s.id = l.source_id ORDER BY l.at DESC, l.id DESC LIMIT ?")
    .all(limit) as unknown as SourceLogEntry[];
}

export interface FeedPreview {
  url: string;
  format: "rss" | "atom";
  /** The feed's own title, when it gives one. */
  title: string | null;
  count: number;
  items: { title: string; url: string | null; publishedAt: string | null }[];
}

export type FeedProbe = { ok: true; feed: FeedPreview } | { ok: false; error: string };

/** Atom by its root element; RSS 2.0 and RSS 1.0 are both read as `rss`. */
export function feedFormat(xml: string): "rss" | "atom" {
  return /<feed[\s>]/.test(xml.slice(0, 4000)) ? "atom" : "rss";
}

const entities: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

/** The first `<title>` in the document, which is the channel's or the feed's before any item's. */
export function feedTitle(xml: string): string | null {
  const m = /<title(?:\s[^>]*)?>([\s\S]*?)<\/title>/i.exec(xml);
  if (!m) return null;
  const text = m[1]!
    .replace(/^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/, "$1")
    .replace(/&(amp|lt|gt|quot|apos);/g, (_, e: string) => entities[e]!)
    .replace(/\s+/g, " ")
    .trim();
  return text ? text.slice(0, 120) : null;
}

/** An address the owner typed: http or https, no credentials in it, of a sane length. */
export function feedAddress(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const text = raw.trim();
  if (!text || text.length > 500) return null;
  try {
    const url = new URL(text);
    if ((url.protocol !== "https:" && url.protocol !== "http:") || url.username || url.password) return null;
    return url.toString();
  } catch {
    return null;
  }
}

/**
 * One request and one parse: what the source would hold if it were added now. Public hosts only,
 * because the address is typed into a form rather than chosen from a publisher's own document.
 */
export async function probeFeed(http: HttpGet, url: string): Promise<FeedProbe> {
  let bytes: Uint8Array;
  try {
    bytes = (await http(url, { publicOnly: true, timeoutMs: 20_000, maxBytes: 10 * 1024 * 1024 })).bytes;
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
  const xml = new TextDecoder("utf-8").decode(bytes);
  let items;
  try {
    items = feedAdapter.parse!(bytes, { url } as SourceRow, new Date()).items;
  } catch (error) {
    return { ok: false, error: `${error instanceof Error ? error.message : String(error)}: the address answered, but not with a feed` };
  }
  if (items.length === 0) return { ok: false, error: "the feed answered and holds no entries, so there is nothing to show that it is the right one" };
  return {
    ok: true,
    feed: {
      url,
      format: feedFormat(xml),
      title: feedTitle(xml),
      count: items.length,
      items: items.slice(0, 5).map((i) => ({ title: i.title, url: i.url ?? null, publishedAt: i.publishedAt ?? null })),
    },
  };
}

export interface NewSource {
  url: string;
  /** Empty when the owner left it to the feed's own title. */
  name: string;
  group: "news" | "vulnerabilities";
  topic: "ai" | null;
  schedule: "hourly" | "daily" | "weekly";
  licence: string | null;
}

const field = (body: Record<string, unknown>, key: string, max: number): string => (typeof body[key] === "string" ? (body[key] as string).trim().slice(0, max) : "");

/** The form, read; a sentence saying what is wrong when it cannot be. */
export function readNewSource(body: Record<string, unknown>): NewSource | string {
  const url = feedAddress(body.url);
  if (!url) return "The address must be a whole http or https URL, with no user name or password in it.";
  const group = field(body, "group", 20);
  const schedule = field(body, "schedule", 10);
  const topic = field(body, "topic", 10);
  return {
    url,
    name: field(body, "name", 100),
    group: group === "vulnerabilities" ? "vulnerabilities" : "news",
    topic: topic === "ai" ? "ai" : null,
    schedule: schedule === "hourly" || schedule === "weekly" ? schedule : "daily",
    licence: field(body, "licence", 200) || null,
  };
}

/** The source already reading this address, if one is. */
export function sourceWithUrl(db: DatabaseSync, url: string): { id: string; name: string } | null {
  return (db.prepare("SELECT id, name FROM sources WHERE url = ?").get(url) as { id: string; name: string } | undefined) ?? null;
}

/** A readable id from the address — `example-com-security-feed` — made unique against the rows there are. */
export function sourceIdFor(db: DatabaseSync, url: string): string {
  const u = new URL(url);
  const base =
    `${u.hostname.replace(/^www\./, "")}${u.pathname}`
      .toLowerCase()
      .replace(/\.(xml|rss|atom)$/, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 48)
      .replace(/-$/, "") || "feed";
  const taken = (id: string) => db.prepare("SELECT 1 FROM sources WHERE id = ?").get(id) !== undefined;
  if (!taken(base)) return base;
  for (let n = 2; ; n += 1) if (!taken(`${base}-${n}`)) return `${base}-${n}`;
}

/** Writes the row and the log line; the caller fetches it once so its entries arrive at once. */
export function addSource(db: DatabaseSync, input: NewSource, feed: FeedPreview, at: string): string {
  const id = sourceIdFor(db, input.url);
  const name = input.name || feed.title || new URL(input.url).hostname;
  db.prepare(
    `INSERT INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes, topic, origin)
     VALUES (?, ?, 'article', ?, ?, ?, ?, 1, ?, ?, ?, ?, 'owner')`,
  ).run(id, name, input.group, input.url, feed.format, input.schedule, input.licence, feed.title ?? name, `Added on this instance on ${at.slice(0, 10)}. Headlines and links only, as for every feed.`, input.topic);
  logSourceChange(db, id, at, "added", null, input.url);
  return id;
}
