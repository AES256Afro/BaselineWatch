import type { DatabaseSync } from "node:sqlite";
import type { ParsedItem, SourceRow } from "./adapters/types.ts";
import { putBlob } from "./blobs.ts";
import type { HttpGet } from "./http.ts";

/**
 * Article images, pulled passively as items arrive: the feed's own media when it carries any
 * (feed.ts sets imageUrl), otherwise the article page's og:image fetched once per new item.
 * Bytes are cached in the content-addressed blob store and served from /img/<hash>, because
 * the CSP (img-src 'self') forbids hot-linking — which would also leak readers' addresses.
 * An image is a nicety: no failure here may fail an ingest, so every miss is just a log line.
 */

export type ImageOrigin = "enclosure" | "body" | "og";

/** Image types worth caching; anything else (svg included, as it can script) is left behind. */
const imageTypes = new Map<string, string>([
  ["jpg", "image/jpeg"],
  ["jpeg", "image/jpeg"],
  ["png", "image/png"],
  ["gif", "image/gif"],
  ["webp", "image/webp"],
  ["avif", "image/avif"],
]);

/** The served content type: the response's when it is a known image type, else sniffed magic bytes. */
export function imageType(contentType: string | null, bytes: Uint8Array): string | null {
  const declared = contentType?.split(";")[0]?.trim().toLowerCase();
  if (declared && [...imageTypes.values()].includes(declared)) return declared;
  if (bytes.length < 12) return null;
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "image/jpeg";
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return "image/png";
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) return "image/gif";
  const ascii = (at: number, s: string) => [...s].every((ch, i) => bytes[at + i] === ch.charCodeAt(0));
  if (ascii(0, "RIFF") && ascii(8, "WEBP")) return "image/webp";
  if (ascii(4, "ftyp") && (ascii(8, "avif") || ascii(8, "avis"))) return "image/avif";
  return null;
}

/** og:image (or twitter:image) out of an article page, however the attributes are ordered. */
export function extractOgImage(page: string): string | null {
  const head = page.slice(0, 300_000);
  for (const meta of head.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = meta[0];
    const name = /(?:property|name)\s*=\s*["']?(og:image(?::secure_url|:url)?|twitter:image(?::src)?)["'\s/>]/i.exec(tag)?.[1];
    if (!name) continue;
    const content = /content\s*=\s*("([^"]*)"|'([^']*)')/i.exec(tag);
    const url = (content?.[2] ?? content?.[3])?.trim();
    if (url && /^https?:\/\//i.test(url)) return url.replace(/&amp;/g, "&");
  }
  return null;
}

export interface ImageDeps {
  http: HttpGet;
  log?: (line: string) => void;
}

const maxImageBytes = 8 * 1024 * 1024;
const maxPageBytes = 3 * 1024 * 1024;
/** og:image page fetches per source per run, so one busy feed cannot turn a fetch into a crawl.
 * Feed-supplied media is exempt: each is exactly one image GET the publisher offered. */
const maxOgFetchesPerRun = 20;

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

async function cacheImage(db: DatabaseSync, dataDir: string, deps: ImageDeps, itemId: number, url: string, origin: ImageOrigin): Promise<boolean> {
  const response = await deps.http(url, { timeoutMs: 20_000, maxBytes: maxImageBytes, headers: { accept: "image/*" } });
  const type = imageType(response.contentType, response.bytes);
  if (!type || response.bytes.length === 0) return false;
  const blob = putBlob(dataDir, response.bytes);
  db.prepare("UPDATE items SET image_blob = ?, image_type = ?, image_origin = ? WHERE id = ?").run(blob.sha256, type, origin, itemId);
  return true;
}

/**
 * Picks up images for the articles a fetch just inserted. Feed-supplied URLs cost one image GET;
 * when the feed carried none and the item links somewhere, the article page is fetched once for
 * its og:image. Items this pass cannot serve keep image_blob NULL and are never retried — passive
 * means images arrive with the news or not at all.
 */
export async function fetchNewItemImages(db: DatabaseSync, dataDir: string, source: SourceRow, fresh: ParsedItem[], deps: ImageDeps): Promise<number> {
  const log = deps.log ?? (() => {});
  let stored = 0;
  let ogFetches = 0;
  for (const item of fresh) {
    if (item.kind !== "article") continue;
    const row = db.prepare("SELECT id, image_blob FROM items WHERE source_id = ? AND external_id = ?").get(source.id, item.externalId) as { id: number; image_blob: string | null } | undefined;
    if (!row || row.image_blob) continue;
    try {
      if (item.imageUrl) {
        if (await cacheImage(db, dataDir, deps, row.id, item.imageUrl, item.imageOrigin ?? "enclosure")) stored += 1;
      } else if (item.url && ogFetches < maxOgFetchesPerRun) {
        ogFetches += 1;
        const page = await deps.http(item.url, { timeoutMs: 20_000, maxBytes: maxPageBytes, headers: { accept: "text/html" } });
        const url = extractOgImage(new TextDecoder("utf-8", { fatal: false }).decode(page.bytes));
        if (url && (await cacheImage(db, dataDir, deps, row.id, url, "og"))) stored += 1;
      }
    } catch (error) {
      log(`image for ${source.id} item ${item.externalId}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return stored;
}

/**
 * The one deliberate exception to "images arrive with the news or not at all": a manual pass
 * over existing news articles that have none, for the backlog from before the pipeline and the
 * tail the per-run cap left behind. One og:image page fetch per item, newest first, politely
 * paced; items that still yield nothing are simply examined again the next time the owner runs
 * it, which is rare enough not to matter.
 */
export async function backfillImages(
  db: DatabaseSync,
  dataDir: string,
  deps: ImageDeps,
  options: { limit?: number; delayMs?: number } = {},
): Promise<{ examined: number; stored: number }> {
  const log = deps.log ?? (() => {});
  const limit = Math.min(Math.max(options.limit ?? 200, 1), 10_000);
  const delayMs = options.delayMs ?? 500;
  const rows = db
    .prepare(
      `SELECT i.id, i.url FROM items i JOIN sources s ON s.id = i.source_id
       WHERE s.group_name = 'news' AND i.kind = 'article' AND i.image_blob IS NULL
         AND i.url IS NOT NULL AND i.url LIKE 'http%'
       ORDER BY COALESCE(i.published_at, i.fetched_at) DESC, i.id DESC LIMIT ?`,
    )
    .all(limit) as { id: number; url: string }[];
  let stored = 0;
  for (const [index, row] of rows.entries()) {
    if (index > 0 && delayMs > 0) await sleep(delayMs);
    try {
      const page = await deps.http(row.url, { timeoutMs: 20_000, maxBytes: maxPageBytes, headers: { accept: "text/html" } });
      const url = extractOgImage(new TextDecoder("utf-8", { fatal: false }).decode(page.bytes));
      if (url && (await cacheImage(db, dataDir, deps, row.id, url, "og"))) stored += 1;
    } catch (error) {
      log(`image backfill for item ${row.id}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return { examined: rows.length, stored };
}

/** The bytes behind /img/<hash>: served only when some item claims the hash, so snapshots stay private. */
export function imageFor(db: DatabaseSync, sha256: string): { sha256: string; type: string } | null {
  if (!/^[0-9a-f]{64}$/.test(sha256)) return null;
  const row = db.prepare("SELECT image_type FROM items WHERE image_blob = ? LIMIT 1").get(sha256) as { image_type: string | null } | undefined;
  return row ? { sha256, type: row.image_type ?? "image/jpeg" } : null;
}
