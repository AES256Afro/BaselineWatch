import { putBlob, sha256Hex } from "../blobs.ts";
import { upsertItems } from "../items.ts";
import { cveIdsIn, plainText, type Adapter, type ParsedItem, type PullContext, type PullOutcome } from "./types.ts";

/**
 * SANS NewsBites, the twice-weekly news digest. SANS publishes no feed for it (the ISC diaries
 * feed is separate and already carried), so the adapter reads the newsletter web pages: the
 * index at sans.org/newsletters/newsbites lists the issues as cards (slug, title, date), and
 * each issue page carries its stories as `c-newsletter-news` sections (date, heading, body,
 * a "Read more in" list of outbound links). Each new issue page is fetched once; issues whose
 * stories are already stored are never fetched again.
 */

export const newsbitesBase = "https://www.sans.org";

/** One issue as the index lists it. */
export interface NewsbitesIssue {
  /** The path's last segment, "xxviii-77": volume and issue, stable per issue. */
  slug: string;
  url: string;
  title: string;
  publishedAt: string | null;
}

const months: Record<string, number> = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

/** "16 Oct 2026", the only date form the pages use, read as noon UTC so tests agree everywhere. */
function cardDate(value: string | null): string | null {
  const match = /(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})/.exec(value ?? "");
  if (!match) return null;
  const month = months[match[2]!.toLowerCase()];
  if (month === undefined) return null;
  return new Date(Date.UTC(Number(match[3]), month, Number(match[1]), 12)).toISOString();
}

/** The issues the index page lists, newest first the way the page orders them. */
export function parseNewsbitesIndex(html: string): NewsbitesIssue[] {
  const issues: NewsbitesIssue[] = [];
  const seen = new Set<string>();
  for (const card of html.matchAll(/<a class="c-resource-card"[^>]*href="\/newsletters\/newsbites\/([a-z0-9-]+)"[^>]*>([\s\S]*?)<\/a>/g)) {
    const slug = card[1]!;
    const body = card[2]!;
    const title = plainText(/resource-card__title">([\s\S]*?)<\/h3>/.exec(body)?.[1], 400);
    if (!title || seen.has(slug)) continue;
    seen.add(slug);
    issues.push({
      slug,
      url: `${newsbitesBase}/newsletters/newsbites/${slug}`,
      title,
      publishedAt: cardDate(/data-list-item-label">([^<]*)</.exec(body)?.[1] ?? null),
    });
  }
  return issues;
}

/** One issue page's stories, in page order; the story index numbers them within the issue. */
export function parseNewsbitesIssue(html: string, issue: NewsbitesIssue): ParsedItem[] {
  const chunks = html.split('<section class="c-newsletter-news">').slice(1);
  return chunks.flatMap((chunk, index) => {
    const title = plainText(/<h3[^>]*>([\s\S]*?)<\/h3>/.exec(chunk)?.[1], 300);
    if (!title) return [];
    const summary = plainText(/<div class="c-rich-text">([\s\S]*?)<\/div>/.exec(chunk)?.[1], 400);
    const outbound = /newsletter-news__read-more-list"[\s\S]*?<a[^>]*href="([^"]+)"/.exec(chunk)?.[1]?.trim();
    const date = cardDate(/newsletter-news__display-date"[^>]*>([^<]*)</.exec(chunk)?.[1] ?? null);
    const cves = cveIdsIn(`${title} ${summary ?? ""}`);
    return [
      {
        kind: "article",
        externalId: `${issue.slug}#${index + 1}`,
        title,
        url: outbound && /^https?:\/\//.test(outbound) ? outbound : issue.url,
        summary,
        publishedAt: date ?? issue.publishedAt,
        signals: { issue: issue.slug, ...(cves.length ? { cves } : {}) },
      } satisfies ParsedItem,
    ];
  });
}

/** Keeps a page's exact bytes, once per distinct content. */
function snapshot(ctx: PullContext, key: string, bytes: Uint8Array, contentType: string | null, at: string): void {
  const sha256 = sha256Hex(bytes);
  const exists = ctx.db.prepare("SELECT id FROM snapshots WHERE source_id = ? AND document_key = ? AND sha256 = ?").get(ctx.source.id, key, sha256);
  if (exists) return;
  const blob = putBlob(ctx.dataDir, bytes);
  ctx.db
    .prepare("INSERT INTO snapshots (source_id, document_key, sha256, bytes, media_type, blob_path, fetched_at, etag, last_modified) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)")
    .run(ctx.source.id, key, sha256, blob.bytes, contentType, blob.relativePath, at);
}

// Two issues a week on a daily schedule: two per pull keeps up, the first pull seeds the two
// newest issues, and the date cursor keeps every later pull off the 360-issue archive.
const maxIssuesPerPull = 2;

export const sansNewsbitesAdapter: Adapter = {
  id: "sans-newsbites",
  async pull(ctx): Promise<PullOutcome> {
    const observedAt = ctx.now().toISOString();
    const index = await ctx.http(ctx.source.url, { headers: { accept: "text/html" }, timeoutMs: 60_000 });
    snapshot(ctx, "index", index.bytes, index.contentType, observedAt);
    const issues = parseNewsbitesIndex(new TextDecoder("utf-8").decode(index.bytes));
    if (issues.length === 0) throw new Error("the NewsBites index listed no issues BaselineWatch could read");
    const stored = ctx.db.prepare("SELECT DISTINCT substr(external_id, 1, instr(external_id, '#') - 1) AS slug FROM items WHERE source_id = ?").all(ctx.source.id) as { slug: string }[];
    const seen = new Set(stored.map((r) => r.slug));
    const cursor = (ctx.db.prepare("SELECT MAX(published_at) AS at FROM items WHERE source_id = ?").get(ctx.source.id) as { at: string | null }).at;
    const fresh = issues.filter((i) => !seen.has(i.slug) && (cursor === null || (i.publishedAt !== null && i.publishedAt >= cursor))).slice(0, maxIssuesPerPull);
    const items: ParsedItem[] = [];
    for (const issue of fresh) {
      const response = await ctx.http(issue.url, { headers: { accept: "text/html" }, timeoutMs: 60_000 });
      snapshot(ctx, issue.slug, response.bytes, response.contentType, observedAt);
      const stories = parseNewsbitesIssue(new TextDecoder("utf-8").decode(response.bytes), issue);
      if (stories.length === 0) throw new Error(`the issue page ${issue.slug} had no stories BaselineWatch could read`);
      items.push(...stories);
    }
    const counts = upsertItems(ctx.db, ctx.source.id, items, observedAt);
    return { items: items.length, inserted: counts.inserted, updated: counts.updated, detail: `${fresh.length} new issue(s) of ${issues.length} listed` };
  },
};
