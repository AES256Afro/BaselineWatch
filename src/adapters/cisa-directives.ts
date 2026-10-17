import { putBlob, sha256Hex } from "../blobs.ts";
import { upsertItems } from "../items.ts";
import { directivePlatforms } from "../stigs.ts";
import { plainText, type Adapter, type AlertDraft, type ParsedItem, type PullContext, type PullOutcome } from "./types.ts";

/**
 * CISA's Binding Operational Directives and Emergency Directives. CISA publishes no feed for
 * them; the listing at cisa.gov/news-events/directives/all is a paged HTML view (ten a page,
 * teaser markup with the date, the kind and the title). The adapter walks the pages, keeps each
 * page's bytes as a snapshot, and stores every directive as a Wire item tagged with the platforms
 * its title names, so the STIG pages can show the directives that touch a platform.
 */

export interface Directive {
  /** The path's last segment, stable per directive page. */
  slug: string;
  url: string;
  title: string;
  kind: "bod" | "ed" | "other";
  /** "BOD 26-04" or "ED 25-03" when the title carries one. */
  code: string | null;
  /** Implementation guidance, supplemental direction or a revision of an earlier directive. */
  supplemental: boolean;
  publishedAt: string | null;
}

export const directivesBase = "https://www.cisa.gov";

function kindOf(meta: string | null, title: string): Directive["kind"] {
  const m = (meta ?? "").toLowerCase();
  if (m.includes("emergency")) return "ed";
  if (m.includes("binding")) return "bod";
  if (/\bED\s+\d{2}-\d{2}\b/.test(title)) return "ed";
  if (/\bBOD\s+\d{2}-\d{2}\b/.test(title)) return "bod";
  return "other";
}

export const kindLabel: Record<Directive["kind"], string> = { bod: "Binding Operational Directive", ed: "Emergency Directive", other: "Directive" };

/** One page of the listing: its directives and the total the page states. */
export function parseDirectivesPage(html: string): { directives: Directive[]; total: number | null } {
  const directives: Directive[] = [];
  for (const row of html.matchAll(/<div\s+class="c-view__row">([\s\S]*?)<\/article>/g)) {
    const body = row[1] ?? "";
    const href = /<a\s+href="(\/news-events\/directives\/[^"]+)"/.exec(body)?.[1];
    if (!href) continue;
    const rawTitle = /<a\s+href="\/news-events\/directives\/[^"]+"[^>]*>\s*(?:<span>)?([\s\S]*?)(?:<\/span>)?\s*<\/a>/.exec(body)?.[1] ?? "";
    const title = plainText(rawTitle, 300);
    if (!title) continue;
    const datetime = /<time[^>]*datetime="([^"]+)"/.exec(body)?.[1];
    const meta = plainText(/c-teaser__meta">([\s\S]*?)<\/div>/.exec(body)?.[1], 100);
    const code = /\b(BOD|ED)\s+(\d{2}-\d{2})\b/.exec(title);
    const date = datetime ? new Date(datetime) : null;
    directives.push({
      slug: href.split("/").pop()!,
      url: `${directivesBase}${href}`,
      title,
      kind: kindOf(meta, title),
      code: code ? `${code[1]} ${code[2]}` : null,
      supplemental: /supplemental|implementation guidance|^V\d+:/i.test(title),
      publishedAt: date && !Number.isNaN(date.getTime()) ? date.toISOString() : null,
    });
  }
  const total = Number(/results-total-wrapper">\s*(\d+)/.exec(html)?.[1]);
  return { directives, total: Number.isInteger(total) ? total : null };
}

const maxPages = 10;

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

/** A directive as a Wire item: the kind and date are CISA's; the platform tags are this product's reading of the title. */
export function directiveItem(d: Directive): ParsedItem {
  const platforms = directivePlatforms(d.title);
  const when = d.publishedAt ? d.publishedAt.slice(0, 10) : null;
  return {
    kind: "article",
    externalId: d.slug,
    title: d.title,
    url: d.url,
    summary: `${kindLabel[d.kind]}${when ? `, ${when}` : ""}${d.supplemental ? "; guidance or supplemental direction" : ""}. Platforms named: ${platforms.includes("all") ? "all" : platforms.join(", ")}.`,
    publishedAt: d.publishedAt,
    signals: { directive: d.code, directiveKind: d.kind, supplemental: d.supplemental, platforms },
  };
}

export const cisaDirectivesAdapter: Adapter = {
  id: "cisa-directives",
  async pull(ctx): Promise<PullOutcome> {
    const observedAt = ctx.now().toISOString();
    const before = new Set((ctx.db.prepare("SELECT external_id FROM items WHERE source_id = ?").all(ctx.source.id) as { external_id: string }[]).map((r) => r.external_id));
    const all: Directive[] = [];
    let total: number | null = null;
    let page = 0;
    for (; page < maxPages; page += 1) {
      const url = page === 0 ? ctx.source.url : `${ctx.source.url}?page=${page}`;
      const response = await ctx.http(url, { headers: { accept: "text/html" }, timeoutMs: 60_000 });
      snapshot(ctx, `all?page=${page}`, response.bytes, response.contentType, observedAt);
      const parsed = parseDirectivesPage(new TextDecoder("utf-8").decode(response.bytes));
      total ??= parsed.total;
      all.push(...parsed.directives);
      if (parsed.directives.length === 0 || (total !== null && all.length >= total)) break;
    }
    if (all.length === 0) throw new Error("the directives listing had no entries BaselineWatch could read");
    const items = all.map(directiveItem);
    const counts = upsertItems(ctx.db, ctx.source.id, items, observedAt);
    // A directive is rare and matters; a first fetch is a back catalogue, not news.
    const alerts: AlertDraft[] =
      ctx.source.fetch_count > 0
        ? items
            .filter((i) => !before.has(i.externalId))
            .map((i) => ({ kind: "directive" as const, title: `CISA directive: ${i.title}`, body: i.summary ?? "", url: i.url }))
        : [];
    return { items: items.length, inserted: counts.inserted, updated: counts.updated, detail: `${all.length} directive(s) over ${page + 1} page(s)`, alerts };
  },
};
