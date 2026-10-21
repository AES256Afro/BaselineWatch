import { plainText, type Adapter, type ParsedItem, type ParseResult } from "./types.ts";

/**
 * Mozilla Foundation Security Advisories, from the index page (mozilla.org has no feed for
 * them): a dated heading per day, and under it one line per advisory with its impact rating
 * and title — "MFSA 2026-116 Security Vulnerabilities fixed in Firefox for Android 158.0.2".
 * Each advisory is one item keyed by its MFSA id; the CVEs are on the advisory page, not here.
 */

export const mozillaBase = "https://www.mozilla.org";

/** How many of the newest advisories a read keeps; the page lists every one since 2005. */
export const mfsaLimit = 80;

const months: Record<string, number> = { january: 0, february: 1, march: 2, april: 3, may: 4, june: 5, july: 6, august: 7, september: 8, october: 9, november: 10, december: 11 };

/** "October 21, 2026", read as noon UTC. */
function headingDate(value: string): string | null {
  const match = /^([A-Za-z]+)\s+(\d{1,2}),\s+(\d{4})$/.exec(value.trim());
  if (!match) return null;
  const month = months[match[1]!.toLowerCase()];
  return month === undefined ? null : new Date(Date.UTC(Number(match[3]), month, Number(match[2]), 12)).toISOString();
}

export function parseMfsaIndex(html: string, limit = mfsaLimit): ParsedItem[] {
  const items: ParsedItem[] = [];
  for (const block of html.matchAll(/<h2>([A-Z][a-z]+ \d{1,2}, \d{4})<\/h2>\s*<ul>([\s\S]*?)<\/ul>/g)) {
    const date = headingDate(block[1]!);
    for (const a of block[2]!.matchAll(/<a href="(\/en-US\/security\/advisories\/(mfsa\d{4}-\d+)\/)">\s*<span class="level ([a-z]+)">([^<]*)<\/span>\s*([^<]*)<\/a>/g)) {
      const label = a[4]!.trim();
      const title = plainText(a[5], 300);
      const product = /fixed in (.+)$/i.exec(title ?? "")?.[1]?.trim() ?? null;
      items.push({
        kind: "article",
        externalId: a[2]!,
        title: title ? `${label}: ${title}` : label,
        url: `${mozillaBase}${a[1]}`,
        summary: `Impact ${a[3]}${product ? `. ${product}` : ""}.`,
        publishedAt: date,
        signals: { impact: a[3], ...(product ? { product } : {}) },
      });
      if (items.length >= limit) return items;
    }
  }
  return items;
}

export const mozillaMfsaAdapter: Adapter = {
  id: "mozilla-mfsa",
  headers: { accept: "text/html" },
  parse(bytes): ParseResult {
    const items = parseMfsaIndex(new TextDecoder("utf-8").decode(bytes));
    if (items.length === 0) throw new Error("the Mozilla advisories page had no advisories BaselineWatch could read");
    return { items, documentKey: "advisories" };
  },
};
