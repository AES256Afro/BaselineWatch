import { cveIdsIn, plainText, type Adapter, type ParsedItem, type ParseResult } from "./types.ts";

/**
 * Apple's security releases page (support.apple.com/100100): one table of every update with
 * security content — name, the devices it is for, the date — newest first. Apple publishes no
 * feed for it. A row with a link is one item keyed by the support article's number; a row
 * without one is an update Apple lists with "no published CVE entries", kept so the owner sees
 * the release went out, keyed by its name and date.
 */

export const appleReleasesUrl = "https://support.apple.com/en-us/100100";

/** How many of the newest rows a read keeps: the table goes back years, and the first read need not. */
export const appleReleaseLimit = 80;

const months: Record<string, number> = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

/** "28 Sep 2026", the one form the table uses, read as noon UTC. */
function rowDate(value: string | null): string | null {
  const match = /(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})/.exec(value ?? "");
  if (!match) return null;
  const month = months[match[2]!.toLowerCase()];
  return month === undefined ? null : new Date(Date.UTC(Number(match[3]), month, Number(match[1]), 12)).toISOString();
}

/** The Apple line a release belongs to, from its first word: iOS, macOS, watchOS, Safari, Xcode… */
export function appleLine(name: string): string | null {
  return /^([A-Za-z]+)/.exec(name)?.[1] ?? null;
}

export function parseAppleReleases(html: string, limit = appleReleaseLimit): ParsedItem[] {
  const items: ParsedItem[] = [];
  for (const row of html.matchAll(/<tr[^<>]*>([\s\S]*?)<\/tr>/g)) {
    const cells = [...row[1]!.matchAll(/<td[^<>]*>([\s\S]*?)<\/td>/g)].map((c) => c[1]!);
    if (cells.length < 3) continue;
    const link = /<a\s[^<>]*href="(https:\/\/support\.apple\.com\/[^"]+)"[^<>]*>([\s\S]*?)<\/a>/.exec(cells[0]!);
    const name = plainText(link ? link[2] : (/<p[^<>]*>([\s\S]*?)<\/p>/.exec(cells[0]!)?.[1] ?? cells[0]), 200);
    if (!name) continue;
    const note = link ? null : plainText(/<div class="note[^"]*">([\s\S]*?)<\/div>/.exec(cells[0]!)?.[1], 300);
    const devices = plainText(cells[1], 400);
    const date = rowDate(plainText(cells[2], 40));
    const id = link ? (/\/(\d+)\/?$/.exec(link[1]!)?.[1] ?? link[1]!) : `${name}@${date?.slice(0, 10) ?? "undated"}`;
    const cves = cveIdsIn(name);
    items.push({
      kind: "article",
      externalId: id,
      title: name,
      url: link ? link[1]! : appleReleasesUrl,
      summary: note ?? (devices ? `For ${devices}.` : null),
      publishedAt: date,
      signals: { line: appleLine(name), devices, ...(cves.length ? { cves } : {}) },
    });
    if (items.length >= limit) break;
  }
  return items;
}

export const appleSecurityAdapter: Adapter = {
  id: "apple-security",
  headers: { accept: "text/html" },
  parse(bytes): ParseResult {
    const items = parseAppleReleases(new TextDecoder("utf-8").decode(bytes));
    if (items.length === 0) throw new Error("the Apple security releases page had no rows BaselineWatch could read");
    return { items, documentKey: "100100" };
  },
};
