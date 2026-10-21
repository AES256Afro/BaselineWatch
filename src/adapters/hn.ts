import { cveIdsIn, isoDate, plainText, type Adapter, type ParsedItem } from "./types.ts";

/**
 * Hacker News through Algolia's search API: the stories matching the security terms, as items.
 */
interface Hit {
  objectID: string;
  title: string | null;
  url: string | null;
  created_at: string;
  points: number | null;
  num_comments: number | null;
  story_text?: string | null;
}

/** Hacker News through the Algolia search API; the query lives in the source URL. */
export const hnAdapter: Adapter = {
  id: "hn",
  headers: { accept: "application/json" },
  parse(bytes) {
    const body = JSON.parse(new TextDecoder("utf-8").decode(bytes)) as { hits?: Hit[] };
    if (!Array.isArray(body.hits)) throw new Error("Algolia response has no hits array");
    const items: ParsedItem[] = body.hits
      .filter((h) => h.title)
      .map((h) => {
        const thread = `https://news.ycombinator.com/item?id=${h.objectID}`;
        const title = plainText(h.title, 300) ?? "(untitled)";
        const cves = cveIdsIn(`${title} ${h.story_text ?? ""}`);
        return {
          kind: "article",
          externalId: h.objectID,
          title,
          url: h.url ?? thread,
          summary: plainText(h.story_text, 400) ?? `${h.points ?? 0} points · ${h.num_comments ?? 0} comments`,
          publishedAt: isoDate(h.created_at),
          signals: { thread, score: h.points ?? 0, comments: h.num_comments ?? 0, ...(cves.length ? { cves } : {}) },
        };
      });
    return { items, documentKey: "search_by_date.json" };
  },
};
