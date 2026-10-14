import { XMLParser } from "fast-xml-parser";
import { cveIdsIn, isoDate, plainText, type Adapter, type ParsedItem } from "./types.ts";

/**
 * A subreddit's new posts. Reddit refuses the JSON listing to anything but a browser or an
 * OAuth app, but serves the Atom feed (/r/<sub>/new.rss) to an identified client, so that is
 * what the sources table points at. The JSON shape is still understood for fixtures and for a
 * future OAuth adapter. Comment bodies are never stored, only the post and a link to the thread.
 */

interface RedditPost {
  id: string;
  title: string;
  url: string;
  permalink: string;
  selftext?: string;
  created_utc: number;
  is_self: boolean;
  domain?: string;
  score?: number;
  num_comments?: number;
  subreddit?: string;
  stickied?: boolean;
}

interface RedditListing {
  data: { children: { kind: string; data: RedditPost }[] };
}

type Node = Record<string, unknown>;

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  textNodeName: "#text",
  trimValues: true,
  processEntities: true,
  isArray: (name) => name === "entry" || name === "link" || name === "category",
});

function text(value: unknown): string | null {
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const t = (value as Node)["#text"];
    if (typeof t === "string" || typeof t === "number") return String(t);
  }
  return null;
}

function fromJson(listing: RedditListing): ParsedItem[] {
  const children = listing?.data?.children;
  if (!Array.isArray(children)) throw new Error("Reddit listing has no data.children");
  return children
    .filter((c) => c.kind === "t3" && c.data && !c.data.stickied)
    .map(({ data: post }) => {
      const thread = `https://www.reddit.com${post.permalink}`;
      const title = plainText(post.title, 300) ?? "(untitled)";
      const cves = cveIdsIn(`${title} ${post.selftext ?? ""}`);
      return {
        kind: "article",
        externalId: `t3_${post.id}`,
        title,
        url: post.is_self ? thread : post.url,
        summary: post.is_self ? plainText(post.selftext, 400) : plainText(`r/${post.subreddit ?? ""} · ${post.domain ?? ""}`, 120),
        publishedAt: isoDate(post.created_utc),
        signals: { thread, score: post.score ?? 0, comments: post.num_comments ?? 0, ...(cves.length ? { cves } : {}) },
      };
    });
}

/** The outbound link in a Reddit Atom entry's HTML: the anchor whose text is "[link]". */
export function outboundLink(contentHtml: string): string | null {
  const match = /href="([^"]+)"[^>]*>\s*\[link\]/i.exec(contentHtml);
  if (!match?.[1]) return null;
  return match[1].replace(/&amp;/g, "&");
}

function fromAtom(xml: string): ParsedItem[] {
  const doc = parser.parse(xml) as Node;
  const feed = doc.feed as Node | undefined;
  if (!feed) throw new Error("not a Reddit Atom feed");
  const entries = (feed.entry as Node[] | undefined) ?? [];
  return entries.flatMap((entry) => {
    const id = text(entry.id);
    const title = plainText(text(entry.title), 300);
    if (!id || !title) return [];
    const links = (entry.link as Node[] | undefined) ?? [];
    const thread = (links.find((l) => typeof l["@_href"] === "string")?.["@_href"] as string | undefined) ?? null;
    const content = text(entry.content) ?? "";
    const outbound = outboundLink(content);
    const categories = (entry.category as Node[] | undefined) ?? [];
    const subreddit = (categories.find((c) => typeof c["@_term"] === "string")?.["@_term"] as string | undefined) ?? "";
    const isSelf = !outbound || (thread !== null && outbound === thread);
    // A self post's content is its text followed by Reddit's "submitted by ... [link] [comments]" trailer.
    const body = plainText(content.split(/submitted by/i)[0] ?? "", 400);
    const cves = cveIdsIn(`${title} ${body ?? ""}`);
    let domain = "";
    try {
      domain = outbound ? new URL(outbound).hostname.replace(/^www\./, "") : "";
    } catch {
      domain = "";
    }
    return [
      {
        kind: "article",
        externalId: id,
        title,
        url: isSelf ? thread : outbound,
        summary: isSelf ? body : plainText(`r/${subreddit} · ${domain}`, 120),
        publishedAt: isoDate(text(entry.published) ?? text(entry.updated)),
        signals: { ...(thread ? { thread } : {}), ...(cves.length ? { cves } : {}) },
      } satisfies ParsedItem,
    ];
  });
}

export const redditAdapter: Adapter = {
  id: "reddit",
  headers: { accept: "application/atom+xml, application/json;q=0.9, */*;q=0.5" },
  parse(bytes) {
    const body = new TextDecoder("utf-8").decode(bytes);
    const first = body.trimStart()[0];
    const items = first === "{" ? fromJson(JSON.parse(body) as RedditListing) : fromAtom(body);
    return { items, documentKey: "new" };
  },
};
