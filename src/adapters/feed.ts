import { XMLParser } from "fast-xml-parser";
import { cveIdsIn, isoDate, plainText, type Adapter, type ParsedItem, type SourceRow } from "./types.ts";

type Node = Record<string, unknown>;

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  textNodeName: "#text",
  cdataPropName: false,
  trimValues: true,
  processEntities: true,
  isArray: (name) => name === "item" || name === "entry" || name === "link" || name === "category",
});

function text(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  if (Array.isArray(value)) return text(value[0]);
  if (typeof value === "object") {
    const node = value as Node;
    if (typeof node["#text"] === "string" || typeof node["#text"] === "number") return String(node["#text"]);
  }
  return null;
}

function atomLink(links: unknown): string | null {
  if (!Array.isArray(links)) return text(links);
  const typed = links as Node[];
  const alternate = typed.find((l) => typeof l["@_href"] === "string" && (!l["@_rel"] || l["@_rel"] === "alternate"));
  const any = typed.find((l) => typeof l["@_href"] === "string");
  return ((alternate ?? any)?.["@_href"] as string | undefined) ?? null;
}

function rssLink(value: unknown): string | null {
  // RSS <link> is text, but a feed that also uses Atom links gives an array of objects.
  if (Array.isArray(value)) {
    for (const entry of value) {
      const t = text(entry);
      if (t && /^https?:\/\//.test(t)) return t;
    }
    return atomLink(value);
  }
  return text(value);
}

function rssItems(channel: Node): ParsedItem[] {
  const items = (channel.item as Node[] | undefined) ?? [];
  return items.flatMap((item) => {
    const title = plainText(text(item.title), 300);
    const link = rssLink(item.link);
    const guid = text(item.guid) ?? link ?? title;
    if (!title || !guid) return [];
    const body = text(item["content:encoded"]) ?? text(item.description);
    const summary = plainText(body);
    const haystack = `${title} ${summary ?? ""}`;
    const cves = cveIdsIn(haystack);
    return [
      {
        kind: "article",
        externalId: guid,
        title,
        url: link,
        summary,
        publishedAt: isoDate(text(item.pubDate) ?? text(item["dc:date"]) ?? text(item.date)),
        ...(cves.length ? { signals: { cves } } : {}),
      } satisfies ParsedItem,
    ];
  });
}

function atomEntries(feed: Node): ParsedItem[] {
  const entries = (feed.entry as Node[] | undefined) ?? [];
  return entries.flatMap((entry) => {
    const title = plainText(text(entry.title), 300);
    const link = atomLink(entry.link);
    const id = text(entry.id) ?? link ?? title;
    if (!title || !id) return [];
    const summary = plainText(text(entry.summary) ?? text(entry.content));
    const cves = cveIdsIn(`${title} ${summary ?? ""}`);
    return [
      {
        kind: "article",
        externalId: id,
        title,
        url: link,
        summary,
        publishedAt: isoDate(text(entry.published) ?? text(entry.updated)),
        ...(cves.length ? { signals: { cves } } : {}),
      } satisfies ParsedItem,
    ];
  });
}

/** RSS 2.0, RSS 1.0 (RDF) and Atom feeds. One adapter, since publishers mix the two freely. */
export const feedAdapter: Adapter = {
  id: "feed",
  parse(bytes, _source: SourceRow) {
    const xml = new TextDecoder("utf-8").decode(bytes);
    const doc = parser.parse(xml) as Node;
    let items: ParsedItem[] = [];
    if (doc.rss && typeof doc.rss === "object") {
      items = rssItems(((doc.rss as Node).channel as Node) ?? {});
    } else if (doc.feed && typeof doc.feed === "object") {
      items = atomEntries(doc.feed as Node);
    } else if (doc["rdf:RDF"] && typeof doc["rdf:RDF"] === "object") {
      items = rssItems(doc["rdf:RDF"] as Node);
    } else {
      throw new Error("not an RSS or Atom document");
    }
    return { items, documentKey: "feed" };
  },
};
