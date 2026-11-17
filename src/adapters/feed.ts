import { XMLParser } from "fast-xml-parser";
import { clipText, cveIdsIn, isoDate, maxPlainTextInput, plainText, type Adapter, type ParsedItem, type SourceRow } from "./types.ts";

/**
 * A draft's status written straight after its title with no space, as CSRC's drafts feed does
 * ("…PortfolioInitial Public Draft"), put after a dash where a reader can find it.
 */
export function draftTitle<T extends string | null>(title: T): T {
  if (title === null) return title;
  return title.replace(/(\S)((?:Initial |Second |Third |Fourth |Final )?(?:Public|Working|Preliminary) Draft(?: \d+)?)$/, "$1 — $2") as T;
}

/** How many CVEs past those in the title and summary an item takes from its body. */
const bodyCveLimit = 50;

/**
 * An item's CVEs: every one its title and summary name, then the first fifty more from the body.
 * The body is read whole because Cisco and GitLab name the CVE at the end, but a vendor roll-up
 * (one CISA ICS item lists 428) would otherwise tie one article to hundreds of CVEs.
 */
function itemCves(title: string, summary: string | null, whole: string | null): string[] {
  const lead = cveIdsIn(`${title} ${summary ?? ""}`);
  const named = new Set(lead);
  const more = cveIdsIn(whole ?? "").filter((id) => !named.has(id)).slice(0, bodyCveLimit);
  return [...lead, ...more];
}

/**
 * The RSS and Atom adapter every feed source shares: entries to timeline items, with the feed's own
 * media or the first image in the body kept as the item's picture.
 */
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

const httpUrl = (value: unknown): string | null => (typeof value === "string" && /^https?:\/\//i.test(value) ? value : null);

/** The first <img src> in an HTML fragment, the way feeds embed a lead image in content:encoded. */
function imageInHtml(fragment: string | null): string | null {
  if (!fragment) return null;
  const match = /<img\b[^<>]*?\bsrc\s*=\s*("([^"]+)"|'([^']+)')/i.exec(fragment);
  return httpUrl(match?.[2] ?? match?.[3] ?? null);
}

/** Feed-supplied media, in order of intent: enclosure, media:content, media:thumbnail. */
function feedImage(item: Node): string | null {
  const nodes = (value: unknown): Node[] => (Array.isArray(value) ? (value as Node[]) : value && typeof value === "object" ? [value as Node] : []);
  for (const enclosure of nodes(item.enclosure)) {
    const type = enclosure["@_type"];
    if (typeof type === "string" && !type.startsWith("image/")) continue;
    const url = httpUrl(enclosure["@_url"]);
    if (url) return url;
  }
  for (const media of nodes(item["media:content"])) {
    const type = media["@_type"];
    const medium = media["@_medium"];
    if (typeof type === "string" && !type.startsWith("image/")) continue;
    if (typeof medium === "string" && medium !== "image") continue;
    const url = httpUrl(media["@_url"]);
    if (url) return url;
  }
  for (const thumb of nodes(item["media:thumbnail"])) {
    const url = httpUrl(thumb["@_url"]);
    if (url) return url;
  }
  return null;
}

function rssItems(channel: Node): ParsedItem[] {
  const items = (channel.item as Node[] | undefined) ?? [];
  return items.flatMap((item) => {
    const title = draftTitle(plainText(text(item.title), 300));
    const link = rssLink(item.link);
    const guid = text(item.guid) ?? link ?? title;
    if (!title || !guid) return [];
    const body = text(item["content:encoded"]) ?? text(item.description);
    // The whole body, as much as plainText reads, not the 600-character summary: Cisco and GitLab name the CVE at the end (itemCves).
    const whole = plainText(body, maxPlainTextInput);
    const summary = clipText(whole, 600);
    const cves = itemCves(title, summary, whole);
    const media = feedImage(item);
    const image = media ?? imageInHtml(body);
    return [
      {
        kind: "article",
        externalId: guid,
        title,
        url: link,
        summary,
        publishedAt: isoDate(text(item.pubDate) ?? text(item["dc:date"]) ?? text(item.date)),
        ...(image ? { imageUrl: image, imageOrigin: media ? ("enclosure" as const) : ("body" as const) } : {}),
        ...(cves.length ? { signals: { cves } } : {}),
      } satisfies ParsedItem,
    ];
  });
}

function atomEntries(feed: Node): ParsedItem[] {
  const entries = (feed.entry as Node[] | undefined) ?? [];
  return entries.flatMap((entry) => {
    const title = draftTitle(plainText(text(entry.title), 300));
    const link = atomLink(entry.link);
    const id = text(entry.id) ?? link ?? title;
    if (!title || !id) return [];
    const body = text(entry.content) ?? text(entry.summary);
    const whole = plainText(body, maxPlainTextInput);
    // The summary prefers the entry's own summary; when that is the body as well, the body's text is cut rather than read twice.
    const summarySource = text(entry.summary) ?? text(entry.content);
    const summary = summarySource === body ? clipText(whole, 600) : plainText(summarySource);
    const cves = itemCves(title, summary, whole);
    const media = feedImage(entry);
    const image = media ?? imageInHtml(body);
    return [
      {
        kind: "article",
        externalId: id,
        title,
        url: link,
        summary,
        publishedAt: isoDate(text(entry.published) ?? text(entry.updated)),
        ...(image ? { imageUrl: image, imageOrigin: media ? ("enclosure" as const) : ("body" as const) } : {}),
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
