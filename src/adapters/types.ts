import type { DatabaseSync } from "node:sqlite";
import type { HttpGet } from "../http.ts";
import type { NormalizedRequirement } from "../oscal.ts";

/** A row of the sources table, as the adapters see it. */
export interface SourceRow {
  id: string;
  name: string;
  kind: "article" | "vulnerability" | "requirement-set" | "setting-set" | "listing";
  group_name: "standards" | "vulnerabilities" | "news";
  url: string;
  format: string;
  schedule: "hourly" | "daily" | "weekly" | "manual";
  enabled: number;
  /** 1 when the licence forbids showing the entries to third parties: owner-only on the pages, never in the API. */
  restricted: number;
  licence: string | null;
  attribution: string | null;
  notes: string | null;
  last_fetch_at: string | null;
  last_status: string | null;
  last_error: string | null;
  etag: string | null;
  last_modified: string | null;
  last_duration_ms: number | null;
  fetch_count: number;
}

export type ItemKind = "article" | "vulnerability" | "kev" | "release";

/** One timeline entry as an adapter produces it; the ingester stores and deduplicates it. */
export interface ParsedItem {
  kind: ItemKind;
  /** Stable within the source: a feed guid, a CVE id, a Reddit post id. */
  externalId: string;
  title: string;
  url: string | null;
  summary: string | null;
  /** ISO 8601, or null when the source gives no date. */
  publishedAt: string | null;
  /** The article's lead image as the feed itself delivered it; the ingester caches the bytes. */
  imageUrl?: string | null;
  /** Where the feed carried it: a media element or an <img> in the body. */
  imageOrigin?: "enclosure" | "body";
  signals?: Record<string, unknown>;
}

export interface ParseResult {
  items: ParsedItem[];
  /** Names the document inside the source for the snapshot store. */
  documentKey: string;
  /** A version the source itself states, such as KEV's catalogVersion. */
  versionLabel?: string | null;
}

/** Settings a pulling adapter may need. */
export interface PullSettings {
  nvdApiKey: string | null;
  nvdBackfillDays: number;
  /** When false the ingester skips caching article images. */
  newsImages?: boolean;
  /** An Ollama address; when set, releases get a generated summary beside the publisher's words. */
  llmUrl?: string | null;
  llmModel?: string;
}

export interface PullContext {
  db: DatabaseSync;
  dataDir: string;
  source: SourceRow;
  http: HttpGet;
  now: () => Date;
  settings: PullSettings;
  log: (line: string) => void;
}

/** Something worth telling the owner about right away. */
export interface AlertDraft {
  kind: "kev" | "release" | "watch" | "directive";
  title: string;
  body: string;
  url?: string | null;
}

export interface PullOutcome {
  /** Records the adapter handled. */
  items: number;
  inserted: number;
  updated: number;
  /** A note for the Sources page, such as the cursor reached. */
  detail?: string;
  /** Alerts the pull raised; the ingester sends them when a notifier is configured. */
  alerts?: AlertDraft[];
}

/** One versioned document a standards source publishes: a catalog, a baseline profile, a STIG. */
export interface DocumentTarget {
  /** Stable within the source across releases: 'catalog', 'profile:moderate', 'stig:windows-server-2025'. */
  key: string;
  url: string;
  versionLabel?: string | null;
  publishedAt?: string | null;
  /** The publisher's own words on why this release exists, when known. */
  rationale?: { text: string; url: string | null } | null;
  /** The document's title as the listing names it, for documents that do not state their own. */
  title?: string | null;
}

/** A publisher's note about one requirement in a release, matched to it by label (STIG id) or ref. */
export interface RequirementNote {
  label?: string;
  ref?: string;
  text: string;
}

export interface ParsedDocument {
  title: string;
  versionLabel: string | null;
  publishedAt: string | null;
  requirements: NormalizedRequirement[];
  /** The publisher's own words on the release, found inside or beside the document. */
  rationale?: { text: string; url: string | null } | null;
  /** Per-requirement notes from the publisher's change log. */
  notes?: RequirementNote[];
}

export interface DocumentContext {
  db: DatabaseSync;
  source: SourceRow;
  http: HttpGet;
}

export interface ListingContext {
  db: DatabaseSync;
  http: HttpGet;
  now: () => Date;
}

/**
 * An adapter does one of three things: turns one fetched feed into timeline items (`parse`),
 * runs its own multi-request pull against a stream such as the NVD API (`pull`), or names the
 * versioned documents of a standard and parses each into requirements (`documents` +
 * `parseDocument`), which the ingester snapshots, stores and diffs against the previous version.
 */
export interface Adapter {
  id: string;
  /** Extra request headers, for sources that need them. */
  headers?: Record<string, string>;
  parse?(bytes: Uint8Array, source: SourceRow, now: Date): ParseResult;
  pull?(ctx: PullContext): Promise<PullOutcome>;
  /** Runs after a parsed document's items are stored, for joins into other tables. */
  after?(db: DatabaseSync, items: ParsedItem[], now: Date): void;
  /** The current documents of a standards source; a listing adapter fetches its index here first. */
  documents?(source: SourceRow, ctx: ListingContext): Promise<DocumentTarget[]> | DocumentTarget[];
  /** Earlier releases, oldest first, so the Register can start with real history. */
  history?(source: SourceRow): DocumentTarget[];
  parseDocument?(bytes: Uint8Array, target: DocumentTarget, ctx: DocumentContext): ParsedDocument | Promise<ParsedDocument>;
}

export const cvePattern = /\bCVE-\d{4}-\d{4,7}\b/g;

/** Every CVE id mentioned in a text, uppercased and unique, in order of first appearance. */
export function cveIdsIn(text: string): string[] {
  const seen = new Set<string>();
  for (const match of text.toUpperCase().matchAll(cvePattern)) seen.add(match[0]);
  return [...seen];
}

/** ISO 8601 or null; never throws. */
export function isoDate(value: unknown): string | null {
  if (typeof value === "number") return Number.isFinite(value) ? new Date(value * (value < 1e12 ? 1000 : 1)).toISOString() : null;
  if (typeof value !== "string" || value.trim() === "") return null;
  const date = new Date(value.trim());
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

const entities: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", hellip: "…", mdash: "—", ndash: "–",
  lsquo: "‘", rsquo: "’", ldquo: "“", rdquo: "”", copy: "©", reg: "®", trade: "™", bull: "•", middot: "·",
  laquo: "«", raquo: "»", times: "×", deg: "°", euro: "€", pound: "£",
};

/** Strips tags, decodes the common entities, collapses whitespace and trims to `max` characters. */
export function plainText(htmlOrText: string | null | undefined, max = 600): string | null {
  if (!htmlOrText) return null;
  const text = htmlOrText
    .replace(/<\s*(br|p|div|li|h\d)[^>]*>/gi, " ")
    .replace(/<[^>]+>/g, "")
    .replace(/&(#\d+|#x[0-9a-f]+|[a-z]+);/gi, (whole, name: string) => {
      const lower = name.toLowerCase();
      if (lower.startsWith("#x")) return String.fromCodePoint(Number.parseInt(lower.slice(2), 16));
      if (lower.startsWith("#")) return String.fromCodePoint(Number(lower.slice(1)));
      return entities[lower] ?? whole;
    })
    .replace(/\s+/g, " ")
    .trim();
  if (text === "") return null;
  return text.length > max ? `${text.slice(0, max - 1).trimEnd()}…` : text;
}

const trackingParams = /^(utm_[a-z]+|fbclid|gclid|mc_cid|mc_eid|ref|source|si)$/i;

/** A URL with tracking parameters, fragments and trailing slashes removed, for duplicate detection across sources. */
export function canonicalUrl(url: string | null): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    u.hash = "";
    u.hostname = u.hostname.toLowerCase().replace(/^www\./, "");
    for (const key of [...u.searchParams.keys()]) if (trackingParams.test(key)) u.searchParams.delete(key);
    u.searchParams.sort();
    let out = u.toString();
    if (u.search === "" && out.endsWith("/")) out = out.slice(0, -1);
    return out.replace(/^http:\/\//, "https://");
  } catch {
    return null;
  }
}
