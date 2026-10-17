import { XMLParser } from "fast-xml-parser";
import type { NormalizedRequirement } from "../oscal.ts";
import { entryText, findEntry, unzipAll } from "../zip.ts";
import { listingRequest, type DisaListingItem } from "./disa.ts";
import { plainText, type Adapter, type DocumentTarget, type ParsedDocument, type SourceRow } from "./types.ts";

/**
 * DISA's Control Correlation Identifiers. Every STIG rule cites CCIs; the CCI list says what each
 * one means and where it sits in NIST SP 800-53 (Revision 4 and Revision 5 indexes such as
 * "AC-11 (1)" or "IA-5 (2) (a) (1)"). That index is the join between a STIG rule and the
 * Register's control pages. The list is one zip with `CCI_List.xml` inside, named in the STIG
 * library listing with its upload date, so an unchanged list costs one small request a week.
 */

/** Where the zip lives when the listing does not name it. */
export const cciListUrl = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/CCI_List.zip";

type Node = Record<string, unknown>;

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  textNodeName: "#text",
  trimValues: true,
  processEntities: true,
  isArray: (name) => name === "cci_item" || name === "reference",
});

function text(value: unknown): string | null {
  if (typeof value === "string") return value.trim() || null;
  if (typeof value === "number") return String(value);
  if (value && typeof value === "object") {
    const t = (value as Node)["#text"];
    if (typeof t === "string" || typeof t === "number") return String(t).trim() || null;
  }
  return null;
}

/**
 * The control a CCI index points at, as the Register writes refs: "AC-1 a 1 (a)" is ac-1,
 * "IA-5 (2) (a) (1)" is ia-5.2, "RA-5 (9).1" is ra-5.9, "IA-13 (03) (d)" is ia-13.3. Statement
 * letters and assessment sub-indexes are dropped; the control or enhancement is what has a page.
 */
export function controlRef(index: string): string | null {
  const m = /^([A-Za-z]{2})-(\d+)(?:\s*\((\d+)\))?/.exec(index.trim());
  if (!m) return null;
  const base = `${m[1]!.toLowerCase()}-${Number(m[2])}`;
  return m[3] ? `${base}.${Number(m[3])}` : base;
}

export interface ParsedCciList extends ParsedDocument {
  /** The list's own version, a date such as 2026-07-14. */
  version: string | null;
}

export function parseCciList(xml: string): ParsedCciList {
  const doc = parser.parse(xml) as Node;
  const list = doc.cci_list as Node | undefined;
  if (!list) throw new Error("not a CCI list");
  const meta = (list.metadata ?? {}) as Node;
  const version = text(meta.version);
  const publishDate = text(meta.publishdate);
  const items = ((list.cci_items as Node | undefined)?.cci_item as Node[] | undefined) ?? [];
  const requirements: NormalizedRequirement[] = [];
  for (const item of items) {
    const id = String(item["@_id"] ?? "").toUpperCase();
    if (!/^CCI-\d{6}$/.test(id)) continue;
    const definition = plainText(text(item.definition), 4000) ?? "";
    const type = text(item.type);
    const status = text(item.status);
    const references = ((item.references as Node | undefined)?.reference as Node[] | undefined) ?? [];
    const indexes = (version: string): string[] =>
      references
        .filter((r) => String(r["@_version"] ?? "") === version && /800-53/.test(String(r["@_title"] ?? "")) && !/800-53A/.test(String(r["@_title"] ?? "")))
        .map((r) => String(r["@_index"] ?? "").trim())
        .filter((i) => i !== "");
    const rev5 = indexes("5");
    const rev4 = indexes("4");
    const related = [...new Set((rev5.length ? rev5 : rev4).map(controlRef).filter((r): r is string => r !== null))].sort();
    requirements.push({
      ref: id.toLowerCase(),
      parentRef: null,
      family: type ? `${type.charAt(0).toUpperCase()}${type.slice(1)}` : null,
      label: id,
      title: definition.length > 140 ? `${definition.slice(0, 139).trimEnd()}…` : definition,
      statement: definition || null,
      guidance: null,
      params: [],
      related,
      sortKey: id,
      status: status === "deprecated" ? "withdrawn" : "active",
      extra: {
        ...(type ? { type } : {}),
        ...(status ? { status } : {}),
        ...(text(item.publishdate) ? { publishDate: text(item.publishdate) } : {}),
        ...(text(item.contributor) ? { contributor: text(item.contributor) } : {}),
        ...(rev5.length ? { rev5 } : {}),
        ...(rev4.length ? { rev4 } : {}),
        ...(rev5.length ? {} : related.length ? { mappedThrough: "rev4" } : {}),
      },
    });
  }
  return {
    title: "DISA Control Correlation Identifiers",
    versionLabel: version,
    publishedAt: publishDate ? `${publishDate}T00:00:00.000Z` : null,
    requirements,
    rationale: null,
    version,
  };
}

const clean = (name: string | undefined): string => (name ?? "").split(String.fromCharCode(0x200b)).join("").trim();

/** The listing entry for the CCI list zip, when the library names one. */
export function cciListingTarget(items: DisaListingItem[]): DocumentTarget | null {
  const item = items.find((i) => /Control Correlation Identifier/i.test(i.RawDownloadType ?? i.DownloadType ?? "") && /\.zip$/i.test(i.DownloadLink ?? "") && /^CCI List$/i.test(clean(i.FileName)));
  if (!item) return null;
  return { key: "cci", url: item.DownloadLink, versionLabel: null, publishedAt: item.UploadDate ? `${item.UploadDate}T00:00:00.000Z` : null };
}

export const cciAdapter: Adapter = {
  id: "disa-cci",
  headers: { accept: "application/zip, application/octet-stream, */*" },
  async documents(source: SourceRow, ctx) {
    // The STIG library's own listing names the zip with an upload date; a date that has not moved means no download.
    const listingUrl = (ctx.db.prepare("SELECT url FROM sources WHERE id = 'disa-stigs'").get() as { url: string } | undefined)?.url;
    if (listingUrl) {
      try {
        const response = await ctx.http(listingUrl, {
          body: listingRequest,
          headers: { "content-type": "application/json", accept: "application/json", referer: "https://www.cyber.mil/stigs/downloads/", origin: "https://www.cyber.mil" },
          timeoutMs: 90_000,
        });
        const listing = JSON.parse(new TextDecoder("utf-8").decode(response.bytes)) as { returnValue?: DisaListingItem[] };
        const target = cciListingTarget(listing.returnValue ?? []);
        if (target) return [target];
      } catch {
        // The listing is a convenience; the fixed address below still works.
      }
    }
    return [{ key: "cci", url: source.url }];
  },
  parseDocument(bytes, target): ParsedDocument {
    const entries = unzipAll(bytes);
    const xml = findEntry(entries, /CCI_List\.xml$/i) ?? findEntry(entries, /\.xml$/i);
    if (!xml) throw new Error("CCI zip has no XML list");
    const parsed = parseCciList(entryText(xml));
    if (parsed.requirements.length === 0) throw new Error("CCI list holds no items");
    return { ...parsed, publishedAt: target.publishedAt ?? parsed.publishedAt };
  },
};
