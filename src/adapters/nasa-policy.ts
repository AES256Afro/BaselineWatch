import type { NormalizedRequirement } from "../oscal.ts";
import { unzipAll, findEntry, entryText } from "../zip.ts";
import type { Adapter, DocumentTarget, ListingContext, ParsedDocument, SourceRow } from "./types.ts";
import { isoDate, plainText } from "./types.ts";

/**
 * NASA's Cybersecurity Policy Reference: the one public document in which NASA OCIO's
 * Cybersecurity Standards and Engineering Team (CSET) world is enumerated. The ASCS technical
 * standards themselves sit behind cset.nasa.gov (NASA access only), but this reference, a Word
 * document on nasa.gov refreshed quarterly, lists every key cybersecurity document by section:
 * the NPD/NPR directives, the NAIIs, the IT handbooks, the NASA standards (NASA-SPEC-2600, the
 * enumeration of ASCS requirements, and the NASA-STD-26xx set), the CIO memoranda, the other
 * federal documents, and the FIPS and NIST publications NASA points its contracts at, each with
 * its dates and often a status note ("Comment period closed", "Revision by NIST in progress").
 *
 * Each listed document is one requirement row here, so a quarterly update diffs as a change
 * register: a directive renewed, a standard revised, a NIST publication swapped for its draft.
 */

/** The page that names the current reference; the adapter follows its .docx link. */
const listingPattern = /href="(https?:\/\/[^"]*cybersecurity-policy-reference[^"]*\.docx[^"]*)"/i;

export const referenceKey = "reference";

interface ReferenceEntry {
  /** The document id as printed: "NPR 2810.1F", "NASA-SPEC-2600 Version 6.0", "SP 800-53 Rev. 5". */
  id: string;
  title: string;
  /** The status note the title carried after an asterisk, when one did. */
  note: string | null;
  date: string | null;
  expiry: string | null;
  /** Memoranda name a sender instead of an id. */
  from: string | null;
}

export interface ReferenceSection {
  heading: string;
  entries: ReferenceEntry[];
}

export interface ParsedReference {
  /** The "Current as of last publication" date, ISO. */
  asOf: string | null;
  sections: ReferenceSection[];
}

/** Word field codes (HYPERLINK …) and deleted text are markup, not content. */
function docxBodyXml(bytes: Uint8Array): string {
  const entries = unzipAll(bytes);
  const doc = findEntry(entries, /^word\/document\.xml$/);
  if (!doc) throw new Error("not a Word document: word/document.xml is missing");
  return entryText(doc)
    .replace(/<w:instrText[^>]*>[\s\S]*?<\/w:instrText>/g, "")
    .replace(/<w:delText[^>]*>[\s\S]*?<\/w:delText>/g, "");
}

/** The readable text of one XML fragment: tags stripped, entities decoded, whitespace collapsed. */
function textOf(xml: string): string {
  return plainText(xml.replace(/<w:tab[^>]*\/>/g, " "), 4000) ?? "";
}

function cellTexts(rowXml: string): string[] {
  return [...rowXml.matchAll(/<w:tc[ >][\s\S]*?<\/w:tc>/g)].map((m) => textOf(m[0]!));
}

const headerCells = new Set(["document id", "memo subject", "subject/title"]);

/**
 * The document is headed paragraphs and eight tables, each table preceded by its section name.
 * Rows whose first cell is the column header ("Document ID", "Memo Subject") are furniture.
 */
export function parseReference(bytes: Uint8Array): ParsedReference {
  const xml = docxBodyXml(bytes);
  const sections: ReferenceSection[] = [];
  let asOf: string | null = null;
  let lastParagraph = "";
  const pieces = xml.split(/(<w:tbl[ >][\s\S]*?<\/w:tbl>)/);
  for (const piece of pieces) {
    if (!piece.startsWith("<w:tbl")) {
      for (const p of piece.matchAll(/<w:p[ >][\s\S]*?<\/w:p>/g)) {
        const text = textOf(p[0]!);
        if (text === "") continue;
        const dated = /Current as of last publication\s*(\d{1,2}\/\d{1,2}\/\d{4})/i.exec(text);
        if (dated) {
          const [month, day, year] = dated[1]!.split("/");
          asOf = isoDate(`${year}-${month!.padStart(2, "0")}-${day!.padStart(2, "0")}T00:00:00Z`);
        }
        lastParagraph = text;
      }
      continue;
    }
    const heading = lastParagraph.replace(/\s*\(NASA account required\).*$/i, "").trim();
    const memos = /^memoranda$/i.test(heading);
    const entries: ReferenceEntry[] = [];
    for (const row of piece.matchAll(/<w:tr[ >][\s\S]*?<\/w:tr>/g)) {
      const cells = cellTexts(row[0]!);
      const first = cells[0]?.trim() ?? "";
      if (first === "" || headerCells.has(first.toLowerCase())) continue;
      // Directives and handbooks: id | title | effective | expiry. Standards, FIPS, NIST and
      // the rest: id | title | date. Memoranda: subject | from | date.
      const [titleRaw, ...noteParts] = (memos ? first : (cells[1] ?? "")).split("*");
      const note = noteParts.join("; ").trim() || null;
      const expiry = memos ? null : cells[3]?.trim() || null;
      entries.push({
        id: first,
        title: (titleRaw ?? "").trim(),
        note,
        date: cells[2]?.trim() || null,
        expiry: expiry && /^not listed$/i.test(expiry) ? null : expiry,
        from: memos ? cells[1]?.trim() || null : null,
      });
    }
    if (entries.length > 0) sections.push({ heading, entries });
  }
  return { asOf, sections };
}

/** Short keys that keep refs unique when the same publication is listed under two sections. */
const sectionKeys: [RegExp, string][] = [
  [/policy directives/i, "directive"],
  [/advisory implementing/i, "naii"],
  [/handbooks/i, "handbook"],
  [/^standards$/i, "standard"],
  [/^memoranda$/i, "memo"],
  [/^other documents$/i, "other"],
  [/^fips documents$/i, "fips"],
  [/^nist documents$/i, "nist"],
];

export function sectionKey(heading: string): string {
  for (const [pattern, key] of sectionKeys) if (pattern.test(heading)) return key;
  return heading.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "section";
}

/**
 * The part of a printed document id that stays across revisions, so a renewal diffs as a
 * revision of the same row: "NPR 2810.1F" and a later "NPR 2810.1G" are both npr-2810.1,
 * "NASA-SPEC-2600 Version 6.0" is nasa-spec-2600, "SP 800-53 Rev. 5" is sp-800-53. A FIPS
 * number's dash digit is the publication itself (140-2 and 140-3 are both listed), so it stays.
 */
export function stableId(printed: string): string {
  let text = printed
    .replace(/\s*\([^)]*\)\s*/g, " ")
    .replace(/\s+Rev(?:ision)?\.?\s*\d+[A-Za-z]?\b/gi, "")
    .replace(/\s+Version\s+[\d.]+\b/gi, "")
    .trim();
  // In a NASA id a trailing letter after digits is the revision: 2810.1F → 2810.1, 8739.8B →
  // 8739.8. In a NIST number it is the publication itself (SP 800-53A), so it stays.
  if (/^(NPD|NPR|NAII|ITS?-HBK|NASA)/i.test(text)) text = text.replace(/(\d)[A-Z]$/, "$1");
  return text
    .toLowerCase()
    .replace(/\.(?!\d)/g, "")
    .replace(/[^a-z0-9.]+/g, "-")
    .replace(/^-|-$/g, "");
}

function sentence(entry: ReferenceEntry): string {
  const parts: string[] = [`Listed as ${entry.id}.`];
  if (entry.from) parts.push(`From ${entry.from}.`);
  if (entry.date) parts.push(`Dated ${entry.date}.`);
  if (entry.expiry) parts.push(/^extended$/i.test(entry.expiry) ? "Expiry extended." : `Expires ${entry.expiry}.`);
  return parts.join(" ");
}

export function referenceRequirements(reference: ParsedReference): NormalizedRequirement[] {
  const rows: NormalizedRequirement[] = [];
  const seen = new Set<string>();
  for (const [index, section] of reference.sections.entries()) {
    const key = sectionKey(section.heading);
    for (const entry of section.entries) {
      const ref = `${key}:${stableId(entry.id)}`;
      // The published tables repeat the odd row (SP 800-56B appears twice); one row is enough.
      if (seen.has(ref)) continue;
      seen.add(ref);
      rows.push({
        ref,
        parentRef: null,
        family: section.heading,
        label: entry.id,
        title: entry.title || entry.id,
        statement: sentence(entry),
        guidance: entry.note,
        params: [],
        related: [],
        // The document's own section order, so the pages read the way NASA wrote it.
        sortKey: `${String(index).padStart(2, "0")}.${ref}`,
        status: "active",
        extra: {},
      });
    }
  }
  return rows;
}

export const nasaPolicyAdapter: Adapter = {
  id: "nasa-cyber-ref",
  async documents(source: SourceRow, ctx: ListingContext): Promise<DocumentTarget[]> {
    const response = await ctx.http(source.url, { headers: { accept: "text/html" }, timeoutMs: 60_000 });
    const href = listingPattern.exec(new TextDecoder("utf-8").decode(response.bytes))?.[1];
    if (!href) throw new Error("the NASA cybersecurity policies page no longer links a Cybersecurity Policy Reference .docx");
    return [{ key: referenceKey, url: href, title: "NASA Cybersecurity Policy Reference" }];
  },
  parseDocument(bytes): ParsedDocument {
    const reference = parseReference(bytes);
    const requirements = referenceRequirements(reference);
    if (requirements.length === 0) throw new Error("no document tables found in the reference .docx");
    const asOfDay = reference.asOf?.slice(0, 10);
    return {
      title: "NASA Cybersecurity Policy Reference",
      versionLabel: asOfDay ? `as of ${asOfDay}` : null,
      publishedAt: reference.asOf,
      requirements,
      rationale: null,
    };
  },
};
