import type { DatabaseSync } from "node:sqlite";
import type { DocumentRow } from "./register.ts";

/**
 * A source's documents read the way a person looks for them: the publication first, then its
 * current version, the draft that will replace it, and the versions before. A source such as NIST
 * PIV holds nineteen publications under nineteen keys; listed flat they are a wall, so publications
 * that share a number are gathered into a series (SP 800-63 with its A, B and C volumes, the three
 * parts of SP 800-73), and a superseded revision held under its own key ("catalog-rev4") is read as
 * an earlier version of the publication it preceded.
 */

export interface OpenDraft {
  title: string;
  url: string | null;
  published_at: string | null;
}

export interface Publication {
  sourceId: string;
  /** The key of the newest version, which the standard's page anchors as `doc-<key>`. */
  key: string;
  /** The publisher's number for it ("SP 800-63B", "FIPS 201"), when it has one; matched against CSRC's drafts. */
  number: string | null;
  /** What the row is headed: the number where the key is one, else the key in words ("Catalog", "High baseline"). */
  label: string;
  /** The publication's full title, under a numbered heading. */
  title: string | null;
  current: DocumentRow | null;
  /** A draft newer than the current version, loaded like any other version. */
  draft: DocumentRow | null;
  /** Every other version, newest first. */
  earlier: DocumentRow[];
  /** CSRC's announcements of a draft of this publication open for comment. */
  openDrafts: OpenDraft[];
}

export interface Series {
  key: string;
  number: string | null;
  title: string;
  publications: Publication[];
}

export function isDraft(versionLabel: string | null): boolean {
  return versionLabel !== null && /\bdraft\b/i.test(versionLabel);
}

/** Where a source's own keys carry no number, the publication they all belong to. */
const sourceNumbers: Record<string, string> = {
  "nist-sp-800-53": "SP 800-53",
  "nist-sp-800-53b": "SP 800-53B",
  "nist-sp-800-171": "SP 800-171",
};

const nistKey = /^(sp|fips|ir)-(.+)$/;

/** "sp-800-63b" → "SP 800-63B", "sp-800-73-pt1" → "SP 800-73 Part 1"; null for a key that is not a NIST number. */
export function numberOfKey(key: string): string | null {
  const m = nistKey.exec(key);
  if (!m) return null;
  let rest = m[2]!.replace(/-rev\d+$/, "");
  let part = "";
  const pt = /-pt(\d+)$/.exec(rest);
  if (pt) {
    part = ` Part ${pt[1]}`;
    rest = rest.slice(0, pt.index);
  }
  return `${m[1]!.toUpperCase()} ${rest.toUpperCase()}${part}`;
}

/** The key a superseded revision shares with the publication it preceded. */
const publicationKey = (key: string): string => key.replace(/-rev\d+$/, "");

/** The key a publication shares with its volumes and parts: "sp-800-63b" and "sp-800-73-pt2" → "sp-800-63", "sp-800-73". */
export function seriesKey(key: string): string {
  return publicationKey(key)
    .replace(/-pt\d+$/, "")
    .replace(/^((?:sp|fips|ir)-[\d-]*\d)[a-z]$/, "$1");
}

/** A key that is not a NIST number, given words: the publisher's own where the key is a slug. */
export function keyLabel(key: string, title: string | null): string {
  if (key === "catalog") return "Catalog";
  if (key === "catalog-rev4") return "Catalog, Revision 4 (withdrawn)";
  if (key.startsWith("profile:")) return `${key.charAt(8).toUpperCase()}${key.slice(9)} baseline`;
  return title ?? key;
}

/** The number a draft announcement names, edition dropped: "SP 800-73-6, … Part 1" → "SP 800-73". */
export function draftNumber(title: string): string | null {
  const m = /\b(SP\s+\d{3,4}-\d+[A-Za-z]?|FIPS\s+\d+|(?:NIST\s*)?IR\s+\d+[A-Za-z]?|CSWP\s+\d+[A-Za-z]?)\b/i.exec(title);
  return m ? m[1]!.replace(/^NIST\s*/i, "").replace(/\s+/g, " ").toUpperCase() : null;
}

/** The drafts CSRC has open for comment, as the csrc-drafts feed last delivered them. */
export function openDrafts(db: DatabaseSync, limit = 100): OpenDraft[] {
  return db
    .prepare("SELECT title, url, published_at FROM items WHERE source_id = 'csrc-drafts' ORDER BY COALESCE(published_at, fetched_at) DESC LIMIT ?")
    .all(limit) as unknown as OpenDraft[];
}

/** Whether an open-for-comment announcement is a draft of this publication; a part must be named as that part. */
function draftOf(number: string, draft: OpenDraft): boolean {
  const named = draft.title ? draftNumber(draft.title) : null;
  if (!named) return false;
  const part = / Part (\d+)$/.exec(number);
  const bare = part ? number.slice(0, part.index) : number;
  if (named !== bare.toUpperCase()) return false;
  return !part || new RegExp(`\\bPart ${part[1]}\\b`, "i").test(draft.title);
}

const byNewest = (a: DocumentRow, b: DocumentRow): number =>
  (b.published_at ?? b.parsed_at).localeCompare(a.published_at ?? a.parsed_at) || b.id - a.id;

const natural = (a: string, b: string): number => a.localeCompare(b, "en", { numeric: true });

/** One source's documents as publications, gathered into series, in the publisher's numeric order. */
export function seriesOf(sourceId: string, documents: DocumentRow[], drafts: OpenDraft[] = []): Series[] {
  const byPublication = new Map<string, DocumentRow[]>();
  for (const d of documents) {
    const key = publicationKey(d.document_key);
    byPublication.set(key, [...(byPublication.get(key) ?? []), d]);
  }
  const publications: Publication[] = [...byPublication.entries()].map(([key, docs]) => {
    docs.sort(byNewest);
    const finals = docs.filter((d) => !isDraft(d.version_label));
    const current = finals[0] ?? null;
    const draft = docs.find((d) => isDraft(d.version_label) && (!current || byNewest(d, current) < 0)) ?? null;
    const newest = current ?? draft ?? docs[0]!;
    const numbered = numberOfKey(key);
    const number = numbered ?? sourceNumbers[sourceId] ?? null;
    return {
      sourceId,
      key: newest.document_key,
      number,
      label: numbered ?? keyLabel(key, newest.title),
      title: numbered ? newest.title : null,
      current,
      draft,
      earlier: docs.filter((d) => d !== current && d !== draft),
      openDrafts: number ? drafts.filter((o) => draftOf(number, o)) : [],
    };
  });

  const bySeries = new Map<string, Publication[]>();
  for (const p of publications) {
    const key = nistKey.test(p.key) ? seriesKey(p.key) : publicationKey(p.key);
    bySeries.set(key, [...(bySeries.get(key) ?? []), p]);
  }
  return [...bySeries.entries()]
    .sort(([a], [b]) => natural(a, b))
    .map(([key, pubs]) => {
      pubs.sort((a, b) => natural(a.key, b.key));
      const base = pubs.find((p) => publicationKey(p.key) === key) ?? pubs[0]!;
      return {
        key,
        number: numberOfKey(key),
        title: pubs.length > 1 ? (base.title ?? base.label).split(/:\s/)[0]! : (base.title ?? base.label),
        publications: pubs,
      };
    });
}

/** A publication's title with its series' words taken off the front: "…Guidelines: Federation and Assertions" → "Federation and Assertions". */
export function titleWithin(series: Series, publication: Publication): string | null {
  const prefix = `${series.title}: `;
  const title = publication.title;
  if (!title || series.publications.length === 1) return title;
  if (title === series.title) return null;
  return title.startsWith(prefix) ? title.slice(prefix.length) : title;
}
