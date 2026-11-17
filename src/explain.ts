import type { RequirementNote } from "./adapters/types.ts";
import { unwrap } from "./pdf.ts";

/**
 * Where publishers put their reasons, and how to read them:
 * DISA's Revision History PDF lists, per release, which rules changed and how; Microsoft's
 * Announcement PDF narrates a baseline revision; NIST's publication page carries a Planning Note.
 */

export interface RevisionHistory {
  /** Per-rule notes, each naming one or more STIG ids. */
  notes: RequirementNote[];
  /** Notes that name no rule ("Requirements were updated throughout..."). */
  general: string[];
  /** The release whose block was read ("V1R4"), or null when the text has no release blocks. */
  version: string | null;
}

/** A STIG id: WN25-00-000020, UBTU-22-231010, and the two-part form Chrome's STIG keeps (DTBC-0055). */
const stigId = /\b(?:[A-Z]{2,5}\d{0,2}-[A-Z0-9]{2,4}-\d{6}|[A-Z]{3,5}-\d{4})\b/g;

const release = String.raw`V\d+R\d+(?:\.\d+)?`;
// A label opening a line heads a block when it ends the line or is followed by " -", ":" or a
// capitalised word ("V1R4 Microsoft"); prose the PDF wrapped ("V2R9 to V2R11.") is not a heading.
const startsBlock = new RegExp(`^(${release})(?=\\s*$|\\s*:|\\s+-|\\s+[A-Z])`);
const namesBlock = new RegExp(`\\b(${release}):`);
const bareRelease = new RegExp(`^${release}$`);

/**
 * DISA's running page header: "UNCLASSIFIED", "<title> STIG Revision History, V1R4 DISA" (a
 * continuous STIG's carries no release), "<date> Developed by … DoW", the page number,
 * "UNCLASSIFIED" again, and on a table page the column heads down to "Release Date". The date of
 * the row the page break cut stands before it and is kept: it ends that row.
 */
const pageHeader = new RegExp(
  [
    String.raw`^[ \t]*UNCLASSIFIED[ \t]*\n\s*[^\n]*?STIG Revision History(?:,\s*${release})?\s+DISA[ \t]*`,
    String.raw`(?:\n\s*(?:\d{1,2} [A-Z][a-z]+ \d{4}\s+)?Developed by[^\n]*)?`,
    String.raw`(?:\n\s*\d+[ \t]*(?=\n))?`,
    String.raw`(?:\n\s*UNCLASSIFIED[ \t]*(?=\n|$))?`,
    String.raw`(?:\n(?:(?!\n\s*-\s)[\s\S]){0,300}?Release Date[ \t]*(?=\n|$))?`,
  ].join(""),
  "gm",
);

/** The text with DISA's page headers taken out, so a header neither heads a block nor joins a note. */
export function stripPageHeaders(flat: string): string {
  return flat.replace(pageHeader, "\n");
}

/**
 * Where each release's block starts. A versioned STIG's history puts the release in the first
 * column at the start of a line ("V1R4 Microsoft"); a continuous STIG's names it inside the
 * description, ending with a colon ("Google Android 16 COBO STIG, V1R4:"). The document-revised
 * column names the release before ("STIG, V1R3"), and when it wraps that label stands alone on
 * the next line ("LTS STIG,\nV2R9"): a bare label after a line ending in a comma is that column,
 * not a heading. Page headers are stripped first (stripPageHeaders).
 */
function blockHeadings(flat: string): { version: string; at: number }[] {
  const out: { version: string; at: number }[] = [];
  let at = 0;
  let previous = "";
  for (const line of flat.split("\n")) {
    const trimmed = line.trim();
    const start = startsBlock.exec(trimmed);
    const named = start ? null : namesBlock.exec(trimmed);
    const wrapped = start && bareRelease.test(trimmed) && previous.endsWith(",");
    if ((start && !wrapped) || named) out.push({ version: (start ?? named)![1]!.toUpperCase(), at });
    if (trimmed !== "") previous = trimmed;
    at += line.length + 1;
  }
  return out;
}

/** A release label's numbers, for finding the newest: V1R10 after V1R9, V2R1 after both. */
function releaseNumbers(label: string): [number, number] {
  const m = /^V(\d+)R(\d+(?:\.\d+)?)$/i.exec(label);
  return m ? [Number(m[1]), Number(m[2])] : [0, 0];
}

/** A release date closing a table row ("30 September 2026"), left on the row's last item. */
const rowDate = /\s+\d{1,2} [A-Z][a-z]+ \d{4}\s*$/;
/** The same date after the row's last sentence: the row ends there, and what follows is the next row's. */
const rowEnd = /[.)"\u201d]\s+\d{1,2} [A-Z][a-z]+ \d{4}\s*$/;
/** The document-revised column of the next row ("Google Android 16 COPE STIG, V1R3"), which is no note. */
const documentRevised = /^(?!.* - ).*,\s*V\d+R\d+(?:\.\d+)?$/;

/**
 * The block of a DISA Revision History for one release, as "- <ids> - <text>" items. The text
 * is the PDF's, so lines are rejoined and the leading "- " markers split the items.
 *
 * The block is the one headed by `versionLabel` ("V1R4"); every block so headed is read, since a
 * package can carry one row per STIG it holds (Android's COBO and COPE), and a note they share is
 * kept once. When no block carries that label, the newest release's is read for a continuous STIG,
 * labelled by its file token (Y26M10); a versioned release the history has not reached yet (V2R11 in
 * a PDF that stops at V2R10) gets nothing, not another release's notes.
 * A row ends at the release date after its last sentence; anything after it is the next row's.
 */
export function parseStigRevisionHistory(text: string, versionLabel: string | null): RevisionHistory {
  const flat = stripPageHeaders(text.replace(/\r/g, "").replace(/\f/g, "\n"));
  const blocks = blockHeadings(flat);
  let slices = [flat];
  let version: string | null = null;
  if (blocks.length) {
    const wanted = versionLabel?.toUpperCase();
    const newest = blocks.reduce((best, b) => {
      const [bv, br] = releaseNumbers(b.version);
      const [v, r] = releaseNumbers(best.version);
      return bv > v || (bv === v && br > r) ? b : best;
    }).version;
    // The newest block stands in only for a continuous STIG's file token (Y26M10); a versioned
    // release the history does not reach yet gets no notes rather than another release's.
    if (wanted && blocks.some((b) => b.version === wanted)) version = wanted;
    else if (wanted && bareRelease.test(wanted)) return { notes: [], general: [], version: null };
    else version = newest;
    slices = blocks.flatMap((b, i) => (b.version === version ? [flat.slice(b.at, blocks[i + 1]?.at ?? flat.length)] : []));
  }
  const items: string[] = [];
  for (const slice of slices) {
    for (const raw of slice.split(/\n\s*-\s+/).slice(1)) {
      const item = unwrap(raw).replace(/\s+/g, " ").trim();
      if (documentRevised.test(item)) continue;
      const undated = item.replace(rowDate, "").trim();
      if (undated.length > 0) items.push(undated);
      if (rowEnd.test(item)) break;
    }
  }
  const notes: RequirementNote[] = [];
  const general: string[] = [];
  const seen = new Set<string>();
  for (const item of items) {
    const sep = item.indexOf(" - ");
    // An id the PDF wrapped at its hyphen comes back "AIOS- 26-016300".
    const head = sep > 0 ? item.slice(0, sep).replace(/-\s+/g, "-") : "";
    const ids = [...head.matchAll(stigId)].map((m) => m[0]);
    if (ids.length && sep > 0) {
      const body = item.slice(sep + 3).trim();
      for (const id of ids) {
        if (seen.has(`${id}\n${body}`)) continue;
        seen.add(`${id}\n${body}`);
        notes.push({ label: id, text: body });
      }
    } else if (!seen.has(item)) {
      seen.add(item);
      general.push(item);
    }
  }
  return { notes, general, version };
}

/** Microsoft's announcement as readable prose, clipped for storage. */
export function announcementText(text: string, max = 8000): string {
  const prose = unwrap(text).split(String.fromCharCode(0xa0)).join(" ").trim();
  return prose.length > max ? `${prose.slice(0, max - 1)}…` : prose;
}

function stripTags(html: string): string {
  return html
    .replace(/<\s*(br|p|div|li|h\d|tr)[^<>]*>/gi, "\n")
    .replace(/<[^<>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/[ \t]+/g, " ")
    .replace(/\n\s*\n+/g, "\n")
    .trim();
}

/**
 * The Planning Note on a CSRC publication page: CSRC marks it as
 * `<strong>Planning Note (<span id='pub-planning-note-date'>date</span>):</strong>` followed by
 * `<span id='pub-planning-note'>…</span>`. Returns the dated note as text, or null.
 */
export function extractPlanningNote(html: string): { date: string | null; text: string } | null {
  const date = /id=['"]pub-planning-note-date['"][^<>]*>([^<]*)</i.exec(html)?.[1]?.trim() ?? null;
  const open = /<span[^<>]*id=['"]pub-planning-note['"][^<>]*>/i.exec(html);
  if (!open) return null;
  const rest = html.slice(open.index + open[0].length);
  // The note's own span closes right before the paragraph that holds it ends.
  const close = /<\/span>\s*(?:<\/p>|<p>|<br|<hr|<h\d|<div)/i.exec(rest);
  const fragment = close ? rest.slice(0, close.index) : rest.slice(0, 8000);
  const text = stripTags(fragment);
  if (text.length < 20) return null;
  return { date, text: text.length > 6000 ? `${text.slice(0, 5999)}…` : text };
}
