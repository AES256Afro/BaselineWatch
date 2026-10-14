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
}

const stigId = /\b[A-Z]{2,5}\d{0,2}-[A-Z0-9]{2,4}-\d{6}\b/g;

/**
 * The block of a DISA Revision History for one version, as "- <ids> - <text>" items. The text
 * is the PDF's, so lines are rejoined and the leading "- " markers split the items.
 */
export function parseStigRevisionHistory(text: string, versionLabel: string | null): RevisionHistory {
  const flat = text.replace(/\r/g, "").replace(/\f/g, "\n");
  // Blocks start with a version label at the start of a line, e.g. "V1R4 Microsoft".
  const blocks = [...flat.matchAll(/^(V\d+R[\d.]+)\b/gm)].map((m) => ({ version: m[1]!, at: m.index! }));
  let slice = flat;
  if (versionLabel && blocks.length) {
    const start = blocks.findIndex((b) => b.version.toUpperCase() === versionLabel.toUpperCase());
    if (start >= 0) {
      const end = blocks[start + 1]?.at ?? flat.length;
      slice = flat.slice(blocks[start]!.at, end);
    }
  }
  const items = slice
    .split(/\n\s*-\s+/)
    .slice(1)
    .map((item) => unwrap(item).replace(/\s+/g, " ").trim())
    .map((item) => item.replace(/\s+\d{1,2} [A-Z][a-z]+ \d{4}\s*$/, "").trim())
    .filter((item) => item.length > 0);
  const notes: RequirementNote[] = [];
  const general: string[] = [];
  for (const item of items) {
    const sep = item.indexOf(" - ");
    const head = sep > 0 ? item.slice(0, sep) : "";
    const ids = [...head.matchAll(stigId)].map((m) => m[0]);
    if (ids.length && sep > 0) {
      const body = item.slice(sep + 3).trim();
      for (const id of ids) notes.push({ label: id, text: body });
    } else {
      general.push(item);
    }
  }
  return { notes, general };
}

/** Microsoft's announcement as readable prose, clipped for storage. */
export function announcementText(text: string, max = 8000): string {
  const prose = unwrap(text).split(String.fromCharCode(0xa0)).join(" ").trim();
  return prose.length > max ? `${prose.slice(0, max - 1)}…` : prose;
}

function stripTags(html: string): string {
  return html
    .replace(/<\s*(br|p|div|li|h\d|tr)[^>]*>/gi, "\n")
    .replace(/<[^>]+>/g, "")
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
  const date = /id=['"]pub-planning-note-date['"][^>]*>([^<]*)</i.exec(html)?.[1]?.trim() ?? null;
  const open = /<span[^>]*id=['"]pub-planning-note['"][^>]*>/i.exec(html);
  if (!open) return null;
  const rest = html.slice(open.index + open[0].length);
  // The note's own span closes right before the paragraph that holds it ends.
  const close = /<\/span>\s*(?:<\/p>|<p>|<br|<hr|<h\d|<div)/i.exec(rest);
  const fragment = close ? rest.slice(0, close.index) : rest.slice(0, 8000);
  const text = stripTags(fragment);
  if (text.length < 20) return null;
  return { date, text: text.length > 6000 ? `${text.slice(0, 5999)}…` : text };
}
