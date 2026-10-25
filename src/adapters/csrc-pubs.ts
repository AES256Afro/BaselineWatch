import { extractPlanningNote } from "../explain.ts";
import type { HttpGet } from "../http.ts";
import type { NormalizedRequirement } from "../oscal.ts";
import { pdfText, unwrap } from "../pdf.ts";
import type { Adapter, DocumentTarget, ListingContext, ParsedDocument, SourceRow } from "./types.ts";
import { isoDate, plainText } from "./types.ts";

/**
 * NIST publications that exist only as PDFs (FIPS 201, the PIV special publications, the
 * Digital Identity Guidelines, the firmware and hardware-security set), tracked by topic.
 *
 * Each publication has a CSRC page that names the current PDF, its date, the revision it
 * supersedes and, once replaced, its successor. The adapter reads that page daily, follows it
 * forward when a new revision has replaced it, downloads the PDF only when the file or its date
 * moved, and turns the PDF's numbered sections into requirements: section 2.7.1 of FIPS 201-3
 * is one row, so a revision is diffed section by section. The PDF's own change log or revision
 * history is the publisher's reason for the release; the page's Planning Note is the fallback.
 * On a publication's first load the revision it superseded is loaded first, so the Register
 * opens on the real diff (FIPS 201-2 → 201-3, SP 800-63-3 → 63-4).
 */

export interface TrackedPublication {
  /** Stable across revisions: fips-201 covers FIPS 201-2 and FIPS 201-3. */
  key: string;
  /** The CSRC page of the revision current when the list was written; a successor is followed from there. */
  page: string;
}

const csrc = "https://csrc.nist.gov/pubs";

/** The publications each source follows (checked 2026-10-19). */
export const publications: Record<string, TrackedPublication[]> = {
  "nist-piv": [
    { key: "fips-201", page: `${csrc}/fips/201-3/final` },
    { key: "sp-800-73-pt1", page: `${csrc}/sp/800/73/pt1/5/final` },
    { key: "sp-800-73-pt2", page: `${csrc}/sp/800/73/pt2/5/final` },
    { key: "sp-800-73-pt3", page: `${csrc}/sp/800/73/pt3/5/final` },
    { key: "sp-800-76", page: `${csrc}/sp/800/76/2/final` },
    { key: "sp-800-78", page: `${csrc}/sp/800/78/5/final` },
    { key: "sp-800-79", page: `${csrc}/sp/800/79/2/final` },
    { key: "sp-800-85a", page: `${csrc}/sp/800/85/a/4/final` },
    { key: "sp-800-87", page: `${csrc}/sp/800/87/r2/final` },
    { key: "sp-800-96", page: `${csrc}/sp/800/96/final` },
    { key: "sp-800-116", page: `${csrc}/sp/800/116/r1/final` },
    { key: "sp-800-156", page: `${csrc}/sp/800/156/final` },
    { key: "sp-800-157", page: `${csrc}/sp/800/157/r1/fpd` },
    { key: "sp-800-217", page: `${csrc}/sp/800/217/fpd` },
    { key: "ir-7863", page: `${csrc}/ir/7863/final` },
    { key: "sp-800-63", page: `${csrc}/sp/800/63/4/final` },
    { key: "sp-800-63a", page: `${csrc}/sp/800/63/a/4/final` },
    { key: "sp-800-63b", page: `${csrc}/sp/800/63/b/4/final` },
    { key: "sp-800-63c", page: `${csrc}/sp/800/63/c/4/final` },
  ],
  "nist-platform": [
    { key: "fips-140", page: `${csrc}/fips/140-3/final` },
    { key: "sp-800-147", page: `${csrc}/sp/800/147/final` },
    { key: "sp-800-147b", page: `${csrc}/sp/800/147/b/final` },
    { key: "sp-800-193", page: `${csrc}/sp/800/193/final` },
    { key: "sp-800-124", page: `${csrc}/sp/800/124/r2/final` },
    { key: "sp-800-219", page: `${csrc}/sp/800/219/r1/final` },
    { key: "sp-800-57-pt1", page: `${csrc}/sp/800/57/pt1/r5/final` },
    { key: "ir-8320", page: `${csrc}/ir/8320/final` },
    { key: "ir-8320a", page: `${csrc}/ir/8320/a/final` },
    { key: "ir-8320b", page: `${csrc}/ir/8320/b/final` },
    { key: "ir-8320d", page: `${csrc}/ir/8320/d/ipd` },
  ],
};

// ---------------------------------------------------------------------------------------------
// The CSRC publication page

export interface PublicationLink {
  url: string;
  text: string;
}

export interface PublicationPage {
  url: string;
  title: string | null;
  /** The short number as CSRC cites it: "FIPS 201-3", "SP 800-157 Rev. 1 (Draft)". */
  number: string | null;
  publishedAt: string | null;
  pdfUrl: string | null;
  planningNote: { date: string | null; text: string } | null;
  supersedes: PublicationLink[];
  supersededBy: PublicationLink[];
  /** The page's Document History, oldest first; `current` marks the page's own entry. */
  history: (PublicationLink & { current: boolean })[];
  withdrawn: boolean;
}

function decodeAttribute(value: string): string {
  return value.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
}

function resolve(href: string, base: string): string {
  try {
    return new URL(decodeAttribute(href), base).toString();
  } catch {
    return href;
  }
}

/**
 * "Federal Information Processing Standard (FIPS) 201-3" → "FIPS 201-3"; NISTIR is shortened to
 * IR as CSRC itself does, and "(Withdrawn)" is dropped: a superseded revision is still that revision.
 */
export function shortNumber(full: string | null | undefined): string | null {
  if (!full) return null;
  const m = /\(([A-Z]+)\)\s*(.+)$/.exec(full);
  const text = m ? `${m[1] === "NISTIR" ? "IR" : m[1]} ${m[2]}` : full;
  return text.replace(/\s*\(Withdrawn\)/i, "").replace(/\s+/g, " ").trim() || null;
}

/**
 * The part of a number that stays across revisions: "SP 800-73-4 (02/12/2016)" and "SP 800-73-5"
 * are both "sp 800-73", "FIPS 201-2" and "FIPS 201-3" both "fips 201". An SP number is series
 * and publication ("800-157", "800-63B", "1800-12"); a FIPS or IR number is one token.
 */
export function baseNumber(text: string): string {
  const bare = text
    .replace(/\s*\([^)]*\)/g, "")
    .replace(/\s+Rev(?:ision)?\.?\s*\d+$/i, "")
    .trim();
  const m = /^([A-Za-z]+)\s+(.+)$/.exec(bare);
  if (!m) return bare.toLowerCase();
  const series = m[1]!.toUpperCase();
  const tokens = m[2]!.split("-");
  const keep = series === "SP" ? 2 : 1;
  return `${series} ${tokens.slice(0, keep).join("-")}`.toLowerCase();
}

export function parsePublicationPage(html: string, url: string): PublicationPage {
  const meta = (name: string): string | null => {
    const value = new RegExp(`<meta name="${name}" content="([^"]*)"`, "i").exec(html)?.[1];
    return value ? decodeAttribute(value) : null;
  };
  const links = (prefix: string): PublicationLink[] => {
    const out: PublicationLink[] = [];
    const re = new RegExp(`<a href="([^"]*)"\\s+id="pub-${prefix}-\\d+"[^<>]*>([\\s\\S]*?)</a>`, "gi");
    for (const m of html.matchAll(re)) out.push({ url: resolve(m[1]!, url), text: plainText(m[2], 200) ?? "" });
    return out;
  };
  const history: PublicationPage["history"] = [];
  for (const m of html.matchAll(/<(a|span)\s+(?:href="([^"]*)"\s+)?id="pub-history-link-\d+"\s+data-current-document='(true|false)'[^<>]*>([\s\S]*?)<\/\1>/gi)) {
    history.push({ url: m[2] ? resolve(m[2], url) : url, text: plainText(m[4], 200) ?? "", current: m[3] === "true" });
  }
  const pdf = /<a href="([^"]*)"\s+id="pub-local-download-link"/i.exec(html)?.[1];
  const date = meta("citation_publication_date");
  return {
    url,
    title: plainText(/<h1 id="pub-title">([\s\S]*?)<\/h1>/i.exec(html)?.[1], 400),
    number: shortNumber(meta("citation_technical_report_number")),
    publishedAt: date ? isoDate(`${date.replace(/\//g, "-")}T00:00:00Z`) : null,
    pdfUrl: pdf ? resolve(pdf, url) : null,
    planningNote: extractPlanningNote(html),
    supersedes: links("supersedes"),
    supersededBy: links("superseded-by"),
    history,
    withdrawn: /id="pub-withdrawn-message"/i.test(html),
  };
}

async function readPage(http: HttpGet, url: string): Promise<PublicationPage> {
  // The successor and draft pages are named by the page before them, so each is a URL read out
  // of a document: public hosts only, the way every derived URL is fetched.
  const response = await http(url, { headers: { accept: "text/html" }, timeoutMs: 60_000, publicOnly: true });
  return parsePublicationPage(new TextDecoder("utf-8").decode(response.bytes), url);
}

/**
 * The page of the newest revision: a superseded publication names its successor, and a draft's
 * Document History ends with the version that replaced it. At most three hops, so a loop in
 * CSRC's links cannot spin.
 */
export async function currentPage(http: HttpGet, url: string): Promise<PublicationPage> {
  let page = await readPage(http, url);
  for (let hop = 0; hop < 3; hop += 1) {
    const newest = page.history[page.history.length - 1];
    const next = page.supersededBy[0]?.url ?? (newest && !newest.current && newest.url !== page.url ? newest.url : null);
    if (!next) break;
    page = await readPage(http, next);
  }
  return page;
}

function targetOf(key: string, page: PublicationPage): DocumentTarget | null {
  if (!page.pdfUrl) return null;
  const note = page.planningNote;
  return {
    key,
    url: page.pdfUrl,
    versionLabel: page.number,
    publishedAt: page.publishedAt,
    title: page.title,
    rationale: note ? { text: `Planning Note${note.date ? ` (${note.date})` : ""}: ${note.text}`, url: page.url } : null,
  };
}

// ---------------------------------------------------------------------------------------------
// The PDF: numbered sections as requirements

type Part = number | string;

export interface NistSection {
  parts: Part[];
  ref: string;
  label: string;
  title: string;
  body: string | null;
}

interface Heading {
  parts: Part[];
  label: string;
  title: string;
}

const pageNumber = /^(?:\d{1,3}|[ivxlc]{1,7}|\d{1,2}-\d{1,3}|[A-Z]-\d{1,3}|Page \d+(?: of \d+)?)$/i;
const leaders = /(?:\.\s?){4,}/;
const endsLikeProse = /[.,;:]$/;
const danglingWord = /\b(?:and|or|of|the|to|a|an|for|in|on|with|by|from|that|which|is|are|as|at|be|its|their)$/i;

/** A line that is a section heading of the document's own outline, with no table-of-contents leaders and no sentence after it. */
export function headingOf(line: string): Heading | null {
  let parts: Part[];
  let label: string;
  let title: string;
  let m: RegExpExecArray | null;
  if ((m = /^Appendix\s+([A-Z])(?:[.:]|\s+[–—-])?\s+(\S.*)$/i.exec(line))) {
    const letter = m[1]!.toUpperCase();
    parts = [letter];
    label = `Appendix ${letter}`;
    title = m[2]!;
  } else if ((m = /^([A-Z])\.(\d{1,2}(?:\.\d{1,2}){0,3})\.?\s+(\S.*)$/.exec(line))) {
    parts = [m[1]!, ...m[2]!.split(".").map(Number)];
    label = `${m[1]}.${m[2]}`;
    title = m[3]!;
  } else if ((m = /^(\d{1,2}(?:\.\d{1,2}){0,4})\.?\s+(\S.*)$/.exec(line))) {
    parts = m[1]!.split(".").map(Number);
    label = m[1]!;
    title = m[2]!;
  } else {
    return null;
  }
  title = title.trim();
  if (title.length < 2 || title.length > 120) return null;
  if (!/^[A-Z0-9“"'(]/.test(title)) return null;
  if (leaders.test(title) || endsLikeProse.test(title) || danglingWord.test(title)) return null;
  return { parts, label, title };
}

function follows(a: Part, b: Part): boolean {
  if (typeof a === "number" && typeof b === "number") return b === a + 1;
  if (typeof a === "string" && typeof b === "string") return b.charCodeAt(0) === a.charCodeAt(0) + 1;
  return false;
}

function samePrefix(a: Part[], b: Part[], length: number): boolean {
  for (let i = 0; i < length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

/** Whether `next` can come right after `prev` in an outline: a first child, the next sibling at any depth, or Appendix A after the numbered sections. */
export function successor(prev: Part[], next: Part[]): boolean {
  if (next.length === prev.length + 1 && samePrefix(prev, next, prev.length) && next[next.length - 1] === 1) return true;
  for (let depth = prev.length; depth >= 1; depth -= 1) {
    if (next.length === depth && samePrefix(prev, next, depth - 1) && follows(prev[depth - 1]!, next[depth - 1]!)) return true;
  }
  return typeof prev[0] === "number" && next.length === 1 && next[0] === "A";
}

/** The page's lines with running headers, footers and page numbers removed, pages joined. */
export function cleanLines(text: string): string[] {
  const pages = text.replace(/\r/g, "").split("\f").map((p) => p.split("\n").map((l) => l.trim()));
  // Running headers and footers recur at the top or bottom of page after page.
  const atEdges = new Map<string, number>();
  for (const lines of pages) {
    const filled = lines.filter((l) => l !== "");
    for (const l of new Set([...filled.slice(0, 4), ...filled.slice(-4)])) if (l.length <= 140 && !pageNumber.test(l)) atEdges.set(l, (atEdges.get(l) ?? 0) + 1);
  }
  const furniture = new Set([...atEdges].filter(([, n]) => n >= 3).map(([l]) => l));
  const out: string[] = [];
  for (const lines of pages) {
    const kept = lines.filter((l) => !furniture.has(l));
    let start = 0;
    let end = kept.length;
    while (start < end && (kept[start] === "" || pageNumber.test(kept[start]!))) start += 1;
    while (end > start && (kept[end - 1] === "" || pageNumber.test(kept[end - 1]!))) end -= 1;
    out.push(...kept.slice(start, end));
  }
  return out;
}

interface Run {
  sections: (Heading & { lines: string[] })[];
}

/**
 * The document's outline, read from its text. Headings are taken only where they continue the
 * outline (1, 1.1, 1.2, 2, … Appendix A, A.1), which keeps numbered list items and cross
 * references out of it; a table of contents without dot leaders starts an outline of its own
 * and loses to the body, which has the text.
 */
export function parseNistSections(text: string): NistSection[] {
  const runs: Run[] = [];
  let active: Run | null = null;
  for (const line of cleanLines(text)) {
    const heading = line === "" ? null : headingOf(line);
    if (heading) {
      let placed = false;
      for (let i = runs.length - 1; i >= 0 && !placed; i -= 1) {
        const run = runs[i]!;
        const last = run.sections[run.sections.length - 1]!;
        if (successor(last.parts, heading.parts)) {
          run.sections.push({ ...heading, lines: [] });
          active = run;
          placed = true;
        }
      }
      if (placed) continue;
      if (heading.parts.length === 1 && heading.parts[0] === 1) {
        active = { sections: [{ ...heading, lines: [] }] };
        runs.push(active);
        continue;
      }
    }
    if (active) active.sections[active.sections.length - 1]!.lines.push(line);
  }
  const size = (run: Run): number => run.sections.reduce((n, s) => n + s.lines.join("\n").length, 0);
  let best: Run | null = null;
  for (const run of runs) if (!best || size(run) >= size(best)) best = run;
  if (!best) return [];
  return best.sections.map((s) => {
    const body = unwrap(s.lines.join("\n"));
    return { parts: s.parts, ref: s.parts.join(".").toLowerCase(), label: s.label, title: s.title, body: body === "" ? null : body };
  });
}

function topLabel(part: Part): string {
  return typeof part === "number" ? String(part) : `Appendix ${part}`;
}

export function sectionRequirements(sections: NistSection[]): NormalizedRequirement[] {
  const topTitles = new Map<Part, string>();
  for (const s of sections) if (s.parts.length === 1) topTitles.set(s.parts[0]!, s.title);
  return sections.map((s) => {
    const top = s.parts[0]!;
    return {
      ref: s.ref,
      parentRef: s.parts.length > 1 ? s.parts.slice(0, -1).join(".").toLowerCase() : null,
      family: `${topLabel(top)} ${topTitles.get(top) ?? ""}`.trim(),
      label: s.label,
      title: s.title,
      statement: s.body,
      guidance: null,
      params: [],
      related: [],
      sortKey: s.parts.map((p) => (typeof p === "number" ? String(p).padStart(3, "0") : p.toLowerCase())).join("."),
      status: "active",
      extra: {},
    };
  });
}

const changeLogTitle = /^(?:revision history|change ?log|changes? (?:from|since|in|to) |summary of changes|document (?:changes|revision|history))/i;

/** The publisher's own account of what changed: the Revision History or Change Log section, with its subsections. Long histories keep their newest end. */
export function changeLog(sections: NistSection[], max = 6000): string | null {
  const log = sections.find((s) => changeLogTitle.test(s.title));
  if (!log) return null;
  const text = sections
    .filter((s) => s === log || s.ref.startsWith(`${log.ref}.`))
    .map((s) => (s === log ? s.body : `${s.label} ${s.title}\n${s.body ?? ""}`))
    .filter((t): t is string => !!t && t.trim() !== "")
    .join("\n\n")
    .trim();
  if (text === "") return null;
  const headed = `${log.label} ${log.title}:\n${text}`;
  return headed.length > max ? `${log.label} ${log.title} (newest part):\n…${headed.slice(-(max - 60))}` : headed;
}

function looksLikeHtml(bytes: Uint8Array): boolean {
  const head = new TextDecoder("utf-8").decode(bytes.subarray(0, 64)).trimStart().toLowerCase();
  return head.startsWith("<!doctype") || head.startsWith("<html") || head.startsWith("<");
}

/** The adapter, over any table of publication lists keyed by source id; the default table is `publications`. */
export function csrcPublicationsAdapter(lists: Record<string, TrackedPublication[]>): Adapter {
  return {
    id: "csrc-pubs",
    headers: { accept: "application/pdf, text/html;q=0.5, */*;q=0.1" },
    async documents(source: SourceRow, ctx: ListingContext): Promise<DocumentTarget[]> {
      const count = ctx.db.prepare("SELECT COUNT(*) AS n FROM documents WHERE source_id = ? AND document_key = ?");
      const targets: DocumentTarget[] = [];
      for (const pub of lists[source.id] ?? []) {
        let page: PublicationPage;
        try {
          page = await currentPage(ctx.http, pub.page);
        } catch {
          // Let the ingester fetch the page itself and report the failure beside the key.
          targets.push({ key: pub.key, url: pub.page, title: pub.key });
          continue;
        }
        const current = targetOf(pub.key, page);
        if (!current) {
          targets.push({ key: pub.key, url: page.url, title: page.title ?? pub.key });
          continue;
        }
        const firstLoad = (count.get(source.id, pub.key) as { n: number }).n === 0;
        if (firstLoad && page.number) {
          // The revision this one replaced, so the first diff the Register shows is the real one.
          const base = baseNumber(page.number);
          const previous = page.supersedes.find((s) => baseNumber(s.text) === base);
          if (previous) {
            try {
              const older = targetOf(pub.key, await readPage(ctx.http, previous.url));
              if (older) targets.push(older);
            } catch {
              // History is a bonus; the current revision still loads.
            }
          }
        }
        targets.push(current);
      }
      return targets;
    },
    async parseDocument(bytes, target): Promise<ParsedDocument> {
      if (looksLikeHtml(bytes)) throw new Error("the publication page gave no PDF to read; has CSRC moved the document?");
      const sections = parseNistSections(await pdfText(bytes));
      if (sections.length === 0) throw new Error("no numbered sections found in this PDF");
      const log = changeLog(sections);
      return {
        title: target.title ?? target.versionLabel ?? target.key,
        versionLabel: target.versionLabel ?? null,
        publishedAt: target.publishedAt ?? null,
        requirements: sectionRequirements(sections),
        rationale: log ? { text: log, url: target.url } : null,
      };
    },
  };
}

export const csrcPubsAdapter: Adapter = csrcPublicationsAdapter(publications);
