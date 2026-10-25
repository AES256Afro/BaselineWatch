import { safeHref } from "./paths.ts";

/**
 * A tiny server-side HTML helper. Interpolated strings are escaped; values wrapped in
 * `Html` (the output of another `html` call, or `raw`) pass through; arrays are joined.
 */
export class Html {
  readonly value: string;
  constructor(value: string) {
    this.value = value;
  }
  toString(): string {
    return this.value;
  }
}

const escapes: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/**
 * The characters XML 1.0 has no way to carry — the C0 controls but tab, newline and return, and
 * the two noncharacters — dropped before anything is escaped.
 *
 * This template is also the XML writer: feeds.ts draws the RSS, the OPML and the sitemap through
 * it ("the html helper's escaping is XML's, so it draws this too"). A conformant parser rejects
 * the *whole document* over one such character, so a single feed title holding `&#1;` — which
 * `plainText` decodes and its whitespace collapse does not catch — used to break every
 * subscriber's reader for the entire feed rather than spoiling one item. The audit of 25 October
 * found it with expat; fast-xml-parser accepts it, which is why no test had.
 */
// eslint-disable-next-line no-control-regex
const forbidden = /[\u0000-\u0008\u000b\u000c\u000e-\u001f￾￿]/g;

/** Drops the characters XML 1.0 cannot carry, escaping nothing. The docx writer needs this half alone. */
export function xmlSafe(text: string): string {
  return text.replace(forbidden, "");
}

export function escapeHtml(text: string): string {
  return xmlSafe(text).replace(/[&<>"']/g, (c) => escapes[c] ?? c);
}

export type HtmlValue = Html | string | number | boolean | null | undefined | HtmlValue[];

function render(value: HtmlValue): string {
  if (value === null || value === undefined || value === false) return "";
  if (value instanceof Html) return value.value;
  if (Array.isArray(value)) return value.map(render).join("");
  if (value === true) return "";
  return escapeHtml(String(value));
}

/**
 * A whole attribute value about to be an address: the chunk before the hole opens `href` or `src`
 * and nothing of the value has been written yet. A hole in the middle of an address (`/img/${hash}`,
 * `${base}/x`) is not this, and is left alone — its literal prefix already says where it points.
 */
const opensAddress = /(?:^|\s)(?:href|src)\s*=\s*["']?$/i;

/**
 * Where a whole `href` or `src` comes from a string the code did not write, it goes through the
 * one rule in paths.ts, and an address that is not one becomes "#". Two hundred interpolations
 * draw a link somewhere in this app; each of them relied on its own author having checked the
 * scheme, and the audit of 25 October found two that had not (a feed's `/\evil.com`, which a
 * browser reads as another site, and Microsoft's own `Remediation.URL` taken raw from its JSON).
 * Doing it here means the next one cannot get it wrong either. A value wrapped in `Html` is the
 * code's own and passes through, as it always has.
 */
function renderValue(chunk: string, value: HtmlValue): string {
  if (typeof value !== "string" || !opensAddress.test(chunk)) return render(value);
  return escapeHtml(safeHref(value) ?? "#");
}

export function html(strings: TemplateStringsArray, ...values: HtmlValue[]): Html {
  let out = "";
  strings.forEach((chunk, i) => {
    out += chunk;
    if (i < values.length) out += renderValue(chunk, values[i]);
  });
  return new Html(out);
}

/** Marks a string as already-safe HTML. Only for literals the code owns. */
export function raw(value: string): Html {
  return new Html(value);
}

/** `target` and `rel` for a link that leaves the site: a new tab, and no opener handle for the target. */
export const newTab: Html = raw('target="_blank" rel="noopener"');

/** `newTab` when the address is an absolute http(s) one; nothing for a path on this site. */
export function newTabIf(href: string | null | undefined): Html {
  return href && /^https?:\/\//i.test(href) ? newTab : raw("");
}

/** A count with thousands separators, the way a person reads one: 7,340. */
export function figure(n: number): string {
  return Number.isFinite(n) ? Math.round(n).toLocaleString("en-US") : "";
}

/** Formats a byte count the way a person reads it. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let n = bytes / 1024;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return `${n < 10 ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}
