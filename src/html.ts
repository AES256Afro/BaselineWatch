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

export function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => escapes[c] ?? c);
}

export type HtmlValue = Html | string | number | boolean | null | undefined | HtmlValue[];

function render(value: HtmlValue): string {
  if (value === null || value === undefined || value === false) return "";
  if (value instanceof Html) return value.value;
  if (Array.isArray(value)) return value.map(render).join("");
  if (value === true) return "";
  return escapeHtml(String(value));
}

export function html(strings: TemplateStringsArray, ...values: HtmlValue[]): Html {
  let out = "";
  strings.forEach((chunk, i) => {
    out += chunk;
    if (i < values.length) out += render(values[i]);
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
