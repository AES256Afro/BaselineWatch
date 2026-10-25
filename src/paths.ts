/**
 * The two readers for an address this app is handed: one for where a form sends the browser next,
 * one for anything that may end up in an `href` or a `src`. Both exist because the same mistake
 * has two shapes — a value that leaves this site when it should not, and a value that is not an
 * address at all — and both are decided in one place so a new page cannot decide differently.
 */

/** A control character of any kind: no address this app writes carries one. */
// eslint-disable-next-line no-control-regex
const control = /[\u0000-\u001f\u007f-\u009f]/;

/**
 * A path on this site to send the browser back to after a form, from a hidden field or a query
 * string the browser could have altered. Anything that is not a plain path on this site (an
 * absolute address, a protocol-relative one, a backslash form some browsers read as a slash, a
 * control character a header cannot carry) becomes the fallback, so no form can bounce a person
 * to another site.
 */
export function safeBack(value: unknown, fallback: string): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("\\") || control.test(value)) return fallback;
  return value;
}

/**
 * An address worth rendering, or nothing. The rule, in one place for every link this app draws:
 * `http(s)://` with something after it, `mailto:`, or a path, query or fragment on this site.
 *
 * The backslash matters as much as the slash. A relative `/\evil.com` is read by the URL parser
 * the way `//evil.com` is — `new URL("/\\evil.com", "https://site/")` is `https://evil.com/` —
 * so a link that looks like a path on this site walks the reader off it. Every other scheme is
 * refused rather than mapped: `javascript:` and `data:` are the ones that script, and a scheme
 * this app has no use for is a scheme it should not be the first to render.
 */
export function safeHref(value: string | null | undefined): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (trimmed === "" || control.test(trimmed) || trimmed.includes("\\")) return null;
  if (/^https?:\/\/./i.test(trimmed) || /^mailto:./i.test(trimmed)) return trimmed;
  // A path on this site, or the query or fragment of the page being drawn. "//" is another site.
  return /^\/(?!\/)/.test(trimmed) || /^[?#]/.test(trimmed) ? trimmed : null;
}
