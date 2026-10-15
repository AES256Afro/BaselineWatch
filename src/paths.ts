/**
 * A path on this site to send the browser back to after a form, from a hidden field or a query
 * string the browser could have altered. Anything that is not a plain path on this site (an
 * absolute address, a protocol-relative one, a backslash form some browsers read as a slash)
 * becomes the fallback, so no form can bounce a person to another site.
 */
export function safeBack(value: unknown, fallback: string): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return fallback;
  return value;
}
