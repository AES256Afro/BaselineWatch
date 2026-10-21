/**
 * The one reader for a column that should hold JSON. Ten modules each kept a copy of this
 * function before N4; one is enough, and the behaviour is the point: a NULL column, an empty
 * string or bytes that are not JSON all read as the fallback, never as an exception, because a
 * row that was written by an older version is not a reason for a page not to draw.
 */
export function parseJson<T>(text: string | null | undefined, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}
