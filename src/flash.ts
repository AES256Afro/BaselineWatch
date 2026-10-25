import type { Request, Response } from "express";
import { parseCookies } from "./auth.ts";

/**
 * A one-shot notice carried from a POST to the page it redirects to. It rides in a short-lived
 * cookie rather than the query string, so nobody can craft a link that puts their own words in
 * a page's notice box. Read once, then cleared.
 */
const cookieName = "bw_notice";
const maxLength = 3500;

const attributes = (secure: boolean): string => `Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;

/** The Set-Cookie header that carries `payload` (a string or a small JSON object) to the next page. */
export function flashHeader(payload: unknown, secure: boolean): string {
  // A fetch's detail can run long; it is cut until the encoded cookie fits, since a browser drops one over 4 KB.
  const encode = (p: unknown): string => encodeURIComponent(JSON.stringify(p) ?? "");
  // Every string in the payload shrinks, not just `detail`: a payload whose long field is some
  // other one (or which has no `detail` at all) used to run the loop down to nothing and then
  // return the oversized cookie anyway, which a browser drops — the notice never arrives.
  const shorten = (p: unknown, keep: number): unknown => {
    if (typeof p === "string") return p.length > keep ? `${p.slice(0, keep)}…` : p;
    if (p === null || typeof p !== "object" || Array.isArray(p)) return p;
    return Object.fromEntries(Object.entries(p as Record<string, unknown>).map(([k, v]) => [k, shorten(v, keep)]));
  };
  let value = encode(payload);
  for (let keep = 1200; value.length > maxLength && keep > 0; keep = Math.floor(keep / 2)) {
    value = encode(shorten(payload, keep));
  }
  // Whatever happened above, the header that goes out fits: a cookie a browser drops is a notice
  // that never arrives, which is worse than one cut short.
  if (value.length > maxLength) value = encode("That worked, but the notice was too long to carry here.");
  return `${cookieName}=${value}; ${attributes(secure)}; Max-Age=120`;
}

/** The notice the last POST left, if any; the cookie is cleared on this response. */
export function takeFlash(req: Request, res: Response, secure: boolean): unknown {
  const raw = parseCookies(req.headers.cookie)[cookieName];
  if (raw === undefined) return undefined;
  res.append("Set-Cookie", `${cookieName}=; ${attributes(secure)}; Max-Age=0`);
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
}

/** The notice as a string, or nothing. */
export function flashText(req: Request, res: Response, secure: boolean): string | undefined {
  const value = takeFlash(req, res, secure);
  return typeof value === "string" ? value.slice(0, 1200) : undefined;
}
