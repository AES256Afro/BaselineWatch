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
  let value = encodeURIComponent(JSON.stringify(payload));
  if (value.length > maxLength) {
    // A fetch's detail can run long; keep the head of it rather than overflow the cookie.
    const shortened = typeof payload === "string" ? `${payload.slice(0, 1000)}…` : { ...(payload as Record<string, unknown>), detail: `${String((payload as Record<string, unknown>).detail ?? "").slice(0, 1000)}…` };
    value = encodeURIComponent(JSON.stringify(shortened));
  }
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
