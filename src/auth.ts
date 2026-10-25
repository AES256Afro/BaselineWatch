import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import type { NextFunction, Request, Response } from "express";
import type { Config } from "./config.ts";

/**
 * The owner's session. Reading the site is open (or not, per BW_PUBLIC_READ); every write needs
 * the owner. There is one owner, identified by BW_ADMIN_PASSWORD. Without a password the app is
 * in single-user mode and writes are open, which is only sensible on a machine nobody else reaches.
 *
 * A session is a stateless signed token in an HttpOnly cookie: `<expires>.<hmac>`.
 */
const sessionCookie = "bw_session";
const sessionDays = 30;

export function signSession(secret: string, expiresAtMs: number): string {
  const mac = createHmac("sha256", secret).update(String(expiresAtMs)).digest("base64url");
  return `${expiresAtMs}.${mac}`;
}

export function verifySession(secret: string, token: string | undefined, nowMs: number): boolean {
  if (!token) return false;
  const dot = token.indexOf(".");
  if (dot <= 0) return false;
  const expiresAt = Number(token.slice(0, dot));
  if (!Number.isFinite(expiresAt) || expiresAt < nowMs) return false;
  const expected = Buffer.from(signSession(secret, expiresAt));
  const given = Buffer.from(token);
  return expected.length === given.length && timingSafeEqual(expected, given);
}

export function passwordMatches(configured: string, given: string): boolean {
  const a = createHash("sha256").update(configured).digest();
  const b = createHash("sha256").update(given).digest();
  return timingSafeEqual(a, b);
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    // The first of a repeated name wins. A browser sends the most specific cookie first — the
    // host-only one this app set — then any a sibling host set for the shared parent domain, so
    // taking the last would let a neighbour on the same domain shadow the session, the look or
    // the notice with one of its own.
    if (Object.hasOwn(out, name)) continue;
    const value = part.slice(eq + 1).trim();
    // A sibling site on the same domain may set a cookie with a bare %; it is not ours to fail on.
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      out[name] = value;
    }
  }
  return out;
}

/** The address a sign-in attempt counts against: an IPv6 client is its whole /64, since one host holds the prefix. */
export function throttleKey(ip: string | undefined): string {
  if (!ip) return "unknown";
  const bare = ip.replace(/^::ffff:/i, "").replace(/%.*$/, "");
  if (isIP(bare) !== 6) return bare;
  const [head = "", tail = ""] = bare.split("::");
  const groups = head ? head.split(":") : [];
  const tailGroups = tail ? tail.split(":") : [];
  while (groups.length + tailGroups.length < 8) groups.push("0");
  return `${[...groups, ...tailGroups]
    .slice(0, 4)
    .map((g) => g.padStart(4, "0"))
    .join(":")}::/64`;
}

export interface AuthState {
  /** True when no password is configured: single-user mode, writes open. */
  open: boolean;
  owner: boolean;
}

export function authState(req: Request, config: Config, nowMs = Date.now()): AuthState {
  if (!config.adminPassword) return { open: true, owner: true };
  const token = parseCookies(req.headers.cookie)[sessionCookie];
  return { open: false, owner: verifySession(config.sessionSecret, token, nowMs) };
}

export function sessionCookieHeader(config: Config, token: string | null, secure: boolean): string {
  const attributes = `Path=/; HttpOnly; SameSite=Strict${secure ? "; Secure" : ""}`;
  if (token === null) return `${sessionCookie}=; ${attributes}; Max-Age=0`;
  return `${sessionCookie}=${token}; ${attributes}; Max-Age=${sessionDays * 24 * 60 * 60}`;
}

export function issueSession(config: Config, nowMs = Date.now()): string {
  return signSession(config.sessionSecret, nowMs + sessionDays * 24 * 60 * 60 * 1000);
}

/** Refuses a state-changing request that did not come from this site's own pages. */
export function sameOriginOnly(req: Request, res: Response, next: NextFunction): void {
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return next();
  const site = req.headers["sec-fetch-site"];
  if (site === "same-origin" || site === "none") return next();
  const origin = req.headers.origin;
  const host = req.headers.host;
  if (typeof origin === "string" && typeof host === "string") {
    try {
      if (new URL(origin).host === host) return next();
    } catch {
      // fall through to refusal
    }
  }
  res.status(403).type("text").send("Refused: this request did not come from BaselineWatch's own pages.");
}

/**
 * A small in-memory allowance for a public route that costs this server a request of its own:
 * at most `limit` hits per key in `windowMs`. Key it with `throttleKey`, so an IPv6 visitor is
 * their /64 and cannot rotate past it; the map is swept once it is large, as the login throttle's is.
 */
export class RateWindow {
  private readonly hits = new Map<string, number[]>();
  private readonly limit: number;
  private readonly windowMs: number;
  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }
  /** Counts a hit and says whether it is within the allowance; a refused hit is not counted. */
  allow(key: string, nowMs: number): boolean {
    if (this.hits.size >= 10_000) {
      for (const [k, at] of this.hits) if (at.every((t) => nowMs - t >= this.windowMs)) this.hits.delete(k);
      for (const k of this.hits.keys()) {
        if (this.hits.size < 10_000) break;
        this.hits.delete(k);
      }
    }
    const recent = (this.hits.get(key) ?? []).filter((t) => nowMs - t < this.windowMs);
    if (recent.length >= this.limit) {
      this.hits.set(key, recent);
      return false;
    }
    recent.push(nowMs);
    this.hits.set(key, recent);
    return true;
  }
  get size(): number {
    return this.hits.size;
  }
}

/** A small in-memory brake on password guessing: after `limit` failures an address waits `windowMs`. */
export class LoginThrottle {
  private readonly failures = new Map<string, { count: number; until: number }>();
  private readonly limit: number;
  private readonly windowMs: number;
  constructor(limit = 5, windowMs = 10 * 60 * 1000) {
    this.limit = limit;
    this.windowMs = windowMs;
  }
  blocked(key: string, nowMs: number): boolean {
    const entry = this.failures.get(key);
    if (!entry) return false;
    if (entry.until < nowMs) {
      this.failures.delete(key);
      return false;
    }
    return entry.count >= this.limit;
  }
  fail(key: string, nowMs: number): void {
    // Expired entries are swept once the map is large, and the oldest live ones go when that frees nothing,
    // so many distinct addresses cannot grow it without bound.
    if (this.failures.size >= 10_000) {
      for (const [k, e] of this.failures) if (e.until < nowMs) this.failures.delete(k);
      for (const k of this.failures.keys()) {
        if (this.failures.size < 10_000) break;
        this.failures.delete(k);
      }
    }
    const entry = this.failures.get(key);
    if (!entry || entry.until < nowMs) this.failures.set(key, { count: 1, until: nowMs + this.windowMs });
    else entry.count += 1;
  }
  clear(key: string): void {
    this.failures.delete(key);
  }
}
