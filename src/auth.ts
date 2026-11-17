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

/**
 * The address a sign-in attempt or an allowance counts against: an IPv6 client is its whole /64,
 * since one host holds the prefix, or a wider prefix when asked. The allowances on heavy pages use
 * /56, the size a home connection is commonly delegated, so one household cannot rotate through
 * 256 fresh allowances.
 */
export function throttleKey(ip: string | undefined, bits: 48 | 56 | 64 = 64): string {
  if (!ip) return "unknown";
  const bare = ip.replace(/^::ffff:/i, "").replace(/%.*$/, "");
  if (isIP(bare) !== 6) return bare;
  const [head = "", tail = ""] = bare.split("::");
  const groups = head ? head.split(":") : [];
  const tailGroups = tail ? tail.split(":") : [];
  while (groups.length + tailGroups.length < 8) groups.push("0");
  const kept = [...groups, ...tailGroups].slice(0, Math.ceil(bits / 16)).map((g) => g.padStart(4, "0").toLowerCase());
  // A /56 keeps the first two hex digits of the fourth group.
  if (bits % 16 !== 0) kept[kept.length - 1] = `${kept[kept.length - 1]!.slice(0, (bits % 16) / 4)}${"0".repeat(4 - (bits % 16) / 4)}`;
  return `${kept.join(":")}::/${bits}`;
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

/**
 * A browser the owner has signed in from before. Behind a tunnel every visitor reaches the app
 * from the same peer address, so the sign-in brake on that peer (forty failures in ten minutes,
 * there to stop a LAN host rotating X-Forwarded-For) is one brake for the whole internet: eight
 * addresses' worth of wrong guesses would close sign-in to the owner too. A browser carrying this
 * mark is let past that one brake; its own address's brake still applies. The mark is a signed
 * expiry like the session, under its own label so neither token passes for the other, and it says
 * nothing but "signed in here once"; it grants no access.
 */
const knownCookie = "bw_known";
const knownDays = 365;

function knownMac(secret: string, expiresAtMs: number): string {
  return createHmac("sha256", secret).update(`known-device:${expiresAtMs}`).digest("base64url");
}

export function isKnownDevice(req: Request, config: Config, nowMs: number): boolean {
  const token = parseCookies(req.headers.cookie)[knownCookie];
  if (!token) return false;
  const dot = token.indexOf(".");
  if (dot <= 0) return false;
  const expiresAt = Number(token.slice(0, dot));
  if (!Number.isFinite(expiresAt) || expiresAt < nowMs) return false;
  const expected = Buffer.from(`${expiresAt}.${knownMac(config.sessionSecret, expiresAt)}`);
  const given = Buffer.from(token);
  return expected.length === given.length && timingSafeEqual(expected, given);
}

export function knownDeviceCookieHeader(config: Config, nowMs: number, secure: boolean): string {
  const expiresAt = nowMs + knownDays * 24 * 60 * 60 * 1000;
  return `${knownCookie}=${expiresAt}.${knownMac(config.sessionSecret, expiresAt)}; Path=/login; HttpOnly; SameSite=Strict${secure ? "; Secure" : ""}; Max-Age=${knownDays * 24 * 60 * 60}`;
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
 * Milliseconds of anonymous heavy work over a sliding window, per address and for everyone. An
 * address past its own share is refused; when everyone's budget is spent, only the addresses that
 * have had a fair share already are refused, so one client cannot use the whole budget to shut out
 * light readers, and many addresses (an IPv6 /48 is 256 /56s) cannot between them hold the event
 * loop. The owner is never counted.
 */
export class WorkBudget {
  private readonly spent: { at: number; ms: number; key: string }[] = [];
  private readonly byKey = new Map<string, number>();
  private total = 0;
  private readonly budgetMs: number;
  private readonly perKeyMs: number;
  private readonly fairMs: number;
  private readonly windowMs: number;
  constructor(budgetMs: number, windowMs: number, perKeyMs = budgetMs, fairMs = 0) {
    this.budgetMs = budgetMs;
    this.windowMs = windowMs;
    this.perKeyMs = perKeyMs;
    this.fairMs = fairMs;
  }
  private trim(nowMs: number): void {
    while (this.spent.length && nowMs - this.spent[0]!.at >= this.windowMs) {
      const old = this.spent.shift()!;
      this.total -= old.ms;
      const left = (this.byKey.get(old.key) ?? 0) - old.ms;
      if (left <= 0.5) this.byKey.delete(old.key);
      else this.byKey.set(old.key, left);
    }
  }
  /** "ok", "self" when this address has spent its own share, or "busy" when everyone's is spent and this address has had a fair part of it. */
  check(key: string, nowMs: number): "ok" | "self" | "busy" {
    this.trim(nowMs);
    const mine = this.byKey.get(key) ?? 0;
    if (mine >= this.perKeyMs) return "self";
    if (this.total >= this.budgetMs && mine >= this.fairMs) return "busy";
    return "ok";
  }
  spend(key: string, ms: number, nowMs: number): void {
    this.trim(nowMs);
    this.spent.push({ at: nowMs, ms, key });
    this.total += ms;
    this.byKey.set(key, (this.byKey.get(key) ?? 0) + ms);
  }
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
