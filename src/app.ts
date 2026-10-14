import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import express, { type Express, type NextFunction, type Request, type Response } from "express";
import type { ItemKind } from "./adapters/types.ts";
import { authState, issueSession, LoginThrottle, passwordMatches, sameOriginOnly, sessionCookieHeader } from "./auth.ts";
import type { Config } from "./config.ts";
import { countRows, databaseBytes } from "./db.ts";
import type { HttpGet } from "./http.ts";
import { getSource, ingestSource, type IngestResult } from "./ingest.ts";
import { renderHome } from "./pages/home.ts";
import { renderLogin } from "./pages/login.ts";
import { renderNotFound } from "./pages/not-found.ts";
import { renderSources } from "./pages/sources.ts";
import { renderWire } from "./pages/wire.ts";
import { productName, productVersion } from "./version.ts";
import { markAllRead, setRead, setStarred, type WireFilters } from "./wire.ts";

export interface AppContext {
  config: Config;
  db: DatabaseSync;
  /** Ids of the migrations the schema carries, for the health report. */
  migrations: string[];
  /** Epoch milliseconds when the process started. */
  startedAt: number;
  now?: () => Date;
  /** Replaces the network for tests. */
  http?: HttpGet;
}

export const publicDir = path.join(import.meta.dirname, "..", "public");

export interface HealthReport {
  ok: boolean;
  name: string;
  version: string;
  uptimeSeconds: number;
  database: { migrations: number; bytes: number; sources: number; snapshots: number; changes: number; items: number };
}

export function healthReport(ctx: AppContext): HealthReport {
  return {
    ok: true,
    name: productName,
    version: productVersion,
    uptimeSeconds: Math.round((Date.now() - ctx.startedAt) / 1000),
    database: {
      migrations: ctx.migrations.length,
      bytes: databaseBytes(ctx.db),
      sources: countRows(ctx.db, "sources"),
      snapshots: countRows(ctx.db, "snapshots"),
      changes: countRows(ctx.db, "changes"),
      items: countRows(ctx.db, "items"),
    },
  };
}

/** Headers every response carries. No inline script or style anywhere, so the policy can be strict. */
function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
}

/** A path on this site to send the browser back to; anything else becomes the fallback. */
export function safeBack(value: unknown, fallback: string): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return fallback;
  return value;
}

function wireFilters(query: Record<string, unknown>): WireFilters {
  const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() !== "" ? v.trim().slice(0, 200) : undefined);
  const kind = str(query.kind);
  const before = Number(str(query.before));
  return {
    source: str(query.source),
    kind: kind === "article" || kind === "kev" || kind === "vulnerability" || kind === "release" ? (kind as ItemKind) : undefined,
    q: str(query.q),
    unread: str(query.unread) === "1",
    before: Number.isInteger(before) && before > 0 ? before : undefined,
  };
}

export function createApp(ctx: AppContext): Express {
  const { config, db } = ctx;
  const now = ctx.now ?? (() => new Date());
  const throttle = new LoginThrottle();
  const app = express();
  app.disable("x-powered-by");
  app.set("etag", "weak");
  app.set("trust proxy", "loopback, linklocal, uniquelocal");
  app.use(securityHeaders);
  app.use(express.urlencoded({ extended: false, limit: "16kb" }));
  app.use(sameOriginOnly);
  app.use("/assets", express.static(publicDir, { index: false, maxAge: "1h", fallthrough: true }));

  const health = (_req: Request, res: Response): void => {
    res.setHeader("Cache-Control", "no-store");
    res.json(healthReport(ctx));
  };
  app.get("/health", health);
  app.get("/api/v1/health", health);

  const secureCookies = (req: Request): boolean => req.secure || config.baseUrl.startsWith("https://");

  // Sign-in is reachable even when reading is closed.
  app.get("/login", (req, res) => {
    const state = authState(req, config, now().getTime());
    res.type("html").send(renderLogin({ next: safeBack(req.query.next, "/"), open: state.open }));
  });
  app.post("/login", (req, res) => {
    const state = authState(req, config, now().getTime());
    const next = safeBack((req.body as Record<string, unknown>).next, "/");
    if (state.open) return res.redirect(303, next);
    const key = req.ip ?? "unknown";
    if (throttle.blocked(key, now().getTime())) {
      return res.status(429).type("html").send(renderLogin({ next, open: false, error: "Too many attempts. Wait ten minutes and try again." }));
    }
    const given = (req.body as Record<string, unknown>).password;
    if (typeof given !== "string" || !config.adminPassword || !passwordMatches(config.adminPassword, given)) {
      throttle.fail(key, now().getTime());
      return res.status(401).type("html").send(renderLogin({ next, open: false, error: "That password is not right." }));
    }
    throttle.clear(key);
    res.setHeader("Set-Cookie", sessionCookieHeader(config, issueSession(config, now().getTime()), secureCookies(req)));
    res.redirect(303, next);
  });
  app.post("/logout", (req, res) => {
    res.setHeader("Set-Cookie", sessionCookieHeader(config, null, secureCookies(req)));
    res.redirect(303, "/");
  });

  // Reading may be closed to everyone but the owner.
  app.use((req, res, next) => {
    const state = authState(req, config, now().getTime());
    res.locals.owner = state.owner;
    res.locals.open = state.open;
    if (config.publicRead || state.owner) return next();
    if (req.method === "GET") return res.status(401).type("html").send(renderLogin({ next: req.originalUrl, open: false }));
    res.status(401).type("text").send("Sign in first.");
  });

  const requireOwner = (req: Request, res: Response, next: NextFunction): void => {
    if (res.locals.owner === true) return next();
    res.status(403).type("text").send("Only the owner can do that. Sign in at /login.");
  };

  app.get("/", (_req, res) => {
    res.type("html").send(renderHome({ config, db, migrations: ctx.migrations, owner: res.locals.owner === true, now: now() }));
  });

  app.get("/wire", (req, res) => {
    res
      .type("html")
      .send(renderWire({ db, filters: wireFilters(req.query as Record<string, unknown>), owner: res.locals.owner === true, open: res.locals.open === true, now: now() }));
  });

  const itemAction = (action: "read" | "unread" | "star" | "unstar") => (req: Request, res: Response) => {
    const id = Number(req.params.id);
    const back = safeBack((req.body as Record<string, unknown>).back, "/wire");
    if (!Number.isInteger(id) || id <= 0) return res.status(404).type("text").send("No such item.");
    const ok = action === "read" || action === "unread" ? setRead(db, id, action === "read") : setStarred(db, id, action === "star");
    if (!ok) return res.status(404).type("text").send("No such item.");
    res.redirect(303, back);
  };
  app.post("/items/:id/read", requireOwner, itemAction("read"));
  app.post("/items/:id/unread", requireOwner, itemAction("unread"));
  app.post("/items/:id/star", requireOwner, itemAction("star"));
  app.post("/items/:id/unstar", requireOwner, itemAction("unstar"));
  app.post("/wire/read-all", requireOwner, (req, res) => {
    const body = req.body as Record<string, unknown>;
    markAllRead(db, wireFilters(body));
    res.redirect(303, safeBack(body.back, "/wire"));
  });

  app.get("/sources", (req, res) => {
    const q = req.query as Record<string, unknown>;
    const notice = typeof q.fetched === "string" && typeof q.status === "string" ? { sourceId: q.fetched, status: q.status, detail: typeof q.detail === "string" ? q.detail : "" } : null;
    res.type("html").send(renderSources({ db, owner: res.locals.owner === true, open: res.locals.open === true, notice }));
  });
  app.post("/sources/:id/fetch", requireOwner, async (req, res) => {
    const source = getSource(db, String(req.params.id));
    if (!source) return res.status(404).type("text").send("No such source.");
    const result: IngestResult = await ingestSource(db, config.dataDir, source, { now, ...(ctx.http ? { http: ctx.http } : {}) });
    const detail = result.status === "ok" ? `${result.items} items, ${result.inserted} new, ${result.updated} changed` : (result.error ?? result.status);
    const params = new URLSearchParams({ fetched: source.id, status: result.status, detail });
    res.redirect(303, `/sources?${params.toString()}`);
  });

  app.use((req, res) => {
    let shown = req.path;
    try {
      shown = decodeURIComponent(req.path);
    } catch {
      // A malformed escape sequence is shown as sent.
    }
    res.status(404).type("html").send(renderNotFound(shown));
  });

  app.use((error: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error(error);
    res.status(500).type("text").send("Something went wrong on the server. The log has the detail.");
  });

  return app;
}
