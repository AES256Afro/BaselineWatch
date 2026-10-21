import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import express, { type Express, type NextFunction, type Request, type Response } from "express";

import { apiChanges, apiDigest, apiItems, apiStandards, apiTriage, apiVuln, apiVulns, type ApiQuery } from "./api.ts";

import { authState, issueSession, LoginThrottle, passwordMatches, sameOriginOnly, sessionCookieHeader, throttleKey } from "./auth.ts";

import type { Config } from "./config.ts";
import { countRows, databaseBytes } from "./db.ts";
import { type HttpGet } from "./http.ts";

import { handleMcpRequest } from "./mcp.ts";

import { renderLogin } from "./pages/login.ts";
import { renderNotFound } from "./pages/not-found.ts";

import { type ReadText, type Resolve } from "./netscan.ts";

import { getBlob } from "./blobs.ts";
import { readBrand, readBrandMarks, type BrandKind } from "./branding.ts";

import { isLook, isScheme, lookCookieHeaders, lookState, type LookState } from "./look.ts";
import { safeBack } from "./paths.ts";
import { productName, productVersion } from "./version.ts";
import { mountBaselines } from "./routes/baselines.ts";
import { publicDir, type RouteContext } from "./routes/context.ts";
import { mountDesk } from "./routes/desk.ts";
import { mountNews } from "./routes/news.ts";

import { mountScan } from "./routes/scan.ts";
import { mountStandards } from "./routes/standards.ts";
import { mountReading } from "./routes/today.ts";
import { mountVulnerabilities } from "./routes/vulnerabilities.ts";

import { storageReport } from "./housekeeping.ts";
import { metricsText, pipelineHealth } from "./pipeline.ts";

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
  /** Replaces DNS and the host's files for the network scan in tests. */
  resolve?: Resolve;
  readFile?: ReadText;
}

export interface HealthReport {
  ok: boolean;
  name: string;
  version: string;
  uptimeSeconds: number;
  database: { migrations: number; bytes: number; sources: number; snapshots: number; changes: number; items: number; vulns: number };
  /** What the instance is holding and when it last let anything go (M13), so growth is watchable from outside. */
  storage: { snapshotBytes: number; keptSnapshots: number; imageBlobs: number; oldestSnapshotAt: string | null; lastHousekeepingAt: string | null };
}

export function healthReport(ctx: AppContext): HealthReport {
  const storage = storageReport(ctx.db);
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
      vulns: countRows(ctx.db, "vulns"),
    },
    storage: {
      snapshotBytes: storage.snapshotBytes,
      keptSnapshots: storage.keptSnapshots,
      imageBlobs: storage.imageBlobs,
      oldestSnapshotAt: storage.oldestSnapshotAt,
      lastHousekeepingAt: storage.lastRun?.ranAt ?? null,
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

export { safeBack } from "./paths.ts";

export function createApp(ctx: AppContext): Express {
  const { config, db } = ctx;
  const now = ctx.now ?? (() => new Date());
  // Every page wears the look the browser chose and the branding the owner uploaded.
  const lookOf = (req: Request): LookState => ({ ...lookState(req, config), brand: readBrand(db) });
  const brandMarks = readBrandMarks(path.join(import.meta.dirname, "..", "docs", "mockups", "logo"));
  const throttle = new LoginThrottle();
  const app = express();
  app.disable("x-powered-by");
  app.set("etag", "weak");
  app.set("trust proxy", "loopback, linklocal, uniquelocal");
  app.use(securityHeaders);
  if (config.baseUrl.startsWith("https://")) {
    // Behind TLS (a tunnel or a proxy), tell browsers to stay on it.
    app.use((_req, res, next) => {
      res.setHeader("Strict-Transport-Security", "max-age=15552000");
      next();
    });
  }
  // The baseline builder's form carries one checkbox per rule, a few hundred fields; everything else stays small.
  app.use("/baselines", express.urlencoded({ extended: false, limit: "1mb", parameterLimit: 5000 }));
  app.use(express.urlencoded({ extended: false, limit: "16kb" }));

  // The MCP endpoint: the read-only API as tools for agents. It sits before the same-origin guard
  // because its clients are programs, not pages, and nothing it offers writes. Stateless: one
  // server and transport per POST, no sessions, so GET (a stream) and DELETE (a session) are not.
  app.post("/mcp", async (req, res) => {
    const state = authState(req, config, now().getTime());
    if (!config.publicRead && !state.owner) {
      res.status(401).json({ jsonrpc: "2.0", error: { code: -32001, message: "Reading is not public on this instance; sign in first." }, id: null });
      return;
    }
    try {
      await handleMcpRequest(db, config.baseUrl, req, res);
    } catch {
      if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error." }, id: null });
    }
  });
  const postOnly = (_req: Request, res: Response): void => {
    res.status(405).set("Allow", "POST").json({ jsonrpc: "2.0", error: { code: -32000, message: "This MCP endpoint is stateless: POST only." }, id: null });
  };
  app.get("/mcp", postOnly);
  app.delete("/mcp", postOnly);

  app.use(sameOriginOnly);
  app.use("/assets", express.static(publicDir, { index: false, maxAge: "1h", fallthrough: true }));
  // The Register's typefaces, served from their packages so the strict CSP (font-src 'self') holds and nothing is fetched from Google.
  for (const family of ["newsreader", "public-sans", "jetbrains-mono"]) {
    app.use(`/assets/fonts/${family}`, express.static(path.join(import.meta.dirname, "..", "node_modules", "@fontsource-variable", family, "files"), { index: false, maxAge: "30d", immutable: true, fallthrough: true }));
  }

  // The branding the owner applied, served like /assets: the sign-in page on a closed instance
  // wears it too. The layout's URLs carry the hash, so those answers can be cached hard; the
  // fixed /favicon.ico cannot, or a replacement would never reach the tab.
  const sendBrand = (kind: BrandKind, cache: string) => (_req: Request, res: Response, next: NextFunction): void => {
    const image = readBrand(db)[kind];
    if (!image) return next();
    const bytes = getBlob(config.dataDir, image.sha256);
    if (!bytes) return next();
    res.setHeader("Cache-Control", cache);
    res.type(image.type).send(bytes);
  };
  app.get("/branding/logo", sendBrand("logo", "public, max-age=31536000, immutable"));
  app.get("/branding/favicon", sendBrand("favicon", "public, max-age=31536000, immutable"));
  app.get("/favicon.ico", sendBrand("favicon", "public, max-age=3600"));

  // The read-only JSON API. Same read gating as the pages (applied below), same data.
  const json = (res: Response, body: unknown): void => {
    res.setHeader("Cache-Control", "no-store");
    res.json(body);
  };
  const apiRead = (handler: (req: Request, res: Response) => void) => (req: Request, res: Response) => {
    const state = authState(req, config, now().getTime());
    if (!config.publicRead && !state.owner) return res.status(401).json({ error: "sign in first" });
    handler(req, res);
  };
  app.get("/api/v1/items", apiRead((req, res) => json(res, { items: apiItems(db, req.query as ApiQuery, config.baseUrl) })));
  app.get("/api/v1/vulns", apiRead((req, res) => json(res, apiVulns(db, req.query as ApiQuery))));
  app.get("/api/v1/vulns/:cve", apiRead((req, res) => {
    const v = apiVuln(db, String(req.params.cve));
    if (!v) return res.status(404).json({ error: "no such CVE" });
    json(res, v);
  }));
  app.get("/api/v1/standards", apiRead((_req, res) => json(res, { standards: apiStandards(db, config.baseUrl) })));
  app.get("/api/v1/changes", apiRead((req, res) => json(res, { changes: apiChanges(db, req.query as ApiQuery, config.baseUrl) })));
  app.get("/api/v1/triage", apiRead((req, res) => json(res, { triage: apiTriage(db, req.query as ApiQuery, config.baseUrl) })));
  app.get("/api/v1/digest", apiRead((_req, res) => json(res, { digest: apiDigest(db) })));

  // The health answer is public so a monitor can poll it; on an instance closed to readers it says only that the app is up.
  const health = (req: Request, res: Response): void => {
    res.setHeader("Cache-Control", "no-store");
    const report = healthReport(ctx);
    const full = config.publicRead || authState(req, config, now().getTime()).owner;
    res.json(full ? report : { ok: report.ok, name: report.name, version: report.version });
  };
  app.get("/health", health);
  app.get("/api/v1/health", health);

  // The same facts a dashboard can scrape (M13.2). Gated like /health: on an instance closed to
  // readers it says only what version is running, which is what a monitor needs to see it is up.
  app.get("/metrics", (req, res) => {
    const full = config.publicRead || authState(req, config, now().getTime()).owner;
    const at = now();
    const h = pipelineHealth(db, at);
    const storage = storageReport(db);
    res.setHeader("Cache-Control", "no-store");
    res.type("text/plain; version=0.0.4; charset=utf-8");
    if (!full) {
      res.send(`# HELP baselinewatch_build_info The running version, as a label on a constant 1.\n# TYPE baselinewatch_build_info gauge\nbaselinewatch_build_info{version="${productVersion}"} 1\n`);
      return;
    }
    res.send(
      metricsText({
        health: h,
        now: at,
        counts: {
          sources: countRows(db, "sources"),
          items: countRows(db, "items"),
          vulns: countRows(db, "vulns"),
          changes: countRows(db, "changes"),
          snapshots: countRows(db, "snapshots"),
        },
        bytes: { database: storage.databaseBytes, snapshots: storage.snapshotBytes },
        images: storage.imageBlobs,
        housekeeping: storage.lastRun
          ? { ranAt: storage.lastRun.ranAt, snapshotsDeleted: storage.lastRun.snapshotsDeleted, blobsDeleted: storage.lastRun.blobsDeleted, vacuumed: storage.lastRun.vacuumed }
          : null,
        uptimeSeconds: Math.round((Date.now() - ctx.startedAt) / 1000),
      }),
    );
  });

  const secureCookies = (req: Request): boolean => req.secure || config.baseUrl.startsWith("https://");

  // Sign-in is reachable even when reading is closed.
  app.get("/login", (req, res) => {
    const state = authState(req, config, now().getTime());
    res.type("html").send(renderLogin({ next: safeBack(req.query.next, "/"), open: state.open, look: lookOf(req) }));
  });
  app.post("/login", (req, res) => {
    const state = authState(req, config, now().getTime());
    const next = safeBack(((req.body ?? {}) as Record<string, unknown>).next, "/");
    if (state.open) return res.redirect(303, next);
    const key = throttleKey(req.ip);
    if (throttle.blocked(key, now().getTime())) {
      return res.status(429).type("html").send(renderLogin({ next, open: false, error: "Too many attempts. Wait ten minutes and try again.", look: lookOf(req) }));
    }
    const given = ((req.body ?? {}) as Record<string, unknown>).password;
    // The configured password is read trimmed, so the typed one is compared the same way.
    if (typeof given !== "string" || !config.adminPassword || !passwordMatches(config.adminPassword, given.trim())) {
      throttle.fail(key, now().getTime());
      return res.status(401).type("html").send(renderLogin({ next, open: false, error: "That password is not right.", look: lookOf(req) }));
    }
    throttle.clear(key);
    res.setHeader("Set-Cookie", sessionCookieHeader(config, issueSession(config, now().getTime()), secureCookies(req)));
    res.redirect(303, next);
  });
  app.post("/logout", (req, res) => {
    res.setHeader("Set-Cookie", sessionCookieHeader(config, null, secureCookies(req)));
    res.redirect(303, "/");
  });

  // The look and the colour scheme, per browser: two cookies and nothing else, so it sits before
  // the read gate (a closed instance still shows its sign-in page the way the browser asked). One
  // button's name and value is the whole request; the other setting keeps its current value.
  app.post("/look", (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const current = lookOf(req);
    const look = body.look === undefined ? current.look : body.look;
    const scheme = body.scheme === undefined ? current.scheme : body.scheme;
    if (!isLook(look) || !isScheme(scheme)) return res.status(400).type("text").send("That look or colour scheme is not one this build has.");
    res.setHeader("Set-Cookie", lookCookieHeaders({ look, scheme }, secureCookies(req)));
    res.redirect(303, safeBack(body.back, "/"));
  });

  // Reading may be closed to everyone but the owner.
  app.use((req, res, next) => {
    const state = authState(req, config, now().getTime());
    res.locals.owner = state.owner;
    res.locals.open = state.open;
    if (config.publicRead || state.owner) return next();
    if (req.method === "GET") return res.status(401).type("html").send(renderLogin({ next: req.originalUrl, open: false, look: lookOf(req) }));
    res.status(401).type("text").send("Sign in first.");
  });

  const requireOwner = (req: Request, res: Response, next: NextFunction): void => {
    if (res.locals.owner === true) return next();
    res.status(403).type("text").send("Only the owner can do that. Sign in at /login.");
  };
  const who = (req: Request, res: Response): { owner: boolean; open: boolean; look: LookState } => ({ owner: res.locals.owner === true, open: res.locals.open === true, look: lookOf(req) });
  const routeContext: RouteContext = { app, config, db, now, ctx, lookOf, who, requireOwner, secureCookies, brandMarks };
  mountNews(routeContext);
  mountReading(routeContext);
  mountStandards(routeContext);
  mountScan(routeContext);
  mountBaselines(routeContext);
  mountVulnerabilities(routeContext);
  mountDesk(routeContext);

  app.use((req, res) => {
    let shown = req.path;
    try {
      shown = decodeURIComponent(req.path);
    } catch {
      // A malformed escape sequence is shown as sent.
    }
    res.status(404).type("html").send(renderNotFound(shown, lookOf(req)));
  });

  app.use((error: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error(error);
    res.status(500).type("text").send("Something went wrong on the server. The log has the detail.");
  });

  return app;
}
