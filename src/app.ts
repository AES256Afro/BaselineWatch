import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import express, { type Express, type NextFunction, type Request, type Response } from "express";
import type { Config } from "./config.ts";
import { countRows, databaseBytes } from "./db.ts";
import { renderHome } from "./pages/home.ts";
import { renderNotFound } from "./pages/not-found.ts";
import { renderSources } from "./pages/sources.ts";
import { productName, productVersion } from "./version.ts";

export interface AppContext {
  config: Config;
  db: DatabaseSync;
  /** Ids of the migrations the schema carries, for the health report. */
  migrations: string[];
  /** Epoch milliseconds when the process started. */
  startedAt: number;
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

export function createApp(ctx: AppContext): Express {
  const app = express();
  app.disable("x-powered-by");
  app.set("etag", "weak");
  app.use(securityHeaders);
  app.use("/assets", express.static(publicDir, { index: false, maxAge: "1h", fallthrough: true }));

  const health = (_req: Request, res: Response): void => {
    res.setHeader("Cache-Control", "no-store");
    res.json(healthReport(ctx));
  };
  app.get("/health", health);
  app.get("/api/v1/health", health);

  app.get("/", (_req, res) => {
    res.type("html").send(renderHome(ctx));
  });
  app.get("/sources", (_req, res) => {
    res.type("html").send(renderSources(ctx));
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
