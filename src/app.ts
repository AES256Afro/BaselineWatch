import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import express, { type Express, type NextFunction, type Request, type Response } from "express";
import type { ItemKind, PullSettings } from "./adapters/types.ts";
import { authState, issueSession, LoginThrottle, passwordMatches, sameOriginOnly, sessionCookieHeader } from "./auth.ts";
import type { Config } from "./config.ts";
import { countRows, databaseBytes } from "./db.ts";
import type { HttpGet } from "./http.ts";
import { getSource, ingestSource, type IngestResult } from "./ingest.ts";
import { renderHome } from "./pages/home.ts";
import { renderLogin } from "./pages/login.ts";
import { renderNotFound } from "./pages/not-found.ts";
import { renderControl, renderRelease, renderStandard } from "./pages/register.ts";
import { renderSources } from "./pages/sources.ts";
import { renderAtlas } from "./pages/atlas.ts";
import { renderDigest } from "./pages/digest.ts";
import { renderToday } from "./pages/today.ts";
import { renderTriage } from "./pages/triage.ts";
import { renderVulnDetail, renderVulnList } from "./pages/vulnerabilities.ts";
import { renderWatchlist } from "./pages/watchlist.ts";
import { renderWire } from "./pages/wire.ts";
import { productName, productVersion } from "./version.ts";
import { recomputeWatchHits, type VulnFilters } from "./vulns.ts";
import { writeDigest } from "./digest.ts";
import { notify, parseNotifyUrl } from "./notify.ts";
import { clearTriage, isTriageState, setTriage, triageCsv, type TriageKind } from "./triage.ts";
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

export function pullSettings(config: Config): PullSettings {
  return { nvdApiKey: config.nvdApiKey, nvdBackfillDays: config.nvdBackfillDays, llmUrl: config.llmUrl, llmModel: config.llmModel };
}

export interface HealthReport {
  ok: boolean;
  name: string;
  version: string;
  uptimeSeconds: number;
  database: { migrations: number; bytes: number; sources: number; snapshots: number; changes: number; items: number; vulns: number };
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
      vulns: countRows(ctx.db, "vulns"),
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

const str = (v: unknown, max = 200): string | undefined => (typeof v === "string" && v.trim() !== "" ? v.trim().slice(0, max) : undefined);

function wireFilters(query: Record<string, unknown>): WireFilters {
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

function vulnFilters(query: Record<string, unknown>, now: Date): VulnFilters {
  const num = (v: unknown): number | undefined => {
    const n = Number(str(v));
    return Number.isFinite(n) ? n : undefined;
  };
  const sort = str(query.sort);
  const offset = num(query.offset);
  return {
    watch: str(query.watch) === "1",
    kev: str(query.kev) === "1",
    minCvss: num(query.min_cvss),
    minEpss: num(query.min_epss),
    changedSince: str(query.changed) === "1" ? new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString() : undefined,
    q: str(query.q),
    sort: sort === "published" || sort === "cvss" || sort === "epss" ? sort : "modified",
    offset: offset !== undefined && offset >= 0 ? Math.floor(offset) : 0,
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
  if (config.baseUrl.startsWith("https://")) {
    // Behind TLS (a tunnel or a proxy), tell browsers to stay on it.
    app.use((_req, res, next) => {
      res.setHeader("Strict-Transport-Security", "max-age=15552000");
      next();
    });
  }
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
  const who = (res: Response): { owner: boolean; open: boolean } => ({ owner: res.locals.owner === true, open: res.locals.open === true });

  app.get("/", (_req, res) => {
    res.type("html").send(renderHome({ config, db, migrations: ctx.migrations, owner: who(res).owner, now: now() }));
  });

  app.get("/today", (req, res) => {
    const since = Number(str(req.query.since));
    const hours = since === 72 || since === 168 ? since : 24;
    res.type("html").send(renderToday({ db, ...who(res), now: now(), hours }));
  });
  app.get("/atlas", (_req, res) => {
    res.type("html").send(renderAtlas({ db, ...who(res), now: now() }));
  });

  app.get("/wire", (req, res) => {
    res.type("html").send(renderWire({ db, filters: wireFilters(req.query as Record<string, unknown>), ...who(res), now: now() }));
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

  app.get("/standards", (_req, res) => res.redirect(302, "/"));
  app.get("/standards/:source", (req, res, next) => {
    const html = renderStandard({ db, sourceId: String(req.params.source), ...who(res), now: now() });
    if (!html) return next();
    res.type("html").send(html);
  });
  app.get("/standards/:source/:doc", (req, res, next) => {
    const documentId = Number(req.params.doc);
    if (!Number.isInteger(documentId) || documentId <= 0) return next();
    const html = renderRelease({ db, sourceId: String(req.params.source), documentId, ...who(res), now: now() });
    if (!html) return next();
    res.type("html").send(html);
  });
  app.get("/standards/:source/:doc/:ref", (req, res, next) => {
    const documentId = Number(req.params.doc);
    if (!Number.isInteger(documentId) || documentId <= 0) return next();
    const html = renderControl({ db, sourceId: String(req.params.source), documentId, ref: String(req.params.ref).toLowerCase(), ...who(res), now: now() });
    if (!html) return next();
    res.type("html").send(html);
  });

  app.get("/vulnerabilities", (req, res) => {
    res.type("html").send(renderVulnList({ db, filters: vulnFilters(req.query as Record<string, unknown>, now()), ...who(res), now: now() }));
  });
  app.get("/vulnerabilities/:cve", (req, res, next) => {
    const cveId = String(req.params.cve).toUpperCase();
    if (!/^CVE-\d{4}-\d{4,7}$/.test(cveId)) return next();
    const html = renderVulnDetail({ db, cveId, ...who(res), now: now() });
    if (!html) return next();
    res.type("html").send(html);
  });

  app.get("/watchlist", (req, res) => {
    res.type("html").send(renderWatchlist({ db, ...who(res), notice: str(req.query.notice, 300) }));
  });
  app.post("/watchlist", requireOwner, (req, res) => {
    const body = req.body as Record<string, unknown>;
    const kind = str(body.kind);
    const value = str(body.value);
    const label = str(body.label, 60) ?? null;
    if (!kind || !["product", "keyword", "baseline", "family"].includes(kind) || !value) {
      return res.status(400).type("text").send("A kind and a value are needed.");
    }
    db.prepare("INSERT OR IGNORE INTO watchlist (kind, value, label, created_at) VALUES (?, ?, ?, ?)").run(kind, value, label, now().toISOString());
    const changed = recomputeWatchHits(db);
    res.redirect(303, `/watchlist?notice=${encodeURIComponent(`Added ${value}; ${changed} CVE(s) re-marked.`)}`);
  });
  app.post("/watchlist/:id/delete", requireOwner, (req, res) => {
    const id = Number(req.params.id);
    if (Number.isInteger(id) && id > 0) {
      db.prepare("DELETE FROM watchlist WHERE id = ?").run(id);
      recomputeWatchHits(db);
    }
    res.redirect(303, "/watchlist");
  });

  app.get("/triage", (req, res) => {
    res.type("html").send(renderTriage({ db, ...who(res), now: now(), notice: str(req.query.notice, 300) }));
  });
  app.get("/triage.csv", requireOwner, (_req, res) => {
    res.setHeader("Content-Disposition", 'attachment; filename="baselinewatch-triage.csv"');
    res.type("text/csv").send(triageCsv(db));
  });
  const triageSubject = (body: Record<string, unknown>): { kind: TriageKind; id: number; key: string } | null => {
    const kind = str(body.kind);
    const id = Number(str(body.id));
    if ((kind !== "item" && kind !== "vuln" && kind !== "control") || !Number.isInteger(id) || id <= 0) return null;
    return { kind, id, key: str(body.key, 200) ?? "" };
  };
  app.post("/triage", requireOwner, (req, res) => {
    const body = req.body as Record<string, unknown>;
    const subject = triageSubject(body);
    const state = str(body.state);
    if (!subject || !isTriageState(state)) return res.status(400).type("text").send("A subject and a state are needed.");
    const note = body.note === undefined ? undefined : (str(body.note, 2000) ?? null);
    const due = body.due === undefined ? undefined : (str(body.due, 10) ?? null);
    if (due && !/^\d{4}-\d{2}-\d{2}$/.test(due)) return res.status(400).type("text").send("The due date must be YYYY-MM-DD.");
    setTriage(db, subject, { state, note, dueAt: due }, now().toISOString());
    res.redirect(303, safeBack(body.back, "/triage"));
  });
  app.post("/triage/clear", requireOwner, (req, res) => {
    const body = req.body as Record<string, unknown>;
    const subject = triageSubject(body);
    if (subject) clearTriage(db, subject);
    res.redirect(303, safeBack(body.back, "/triage"));
  });

  app.get("/digest", (_req, res) => {
    res.type("html").send(renderDigest({ db, ...who(res), now: now(), period: config.digest, hour: config.digestHour, timeZone: config.timeZone, notifyConfigured: parseNotifyUrl(config.notifyUrl) !== null }));
  });
  app.post("/digest/run", requireOwner, async (_req, res) => {
    const period = config.digest === "off" ? "daily" : config.digest;
    const row = writeDigest(db, { now: now(), baseUrl: config.baseUrl, period });
    await notify(db, parseNotifyUrl(config.notifyUrl), { kind: "digest", title: `BaselineWatch ${period} digest`, body: row.text.slice(0, 3500), url: `${config.baseUrl}/digest` }, ctx.http, now);
    res.redirect(303, "/digest");
  });

  app.get("/sources", (req, res) => {
    const q = req.query as Record<string, unknown>;
    const notice = typeof q.fetched === "string" && typeof q.status === "string" ? { sourceId: q.fetched, status: q.status, detail: typeof q.detail === "string" ? q.detail : "" } : null;
    res.type("html").send(renderSources({ db, ...who(res), notice }));
  });
  app.post("/sources/:id/fetch", requireOwner, async (req, res) => {
    const source = getSource(db, String(req.params.id));
    if (!source) return res.status(404).type("text").send("No such source.");
    const result: IngestResult = await ingestSource(db, config.dataDir, source, {
      now,
      settings: pullSettings(config),
      log: (line) => console.log(line),
      transport: parseNotifyUrl(config.notifyUrl),
      baseUrl: config.baseUrl,
      ...(ctx.http ? { http: ctx.http } : {}),
    });
    const detail = result.status === "ok" ? (result.detail ?? `${result.items} items, ${result.inserted} new, ${result.updated} changed`) : (result.error ?? result.status);
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
