import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import express, { type Express, type NextFunction, type Request, type Response } from "express";
import { cisAdapter, cisKey } from "./adapters/cis.ts";
import type { ItemKind, PullSettings } from "./adapters/types.ts";
import { apiChanges, apiDigest, apiItems, apiStandards, apiTriage, apiVuln, apiVulns, type ApiQuery } from "./api.ts";
import { boundaryOf, parseMultipart } from "./multipart.ts";
import { authState, issueSession, LoginThrottle, passwordMatches, sameOriginOnly, sessionCookieHeader } from "./auth.ts";
import type { Config } from "./config.ts";
import { countRows, databaseBytes } from "./db.ts";
import type { HttpGet } from "./http.ts";
import { getSource, ingestSource, storeUploadedDocument, type IngestResult } from "./ingest.ts";
import { handleMcpRequest } from "./mcp.ts";
import { renderHome } from "./pages/home.ts";
import { renderLogin } from "./pages/login.ts";
import { renderNotFound } from "./pages/not-found.ts";
import { renderBrowse, renderControl, renderRelease, renderStandard } from "./pages/register.ts";
import { renderSources } from "./pages/sources.ts";
import { renderStigPlatform, renderStigsIndex } from "./pages/stigs.ts";
import { renderBaselinesIndex, renderBuilder } from "./pages/baselines.ts";
import { renderTestPlan } from "./pages/testplans.ts";
import { renderPlatforms } from "./pages/platforms.ts";
import { buildTestPlan, exportPlan, isArea, isPlanFormat, isPlanPlatform, type PlanOptions } from "./testplans.ts";
import { buildProfile, isBuilderPlatform, isSectionId, sectionOf, type ProfileOptions } from "./baselines.ts";
import { exportProfile, isExportFormat, isFlavour, type Flavour } from "./exports.ts";
import { isPlatformId, type Cat } from "./stigs.ts";
import { renderAtlas } from "./pages/atlas.ts";
import { renderDigest } from "./pages/digest.ts";
import { renderGuide } from "./pages/guide.ts";
import { renderScan, renderScanWhy } from "./pages/scan.ts";
import { probeGif, probePaths, resolverCheckSources } from "./scan.ts";
import { renderToday } from "./pages/today.ts";
import { renderTriage } from "./pages/triage.ts";
import { renderVulnDetail, renderVulnList } from "./pages/vulnerabilities.ts";
import { renderWatchlist } from "./pages/watchlist.ts";
import { renderNews } from "./pages/wire.ts";
import { getBlob } from "./blobs.ts";
import { imageFor } from "./images.ts";
import { isLook, isScheme, lookCookieHeaders, lookState, type LookState } from "./look.ts";
import { safeBack } from "./paths.ts";
import { productName, productVersion } from "./version.ts";
import { isPlatformKey, platformKeys } from "./platforms.ts";
import { parsePackageValue, recomputeWatchHits, type VulnFilters } from "./vulns.ts";
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
  return { nvdApiKey: config.nvdApiKey, nvdBackfillDays: config.nvdBackfillDays, newsImages: config.newsImages, llmUrl: config.llmUrl, llmModel: config.llmModel };
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

/**
 * The Scan page's own policy, the one exception to script-src 'none': its single self-hosted module
 * script, the probe images from this origin and from BW_PROBE_ORIGIN when set, and connections to
 * the two resolvers' self-check hosts. Still no inline script or style anywhere; every other route
 * keeps the policy above.
 */
export function scanPolicy(probeOrigin: string | null): string {
  const img = probeOrigin ? `'self' data: ${probeOrigin}` : "'self' data:";
  return `default-src 'self'; script-src 'self'; style-src 'self'; img-src ${img}; font-src 'self'; connect-src 'self' ${resolverCheckSources.join(" ")}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`;
}

export { safeBack } from "./paths.ts";

const str = (v: unknown, max = 200): string | undefined => (typeof v === "string" && v.trim() !== "" ? v.trim().slice(0, max) : undefined);

function wireFilters(query: Record<string, unknown>): WireFilters {
  const kind = str(query.kind);
  const group = str(query.group);
  const before = Number(str(query.before));
  return {
    source: str(query.source),
    group: group === "news" || group === "vulnerabilities" || group === "standards" ? group : undefined,
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
    res.type("html").send(renderLogin({ next: safeBack(req.query.next, "/"), open: state.open, look: lookState(req, config) }));
  });
  app.post("/login", (req, res) => {
    const state = authState(req, config, now().getTime());
    const next = safeBack((req.body as Record<string, unknown>).next, "/");
    if (state.open) return res.redirect(303, next);
    const key = req.ip ?? "unknown";
    if (throttle.blocked(key, now().getTime())) {
      return res.status(429).type("html").send(renderLogin({ next, open: false, error: "Too many attempts. Wait ten minutes and try again.", look: lookState(req, config) }));
    }
    const given = (req.body as Record<string, unknown>).password;
    if (typeof given !== "string" || !config.adminPassword || !passwordMatches(config.adminPassword, given)) {
      throttle.fail(key, now().getTime());
      return res.status(401).type("html").send(renderLogin({ next, open: false, error: "That password is not right.", look: lookState(req, config) }));
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
    const body = req.body as Record<string, unknown>;
    const current = lookState(req, config);
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
    if (req.method === "GET") return res.status(401).type("html").send(renderLogin({ next: req.originalUrl, open: false, look: lookState(req, config) }));
    res.status(401).type("text").send("Sign in first.");
  });

  const requireOwner = (req: Request, res: Response, next: NextFunction): void => {
    if (res.locals.owner === true) return next();
    res.status(403).type("text").send("Only the owner can do that. Sign in at /login.");
  };
  const who = (req: Request, res: Response): { owner: boolean; open: boolean; look: LookState } => ({ owner: res.locals.owner === true, open: res.locals.open === true, look: lookState(req, config) });

  // News is home; the Register (the old home) lives at /register; /wire stays good as an alias.
  app.get("/", (req, res) => {
    res.type("html").send(renderNews({ db, filters: wireFilters(req.query as Record<string, unknown>), ...who(req, res), now: now() }));
  });
  app.get("/wire", (req, res) => {
    const at = req.originalUrl.indexOf("?");
    res.redirect(301, at === -1 ? "/" : `/${req.originalUrl.slice(at)}`);
  });
  app.get("/register", (req, res) => {
    const { owner, look } = who(req, res);
    res.type("html").send(renderHome({ config, db, migrations: ctx.migrations, owner, look, now: now() }));
  });

  // Cached article images, served only by a hash some item carries, so snapshots stay private.
  app.get("/img/:hash", (req, res, next) => {
    const image = imageFor(db, String(req.params.hash));
    if (!image) return next();
    const bytes = getBlob(config.dataDir, image.sha256);
    if (!bytes) return next();
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    res.type(image.type).send(bytes);
  });

  app.get("/today", (req, res) => {
    const since = Number(str(req.query.since));
    const hours = since === 72 || since === 168 ? since : 24;
    res.type("html").send(renderToday({ db, ...who(req, res), now: now(), hours }));
  });
  app.get("/atlas", (req, res) => {
    res.type("html").send(renderAtlas({ db, ...who(req, res), now: now() }));
  });
  app.get("/guide", (req, res) => {
    res.type("html").send(renderGuide(who(req, res)));
  });

  // The Scan area (M12.1): the one page with a script, under its own policy; the why page and the
  // probe images stay under the strict one. The probes are one GIF at four names, never cached and
  // readable cross-site, so a second instance named by BW_PROBE_ORIGIN can serve the cross-site set.
  app.get("/scan", (req, res) => {
    res.setHeader("Content-Security-Policy", scanPolicy(config.probeOrigin));
    res.setHeader("Cache-Control", "no-store");
    res.type("html").send(renderScan({ ...who(req, res), probeOrigin: config.probeOrigin }));
  });
  app.get("/scan/why", (req, res) => {
    res.type("html").send(renderScanWhy(who(req, res)));
  });
  const probe = (_req: Request, res: Response): void => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
    res.type("image/gif").send(probeGif);
  };
  for (const probePath of probePaths) app.get(probePath, probe);

  const itemAction = (action: "read" | "unread" | "star" | "unstar") => (req: Request, res: Response) => {
    const id = Number(req.params.id);
    const back = safeBack((req.body as Record<string, unknown>).back, "/");
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
    res.redirect(303, safeBack(body.back, "/"));
  });

  app.get("/standards", (_req, res) => res.redirect(302, "/register"));
  app.get("/standards/:source", (req, res, next) => {
    const html = renderStandard({ db, sourceId: String(req.params.source), ...who(req, res), now: now(), notice: str(req.query.notice, 300) });
    if (!html) return next();
    res.type("html").send(html);
  });
  app.get("/standards/:source/:doc", (req, res, next) => {
    const documentId = Number(req.params.doc);
    if (!Number.isInteger(documentId) || documentId <= 0) return next();
    const html = renderRelease({ db, sourceId: String(req.params.source), documentId, ...who(req, res), now: now() });
    if (!html) return next();
    res.type("html").send(html);
  });
  app.get("/standards/:source/:doc/browse", (req, res, next) => {
    const documentId = Number(req.params.doc);
    if (!Number.isInteger(documentId) || documentId <= 0) return next();
    const html = renderBrowse({ db, sourceId: String(req.params.source), documentId, q: str(req.query.q, 100), family: str(req.query.family, 40), ...who(req, res) });
    if (!html) return next();
    res.type("html").send(html);
  });
  app.get("/standards/:source/:doc/:ref", (req, res, next) => {
    const documentId = Number(req.params.doc);
    if (!Number.isInteger(documentId) || documentId <= 0) return next();
    const html = renderControl({ db, sourceId: String(req.params.source), documentId, ref: String(req.params.ref).toLowerCase(), ...who(req, res), now: now() });
    if (!html) return next();
    res.type("html").send(html);
  });

  app.get("/stigs", (req, res) => {
    res.type("html").send(renderStigsIndex({ db, ...who(req, res), now: now() }));
  });
  app.get("/stigs/:platform", (req, res, next) => {
    const platform = String(req.params.platform);
    if (!isPlatformId(platform)) return next();
    const catParam = str(req.query.cat, 3);
    const cat: Cat | undefined = catParam === "1" ? "CAT I" : catParam === "2" ? "CAT II" : catParam === "3" ? "CAT III" : undefined;
    res.type("html").send(renderStigPlatform({ db, platform, stigKey: str(req.query.stig, 120), cat, ...who(req, res), now: now() }));
  });

  // The baseline builder: ordinary forms, nothing stored. GET draws the strict profile; POST
  // redraws it with the unticked items dropped; export answers either way, so a JSON export
  // with query fields is also an API. The page draws one section at a time: `shown` names the
  // section whose checkboxes are in the form, hidden `drop` fields carry the other sections'
  // drops, and a `section` button picks the next one to draw.
  const list = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => String(x)) : typeof v === "string" ? [v] : []);
  const profileOptions = (platform: ProfileOptions["platform"], fields: Record<string, unknown>): ProfileOptions => {
    const applied = str(fields.applied) === "1";
    const keep = applied ? new Set(list(fields.keep).slice(0, 5000)) : null;
    const drop = list(fields.drop).slice(0, 5000);
    const shown = str(fields.shown, 20);
    const options: ProfileOptions = { platform, stig: str(fields.stig, 160), sct: str(fields.sct, 160), mscp: str(fields.mscp, 160), cat3: str(fields.cat3) === "1" };
    if (keep) {
      // The form sends what is kept; the profile wants what is dropped: everything it holds that was not sent.
      const all = buildProfile(db, options).items;
      if (isSectionId(shown)) {
        // Only one section's checkboxes were drawn; the other sections' drops rode along as hidden fields.
        const carried = new Set(drop);
        options.drop = all.filter((i) => (sectionOf(i) === shown ? !keep.has(i.id) : carried.has(i.id))).map((i) => i.id);
      } else options.drop = all.filter((i) => !keep.has(i.id)).map((i) => i.id);
    } else if (drop.length) options.drop = drop;
    return options;
  };
  const flavourOf = (fields: Record<string, unknown>): Flavour => (isFlavour(fields.flavour) ? fields.flavour : "plain");
  app.get("/baselines", (req, res) => {
    res.type("html").send(renderBaselinesIndex({ db, ...who(req, res) }));
  });
  const drawBuilder = (req: Request, res: Response, next: NextFunction, fields: Record<string, unknown>): void => {
    const platform = String(req.params.platform);
    if (!isBuilderPlatform(platform)) return next();
    const profile = buildProfile(db, profileOptions(platform, fields));
    const section = str(fields.section, 20) ?? str(fields.shown, 20);
    res.type("html").send(renderBuilder({ db, profile, flavour: flavourOf(fields), section: isSectionId(section) ? section : undefined, text: str(fields.text) === "1", ...who(req, res) }));
  };
  app.get("/baselines/:platform", (req, res, next) => drawBuilder(req, res, next, req.query as Record<string, unknown>));
  app.post("/baselines/:platform", (req, res, next) => drawBuilder(req, res, next, (req.body ?? {}) as Record<string, unknown>));
  const sendExport = (req: Request, res: Response, next: NextFunction, fields: Record<string, unknown>): void => {
    const platform = String(req.params.platform);
    if (!isBuilderPlatform(platform)) return next();
    const format = isExportFormat(fields.format) ? fields.format : "json";
    const profile = buildProfile(db, profileOptions(platform, fields));
    const out = exportProfile(profile, format, flavourOf(fields), { baseUrl: config.baseUrl, generatedAt: now().toISOString(), version: productVersion });
    res.setHeader("Content-Disposition", `attachment; filename="${out.filename}"`);
    res.setHeader("Cache-Control", "no-store");
    res.type(out.contentType).send(out.body);
  };
  app.get("/baselines/:platform/export", (req, res, next) => sendExport(req, res, next, req.query as Record<string, unknown>));
  app.post("/baselines/:platform/export", (req, res, next) => sendExport(req, res, next, (req.body ?? {}) as Record<string, unknown>));

  // Test plans: the same form shape over the derived checks and the owner's templates, drawn one
  // area at a time the way the builder draws one section: `shown` names the area whose checkboxes
  // are in the form, hidden `drop` fields carry the other areas' drops, `section` picks the next.
  const planOptions = (platform: PlanOptions["platform"], fields: Record<string, unknown>): PlanOptions => {
    const applied = str(fields.applied) === "1";
    const keep = applied ? new Set(list(fields.keep).slice(0, 5000)) : null;
    const drop = list(fields.drop).slice(0, 5000);
    const shown = str(fields.shown, 20);
    // The areas to test ride along as checkboxes once the form has been applied; a first GET tests every area.
    // The hidden `areas` marker says the area checkboxes were drawn, so an empty list means none; an older form or a script without it tests every area.
    const chosen = str(fields.areas) === "1" || fields.area !== undefined ? list(fields.area).filter(isArea) : undefined;
    const base: PlanOptions = { platform, stig: str(fields.stig, 160), mscp: str(fields.mscp, 160), cat3: str(fields.cat3) === "1", templates: applied ? str(fields.templates) === "1" : str(fields.templates) !== "0", version: str(fields.version, 40), hardware: str(fields.hardware, 60), areas: chosen };
    if (keep) {
      const all = buildTestPlan(db, base).items;
      if (isArea(shown)) {
        // Only one area's checkboxes were drawn; the other areas' drops rode along as hidden fields.
        const carried = new Set(drop);
        return { ...base, drop: all.filter((i) => (i.area === shown ? !keep.has(i.id) : carried.has(i.id))).map((i) => i.id) };
      }
      return { ...base, drop: all.filter((i) => !keep.has(i.id)).map((i) => i.id) };
    }
    return drop.length ? { ...base, drop } : base;
  };
  const drawPlan = (req: Request, res: Response, next: NextFunction, fields: Record<string, unknown>): void => {
    const platform = String(req.params.platform);
    if (!isPlanPlatform(platform)) return next();
    const area = str(fields.section, 20) ?? str(fields.shown, 20);
    res.type("html").send(renderTestPlan({ db, plan: buildTestPlan(db, planOptions(platform, fields)), area: isArea(area) ? area : undefined, ...who(req, res) }));
  };
  app.get("/platforms", (req, res) => {
    res.type("html").send(renderPlatforms({ db, now: now(), ...who(req, res) }));
  });
  app.get("/baselines/:platform/tests", (req, res, next) => drawPlan(req, res, next, req.query as Record<string, unknown>));
  app.post("/baselines/:platform/tests", (req, res, next) => drawPlan(req, res, next, (req.body ?? {}) as Record<string, unknown>));
  const sendPlan = (req: Request, res: Response, next: NextFunction, fields: Record<string, unknown>): void => {
    const platform = String(req.params.platform);
    if (!isPlanPlatform(platform)) return next();
    const out = exportPlan(buildTestPlan(db, planOptions(platform, fields)), isPlanFormat(fields.format) ? fields.format : "json", { baseUrl: config.baseUrl, generatedAt: now().toISOString(), version: productVersion });
    res.setHeader("Content-Disposition", `attachment; filename="${out.filename}"`);
    res.setHeader("Cache-Control", "no-store");
    res.type(out.contentType).send(typeof out.body === "string" ? out.body : Buffer.from(out.body));
  };
  app.get("/baselines/:platform/tests/export", (req, res, next) => sendPlan(req, res, next, req.query as Record<string, unknown>));
  app.post("/baselines/:platform/tests/export", (req, res, next) => sendPlan(req, res, next, (req.body ?? {}) as Record<string, unknown>));

  app.get("/vulnerabilities", (req, res) => {
    res.type("html").send(renderVulnList({ db, filters: vulnFilters(req.query as Record<string, unknown>, now()), ...who(req, res), now: now() }));
  });
  app.get("/vulnerabilities/:cve", (req, res, next) => {
    const cveId = String(req.params.cve).toUpperCase();
    if (!/^CVE-\d{4}-\d{4,7}$/.test(cveId)) return next();
    const html = renderVulnDetail({ db, cveId, ...who(req, res), now: now() });
    if (!html) return next();
    res.type("html").send(html);
  });

  app.get("/watchlist", (req, res) => {
    res.type("html").send(renderWatchlist({ db, ...who(req, res), notice: str(req.query.notice, 300) }));
  });
  app.post("/watchlist", requireOwner, (req, res) => {
    const body = req.body as Record<string, unknown>;
    const kind = str(body.kind);
    const value = str(body.value);
    const label = str(body.label, 60) ?? null;
    if (!kind || !["product", "keyword", "baseline", "family", "package", "platform"].includes(kind) || !value) {
      return res.status(400).type("text").send("A kind and a value are needed.");
    }
    if (kind === "package" && !parsePackageValue(value)) {
      return res.status(400).type("text").send("A package is written ecosystem:name, such as npm:express or PyPI:django.");
    }
    if (kind === "platform" && !isPlatformKey(value.toLowerCase())) {
      return res.status(400).type("text").send(`A platform is one of ${platformKeys.join(", ")}.`);
    }
    db.prepare("INSERT OR IGNORE INTO watchlist (kind, value, label, created_at) VALUES (?, ?, ?, ?)").run(kind, kind === "platform" ? value.toLowerCase() : value, label, now().toISOString());
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
    res.type("html").send(renderTriage({ db, ...who(req, res), now: now(), notice: str(req.query.notice, 300) }));
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

  app.get("/digest", (req, res) => {
    res.type("html").send(renderDigest({ db, ...who(req, res), now: now(), period: config.digest, hour: config.digestHour, timeZone: config.timeZone, notifyConfigured: parseNotifyUrl(config.notifyUrl) !== null }));
  });
  app.post("/digest/run", requireOwner, async (_req, res) => {
    const period = config.digest === "off" ? "daily" : config.digest;
    const row = writeDigest(db, { now: now(), baseUrl: config.baseUrl, period });
    await notify(db, parseNotifyUrl(config.notifyUrl), { kind: "digest", title: `BaselineWatch ${period} digest`, body: row.text.slice(0, 3500), url: `${config.baseUrl}/digest` }, ctx.http, now);
    res.redirect(303, "/digest");
  });

  // CIS Benchmarks come in by hand: the owner uploads the PDF, the Register diffs it against the last upload of the same benchmark.
  app.post("/uploads/cis", requireOwner, async (req, res) => {
    const boundary = boundaryOf(req.headers["content-type"]);
    if (!boundary) return res.status(400).type("text").send("Send the PDF as multipart/form-data.");
    const chunks: Buffer[] = [];
    let size = 0;
    const limit = 60 * 1024 * 1024;
    try {
      for await (const chunk of req) {
        size += (chunk as Buffer).length;
        if (size > limit) {
          res.status(413).type("text").send("That file is larger than 60 MB.");
          return;
        }
        chunks.push(chunk as Buffer);
      }
    } catch {
      return res.status(400).type("text").send("The upload did not complete.");
    }
    const form = parseMultipart(new Uint8Array(Buffer.concat(chunks)), boundary);
    const file = form.files.find((f) => f.field === "pdf") ?? form.files[0];
    if (!file || file.bytes.length === 0) return res.status(400).type("text").send("No PDF was attached.");
    const source = getSource(db, "cis-benchmarks");
    if (!source) return res.status(500).type("text").send("The CIS source is missing from the database.");
    const versionLabel = str(form.fields.version, 40) ?? null;
    const publishedAt = str(form.fields.published, 10);
    const outcome = await storeUploadedDocument(db, config.dataDir, source, cisAdapter, file.bytes, {
      filename: file.filename,
      keyFor: (title) => cisKey(title, file.filename),
      versionLabel,
      publishedAt: publishedAt && /^\d{4}-\d{2}-\d{2}$/.test(publishedAt) ? `${publishedAt}T00:00:00.000Z` : null,
      now,
    });
    if (outcome.status === "error") return res.status(422).type("text").send(`Could not read that benchmark: ${outcome.error}`);
    const notice = outcome.status === "unchanged" ? `${file.filename} was already loaded.` : `${file.filename} loaded as ${outcome.key} ${outcome.versionLabel ?? ""}: ${outcome.summary}`;
    res.redirect(303, `/standards/cis-benchmarks?notice=${encodeURIComponent(notice)}`);
  });

  app.get("/sources", (req, res) => {
    const q = req.query as Record<string, unknown>;
    const notice = typeof q.fetched === "string" && typeof q.status === "string" ? { sourceId: q.fetched, status: q.status, detail: typeof q.detail === "string" ? q.detail : "" } : null;
    res.type("html").send(renderSources({ db, ...who(req, res), notice }));
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
    res.status(404).type("html").send(renderNotFound(shown, lookState(req, config)));
  });

  app.use((error: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error(error);
    res.status(500).type("text").send("Something went wrong on the server. The log has the detail.");
  });

  return app;
}
