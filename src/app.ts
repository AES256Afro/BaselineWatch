import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import express, { type Express, type NextFunction, type Request, type Response } from "express";
import { cisAdapter, cisKey } from "./adapters/cis.ts";
import type { ItemKind, PullSettings } from "./adapters/types.ts";
import { apiChanges, apiDigest, apiItems, apiStandards, apiTriage, apiVuln, apiVulns, type ApiQuery } from "./api.ts";
import { boundaryOf, parseMultipart } from "./multipart.ts";
import { authState, issueSession, LoginThrottle, passwordMatches, sameOriginOnly, sessionCookieHeader, throttleKey } from "./auth.ts";
import { flashHeader, flashText, takeFlash } from "./flash.ts";
import type { Config } from "./config.ts";
import { countRows, databaseBytes } from "./db.ts";
import { httpGet, type HttpGet } from "./http.ts";
import { getSource, ingestSource, setSourceEnabled, storeUploadedDocument, type IngestResult } from "./ingest.ts";
import { handleMcpRequest } from "./mcp.ts";
import { renderAppearance } from "./pages/appearance.ts";
import { renderCatalog } from "./pages/catalog.ts";
import { renderControls } from "./pages/controls.ts";
import { renderHome } from "./pages/home.ts";
import { renderLogin } from "./pages/login.ts";
import { renderNotFound } from "./pages/not-found.ts";
import { renderBrowse, renderControl, renderRelease, renderStandard } from "./pages/register.ts";
import { renderSources } from "./pages/sources.ts";
import { renderStigPlatform, renderStigsIndex } from "./pages/stigs.ts";
import { renderBaselinesIndex, renderBuilder } from "./pages/baselines.ts";
import { renderDecide, renderDecisionBoard } from "./pages/decisions.ts";
import { decisionsCsv, isDecisionKind, saveDecision } from "./decisions.ts";
import { renderTestPlan } from "./pages/testplans.ts";
import { renderPlatforms } from "./pages/platforms.ts";
import { buildTestPlan, exportPlan, isArea, isPlanFormat, isPlanPlatform, type PlanOptions } from "./testplans.ts";
import { buildProfile, isBuilderPlatform, isSectionId, sectionOf, type ProfileOptions } from "./baselines.ts";
import { exportProfile, isExportFormat, isFlavour, publicProfile, type Flavour } from "./exports.ts";
import { isPlatformId, type Cat } from "./stigs.ts";
import { renderAtlas } from "./pages/atlas.ts";
import { renderDigest } from "./pages/digest.ts";
import { renderGuide } from "./pages/guide.ts";
import { renderScan, renderScanWhy } from "./pages/scan.ts";
import { isGuidePlatform, renderScanGuide, renderScanGuideIndex } from "./pages/scan-guide.ts";
import { renderScanNetwork } from "./pages/scan-network.ts";
import { netScanEnabled, netSettingKeys, networkSummary, runNetworkScan, setSetting, type ReadText, type Resolve } from "./netscan.ts";
import { probeGif, probePaths, resolverCheckSources } from "./scan.ts";
import { readScanScripts, scanScriptFiles, sumsFile, sumsText } from "./scan-scripts.ts";
import { renderToday } from "./pages/today.ts";
import { renderTriage } from "./pages/triage.ts";
import { renderVulnDetail, renderVulnList } from "./pages/vulnerabilities.ts";
import { renderWatchlist } from "./pages/watchlist.ts";
import { renderNews } from "./pages/wire.ts";
import { getBlob } from "./blobs.ts";
import { applyBrandMark, clearBrandImage, isBrandKind, maxBrandBytes, readBrand, readBrandMarks, saveBrandImage, type BrandKind } from "./branding.ts";
import { renderBranding } from "./pages/branding.ts";
import { imageFor } from "./images.ts";
import { isLook, isScheme, lookCookieHeaders, lookState, type LookState } from "./look.ts";
import { safeBack } from "./paths.ts";
import { productName, productVersion } from "./version.ts";
import { isPlatformKey, platformKeys } from "./platforms.ts";
import { parsePackageValue, recomputeWatchHits, type VulnFilters } from "./vulns.ts";
import { writeDigest } from "./digest.ts";
import { notify, parseNotifyUrl } from "./notify.ts";
import { storageReport } from "./housekeeping.ts";
import { checkLatestRelease, metricsText, pipelineHealth } from "./pipeline.ts";
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
  /** Replaces DNS and the host's files for the network scan in tests. */
  resolve?: Resolve;
  readFile?: ReadText;
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

// Control characters other than tab and line breaks are stripped: a NUL in a search term would be an FTS5 syntax error.
const str = (v: unknown, max = 200): string | undefined => {
  if (typeof v !== "string") return undefined;
  const clean = v.replace(/(?![\t\n\r])\p{Cc}/gu, "").trim();
  return clean === "" ? undefined : clean.slice(0, max);
};

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
  const severity = str(query.severity)?.toLowerCase();
  // A window in hours: "1" is the 24 h the links have always carried; the Today page sends its own (72, 168).
  const hours = (v: unknown): number | undefined => {
    const s = str(v);
    if (!s) return undefined;
    if (s === "1") return 24;
    const n = Number(s);
    return Number.isInteger(n) && n >= 1 && n <= 24 * 90 ? n : undefined;
  };
  const sinceHours = (h: number | undefined): string | undefined => (h === undefined ? undefined : new Date(now.getTime() - h * 60 * 60 * 1000).toISOString());
  const changedHours = hours(query.changed);
  const newHours = hours(query.new);
  const platform = str(query.platform);
  return {
    watch: str(query.watch) === "1",
    kev: str(query.kev) === "1",
    platform: isPlatformKey(platform) ? platform : undefined,
    minCvss: num(query.min_cvss),
    severity: severity === "critical" || severity === "high" || severity === "medium" || severity === "low" || severity === "unscored" ? severity : undefined,
    minEpss: num(query.min_epss),
    maxEpss: num(query.max_epss),
    noEpss: str(query.epss) === "none",
    changedSince: sinceHours(changedHours),
    changedHours,
    newSince: sinceHours(newHours),
    newHours,
    label: str(query.label, 60),
    q: str(query.q),
    sort: sort === "published" || sort === "cvss" || sort === "epss" ? sort : "modified",
    // A whole number SQLite can bind, capped: 1e300 or 1.5 would be a datatype mismatch and a 500.
    offset: offset !== undefined && offset >= 0 && Number.isSafeInteger(Math.floor(offset)) ? Math.min(Math.floor(offset), 1_000_000) : 0,
  };
}

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
    res.type("html").send(renderScan({ ...who(req, res), probeOrigin: config.probeOrigin, network: networkSummary(db) }));
  });
  app.get("/scan/why", (req, res) => {
    res.type("html").send(renderScanWhy(who(req, res)));
  });

  // The network check (M12.3): the stored daily scan, and the owner's switches. The scan is
  // opt-in because it sends packets on the owner's network; the dashboard tokens are stored in
  // app_settings, used only against the address the owner gave, and never rendered.
  app.get("/scan/network", (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.type("html").send(renderScanNetwork({ db, ...who(req, res), now: now(), notice: flashText(req, res, secureCookies(req)) }));
  });
  app.post("/scan/network/enable", requireOwner, (req, res) => {
    const on = str(((req.body ?? {}) as Record<string, unknown>).on) === "1";
    setSetting(db, netSettingKeys.enabled, on ? "1" : null, now().toISOString());
    res.append("Set-Cookie", flashHeader(on ? "The daily network scan is on; the first run happens on the scheduler's next pass, or press Run now." : "The daily network scan is off. Stored runs stay.", secureCookies(req)));
    res.redirect(303, "/scan/network");
  });
  app.post("/scan/network/run", requireOwner, async (req, res) => {
    if (!netScanEnabled(db)) return res.status(400).type("text").send("Turn the network scan on first; it sends packets on your network.");
    const scan = await runNetworkScan(db, {
      now,
      transport: parseNotifyUrl(config.notifyUrl),
      baseUrl: config.baseUrl,
      log: (line) => console.log(line),
      ...(ctx.http ? { http: ctx.http } : {}),
      ...(ctx.resolve ? { resolve: ctx.resolve } : {}),
      ...(ctx.readFile ? { readFile: ctx.readFile } : {}),
    });
    const counted = (db.prepare("SELECT COUNT(*) AS n FROM net_canaries WHERE scan_id = ?").get(scan.id) as { n: number }).n;
    res.append("Set-Cookie", flashHeader(scan.error && counted === 0 ? `The run found nothing to resolve: ${scan.error}.` : `Ran: ${counted} canaries resolved through ${scan.resolver ?? "no resolver"}.`, secureCookies(req)));
    res.redirect(303, "/scan/network");
  });
  app.post("/scan/network/settings", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const lanUrl = (value: string): string | null => {
      try {
        const url = new URL(value);
        if (!/^https?:$/.test(url.protocol) || url.username || url.password) return null;
        return value.replace(/\/+$/, "");
      } catch {
        return null;
      }
    };
    // An empty field keeps the stored value; a whitespace-only one clears it; anything else replaces it.
    const fields: [string, string, boolean][] = [
      ["pihole_url", netSettingKeys.piholeUrl, true],
      ["pihole_token", netSettingKeys.piholeToken, false],
      ["adguard_url", netSettingKeys.adguardUrl, true],
      ["adguard_token", netSettingKeys.adguardToken, false],
    ];
    for (const [field, key, isUrl] of fields) {
      const raw = body[field];
      if (typeof raw !== "string" || raw === "") continue;
      const value = raw.trim().slice(0, 500);
      if (value === "") {
        setSetting(db, key, null, now().toISOString());
        continue;
      }
      if (isUrl) {
        const url = lanUrl(value);
        if (!url) return res.status(400).type("text").send(`${field} must be an http(s) address such as http://192.0.2.10.`);
        setSetting(db, key, url, now().toISOString());
      } else setSetting(db, key, value, now().toISOString());
    }
    res.append("Set-Cookie", flashHeader("Saved. Tokens are stored on this instance and never shown again.", secureCookies(req)));
    res.redirect(303, "/scan/network");
  });
  // The manual guide (M12.2) and its scripts: static files under public/scan, read once so the sums
  // shown beside the links are of the bytes served, and served as plain text so a person can read a
  // script in the browser before downloading it. Every one of these pages keeps the strict policy.
  const scanScripts = readScanScripts(path.join(publicDir, "scan"));
  app.get("/scan/guide", (req, res) => {
    res.type("html").send(renderScanGuideIndex({ ...who(req, res), scripts: scanScripts }));
  });
  app.get("/scan/guide/:platform", (req, res, next) => {
    const platform = String(req.params.platform);
    if (!isGuidePlatform(platform)) return next();
    res.type("html").send(renderScanGuide(platform, { ...who(req, res), scripts: scanScripts }));
  });
  app.get("/scan/scripts/:file", (req, res, next) => {
    const file = String(req.params.file);
    if (!scanScriptFiles.includes(file)) return next();
    const script = scanScripts.find((s) => s.file === file);
    const body = file === sumsFile ? Buffer.from(sumsText(scanScripts), "utf8") : script?.content;
    if (!body) return next();
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Content-Disposition", `inline; filename="${file}"`);
    res.setHeader("Cache-Control", "public, max-age=300");
    res.send(body);
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
    const back = safeBack(((req.body ?? {}) as Record<string, unknown>).back, "/");
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
    const body = (req.body ?? {}) as Record<string, unknown>;
    markAllRead(db, wireFilters(body));
    res.redirect(303, safeBack(body.back, "/"));
  });

  // The ladder's third rung (/guide#ladder): one rule at a time, across every standard's current version.
  app.get("/controls", (req, res) => {
    const state = authState(req, config, now().getTime());
    const q = typeof req.query.q === "string" ? req.query.q.slice(0, 200) : undefined;
    res.type("html").send(renderControls({ db, q, now: now(), owner: state.owner, open: state.open, look: lookOf(req) }));
  });

  app.get("/appearance", (req, res) => {
    const state = authState(req, config, now().getTime());
    res.type("html").send(renderAppearance({ owner: state.owner, open: state.open, look: lookOf(req) }));
  });

  app.get("/standards", (req, res) => {
    res.type("html").send(renderCatalog({ db, ...who(req, res), now: now() }));
  });
  app.get("/standards/:source", (req, res, next) => {
    const html = renderStandard({ db, sourceId: String(req.params.source), ...who(req, res), now: now(), notice: flashText(req, res, secureCookies(req)) });
    if (!html) return next();
    res.type("html").send(html);
  });
  app.get("/standards/:source/:doc", (req, res, next) => {
    const documentId = Number(req.params.doc);
    if (!Number.isInteger(documentId) || documentId <= 0) return next();
    const html = renderRelease({ db, sourceId: String(req.params.source), documentId, family: str(req.query.family, 40), ...who(req, res), now: now() });
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
    // A reader who is not the owner takes the profile without Microsoft's values: on screen only, never in bulk.
    const out = exportProfile(who(req, res).owner ? profile : publicProfile(profile), format, flavourOf(fields), { baseUrl: config.baseUrl, generatedAt: now().toISOString(), version: productVersion });
    res.setHeader("Content-Disposition", `attachment; filename="${out.filename}"`);
    res.setHeader("Cache-Control", "no-store");
    res.type(out.contentType).send(out.body);
  };
  app.get("/baselines/:platform/export", (req, res, next) => sendExport(req, res, next, req.query as Record<string, unknown>));

  // Decisions: the owner's answer to each item's recommendation (apply, modify, exclude), stored.
  // The board lists them per platform (and as CSV); the decide page shows one item against its
  // recommendation. CAT III rules are included so a decision on one is always reachable.
  const decisionProfile = (platform: ProfileOptions["platform"], fields: Record<string, unknown>) => buildProfile(db, { platform, stig: str(fields.stig, 160), mscp: str(fields.mscp, 160), sct: str(fields.sct, 160), cat3: true });
  app.get("/baselines/:platform/decisions", (req, res, next) => {
    const platform = String(req.params.platform);
    if (!isBuilderPlatform(platform)) return next();
    const saved = Number(str(req.query.saved, 6) ?? "");
    res.type("html").send(renderDecisionBoard({ profile: decisionProfile(platform, req.query as Record<string, unknown>), ...(Number.isInteger(saved) && saved >= 0 && req.query.saved !== undefined ? { saved } : {}), ...who(req, res) }));
  });
  app.get("/baselines/:platform/decisions.csv", (req, res, next) => {
    const platform = String(req.params.platform);
    if (!isBuilderPlatform(platform)) return next();
    const profile = decisionProfile(platform, req.query as Record<string, unknown>);
    res.setHeader("Content-Disposition", `attachment; filename="baselinewatch-${platform}-decisions.csv"`);
    res.setHeader("Cache-Control", "no-store");
    // Microsoft's values are quoted on screen only: a reader who is not the owner downloads the decisions without them.
    res.type("text/csv; charset=utf-8").send(decisionsCsv(who(req, res).owner ? profile : publicProfile(profile), config.baseUrl));
  });
  app.get("/baselines/:platform/decide", (req, res, next) => {
    const platform = String(req.params.platform);
    if (!isBuilderPlatform(platform)) return next();
    const id = str(req.query.item, 300);
    const profile = decisionProfile(platform, req.query as Record<string, unknown>);
    const item = id ? profile.items.find((i) => i.id === id) : undefined;
    if (!item) return next();
    res.type("html").send(renderDecide({ profile, item, saved: str(req.query.saved) === "1", ...who(req, res) }));
  });
  app.post("/baselines/:platform/decide", requireOwner, (req, res, next) => {
    const platform = String(req.params.platform);
    if (!isBuilderPlatform(platform)) return next();
    const fields = (req.body ?? {}) as Record<string, unknown>;
    const id = str(fields.item, 300);
    const item = id ? decisionProfile(platform, fields).items.find((i) => i.id === id) : undefined;
    if (!item || !isDecisionKind(fields.decision)) return void res.status(400).type("text").send("Pick an item and a decision.");
    saveDecision(db, platform, item.id, { decision: fields.decision, value: str(fields.value, 500) ?? null, reason: str(fields.reason, 2000) ?? null, owner: str(fields.owner, 120) ?? null }, now());
    res.redirect(303, `/baselines/${platform}/decide?item=${encodeURIComponent(item.id)}&saved=1`);
  });
  // The builder's unticked items, recorded as not applying in one go, with one reason for all of them.
  app.post("/baselines/:platform/decide-unticked", requireOwner, (req, res, next) => {
    const platform = String(req.params.platform);
    if (!isBuilderPlatform(platform)) return next();
    const fields = (req.body ?? {}) as Record<string, unknown>;
    const profile = buildProfile(db, profileOptions(platform, fields));
    const reason = str(fields.reason, 2000) ?? null;
    const owner = str(fields.owner, 120) ?? null;
    let saved = 0;
    // One transaction for the whole set: all the exclusions land, or none do, and one fsync rather than hundreds.
    db.exec("BEGIN IMMEDIATE");
    try {
      for (const item of profile.items) {
        if (item.included || item.decision?.decision === "exclude") continue;
        saveDecision(db, platform, item.id, { decision: "exclude", reason, owner }, now());
        saved += 1;
      }
      db.exec("COMMIT");
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
    res.redirect(303, `/baselines/${platform}/decisions?saved=${saved}`);
  });
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
    const base: PlanOptions = { platform, stig: str(fields.stig, 160), mscp: str(fields.mscp, 160), cat3: str(fields.cat3) === "1", templates: applied ? str(fields.templates) === "1" : str(fields.templates) !== "0", version: str(fields.version, 40), hardware: str(fields.hardware, 60), areas: chosen, style: str(fields.style, 20) };
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
  // Renamed from Platforms to Fleet (it is the owner's own inventory, and src/fleet.ts always
  // called it that); the old address keeps working the way /wire does.
  app.get("/platforms", (_req, res) => {
    res.redirect(301, "/fleet");
  });
  app.get("/fleet", (req, res) => {
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
    res.type("html").send(renderWatchlist({ db, ...who(req, res), notice: flashText(req, res, secureCookies(req)) }));
  });
  app.post("/watchlist", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
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
    res.append("Set-Cookie", flashHeader(`Added ${value}; ${changed} CVE(s) re-marked.`, secureCookies(req)));
    res.redirect(303, "/watchlist");
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
    res.type("html").send(renderTriage({ db, ...who(req, res), now: now(), notice: flashText(req, res, secureCookies(req)), dismissed: str(req.query.dismissed) === "1" }));
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
    const body = (req.body ?? {}) as Record<string, unknown>;
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
    const body = (req.body ?? {}) as Record<string, unknown>;
    const subject = triageSubject(body);
    if (subject) clearTriage(db, subject);
    res.redirect(303, safeBack(body.back, "/triage"));
  });

  app.get("/digest", (req, res) => {
    res.type("html").send(renderDigest({ db, ...who(req, res), now: now(), period: config.digest, hour: config.digestHour, timeZone: config.timeZone, notifyConfigured: parseNotifyUrl(config.notifyUrl) !== null, baseUrl: config.baseUrl }));
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
      // Leaving the loop early must not destroy the socket, or the 413 never reaches the browser.
      for await (const chunk of req.iterator({ destroyOnReturn: false })) {
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
    const form = parseMultipart(Buffer.concat(chunks), boundary);
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
    res.append("Set-Cookie", flashHeader(notice, secureCookies(req)));
    res.redirect(303, "/standards/cis-benchmarks");
  });

  app.get("/sources", (req, res) => {
    // The outcome of a Fetch now, or of a Turn on or Turn off, rides over in the flash cookie, never in the query string, so no link can forge one.
    const flash = takeFlash(req, res, secureCookies(req)) as { sourceId?: unknown; status?: unknown; detail?: unknown } | undefined;
    const notice =
      flash && typeof flash.sourceId === "string" && typeof flash.status === "string"
        ? { sourceId: flash.sourceId.slice(0, 80), status: flash.status.slice(0, 20), detail: typeof flash.detail === "string" ? flash.detail.slice(0, 1200) : "" }
        : null;
    res.type("html").send(renderSources({ db, ...who(req, res), notice }));
  });
  // Turning a source on or off: the scheduler reads the flag on its next pass; what was loaded stays.
  const setEnabled = (enabled: boolean) => (req: Request, res: Response) => {
    const source = getSource(db, String(req.params.id));
    if (!source) return res.status(404).type("text").send("No such source.");
    setSourceEnabled(db, source.id, enabled);
    const detail = enabled ? `checked ${source.schedule} from the scheduler's next pass; Fetch now runs it at once` : "no longer fetched; what was loaded stays on the Register";
    res.append("Set-Cookie", flashHeader({ sourceId: source.id, status: enabled ? "enabled" : "disabled", detail }, secureCookies(req)));
    res.redirect(303, `/sources#src-${source.id}`);
  };
  // Branding (the Desk): the owner picks one of the repo's marks or uploads an image, and every
  // page wears it at once. The bytes go to the blob store; app_settings carries hash and type.
  app.get("/branding", (req, res) => {
    res.type("html").send(renderBranding({ brand: readBrand(db), marks: brandMarks, ...who(req, res), notice: flashText(req, res, secureCookies(req)) }));
  });
  app.get("/branding/marks/:id", (req, res, next) => {
    const mark = brandMarks.find((m) => m.id === String(req.params.id));
    if (!mark) return next();
    res.setHeader("Cache-Control", "public, max-age=86400");
    res.type("image/svg+xml").send(Buffer.from(mark.bytes));
  });
  app.post("/branding/mark", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const kind = str(body.kind, 10);
    const mark = brandMarks.find((m) => m.id === str(body.mark, 80));
    if (!isBrandKind(kind) || !mark) return res.status(400).type("text").send("Pick a mark and whether it is the logo or the favicon.");
    applyBrandMark(db, config.dataDir, kind, mark, now().toISOString());
    res.append("Set-Cookie", flashHeader(`${mark.title} is now the ${kind}, on every page at once.`, secureCookies(req)));
    res.redirect(303, "/branding");
  });
  app.post("/branding/:kind", requireOwner, async (req, res, next) => {
    const kind = String(req.params.kind);
    if (!isBrandKind(kind)) return next();
    const boundary = boundaryOf(req.headers["content-type"]);
    if (!boundary) return res.status(400).type("text").send("Send the image as multipart/form-data.");
    const chunks: Buffer[] = [];
    let size = 0;
    // The image plus the form's own framing; what the file itself may hold is branding.ts's call.
    const limit = maxBrandBytes + 16 * 1024;
    try {
      // Leaving the loop early must not destroy the socket, or the 413 never reaches the browser.
      for await (const chunk of req.iterator({ destroyOnReturn: false })) {
        size += (chunk as Buffer).length;
        if (size > limit) {
          res.status(413).type("text").send("That file is larger than 2 MB.");
          return;
        }
        chunks.push(chunk as Buffer);
      }
    } catch {
      return res.status(400).type("text").send("The upload did not complete.");
    }
    const form = parseMultipart(Buffer.concat(chunks), boundary);
    const file = form.files.find((f) => f.field === "image") ?? form.files[0];
    if (!file || file.bytes.length === 0) return res.status(400).type("text").send("No image was attached.");
    const outcome = saveBrandImage(db, config.dataDir, kind, file.bytes, now().toISOString());
    if (!outcome.ok) return res.status(422).type("text").send(`Could not use ${file.filename}: ${outcome.error}.`);
    res.append("Set-Cookie", flashHeader(`${file.filename} is now the ${kind}, on every page at once.`, secureCookies(req)));
    res.redirect(303, "/branding");
  });
  app.post("/branding/:kind/remove", requireOwner, (req, res, next) => {
    const kind = String(req.params.kind);
    if (!isBrandKind(kind)) return next();
    clearBrandImage(db, kind);
    res.append("Set-Cookie", flashHeader(kind === "logo" ? "The logo is removed; the masthead carries the wordmark alone." : "The favicon is removed.", secureCookies(req)));
    res.redirect(303, "/branding");
  });

  // The one request this product makes about itself, and only when the owner asks for it (M13.2).
  app.post("/sources/check-version", requireOwner, async (req, res) => {
    const result = await checkLatestRelease(db, ctx.http ?? httpGet, now());
    res.append(
      "Set-Cookie",
      flashHeader(
        {
          sourceId: "this instance",
          status: result.version ? "ok" : "error",
          detail: result.version
            ? result.newer
              ? `${result.version} is published; this instance runs ${productVersion}`
              : `${productVersion} is the newest release`
            : "GitHub did not answer with a version",
        },
        secureCookies(req),
      ),
    );
    res.redirect(303, "/sources#storage");
  });

  app.post("/sources/:id/enable", requireOwner, setEnabled(true));
  app.post("/sources/:id/disable", requireOwner, setEnabled(false));
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
    res.append("Set-Cookie", flashHeader({ sourceId: source.id, status: result.status, detail }, secureCookies(req)));
    res.redirect(303, `/sources#src-${source.id}`);
  });

  app.use((req, res) => {
    let shown = req.path;
    try {
      shown = decodeURIComponent(req.path);
    } catch {
      // A malformed escape sequence is shown as sent.
    }
    res.status(404).type("html").send(renderNotFound(shown, lookOf(req)));
  });

  app.use((error: Error & { status?: number; statusCode?: number; type?: string }, _req: Request, res: Response, _next: NextFunction) => {
    // The body parser throws for a request that is the client's fault — too large for the route's
    // limit, or not the encoding it claims — with the status it means. That is an answer to send,
    // not a failure to log: a 20 kB triage note is a 413, and the log stays for real faults.
    const status = error.status ?? error.statusCode;
    if (typeof status === "number" && status >= 400 && status < 500) {
      res.status(status).type("text").send(status === 413 ? "That request is larger than this page accepts." : "That request could not be read.");
      return;
    }
    console.error(error);
    res.status(500).type("text").send("Something went wrong on the server. The log has the detail.");
  });

  return app;
}
