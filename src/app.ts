import { setSiteBase } from "./pages/layout.ts";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { createGzip, gzipSync } from "node:zlib";
import express, { type Express, type NextFunction, type Request, type Response } from "express";

import { ApiRefusal, apiChanges, apiDigest, apiItems, apiStandards, apiTriage, apiVuln, apiVulns, type ApiQuery } from "./api.ts";

import { authState, isKnownDevice, issueSession, knownDeviceCookieHeader, LoginThrottle, passwordMatches, RateWindow, sameOriginOnly, sessionCookieHeader, throttleKey, WorkBudget } from "./auth.ts";

import type { Config } from "./config.ts";
import { countRows, databaseBytes } from "./db.ts";
import { type HttpGet } from "./http.ts";

import { handleMcpRequest, maxMcpRequestBytes } from "./mcp.ts";

import { renderLogin } from "./pages/login.ts";
import { renderNotFound } from "./pages/not-found.ts";

import { type ReadText, type Resolve } from "./netscan.ts";

import { getBlob } from "./blobs.ts";
import { readBrand, readBrandMarks, type BrandKind } from "./branding.ts";

import { isLook, isScheme, lookCookieHeaders, lookState, type LookState } from "./look.ts";
import { safeBack } from "./paths.ts";
import { productName, productVersion } from "./version.ts";
import { nodeDns, type DnsLookup, type TlsProbe } from "./domaincheck.ts";
import { robotsText } from "./feeds.ts";
import { mountBaselines } from "./routes/baselines.ts";
import { publicDir, type RouteContext } from "./routes/context.ts";
import { mountDesk } from "./routes/desk.ts";
import { mountFeeds } from "./routes/feeds.ts";
import { mountNews } from "./routes/news.ts";

import { mountScan } from "./routes/scan.ts";
import { mountSearch } from "./routes/search.ts";
import { mountStandards } from "./routes/standards.ts";
import { mountReading } from "./routes/today.ts";
import { mountVulnerabilities } from "./routes/vulnerabilities.ts";

import { storageReport } from "./housekeeping.ts";
import { nodeReverse, VisitRecorder, visitKind, type ReverseLookup } from "./visits.ts";
import { metricsText, pipelineHealth } from "./pipeline.ts";

/**
 * The Express app, assembled: security headers and body limits, the MCP endpoint, the assets, the
 * read-only API, health and metrics, sign-in and the look switch, the read gate that decides who is
 * asking, and then one mount call per area under src/routes/. Nothing about a page lives here.
 */
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
  /** Replaces the resolver and the TLS handshake for the domain check in tests. */
  dns?: DnsLookup;
  tls?: TlsProbe;
  /** Replaces the reverse DNS the visit count names a reader's network by, in tests. */
  reverse?: ReverseLookup;
  /** Set by createApp when visits are counted, so a test can wait for the network names to be written. */
  visits?: VisitRecorder;
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

/** Text worth compressing; a zip, a PDF, an image or a font is compressed already, and an event stream must not wait for a buffer. */
const compressibleType = /^(text\/(?!event-stream)|application\/(json|javascript|xml|rss\+xml|atom\+xml|xhtml\+xml|manifest\+json|ld\+json|x-ndjson)|image\/svg\+xml)/i;
/** Below this a response goes as it is: gzip's header and the CPU cost outweigh the bytes saved. */
const gzipThreshold = 8 * 1024;

/**
 * gzip for text responses over 8 KB, with node:zlib and no dependency. A page here runs to 100 KB
 * of HTML and the stylesheet to 60 KB, compressed to a fifth. Only when the request accepts gzip,
 * never for HEAD, a 304, a 206, a 204 or a body something already encoded; Vary: Accept-Encoding on every
 * compressible answer, its 304s and 206s included, so a shared cache keeps the two apart. It works at res.write/res.end, after
 * Express has set the ETag and answered a conditional request with 304, so that behaviour is
 * unchanged (the weak ETag names the content, which is the same either way).
 */
function gzipText(req: Request, res: Response, next: NextFunction): void {
  const accepts = /\bgzip\b/i.test(String(req.headers["accept-encoding"] ?? "")) && req.method !== "HEAD";
  const write = res.write.bind(res) as (chunk: unknown, encoding?: BufferEncoding) => boolean;
  const end = res.end.bind(res) as (chunk?: unknown, encoding?: BufferEncoding) => Response;
  let decided: "plain" | "gzip" | null = null;
  let gzip: ReturnType<typeof createGzip> | null = null;
  const toBuffer = (chunk: unknown, encoding?: unknown): Buffer | null =>
    chunk === undefined || chunk === null || typeof chunk === "function" ? null : Buffer.isBuffer(chunk) ? chunk : typeof chunk === "string" ? Buffer.from(chunk, typeof encoding === "string" ? (encoding as BufferEncoding) : "utf8") : chunk instanceof Uint8Array ? Buffer.from(chunk) : null;
  // Decided once, at the first byte, from the headers as they stand then.
  const decide = (firstLength: number | null, ending: boolean): "plain" | "gzip" => {
    if (decided) return decided;
    decided = "plain";
    if (res.headersSent || res.statusCode < 200 || res.statusCode === 204) return decided;
    const type = String(res.getHeader("Content-Type") ?? "");
    // A 304 or a 206 is never compressed, but it carries the Vary its full answer would, so a
    // shared cache revalidating one variant does not hand it to a client that asked for the other.
    // Express strips a 304's Content-Type, so a 304 is given it whatever its type was.
    if (res.statusCode === 304 || res.statusCode === 206) {
      if (res.statusCode === 304 || compressibleType.test(type)) res.vary("Accept-Encoding");
      return decided;
    }
    if (!compressibleType.test(type) || res.getHeader("Content-Encoding")) return decided;
    const declared = Number(res.getHeader("Content-Length"));
    const length = Number.isFinite(declared) && declared > 0 ? declared : ending ? (firstLength ?? 0) : null;
    if (length !== null && length < gzipThreshold) return decided;
    res.vary("Accept-Encoding");
    if (!accepts || /\bno-transform\b/i.test(String(res.getHeader("Cache-Control") ?? ""))) return decided;
    res.setHeader("Content-Encoding", "gzip");
    res.removeHeader("Content-Length");
    // A byte range of the plain body means nothing against the gzip stream.
    res.removeHeader("Accept-Ranges");
    decided = "gzip";
    return decided;
  };
  res.write = ((chunk: unknown, encoding?: unknown, callback?: unknown): boolean => {
    const buffer = toBuffer(chunk, encoding);
    if (decide(buffer?.length ?? 0, false) === "plain") return write.call(res, chunk, encoding as BufferEncoding);
    if (!gzip) {
      gzip = createGzip();
      gzip.on("data", (data: Buffer) => write(data));
      gzip.on("end", () => end());
    }
    if (buffer) gzip.write(buffer);
    if (typeof callback === "function") (callback as () => void)();
    else if (typeof encoding === "function") (encoding as () => void)();
    return true;
  }) as Response["write"];
  res.end = ((chunk?: unknown, encoding?: unknown, callback?: unknown): Response => {
    const buffer = toBuffer(chunk, encoding);
    if (decide(buffer?.length ?? 0, true) === "plain") return end.call(res, chunk, encoding as BufferEncoding);
    const done = typeof callback === "function" ? callback : typeof encoding === "function" ? encoding : typeof chunk === "function" ? chunk : null;
    if (gzip) {
      // A streamed body (express.static): the rest goes through the same stream, which ends the response.
      if (buffer) gzip.write(buffer);
      gzip.end();
      if (done) res.once("finish", done as () => void);
      return res;
    }
    // One body handed over whole (res.send): compressed at once, with its length.
    const body = gzipSync(buffer ?? Buffer.alloc(0));
    res.setHeader("Content-Length", body.length);
    if (done) res.once("finish", done as () => void);
    return end.call(res, body);
  }) as Response["end"];
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
  // A second brake on the connection's own address. The default proxy trust believes every
  // private address, so a LAN host could rotate X-Forwarded-For and start the count afresh each
  // try; forty failures in ten minutes from one peer end its turn whatever address it claims.
  const peerThrottle = new LoginThrottle(40, 10 * 60 * 1000);
  const app = express();
  setSiteBase(config.baseUrl);
  app.disable("x-powered-by");
  app.set("etag", "weak");
  app.set("trust proxy", config.trustedProxies);
  app.use(securityHeaders);
  app.use(gzipText);
  // Who reads the site (src/visits.ts): each finished page, feed or API answer to anyone but the
  // owner, counted here on the server, so nothing runs in the reader's browser and the CSP stays
  // as strict as it is. The read gate further down has not run yet, so the owner is read from the
  // session when the answer is finished; the path is the original one, before any mount stripped it.
  if (config.visits) {
    const visits = new VisitRecorder(db, { reverse: ctx.reverse ?? nodeReverse(), forward: ctx.dns ?? nodeDns(), timeZone: config.timeZone, log: (line) => console.error(line) });
    ctx.visits = visits;
    app.use((req, res, next) => {
      res.once("finish", () => {
        try {
          const path = new URL(req.originalUrl, "http://visit.invalid").pathname;
          const kind = visitKind(req.method, path, res.statusCode, String(res.getHeader("Content-Type") ?? ""));
          if (!kind || res.locals.owner === true || authState(req, config, now().getTime()).owner) return;
          visits.record({
            at: now(),
            ip: req.ip,
            host: req.hostname ?? "",
            path,
            kind,
            status: res.statusCode,
            userAgent: req.get("user-agent") ?? "",
            acceptLanguage: Boolean(req.get("accept-language")),
            fetchMetadata: Boolean(req.get("sec-fetch-mode")),
            country: req.get("cf-ipcountry"),
            referer: req.get("referer"),
            optOut: req.get("sec-gpc") === "1" || req.get("dnt") === "1",
          });
        } catch (error) {
          console.error("[visits]", error instanceof Error ? error.message : String(error));
        }
      });
      next();
    });
  }
  if (config.baseUrl.startsWith("https://")) {
    // Behind TLS (a tunnel or a proxy), tell browsers to stay on it.
    app.use((_req, res, next) => {
      res.setHeader("Strict-Transport-Security", "max-age=15552000");
      next();
    });
  }
  // The baseline builder's form carries one checkbox per rule, a few hundred fields; everything else stays small.
  app.use("/baselines", express.urlencoded({ extended: false, limit: "1mb", parameterLimit: 5000 }));
  // The device report is one field holding a package list; a Linux one runs to a hundred kilobytes or two.
  app.use("/scan/devices", express.urlencoded({ extended: false, limit: "2mb" }));
  app.use(express.urlencoded({ extended: false, limit: "16kb" }));

  // The MCP endpoint: the read-only API as tools for agents. It sits before the same-origin guard
  // because its clients are programs, not pages, and nothing it offers writes. Stateless: one
  // server and transport per POST, no sessions, so GET (a stream) and DELETE (a session) are not.
  //
  // It is the one route an anonymous caller can make the database work hard on, and it sits ahead
  // of the same-origin guard, so it carries its own allowance: generous enough that an agent
  // working through a question never notices, narrow enough that it is not a free amplifier.
  const mcpCalls = new RateWindow(120, 60_000);
  // Anonymous heavy work (the table, search, the builder, the API, MCP) shares twenty seconds a
  // minute across every address, a third of the event loop at most; one address may spend five of
  // them, and when all twenty are gone an address that has had one second still is refused while a
  // light reader is served.
  const anonymousWork = new WorkBudget(20_000, 60_000, 5_000, 1_000);
  const busy = "The site is busy; try again in half a minute.";
  const heavySelf = "This address has asked for a lot of the site's time this minute; try again in a minute.";
  // What is charged is the event loop's time, not the reader's wait. A route that renders in one
  // go is charged until it finishes (or the client resets the socket, which still made the query
  // run). A route that waits on the network (the domain check, the InternetDB lookup) sets
  // res.locals.uncharged and carries its own allowances: it is charged only for the part that ran
  // before its first wait (res.locals.syncMs, set by the gate below), never for seconds spent
  // waiting on someone else's server.
  const timed = (req: Request, res: Response): void => {
    const started = performance.now();
    const key = throttleKey(req.ip, 56);
    let charged = false;
    const charge = (): void => {
      if (charged) return;
      charged = true;
      const wall = performance.now() - started;
      const sync = typeof res.locals.syncMs === "number" ? res.locals.syncMs : wall;
      anonymousWork.spend(key, res.locals.uncharged === true ? sync : wall, now().getTime());
    };
    res.once("finish", charge);
    res.once("close", charge);
  };
  // The pages a stranger can make the database work hardest on (the table under any filter, its CSV,
  // search, the baseline builder, the API, the News and its feed under a filter) carry an allowance
  // per address, an IPv6 /56 being one address: a reader never meets it, a loop that would hold the
  // event loop does. Together they also draw on the shared budget above. The owner is not counted.
  const heavyReads = new RateWindow(90, 60_000);
  /** Counts one anonymous heavy read; false when it was refused, with the answer already sent. */
  const heavyAllowed = (req: Request, res: Response, light = false): boolean => {
    if (!heavyReads.allow(throttleKey(req.ip, 56), now().getTime())) {
      res.status(429).set("Retry-After", "60").type("text").send("Too many requests from this address for these pages; ninety a minute is the allowance. Try again in a minute.");
      return false;
    }
    return budgetAllowed(req, res, light);
  };
  /**
   * Charges any anonymous request's time to the budget; false when the address or everyone is out of it.
   * A light request (an image, the unfiltered News, a CVE's own page) is refused only when this
   * address has spent its own share, never because others have spent everyone's.
   */
  const budgetAllowed = (req: Request, res: Response, light = false): boolean => {
    let budget = anonymousWork.check(throttleKey(req.ip, 56), now().getTime());
    if (budget === "busy" && light) budget = "ok";
    if (budget !== "ok") {
      res.status(budget === "self" ? 429 : 503).set("Retry-After", budget === "self" ? "60" : "30").type("text").send(budget === "self" ? heavySelf : busy);
      return false;
    }
    timed(req, res);
    return true;
  };
  // Parsed here, not by the transport, so a batch can be counted before any of it runs.
  app.post("/mcp", express.json({ limit: maxMcpRequestBytes }), async (req, res) => {
    const state = authState(req, config, now().getTime());
    if (!config.publicRead && !state.owner) {
      res.status(401).json({ jsonrpc: "2.0", error: { code: -32001, message: "Reading is not public on this instance; sign in first." }, id: null });
      return;
    }
    // A JSON-RPC batch is many calls in one POST; each one counts, and a stranger's batch is short.
    const calls = Array.isArray(req.body) ? req.body.length : 1;
    if (!state.owner && calls > 5) {
      res.status(400).json({ jsonrpc: "2.0", error: { code: -32600, message: "A batch of more than five calls is not taken from an anonymous caller." }, id: null });
      return;
    }
    let allowed = true;
    for (let i = 0; i < calls && allowed; i++) allowed = state.owner || mcpCalls.allow(throttleKey(req.ip, 56), now().getTime());
    if (!allowed) {
      res.status(429).set("Retry-After", "60").json({ jsonrpc: "2.0", error: { code: -32000, message: "Too many calls from this address; a hundred and twenty a minute is the allowance." }, id: null });
      return;
    }
    if (!state.owner) {
      const budget = anonymousWork.check(throttleKey(req.ip, 56), now().getTime());
      if (budget !== "ok") {
        res.status(budget === "self" ? 429 : 503).set("Retry-After", budget === "self" ? "60" : "30").json({ jsonrpc: "2.0", error: { code: -32000, message: budget === "self" ? heavySelf : busy }, id: null });
        return;
      }
      timed(req, res);
    }
    try {
      await handleMcpRequest(db, config.baseUrl, req, res, req.body);
    } catch (error) {
      console.error("[mcp]", error instanceof Error ? error.message : String(error));
      if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error." }, id: null });
    }
  });
  const postOnly = (_req: Request, res: Response): void => {
    res.status(405).set("Allow", "POST").json({ jsonrpc: "2.0", error: { code: -32000, message: "This MCP endpoint is stateless: POST only." }, id: null });
  };
  app.get("/mcp", postOnly);
  app.delete("/mcp", postOnly);

  app.use(sameOriginOnly);
  // The stylesheet's address carries a hash of its bytes (`?v=`), so any change is a new address and that
  // one can be kept a year; everything else under /assets, the scan scripts among it, keeps the hour.
  app.use(
    "/assets",
    express.static(publicDir, {
      index: false,
      fallthrough: true,
      cacheControl: false,
      setHeaders: (res, file) => {
        const versioned = path.basename(file) === "app.css" && typeof (res as unknown as Response).req.query.v === "string";
        res.setHeader("Cache-Control", versioned ? "public, max-age=31536000, immutable" : "public, max-age=3600");
      },
    }),
  );
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
    if (!state.owner && !heavyAllowed(req, res)) return;
    handler(req, res);
  };
  app.get("/api/v1/items", apiRead((req, res) => json(res, { items: apiItems(db, req.query as ApiQuery, config.baseUrl, authState(req, config, now().getTime()).owner) })));
  app.get("/api/v1/vulns", apiRead((req, res) => json(res, apiVulns(db, req.query as ApiQuery, now(), authState(req, config, now().getTime()).owner))));
  app.get("/api/v1/vulns/:cve", apiRead((req, res) => {
    const v = apiVuln(db, String(req.params.cve), authState(req, config, now().getTime()).owner);
    if (!v) return res.status(404).json({ error: "no such CVE" });
    json(res, v);
  }));
  app.get("/api/v1/standards", apiRead((_req, res) => json(res, { standards: apiStandards(db, config.baseUrl) })));
  app.get("/api/v1/changes", apiRead((req, res) => json(res, { changes: apiChanges(db, req.query as ApiQuery, config.baseUrl) })));
  app.get("/api/v1/triage", apiRead((req, res) => json(res, { triage: apiTriage(db, req.query as ApiQuery, config.baseUrl, authState(req, config, now().getTime()).owner) })));
  app.get("/api/v1/digest", apiRead((req, res) => json(res, { digest: apiDigest(db, authState(req, config, now().getTime()).owner) })));

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
    const owner = authState(req, config, at.getTime()).owner;
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
          exploits: countRows(db, "exploits"),
          msrcVulns: countRows(db, "msrc_vulns"),
          certificates: owner ? countRows(db, "ct_certs") : null,
          deviceReadings: owner ? countRows(db, "device_readings") : null,
        },
        bytes: { database: storage.databaseBytes, snapshots: storage.snapshotBytes },
        images: storage.imageBlobs,
        housekeeping: storage.lastRun
          ? {
              ranAt: storage.lastRun.ranAt,
              snapshotsDeleted: storage.lastRun.snapshotsDeleted,
              blobsDeleted: storage.lastRun.blobsDeleted,
              networkScansDeleted: storage.lastRun.networkScansDeleted,
              deviceReadingsDeleted: owner ? (storage.lastRun.deviceReadingsDeleted ?? 0) : null,
              vacuumed: storage.lastRun.vacuumed,
            }
          : null,
        uptimeSeconds: Math.round((Date.now() - ctx.startedAt) / 1000),
      }),
    );
  });

  // Everything from here on is a page, and a page differs for the owner: their triage notes,
  // their sources, their branding form, the controls on every list. This app is meant to sit
  // behind a tunnel or a reverse proxy (BW_TRUSTED_PROXIES, an https base URL), and a shared
  // cache there would be entitled to store the owner's copy and hand it to the next visitor —
  // twenty-one pages said nothing at all about caching before the audit of 25 October. The
  // assets, the branding images, /img and the feeds set their own directives after this and so
  // keep their long or public caches; `no-cache` means revalidate, not "do not store", so a
  // private cache in the owner's own browser still works as it did.
  app.use((_req, res, next) => {
    res.setHeader("Cache-Control", "private, no-cache");
    res.setHeader("Vary", "Cookie");
    next();
  });

  /**
   * Whether a cookie may be marked `Secure`, decided from what this instance knows rather than
   * from a header a peer can write. `req.secure` reads `X-Forwarded-Proto`, which the default
   * proxy trust believes from every private address — so a LAN host could send
   * `X-Forwarded-Proto: https` to a plain-HTTP instance, get the session cookie marked `Secure`,
   * and the browser would then refuse to send it: the owner cannot stay signed in, and nothing
   * says why. The configured base URL is the owner's own statement, and `encrypted` is the real
   * socket; neither is forgeable from the outside.
   */
  const secureCookies = (req: Request): boolean => config.baseUrl.startsWith("https://") || (req.socket as { encrypted?: boolean }).encrypted === true;

  // Sign-in is reachable even when reading is closed.
  app.get("/login", (req, res) => {
    const state = authState(req, config, now().getTime());
    res.type("html").send(renderLogin({ next: safeBack(req.query.next, "/"), open: state.open, look: lookOf(req) }));
  });
  app.post("/login", (req, res) => {
    const state = authState(req, config, now().getTime());
    const next = safeBack(((req.body ?? {}) as Record<string, unknown>).next, "/");
    if (state.open) return res.redirect(303, next);
    // A /56 per sign-in key, as on the heavy pages: one household cannot rotate through 256 fresh brakes.
    const key = throttleKey(req.ip, 56);
    const peer = throttleKey(req.socket.remoteAddress ?? undefined);
    // A browser the owner signed in from before is let past the peer's brake, which behind a tunnel is everyone's.
    const known = isKnownDevice(req, config, now().getTime());
    if (throttle.blocked(key, now().getTime()) || (!known && peerThrottle.blocked(peer, now().getTime()))) {
      return res.status(429).type("html").send(renderLogin({ next, open: false, error: "Too many attempts. Wait ten minutes and try again.", look: lookOf(req) }));
    }
    const given = ((req.body ?? {}) as Record<string, unknown>).password;
    // The configured password is read trimmed, so the typed one is compared the same way.
    if (typeof given !== "string" || !config.adminPassword || !passwordMatches(config.adminPassword, given.trim())) {
      throttle.fail(key, now().getTime());
      peerThrottle.fail(peer, now().getTime());
      return res.status(401).type("html").send(renderLogin({ next, open: false, error: "That password is not right.", look: lookOf(req) }));
    }
    throttle.clear(key);
    peerThrottle.clear(peer);
    res.setHeader("Set-Cookie", [sessionCookieHeader(config, issueSession(config, now().getTime()), secureCookies(req)), knownDeviceCookieHeader(config, now().getTime(), secureCookies(req))]);
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

  // A crawler is told the truth ahead of the gate: a closed instance has nothing to index.
  app.get("/robots.txt", (_req, res) => {
    res.type("text/plain").send(robotsText(config.publicRead, config.baseUrl));
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
    // A form posted after the session lapsed: say so, and offer the way back to the page it came
    // from rather than a bare line of text that loses the reader's place.
    let from = "/";
    try {
      const referer = req.get("referer");
      if (referer) {
        const u = new URL(referer);
        if (u.host === req.get("host")) from = safeBack(u.pathname + u.search, "/");
      }
    } catch {
      // An unparseable Referer is no place to go back to.
    }
    // A page asked for (a CSV, the triage board) is where to go after signing in; a form sent is
    // lost, so the way back is the page it was sent from, and the reader is told it was not saved.
    const sent = req.method !== "GET" && req.method !== "HEAD";
    res.status(403).type("html").send(renderLogin({ next: sent ? from : safeBack(req.originalUrl, "/"), open: false, error: sent ? "Only the owner can do that. If you were signed in, the sign-in has lapsed: sign in again and you will be taken back. What you sent was not saved." : "That page is the owner's. Sign in to see it.", look: lookOf(req) }));
  };
  const who = (req: Request, res: Response): { owner: boolean; open: boolean; look: LookState } => ({ owner: res.locals.owner === true, open: res.locals.open === true, look: lookOf(req) });
  // The heavy pages' allowance (defined with the budget above; the API counts in apiRead).
  const heavyPath = /^\/(vulnerabilities|search|baselines)(\/|\.csv|$)/i;
  const filteredNews = /^\/(feed\.xml)?$/i;
  const cvePage = /^\/vulnerabilities\/CVE-\d{4}-\d+$/i;
  app.use((req, res, next) => {
    // Case-blind and HEAD-aware, as Express's own routing is: /SEARCH and a HEAD do the same work.
    if (res.locals.owner === true || (req.method !== "GET" && req.method !== "HEAD" && req.method !== "POST")) return next();
    // The named pages carry the per-address allowance as well; every other page still draws on the
    // budget, since /controls?q=, /today and the standards' pages cost as much as some of them.
    const heavy = heavyPath.test(req.path) || (filteredNews.test(req.path) && Object.keys(req.query).length > 0);
    // The pages a reader comes for are never turned away because others have spent the shared
    // budget: an image, the News unfiltered, a CVE's own page, each cacheable and cheap.
    const plain = (req.method === "GET" || req.method === "HEAD") && Object.keys(req.query).length === 0;
    const light = /^\/img\//.test(req.path) || (plain && (req.path === "/" || cvePage.test(req.path)));
    if (!(heavy ? heavyAllowed(req, res, light) : budgetAllowed(req, res, light))) return;
    // The handler's own time on the event loop: everything up to its first wait runs inside next().
    const started = performance.now();
    next();
    res.locals.syncMs = performance.now() - started;
  });
  const routeContext: RouteContext = { app, config, db, now, ctx, lookOf, who, requireOwner, secureCookies, brandMarks };
  mountNews(routeContext);
  mountReading(routeContext);
  mountStandards(routeContext);
  mountScan(routeContext);
  mountBaselines(routeContext);
  mountVulnerabilities(routeContext);
  mountFeeds(routeContext);
  mountSearch(routeContext);
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

  app.use((error: Error & { status?: number; statusCode?: number; type?: string }, _req: Request, res: Response, _next: NextFunction) => {
    // The body parser throws for a request that is the client's fault — too large for the route's
    // limit, or not the encoding it claims — with the status it means. That is an answer to send,
    // not a failure to log: a 20 kB triage note is a 413, and the log stays for real faults.
    const status = error.status ?? error.statusCode;
    // The API's own refusals (a release id that is unknown, licensed or restricted: one 404, so it
    // never says which exist) answer in JSON with their reason.
    if (error instanceof ApiRefusal) {
      res.status(error.status).json({ error: error.message });
      return;
    }
    if (typeof status === "number" && status >= 400 && status < 500) {
      res.status(status).type("text").send(status === 413 ? "That request is larger than this page accepts." : "That request could not be read.");
      return;
    }
    console.error(error);
    res.status(500).type("text").send("Something went wrong on the server. The log has the detail.");
  });

  return app;
}
