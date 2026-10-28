import { checkDomain, nodeDns, nodeTls, parseSelectors, validDomain, type DnsLookup, type DomainReport } from "../domaincheck.ts";
import { HttpError, httpGet } from "../http.ts";
import { renderScanDomain } from "../pages/scan-domain.ts";
import { lookUpExposure, whatWasSeen, type RequestFacts } from "../seen.ts";
import { exposureKeys, runExposureScan, validRouterUrl } from "../exposure.ts";
import { recentCerts } from "../ct.ts";
import { privateAddress } from "../http.ts";
import { RateWindow, throttleKey } from "../auth.ts";
import { isIP } from "node:net";
import type { TLSSocket } from "node:tls";
import type { Request, Response } from "express";
import path from "node:path";

import { flashHeader, flashText } from "../flash.ts";

import { renderScan, renderScanWhy } from "../pages/scan.ts";
import { isGuidePlatform, renderScanGuide, renderScanGuideIndex } from "../pages/scan-guide.ts";
import { renderScanDevices } from "../pages/scan-devices.ts";
import { renderScanHistory } from "../pages/scan-history.ts";
import { isReleaseLine, latestBrowser, readDevice, readReport, type LatestRelease } from "../inventory.ts";
import { deleteDevice, deviceName, latestReadings, readingChanges, readingsOf, recordReading } from "../devices.ts";
import { renderScanNetwork } from "../pages/scan-network.ts";
import { netScanEnabled, netSettingKeys, networkSummary, runNetworkScan, setSetting } from "../netscan.ts";
import { probeGif, probePaths, resolverCheckSources } from "../scan.ts";
import { readScanScripts, scanScriptFiles, sumsFile, sumsText } from "../scan-scripts.ts";

import { parseNotifyUrl } from "../notify.ts";

import { safeFilename } from "../paths.ts";
import { str } from "./query.ts";
import { publicDir, type RouteContext } from "./context.ts";

/**
 * Scan: the one page with a script, the network check, the guides, the scripts and the probes. Mounted by createApp in app.ts, which hands over the
 * app, the config, the database, the clock and the helpers every route shares.
 */
export function mountScan(r: RouteContext): void {
  const { app, config, db, now, ctx, who, requireOwner, secureCookies } = r;
  // The Scan area (M12.1): the one page with a script, under its own policy; the why page and the
  // probe images stay under the strict one. The probes are one GIF at four names, never cached and
  // readable cross-site, so a second instance named by BW_PROBE_ORIGIN can serve the cross-site set.
  // The request as this server saw it (S2): the address Express resolved through the trusted
  // proxies, the headers, and the TLS protocol only when this process ended TLS itself.
  const facts = (req: Request): RequestFacts => {
    const socket = req.socket as Partial<TLSSocket>;
    return { ip: req.ip ?? null, headers: req.headers, protocol: req.protocol, httpVersion: req.httpVersion, tlsProtocol: typeof socket.getProtocol === "function" && socket.encrypted ? (socket.getProtocol() ?? null) : null };
  };
  const scanPage = (req: Request, res: Response, extra: { exposure?: Awaited<ReturnType<typeof lookUpExposure>> | null; exposureError?: string | null } = {}): void => {
    res.setHeader("Content-Security-Policy", scanPolicy(config.probeOrigin));
    res.setHeader("Cache-Control", "no-store");
    res.type("html").send(renderScan({ ...who(req, res), probeOrigin: config.probeOrigin, network: networkSummary(db), seen: whatWasSeen(db, facts(req)), ...extra }));
  };
  app.get("/scan", (req, res) => scanPage(req, res));
  // What this server received from a request the page's script made (S1): the Referer as it
  // arrived, and the transport. Readable cross-origin so a second origin can answer the same.
  app.get("/scan/echo", (req, res) => {
    const f = facts(req);
    const ip = (f.ip ?? "").replace(/^::ffff:/, "");
    const one = (v: string | string[] | undefined): string | null => (Array.isArray(v) ? (v[0] ?? null) : (v ?? null));
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Vary", "Origin");
    res.json({ referer: one(req.headers.referer), origin: one(req.headers.origin), secFetchSite: one(req.headers["sec-fetch-site"]), family: isIP(ip) === 6 ? "IPv6" : isIP(ip) === 4 ? "IPv4" : null, httpVersion: f.httpVersion, protocol: f.protocol, tls: f.tlsProtocol });
  });
  // One InternetDB lookup, of a public address, when the visitor asks; a visitor may ask about
  // their own address a few times, not about the internet.
  const lookedUp = new RateWindow(6, 10 * 60_000);
  // …and the instance as a whole has a ceiling. The per-address allowances below are keyed on the
  // /64, which one visitor cannot rotate past — but a thousand addresses each within their own
  // allowance still add up, and these two routes are the only ones where an anonymous request
  // costs this server a request of its own (a lookup, a handshake, a GET). The ceiling is the
  // difference between a slow afternoon and this instance being someone's scanner.
  const everyone = new RateWindow(600, 10 * 60_000);
  const ceiling = "This instance is answering as many of these as it will for now; the check costs it a request of its own. Try again in a little while.";
  app.post("/scan/exposure", async (req, res) => {
    const ip = (str(((req.body ?? {}) as Record<string, unknown>).ip, 64) ?? "").replace(/^::ffff:/, "");
    if (!isIP(ip) || privateAddress(ip)) return res.status(400).type("text").send("The lookup takes one public address.");
    // A visitor asks about the address they came from; the owner may ask about any.
    const own = (req.ip ?? "").replace(/^::ffff:/, "");
    if (res.locals.owner !== true && ip !== own) return res.status(403).type("text").send("A visitor may look up the address they are visiting from, and no other.");
    if (!lookedUp.allow(throttleKey(req.ip), now().getTime())) return res.status(429).type("text").send("Six lookups in ten minutes from this address; try again later.");
    if (!everyone.allow("scan", now().getTime())) return res.status(429).set("Retry-After", "600").type("text").send(ceiling);
    try {
      scanPage(req, res, { exposure: await lookUpExposure(ctx.http ?? httpGet, ip) });
    } catch (error) {
      // What went wrong, in the visitor's terms: never the URL asked or the error's own text.
      const code = (error as { code?: string; cause?: { code?: string } }).cause?.code ?? (error as { code?: string }).code;
      scanPage(req, res, { exposureError: error instanceof HttpError ? `InternetDB answered ${error.status}` : code ? `no answer from InternetDB (${code})` : "no answer from InternetDB" });
    }
  });
  // Check a domain (S3): lookups only, from this server. A visitor may ask about any public name,
  // so each answer is kept ten minutes and each address gets a dozen checks in that time.
  const domainDeps = { dns: ctx.dns ?? nodeDns(), tls: ctx.tls ?? nodeTls(), http: ctx.http ?? httpGet, now };
  // The resolver is the host's, which on a home server is the LAN's: a split-horizon name under a
  // real domain (nas.example.com → 192.168.1.20) answers with the inside address. A visitor is told
  // the name has one and not what it is; the owner, whose network it is, sees it.
  const outsideView = (dns: DnsLookup): DnsLookup => async (name, type) => {
    const answer = await dns(name, type);
    if (type !== "A" && type !== "AAAA") return answer;
    const shown = answer.records.filter((a) => !privateAddress(a));
    const hidden = answer.records.length - shown.length;
    return hidden === 0 ? answer : { ...answer, records: shown, detail: `${hidden} private address${hidden === 1 ? "" : "es"} not shown` };
  };
  const visitorDomainDeps = { ...domainDeps, dns: outsideView(domainDeps.dns) };
  const reports = new Map<string, { at: number; report: DomainReport }>();
  const tenMinutes = 10 * 60_000;
  const asked = new RateWindow(12, tenMinutes);
  const ownDomains = (): string[] => ((db.prepare("SELECT value FROM app_settings WHERE key = 'scan.domains'").get() as { value: string } | undefined)?.value ?? "").split(",").map((d) => d.trim()).filter((d) => d);
  app.get("/scan/domain", async (req, res) => {
    const query = req.query as Record<string, unknown>;
    const typed = str(query.name, 260);
    const selectorText = str(query.selectors, 200) ?? "";
    // The owner's list of domains, and the certificates logged for them, are the owner's to see.
    const own = res.locals.owner === true ? ownDomains() : [];
    const base = { ...who(req, res), selectors: selectorText, own };
    res.setHeader("Cache-Control", "no-store");
    if (!typed) return res.type("html").send(renderScanDomain({ ...base, domain: null, report: null, problem: null }));
    const domain = validDomain(typed);
    const certs = domain && own.includes(domain) ? recentCerts(db, domain) : [];
    if (!domain) return res.status(400).type("html").send(renderScanDomain({ ...base, domain: typed.slice(0, 80), report: null, problem: `“${typed.slice(0, 80)}” is not a public domain name this check can read.` }));
    const selectors = parseSelectors(selectorText);
    const owner = res.locals.owner === true;
    // Kept apart: the owner's answer can carry inside addresses a visitor's must not.
    const key = `${owner ? "owner" : "visitor"}|${domain}|${selectors.join(",")}`;
    const t = now().getTime();
    const cached = reports.get(key);
    if (cached && t - cached.at < tenMinutes) return res.type("html").send(renderScanDomain({ ...base, domain, report: cached.report, problem: null, certs }));
    if (!asked.allow(throttleKey(req.ip), t)) return res.status(429).type("html").send(renderScanDomain({ ...base, domain, report: null, problem: "A dozen checks in ten minutes from this address; try again in a little while." }));
    if (!everyone.allow("scan", t)) return res.status(429).set("Retry-After", "600").type("html").send(renderScanDomain({ ...base, domain, report: null, problem: ceiling }));
    const report = await checkDomain(domain, owner ? domainDeps : visitorDomainDeps, { selectors });
    if (reports.size >= 200) reports.delete(reports.keys().next().value as string);
    reports.set(key, { at: t, report });
    res.type("html").send(renderScanDomain({ ...base, domain, report, problem: null, certs }));
  });
  app.post("/scan/domain/own", requireOwner, (req, res) => {
    const typed = str(((req.body ?? {}) as Record<string, unknown>).domains, 500) ?? "";
    const domains = [...new Set(typed.split(",").map((d) => validDomain(d)).filter((d): d is string => d !== null))].slice(0, 20);
    setSetting(db, "scan.domains", domains.length ? domains.join(",") : null, now().toISOString());
    res.redirect(303, "/scan/domain");
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
  // The guide's scripts and their sums, read once at mount: the device page lists them to download
  // and the guide pages link them, and hashing every file twice at start said nothing extra.
  const scanScripts = readScanScripts(path.join(publicDir, "scan"));
  // Is this device affected? (S7): the owner pastes the inventory script's report; it is read and answered, never stored.
  app.get("/scan/devices", (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    const w = who(req, res);
    const device = deviceName((req.query as Record<string, unknown>).device);
    const history = w.owner && device ? { device, readings: readingsOf(db, device) } : null;
    res.type("html").send(renderScanDevices({ ...w, scripts: scanScripts, now: now(), devices: w.owner ? latestReadings(db) : [], history }));
  });
  app.post("/scan/devices", requireOwner, async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    const w = who(req, res);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const text = str(body.report, 2_000_000) ?? "";
    const device = deviceName(body.device);
    if (!device) return res.status(400).type("html").send(renderScanDevices({ ...w, scripts: scanScripts, now: now(), devices: latestReadings(db), problem: "Name the device: letters, digits, spaces, a dot or a dash, up to sixty characters." }));
    let report;
    try {
      report = readReport(text);
    } catch (error) {
      return res.status(400).type("html").send(renderScanDevices({ ...w, scripts: scanScripts, now: now(), devices: latestReadings(db), problem: error instanceof Error ? error.message : String(error) }));
    }
    const findings = await readDevice(db, ctx.http ?? httpGet, report);
    const previous = readingsOf(db, device, 1)[0] ?? null;
    const reading = recordReading(db, device, report, findings, now().toISOString());
    const changes = readingChanges(previous, reading);
    res.type("html").send(renderScanDevices({ ...w, scripts: scanScripts, now: now(), report, findings, devices: latestReadings(db), recorded: { device, ...changes } }));
  });
  app.post("/scan/devices/forget", requireOwner, (req, res) => {
    const device = deviceName(((req.body ?? {}) as Record<string, unknown>).device);
    if (!device || deleteDevice(db, device) === 0) return res.status(404).type("text").send("No readings under that name.");
    res.redirect(303, "/scan/devices");
  });
  // The browser check's version row asks what the vendor feeds say is newest (S1).
  app.get("/scan/browser-check", (req, res) => {
    const query = req.query as Record<string, unknown>;
    const browser = str(query.browser, 20)?.toLowerCase();
    const version = str(query.version, 40) ?? null;
    res.setHeader("Cache-Control", "no-store");
    if (!isReleaseLine(browser)) return res.status(400).json({ error: "browser is chrome, firefox, safari, edge, ios or ipados" });
    const latest: LatestRelease | null = latestBrowser(db, browser, version);
    res.json(latest ? { browser, latest: latest.version, newerLine: latest.newerLine, newer: latest.newer.slice(0, 8).map((n) => ({ title: n.title, url: n.url, version: n.version, published: n.published_at })) } : { browser, latest: null, newerLine: null, newer: [] });
  });
  app.get("/scan/history", (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.type("html").send(renderScanHistory({ db, ...who(req, res), now: now() }));
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
  // Router and exposure (S4): the owner's switches, and a run on demand.
  app.post("/scan/exposure/settings", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const at = now().toISOString();
    const on = str(body.on) === "1";
    setSetting(db, exposureKeys.enabled, on ? "1" : null, at);
    if (str(body.keep) !== "1") {
      const typed = str(body.router_url, 200);
      const router = typed ? validRouterUrl(typed) : null;
      if (typed && !router) return res.status(400).type("text").send("The router address is http or https to a private address or a LAN name, with no credentials.");
      setSetting(db, exposureKeys.routerUrl, router, at);
      setSetting(db, exposureKeys.vendor, str(body.vendor, 60)?.toLowerCase().replace(/[^a-z0-9._-]/g, "") || null, at);
      setSetting(db, exposureKeys.model, str(body.model, 60) ?? null, at);
    }
    res.append("Set-Cookie", flashHeader(on ? "Exposure check on; it runs daily, or press Run now." : "Exposure check off. The last run stays.", secureCookies(req)));
    res.redirect(303, "/scan/network#exposure");
  });
  app.post("/scan/exposure/run", requireOwner, async (req, res) => {
    const run = await runExposureScan(db, { http: ctx.http ?? httpGet, now, transport: parseNotifyUrl(config.notifyUrl), baseUrl: config.baseUrl, log: (line) => console.log(line) });
    res.append("Set-Cookie", flashHeader(`Ran: ${run.findings.filter((f) => f.state === "bad" || f.state === "warn").length} finding(s), public address ${run.publicIp ?? "unknown"}.`, secureCookies(req)));
    res.redirect(303, "/scan/network#exposure");
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
    res.setHeader("Content-Disposition", `inline; filename="${safeFilename(file)}"`);
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
}

/**
 * The Scan page's own policy, the one exception to script-src 'none': its single self-hosted module
 * script, the probe images from this origin and from BW_PROBE_ORIGIN when set, and connections to
 * the two resolvers' self-check hosts. Still no inline script or style anywhere; every other route
 * keeps the policy above.
 */
function scanPolicy(probeOrigin: string | null): string {
  const img = probeOrigin ? `'self' data: ${probeOrigin}` : "'self' data:";
  const connect = probeOrigin ? `'self' ${probeOrigin} ${resolverCheckSources.join(" ")}` : `'self' ${resolverCheckSources.join(" ")}`;
  return `default-src 'self'; script-src 'self'; style-src 'self'; img-src ${img}; font-src 'self'; connect-src ${connect}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`;
}
