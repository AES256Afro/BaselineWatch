import { checkDomain, nodeDns, nodeTls, parseSelectors, validDomain, type DomainReport } from "../domaincheck.ts";
import { httpGet } from "../http.ts";
import { renderScanDomain } from "../pages/scan-domain.ts";
import type { Request, Response } from "express";
import path from "node:path";

import { flashHeader, flashText } from "../flash.ts";

import { renderScan, renderScanWhy } from "../pages/scan.ts";
import { isGuidePlatform, renderScanGuide, renderScanGuideIndex } from "../pages/scan-guide.ts";
import { renderScanNetwork } from "../pages/scan-network.ts";
import { netScanEnabled, netSettingKeys, networkSummary, runNetworkScan, setSetting } from "../netscan.ts";
import { probeGif, probePaths, resolverCheckSources } from "../scan.ts";
import { readScanScripts, scanScriptFiles, sumsFile, sumsText } from "../scan-scripts.ts";

import { parseNotifyUrl } from "../notify.ts";

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
  app.get("/scan", (req, res) => {
    res.setHeader("Content-Security-Policy", scanPolicy(config.probeOrigin));
    res.setHeader("Cache-Control", "no-store");
    res.type("html").send(renderScan({ ...who(req, res), probeOrigin: config.probeOrigin, network: networkSummary(db) }));
  });
  // Check a domain (S3): lookups only, from this server. A visitor may ask about any public name,
  // so each answer is kept ten minutes and each address gets a dozen checks in that time.
  const domainDeps = { dns: ctx.dns ?? nodeDns(), tls: ctx.tls ?? nodeTls(), http: ctx.http ?? httpGet, now };
  const reports = new Map<string, { at: number; report: DomainReport }>();
  const asked = new Map<string, number[]>();
  const tenMinutes = 10 * 60_000;
  const ownDomains = (): string[] => ((db.prepare("SELECT value FROM app_settings WHERE key = 'scan.domains'").get() as { value: string } | undefined)?.value ?? "").split(",").map((d) => d.trim()).filter((d) => d);
  app.get("/scan/domain", async (req, res) => {
    const query = req.query as Record<string, unknown>;
    const typed = str(query.name, 260);
    const selectorText = str(query.selectors, 200) ?? "";
    const base = { ...who(req, res), selectors: selectorText, own: ownDomains() };
    res.setHeader("Cache-Control", "no-store");
    if (!typed) return res.type("html").send(renderScanDomain({ ...base, domain: null, report: null, problem: null }));
    const domain = validDomain(typed);
    if (!domain) return res.status(400).type("html").send(renderScanDomain({ ...base, domain: typed.slice(0, 80), report: null, problem: `“${typed.slice(0, 80)}” is not a public domain name this check can read.` }));
    const selectors = parseSelectors(selectorText);
    const key = `${domain}|${selectors.join(",")}`;
    const t = now().getTime();
    const cached = reports.get(key);
    if (cached && t - cached.at < tenMinutes) return res.type("html").send(renderScanDomain({ ...base, domain, report: cached.report, problem: null }));
    const recent = (asked.get(req.ip ?? "?") ?? []).filter((at) => t - at < tenMinutes);
    if (recent.length >= 12) return res.status(429).type("html").send(renderScanDomain({ ...base, domain, report: null, problem: "A dozen checks in ten minutes from this address; try again in a little while." }));
    asked.set(req.ip ?? "?", [...recent, t]);
    const report = await checkDomain(domain, domainDeps, { selectors });
    if (reports.size >= 200) reports.delete(reports.keys().next().value as string);
    reports.set(key, { at: t, report });
    res.type("html").send(renderScanDomain({ ...base, domain, report, problem: null }));
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
}

/**
 * The Scan page's own policy, the one exception to script-src 'none': its single self-hosted module
 * script, the probe images from this origin and from BW_PROBE_ORIGIN when set, and connections to
 * the two resolvers' self-check hosts. Still no inline script or style anywhere; every other route
 * keeps the policy above.
 */
function scanPolicy(probeOrigin: string | null): string {
  const img = probeOrigin ? `'self' data: ${probeOrigin}` : "'self' data:";
  return `default-src 'self'; script-src 'self'; style-src 'self'; img-src ${img}; font-src 'self'; connect-src 'self' ${resolverCheckSources.join(" ")}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`;
}
