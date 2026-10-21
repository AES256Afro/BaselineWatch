import { isIP } from "node:net";
import type { DatabaseSync } from "node:sqlite";
import { localClock } from "./digest.ts";
import { HttpError, privateAddress, type HttpGet } from "./http.ts";
import { parseJson } from "./json.ts";
import { getSetting, setSetting } from "./netscan.ts";
import { notify, type Transport } from "./notify.ts";
import { lookUpExposure, type Exposure } from "./seen.ts";

/**
 * Router and exposure (Scan 2.0, S4): what the internet sees of this network and what the router
 * gives away on the LAN, read once a day from this server and stored so a change is a finding.
 * The public address comes from Cloudflare's trace (a host the network check already contacts),
 * InternetDB says what Shodan last saw of it, the router's admin page is read for whether it
 * redirects to HTTPS and what it announces, and the vendor and model the owner typed are matched
 * against the CVE table and the KEV. Owner-only, opt-in like the network check: it names the
 * owner's own address and ports. Nothing is scanned from here; no packet goes to a host that did
 * not ask for one, and the router is asked for its front page alone.
 */

export const exposureKeys = {
  enabled: "exposure.enabled",
  routerUrl: "exposure.router_url",
  vendor: "exposure.router_vendor",
  model: "exposure.router_model",
  last: "exposure.last",
  previous: "exposure.previous",
} as const;

/** Cloudflare's trace, which answers `ip=` for whoever asks; the same host answers the DNSSEC question. */
export const traceUrl = "https://cloudflare-dns.com/cdn-cgi/trace";

export type ExposureState = "ok" | "warn" | "bad" | "na";

export interface ExposureFinding {
  id: "public-address" | "internet" | "router-admin" | "router-firmware";
  title: string;
  state: ExposureState;
  text: string;
  quoted: string[];
}

export interface RouterRead {
  url: string;
  /** What http:// answered: a redirect to https, a page, or nothing. */
  plainStatus: number | null;
  redirectsToHttps: boolean;
  tlsStatus: number | null;
  server: string | null;
  title: string | null;
  error: string | null;
}

export interface FirmwareMatch {
  vendor: string;
  model: string | null;
  kev: string[];
  cves: { cve_id: string; cvss_score: number | null; kev: number; description: string | null }[];
}

export interface ExposureRun {
  at: string;
  publicIp: string | null;
  internet: Exposure | null;
  router: RouterRead | null;
  firmware: FirmwareMatch | null;
  findings: ExposureFinding[];
}

export interface ExposureDeps {
  http: HttpGet;
  now?: () => Date;
  transport?: Transport | null;
  baseUrl?: string;
  log?: (line: string) => void;
}

export function exposureEnabled(db: DatabaseSync): boolean {
  return getSetting(db, exposureKeys.enabled) === "1";
}

export function latestExposure(db: DatabaseSync): ExposureRun | null {
  return parseJson<ExposureRun | null>(getSetting(db, exposureKeys.last), null);
}

/** A router address as the owner types it: http or https to a private address or a LAN name, no credentials. */
export function validRouterUrl(value: string): string | null {
  try {
    const url = new URL(value.trim().includes("://") ? value.trim() : `http://${value.trim()}`);
    if (!/^https?:$/.test(url.protocol) || url.username || url.password) return null;
    const host = url.hostname.replace(/^\[|\]$/g, "");
    if (!host) return null;
    if (isIP(host) && !privateAddress(host)) return null;
    if (!isIP(host) && host.includes(".") && !/\.(local|lan|home|internal)$/i.test(host)) return null;
    return `${url.protocol}//${url.host}`;
  } catch {
    return null;
  }
}

/** The public address as Cloudflare's trace saw this server ask; null when it did not answer. */
export async function publicAddress(http: HttpGet): Promise<string | null> {
  try {
    const response = await http(traceUrl, { timeoutMs: 10_000, maxBytes: 8192, headers: { accept: "text/plain" } });
    const ip = /^ip=(.+)$/m.exec(new TextDecoder().decode(response.bytes))?.[1]?.trim() ?? "";
    return isIP(ip) && !privateAddress(ip) ? ip : null;
  } catch {
    return null;
  }
}

/** The router's front page, over plain HTTP first (does it redirect?) and then over TLS; the page's title and Server header, never its contents. */
export async function readRouter(http: HttpGet, url: string): Promise<RouterRead> {
  const read: RouterRead = { url, plainStatus: null, redirectsToHttps: false, tlsStatus: null, server: null, title: null, error: null };
  const origin = new URL(url);
  const titleOf = (bytes: Uint8Array): string | null => /<title[^>]*>([\s\S]*?)<\/title>/i.exec(new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(0, 65536)))?.[1]?.replace(/\s+/g, " ").trim().slice(0, 120) ?? null;
  try {
    const plain = await http(`http://${origin.host}/`, { timeoutMs: 8000, maxBytes: 256 * 1024, redirect: "manual", headers: { accept: "text/html" } });
    read.plainStatus = plain.status;
    read.server = plain.headers?.server ?? null;
    read.title = titleOf(plain.bytes);
  } catch (error) {
    if (error instanceof HttpError) {
      read.plainStatus = error.status;
      read.redirectsToHttps = /^https:\/\//i.test(error.headers.location ?? "");
      read.server = error.headers.server ?? null;
    } else {
      read.error = (error as { code?: string; cause?: { code?: string } }).cause?.code ?? (error as { code?: string }).code ?? (error instanceof Error ? error.message : String(error));
    }
  }
  try {
    const secure = await http(`https://${origin.host}/`, { timeoutMs: 8000, maxBytes: 256 * 1024, headers: { accept: "text/html" } });
    read.tlsStatus = secure.status;
    read.server = read.server ?? secure.headers?.server ?? null;
    read.title = read.title ?? titleOf(secure.bytes);
  } catch (error) {
    if (error instanceof HttpError) read.tlsStatus = error.status;
    else if (read.error === null) read.error = (error as { code?: string; cause?: { code?: string } }).cause?.code ?? (error as { code?: string }).code ?? null;
  }
  return read;
}

/** CVEs in the table whose vendor is the router's and, when a model is named, that name the model; the KEV ones first. */
export function matchFirmware(db: DatabaseSync, vendor: string, model: string | null): FirmwareMatch {
  const v = vendor.trim().toLowerCase().replace(/\s+/g, "");
  const like = `%"${v}"%`;
  const rows = (
    model
      ? db.prepare("SELECT cve_id, cvss_score, kev, description FROM vulns WHERE lower(vendors_json) LIKE ? AND (lower(products_json) LIKE ? OR lower(description) LIKE ?) ORDER BY kev DESC, cvss_score DESC LIMIT 40").all(like, `%${model.trim().toLowerCase()}%`, `%${model.trim().toLowerCase()}%`)
      : db.prepare("SELECT cve_id, cvss_score, kev, description FROM vulns WHERE lower(vendors_json) LIKE ? AND kev = 1 ORDER BY cvss_score DESC LIMIT 40").all(like)
  ) as { cve_id: string; cvss_score: number | null; kev: number; description: string | null }[];
  return { vendor: vendor.trim(), model: model?.trim() || null, kev: rows.filter((r) => r.kev === 1).map((r) => r.cve_id), cves: rows };
}

/** The findings a run's facts add up to, each with what it rests on. */
export function judgeExposure(run: Omit<ExposureRun, "findings">): ExposureFinding[] {
  const out: ExposureFinding[] = [];
  out.push(run.publicIp ? { id: "public-address", title: "Public address", state: "ok", text: `This network reaches the internet as ${run.publicIp}, as Cloudflare's trace saw this server ask.`, quoted: [`ip=${run.publicIp}`] } : { id: "public-address", title: "Public address", state: "na", text: "Cloudflare's trace did not answer, so the public address is unknown this run.", quoted: [] });
  if (run.internet) {
    const i = run.internet;
    if (i.nothing) out.push({ id: "internet", title: "What the internet sees", state: "ok", text: "Shodan has nothing on record for this address: no open port, no known flaw. The good answer.", quoted: [] });
    else out.push({ id: "internet", title: "What the internet sees", state: i.vulns.length ? "bad" : "warn", text: `${i.ports.length} open port(s) on record${i.vulns.length ? ` and ${i.vulns.length} known flaw(s)` : ""}: a service your router or ISP exposes. Turn off remote management and UPnP, or forward only what you mean to.`, quoted: [`Ports: ${i.ports.join(", ") || "none"}`, ...(i.hostnames.length ? [`Hostnames: ${i.hostnames.slice(0, 6).join(", ")}`] : []), ...(i.cpes.length ? [`Software: ${i.cpes.slice(0, 6).join(", ")}`] : []), ...(i.vulns.length ? [`CVEs: ${i.vulns.slice(0, 12).join(", ")}`] : [])] });
  } else out.push({ id: "internet", title: "What the internet sees", state: "na", text: "No InternetDB answer this run.", quoted: [] });
  if (run.router) {
    const r = run.router;
    const quoted = [...(r.server ? [`Server: ${r.server}`] : []), ...(r.title ? [`Title: ${r.title}`] : [])];
    if (r.plainStatus === null && r.tlsStatus === null) out.push({ id: "router-admin", title: "Router admin page", state: "na", text: `${r.url} did not answer${r.error ? ` (${r.error})` : ""}: wrong address, or the admin page is off from this network.`, quoted });
    else if (r.redirectsToHttps || (r.plainStatus === null && r.tlsStatus !== null)) out.push({ id: "router-admin", title: "Router admin page", state: "ok", text: "The admin page is served over HTTPS; plain HTTP redirects to it or is not served.", quoted });
    else if (r.plainStatus !== null && r.plainStatus < 400) out.push({ id: "router-admin", title: "Router admin page", state: "warn", text: "The admin page is served over plain HTTP on the LAN: the password crosses the network in clear. Turn HTTPS on in the router if it offers it.", quoted });
    else out.push({ id: "router-admin", title: "Router admin page", state: "na", text: `The router answered ${r.plainStatus ?? r.tlsStatus} without a page.`, quoted });
  } else out.push({ id: "router-admin", title: "Router admin page", state: "na", text: "No router address is set; the owner names it under settings.", quoted: [] });
  if (run.firmware) {
    const f = run.firmware;
    const quoted = f.cves.slice(0, 8).map((c) => `${c.cve_id}${c.kev ? " (KEV)" : ""}${c.cvss_score !== null ? ` CVSS ${c.cvss_score.toFixed(1)}` : ""}: ${(c.description ?? "").slice(0, 100)}`);
    if (f.kev.length) out.push({ id: "router-firmware", title: "Router firmware", state: "bad", text: `${f.kev.length} CVE(s) for ${f.vendor}${f.model ? ` ${f.model}` : ""} are on CISA's Known Exploited Vulnerabilities list. Update the firmware today; the CVE page carries the vendor's advisory.`, quoted });
    else if (f.cves.length) out.push({ id: "router-firmware", title: "Router firmware", state: "warn", text: `${f.cves.length} CVE(s) in the table name ${f.vendor}${f.model ? ` ${f.model}` : ""}; none is on the KEV. Keep the firmware current.`, quoted });
    else out.push({ id: "router-firmware", title: "Router firmware", state: "ok", text: `No CVE in the table names ${f.vendor}${f.model ? ` ${f.model}` : ""}${f.model ? "" : " on the KEV"}.`, quoted: [] });
  } else out.push({ id: "router-firmware", title: "Router firmware", state: "na", text: "No vendor is set; the owner names the router's vendor and model under settings, and the table is searched for them.", quoted: [] });
  return out;
}

/** What changed between two runs that is worth a notification the moment it is seen. */
export function exposureChanges(previous: ExposureRun | null, current: ExposureRun): string[] {
  const lines: string[] = [];
  if (!previous) return lines;
  if (previous.publicIp && current.publicIp && previous.publicIp !== current.publicIp) lines.push(`The public address changed: ${previous.publicIp} → ${current.publicIp}.`);
  const before = new Set(previous.internet?.ports ?? []);
  const newPorts = (current.internet?.ports ?? []).filter((p) => !before.has(p));
  if (newPorts.length) lines.push(`Newly open on the public address: port(s) ${newPorts.join(", ")}.`);
  const knownVulns = new Set(previous.internet?.vulns ?? []);
  const newVulns = (current.internet?.vulns ?? []).filter((v) => !knownVulns.has(v));
  if (newVulns.length) lines.push(`Shodan now lists ${newVulns.join(", ")} for the public address.`);
  const knownKev = new Set(previous.firmware?.kev ?? []);
  const newKev = (current.firmware?.kev ?? []).filter((k) => !knownKev.has(k));
  if (newKev.length) lines.push(`Router firmware: ${newKev.join(", ")} added to the KEV.`);
  if (previous.router?.redirectsToHttps && current.router && !current.router.redirectsToHttps && current.router.plainStatus !== null && current.router.plainStatus < 400) lines.push("The router's admin page no longer redirects to HTTPS.");
  return lines;
}

/** One run: the facts, the findings, the stored result, and a notification only when something changed. */
export async function runExposureScan(db: DatabaseSync, deps: ExposureDeps): Promise<ExposureRun> {
  const now = deps.now ?? (() => new Date());
  const at = now().toISOString();
  const log = deps.log ?? (() => {});
  const publicIp = await publicAddress(deps.http);
  let internet: Exposure | null = null;
  if (publicIp) {
    try {
      internet = await lookUpExposure(deps.http, publicIp);
    } catch (error) {
      log(`[exposure] InternetDB did not answer: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  const routerUrl = getSetting(db, exposureKeys.routerUrl);
  const router = routerUrl ? await readRouter(deps.http, routerUrl) : null;
  const vendor = getSetting(db, exposureKeys.vendor);
  const firmware = vendor ? matchFirmware(db, vendor, getSetting(db, exposureKeys.model)) : null;
  const facts = { at, publicIp, internet, router, firmware };
  const run: ExposureRun = { ...facts, findings: judgeExposure(facts) };
  const previous = latestExposure(db);
  setSetting(db, exposureKeys.previous, previous ? JSON.stringify(previous) : null, at);
  setSetting(db, exposureKeys.last, JSON.stringify(run), at);
  const changes = exposureChanges(previous, run);
  log(`[exposure] ran: ${run.findings.map((f) => `${f.id}=${f.state}`).join(" ")}${changes.length ? `; ${changes.length} change(s)` : ""}`);
  if (changes.length) {
    await notify(db, deps.transport ?? null, { kind: "network", title: "Exposure changed", body: changes.join("\n"), url: deps.baseUrl ? `${deps.baseUrl}/scan/network#exposure` : null }, deps.http, now);
  }
  return run;
}

/** Due once per local date while on, like the network scan. */
export function exposureDue(db: DatabaseSync, timeZone: string, now: Date): boolean {
  if (!exposureEnabled(db)) return false;
  const last = latestExposure(db);
  if (!last) return true;
  return localClock(new Date(last.at), timeZone).dateKey !== localClock(now, timeZone).dateKey;
}

export async function maybeRunExposureScan(db: DatabaseSync, options: ExposureDeps & { timeZone: string }): Promise<boolean> {
  const now = options.now ?? (() => new Date());
  if (!exposureDue(db, options.timeZone, now())) return false;
  await runExposureScan(db, options);
  return true;
}
