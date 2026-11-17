import { Resolver } from "node:dns/promises";
import tls from "node:tls";
import { HttpError, privateAddress, resolveHost, type HttpGet } from "./http.ts";
import { parseJson } from "./json.ts";
import { counted } from "./words.ts";

/**
 * Check a domain (Scan 2.0, S3): its posture read by DNS and HTTPS alone, the way internet.nl
 * and Hardenize read it — DNSSEC, the addresses and name servers, SPF, DMARC, DKIM, MTA-STS,
 * TLS-RPT, CAA, HSTS and the other security headers, the certificate, security.txt. Every record
 * is quoted beside its verdict so the reader learns what the record says, not only that it
 * passed. Lookups only: DNS questions to the host's resolver, one DoH question to Cloudflare for
 * the DNSSEC verdict, and GETs of the domain's own front page and well-known files. No port is
 * probed beyond 443 (and 80, to see whether it redirects). The dependencies are injected so the
 * tests run against recorded answers.
 */

export type DnsType = "A" | "AAAA" | "NS" | "MX" | "TXT" | "CAA";

export interface DnsAnswer {
  records: string[];
  code: "ok" | "nxdomain" | "nodata" | "error";
  detail?: string;
}

export type DnsLookup = (name: string, type: DnsType) => Promise<DnsAnswer>;

export interface TlsFacts {
  protocol: string | null;
  cipher: string | null;
  issuer: string | null;
  subject: string | null;
  validTo: string | null;
  names: string[];
  /** Whether Node's trust store accepts the chain. */
  authorized: boolean;
  authorizationError: string | null;
}

export type TlsProbe = (host: string) => Promise<TlsFacts | { error: string }>;

export interface DomainDeps {
  dns: DnsLookup;
  http: HttpGet;
  tls: TlsProbe;
  now: () => Date;
}

export type FindingState = "ok" | "warn" | "bad" | "na";

export interface Finding {
  id: string;
  group: "names" | "mail" | "web";
  title: string;
  state: FindingState;
  text: string;
  /** The records or headers the verdict rests on, verbatim. */
  quoted: string[];
  /** MTA-STS only: the policy was longer than stsPolicyLines, so `quoted` holds part of it. */
  policyCut?: boolean;
}

export interface DomainReport {
  domain: string;
  checkedAt: string;
  durationMs: number;
  /** Whether the domain receives mail (an MX that is not the null MX). */
  mail: boolean;
  findings: Finding[];
  counts: Record<FindingState, number>;
}

/** The DoH question whose AD flag says whether the domain is DNSSEC-signed and validated; Cloudflare's resolver is already a probe host of the network check. */
export const dohJsonUrl = (name: string): string => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=A`;

/** DKIM selectors tried when none is named: the ones the common mail providers publish under. */
export const commonSelectors = ["google", "selector1", "selector2", "default", "k1", "dkim", "mail", "s1", "fm1", "zoho", "pm", "mg"];

// Names that never resolve on the public internet: RFC 2606 and 6761's (test, example, invalid,
// localhost), the special-use ones (local, onion, arpa, internal), and the suffixes home and
// office networks give themselves (home, lan, localdomain, corp, intranet, private).
const reservedTlds = new Set(["local", "localhost", "localdomain", "internal", "intranet", "corp", "private", "lan", "home", "test", "example", "invalid", "onion", "arpa"]);

/** A public host name as a person types it (with or without a scheme or path), lowercased, or null. */
export function validDomain(input: string): string | null {
  const name = input.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/[/?#].*$/, "").replace(/\.$/, "");
  if (name.length === 0 || name.length > 253) return null;
  if (!/^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/.test(name)) return null;
  const tld = name.split(".").pop()!;
  if (/^\d+$/.test(tld) || reservedTlds.has(tld)) return null;
  return name;
}

/**
 * A name a DNS record points at, when it is a public one: validDomain's rule, except that a label
 * may carry an underscore as service names do (_spf.google.com), and the top label must be a
 * real top-level domain's shape. Null for a single label, an address, or a reserved suffix.
 */
export function publicRecordName(input: string): string | null {
  const name = input.trim().toLowerCase().replace(/\.$/, "");
  if (name.length === 0 || name.length > 253) return null;
  if (!/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$/.test(name)) return null;
  const tld = name.split(".").pop()!;
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(tld) || reservedTlds.has(tld)) return null;
  return name;
}

/** Selector names as typed, comma or space separated, each a DNS label. */
export function parseSelectors(input: string | undefined): string[] {
  if (!input) return [];
  return [...new Set(input.toLowerCase().split(/[\s,]+/).filter((s) => /^[a-z0-9_-]{1,63}$/.test(s)))].slice(0, 12);
}

/** The real resolver: the host's, four seconds a question, errors read as the answer they are. */
export function nodeDns(): DnsLookup {
  const resolver = new Resolver({ timeout: 4000, tries: 2 });
  return async (name, type) => {
    try {
      switch (type) {
        case "A":
          return { records: await resolver.resolve4(name), code: "ok" };
        case "AAAA":
          return { records: await resolver.resolve6(name), code: "ok" };
        case "NS":
          return { records: (await resolver.resolveNs(name)).sort(), code: "ok" };
        case "MX":
          return { records: (await resolver.resolveMx(name)).sort((a, b) => a.priority - b.priority).map((m) => `${m.priority} ${m.exchange}`), code: "ok" };
        case "TXT":
          return { records: (await resolver.resolveTxt(name)).map((chunks) => chunks.join("")), code: "ok" };
        case "CAA":
          return { records: (await resolver.resolveCaa(name)).map((c) => caaLine({ ...c })), code: "ok" };
      }
    } catch (error) {
      const code = (error as { code?: string }).code ?? "";
      return { records: [], code: code === "ENOTFOUND" ? "nxdomain" : code === "ENODATA" ? "nodata" : "error", detail: code || String(error) };
    }
  };
}

/**
 * One CAA record in zone-file form, whatever its tag: issue, issuewild and iodef, and the
 * contactemail, contactphone or any other tag a zone publishes (Node returns each as a key of
 * its own beside `critical`).
 */
export function caaLine(record: Record<string, unknown>): string {
  // nodeDns calls resolveCaa, whose records carry `critical` and one key per tag. A record from
  // resolveAny also carries `type: "CAA"`, which is the record type, not a tag; it is left out.
  const tags = Object.entries(record).filter(([k, v]) => k !== "critical" && k !== "type" && v !== undefined);
  return `${String(record.critical ?? 0)} ${tags.map(([k, v]) => `${k} "${String(v)}"`).join(" ")}`.trim();
}

/** A certificate field, which Node types as one string or several. */
const one = (value: string | string[] | undefined): string | null => (Array.isArray(value) ? (value[0] ?? null) : (value ?? null));

/** The addresses a name resolves to; the real one is the system resolver, a test hands in its own. */
export type AddressLookup = (host: string) => Promise<{ address: string }[]>;

/** What the probe answers for a name that points inside a private network: it is not touched. */
export const privateAddressError = "private address";

/** An ISO date from a certificate's validity string, or null when the string is not a date. */
export function certificateDate(value: string | undefined): string | null {
  if (!value) return null;
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? null : at.toISOString();
}

/** What the handshake learned, read off the socket. A malformed field reads as missing. */
export function peerFacts(socket: Pick<tls.TLSSocket, "getPeerCertificate" | "getProtocol" | "getCipher" | "authorized" | "authorizationError">): TlsFacts {
  const cert = socket.getPeerCertificate(false);
  const names = (typeof cert.subjectaltname === "string" ? cert.subjectaltname : "").split(",").map((s) => s.trim().replace(/^DNS:/, "")).filter((s) => s);
  return {
    protocol: socket.getProtocol(),
    cipher: socket.getCipher()?.name ?? null,
    issuer: one(cert.issuer?.O) ?? one(cert.issuer?.CN),
    subject: one(cert.subject?.CN),
    validTo: certificateDate(cert.valid_to),
    names,
    authorized: socket.authorized,
    authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
  };
}

/**
 * One TLS handshake with the domain's own name, reading the protocol, the cipher and the
 * certificate; nothing is sent after. The name is resolved first and the handshake goes to the
 * address that was vetted: a visitor can point any public name at a LAN address, and this server
 * sits on the owner's LAN, so a name that resolves to a private address is answered without a
 * packet, and the address the HTTP legs vetted is the one connected to, not a second resolution.
 */
export function nodeTls(resolveAddresses: AddressLookup = (host) => resolveHost(host, { tries: 1 })): TlsProbe {
  return async (host) => {
    let addresses: { address: string }[];
    try {
      addresses = await resolveAddresses(host);
    } catch (error) {
      return { error: (error as NodeJS.ErrnoException).code ?? "ENOTFOUND" };
    }
    if (addresses.length === 0) return { error: "ENOTFOUND" };
    if (addresses.some((a) => privateAddress(a.address))) return { error: privateAddressError };
    const address = addresses[0]!.address;
    return new Promise((resolve) => {
      let settled = false;
      const done = (facts: TlsFacts | { error: string }): void => {
        if (settled) return;
        settled = true;
        resolve(facts);
      };
      const socket = tls.connect({ host: address, port: 443, servername: host, timeout: 8000, rejectUnauthorized: false }, () => {
        // This callback runs outside any request's error handling: a throw here ends the process,
        // and the certificate is the other side's to write. Whatever it holds, the answer is a fact
        // or an error, never an exception.
        try {
          done(peerFacts(socket));
        } catch {
          done({ error: "the certificate could not be read" });
        } finally {
          socket.end();
        }
      });
      socket.on("timeout", () => {
        socket.destroy();
        done({ error: "timeout" });
      });
      socket.on("error", (error: NodeJS.ErrnoException) => done({ error: error.code ?? error.message }));
    });
  };
}

interface Fetched {
  status: number | null;
  headers: Record<string, string>;
  text: string | null;
  error: string | null;
}

/** A GET that answers with what came back, a refused status included, never throwing. */
async function fetched(http: HttpGet, url: string, options: { manual?: boolean; text?: boolean } = {}): Promise<Fetched> {
  try {
    const response = await http(url, { timeoutMs: 8000, maxBytes: 512 * 1024, publicOnly: true, resolveTries: 1, headers: { accept: "text/html, text/plain;q=0.9, */*;q=0.5" }, ...(options.manual ? { redirect: "manual" as const } : {}) });
    return { status: response.status, headers: response.headers ?? {}, text: options.text ? new TextDecoder("utf-8", { fatal: false }).decode(response.bytes).slice(0, 4000) : null, error: null };
  } catch (error) {
    if (error instanceof HttpError) return { status: error.status, headers: error.headers, text: null, error: null };
    const code = (error as { code?: string; cause?: { code?: string } }).cause?.code ?? (error as { code?: string }).code;
    return { status: null, headers: {}, text: null, error: code ?? (error instanceof Error ? error.message : String(error)) };
  }
}

/** The SPF terms that cost a DNS lookup (RFC 7208 §4.6.4): include, a, mx, ptr, exists and the redirect modifier. */
const spfLookupTerm = /^[+\-~?]?(?:include:|a(?:[:/]|$)|mx(?:[:/]|$)|ptr(?::|$)|exists:|redirect=)/i;

/** The terms of an SPF record after v=spf1. */
const spfTerms = (record: string): string[] => record.trim().split(/\s+/).slice(1).filter((t) => t);

export interface SpfLookups {
  /** The lookups a receiver makes evaluating the record, counted through every include and redirect. */
  count: number;
  /** The include or redirect targets that publish no SPF record: a permanent error for a receiver. */
  missing: string[];
  /** The include or redirect targets that publish more than one SPF record: a permanent error too. */
  multiple: string[];
  /** Whether the walk stopped at its depth or query cap before the end. */
  capped: boolean;
}

/**
 * The lookups the record costs, counted the way RFC 7208 §4.6.4 counts them: every include, a,
 * mx, ptr, exists and redirect, and recursively the same terms in the record each include or
 * redirect names. A redirect beside an all term is never followed, so it is not counted. The
 * walk stops at ten levels and ten TXT questions, the ten lookups RFC 7208 allows a receiver; a
 * target written with a macro is counted and not followed. Neither is a target that is not a
 * public name (publicRecordName: a single label, localhost, .local, .lan, .internal, .home.arpa and
 * the like): the record is a visitor's, and following it would put their names to the host's own
 * resolver, which answers for the LAN.
 */
export async function spfLookups(record: string, dns: DnsLookup, limits: { depth?: number; queries?: number } = {}): Promise<SpfLookups> {
  const out: SpfLookups = { count: 0, missing: [], multiple: [], capped: false };
  let queries = limits.queries ?? 10;
  const walk = async (rec: string, depth: number): Promise<void> => {
    const terms = spfTerms(rec);
    const hasAll = terms.some((t) => /^[+\-~?]?all$/i.test(t));
    const targets: string[] = [];
    for (const term of terms) {
      if (!spfLookupTerm.test(term)) continue;
      const redirect = /^redirect=(.+)$/i.exec(term)?.[1];
      if (redirect !== undefined && hasAll) continue;
      out.count += 1;
      const target = redirect ?? /^[+\-~?]?include:(.+)$/i.exec(term)?.[1];
      const name = target !== undefined && !target.includes("%") ? publicRecordName(target) : null;
      if (name !== null) targets.push(name);
    }
    if (targets.length === 0) return;
    if (depth >= (limits.depth ?? 10) || out.count > 10) {
      out.capped = true;
      return;
    }
    const allowed = targets.slice(0, Math.max(0, queries));
    if (allowed.length < targets.length) out.capped = true;
    queries -= allowed.length;
    const answers = await Promise.all(allowed.map(async (t) => ({ t, answer: await dns(t, "TXT") })));
    for (const { t, answer } of answers) {
      const spf = spfRecords(answer.records);
      if (spf.length === 1) await walk(spf[0]!, depth + 1);
      else if (spf.length > 1) out.multiple.push(t);
      else if (answer.code !== "error") out.missing.push(t);
    }
  };
  await walk(record, 0);
  return out;
}

/** The SPF records among a name's TXT records, trimmed. */
const spfRecords = (records: string[]): string[] => records.map((r) => r.trim()).filter((r) => /^v=spf1(\s|$)/i.test(r));

/** The one SPF record among a name's TXT records, or null when there is none or more than one. */
const spfRecord = (records: string[]): string | null => {
  const spf = spfRecords(records);
  return spf.length === 1 ? spf[0]! : null;
};

/**
 * Reads the SPF record as a receiver would: one record, how it ends, and how many lookups it
 * costs. `counted` is the recursive count from spfLookups; without it only the record's own terms
 * are counted, which is a floor.
 */
export function judgeSpf(records: string[], mail: boolean, counted?: SpfLookups): Finding {
  const spf = spfRecords(records);
  if (spf.length === 0) return { id: "spf", group: "mail", title: "SPF", state: mail ? "bad" : "warn", text: mail ? "No SPF record: receivers cannot tell forged mail from this domain's own." : "No SPF record. A domain that sends no mail should still say so (v=spf1 -all), or anyone can send as it.", quoted: [] };
  if (spf.length > 1) return { id: "spf", group: "mail", title: "SPF", state: "bad", text: `${spf.length} SPF records: receivers treat more than one as a permanent error and ignore them all.`, quoted: spf };
  const record = spf[0]!;
  const lookups = counted?.count ?? spfTerms(record).filter((t) => spfLookupTerm.test(t)).length;
  const through = counted ? " counted through its includes" : "";
  const all = /([+\-~?]?)all\s*$/i.exec(record)?.[1] ?? null;
  const quoted = [`TXT "${record}"`];
  if (lookups > 10) return { id: "spf", group: "mail", title: "SPF", state: "bad", text: `${lookups}${counted?.capped ? " or more" : ""} DNS lookups${through || " in the record"}; the limit is 10, past which receivers give a permanent error.`, quoted };
  if (counted && counted.multiple.length) return { id: "spf", group: "mail", title: "SPF", state: "bad", text: `The record includes ${counted.multiple.join(", ")}, which ${counted.multiple.length === 1 ? "publishes" : "publish"} more than one SPF record: receivers give a permanent error.`, quoted };
  if (counted && counted.missing.length) return { id: "spf", group: "mail", title: "SPF", state: "bad", text: `The record includes ${counted.missing.join(", ")}, which ${counted.missing.length === 1 ? "publishes" : "publish"} no SPF record: receivers give a permanent error.`, quoted };
  if (all === "-") return { id: "spf", group: "mail", title: "SPF", state: "ok", text: `One record ending -all (hard fail), ${lookups} of 10 lookups${through}.`, quoted };
  if (all === "~") return { id: "spf", group: "mail", title: "SPF", state: "ok", text: `One record ending ~all (soft fail), ${lookups} of 10 lookups${through}; with DMARC at reject that is enough.`, quoted };
  if (all === "?" || all === "+" || all === "") return { id: "spf", group: "mail", title: "SPF", state: "bad", text: `The record ends ${all}all: it names senders and then permits everyone, which protects nothing.`, quoted };
  return { id: "spf", group: "mail", title: "SPF", state: "warn", text: `The record has no all term, so a sender it does not name is neither passed nor failed.`, quoted };
}

/** An MTA-STS policy's non-empty lines, trimmed. */
function stsPolicyLinesOf(text: string | null | undefined): string[] {
  return text ? text.split("\n").map((l) => l.trim()).filter((l) => l !== "") : [];
}

const stsPolicyLineCount = (text: string | null | undefined): number => stsPolicyLinesOf(text).length;

/** The most policy lines quoted; a longer policy is cut, says so, and marks the finding policyCut. */
export const stsPolicyLines = 20;

/**
 * An MTA-STS policy quoted line by line, whole up to stsPolicyLines, so the fix that moves it to
 * enforce keeps every mx and the max_age. A longer one ends in a line saying how many were left
 * out, which the fix reads as "not the whole policy".
 */
function stsPolicyQuote(text: string | null | undefined): string[] {
  const lines = stsPolicyLinesOf(text);
  const shown = lines.slice(0, stsPolicyLines).map((l) => `policy: ${l}`);
  return lines.length > stsPolicyLines ? [...shown, `(${lines.length - stsPolicyLines} more policy lines not shown)`] : shown;
}

/** DMARC's policy as published: reject, quarantine, none, or absent. */
export function judgeDmarc(records: string[], mail: boolean): Finding {
  const rec = records.map((r) => r.trim()).find((r) => /^v=DMARC1(\s|;|$)/i.test(r));
  if (!rec) return { id: "dmarc", group: "mail", title: "DMARC", state: mail ? "bad" : "warn", text: "No DMARC record at _dmarc: SPF and DKIM results tell receivers nothing about what to do with a failure, and no reports come back.", quoted: [] };
  const tags = Object.fromEntries(rec.split(";").map((part) => part.trim().split("=").map((s) => s.trim())).filter((kv) => kv.length === 2).map(([k, v]) => [k!.toLowerCase(), v!]));
  const policy = (tags.p ?? "").toLowerCase();
  const quoted = [`TXT "${rec}"`];
  const reports = tags.rua ? " Aggregate reports go to " + tags.rua + "." : " No rua: no aggregate reports come back.";
  const pct = tags.pct && tags.pct !== "100" ? ` Only pct=${tags.pct} of failing mail is subject to it.` : "";
  if (policy === "reject") return { id: "dmarc", group: "mail", title: "DMARC", state: pct ? "warn" : "ok", text: `Policy reject: mail that fails both SPF and DKIM alignment is refused.${pct}${reports}`, quoted };
  if (policy === "quarantine") return { id: "dmarc", group: "mail", title: "DMARC", state: "ok", text: `Policy quarantine: failing mail goes to spam. Reject is the end state.${pct}${reports}`, quoted };
  if (policy === "none") return { id: "dmarc", group: "mail", title: "DMARC", state: "warn", text: `Policy none: failures are reported but nothing is refused. Monitoring is the first step; quarantine or reject is the point.${reports}`, quoted };
  return { id: "dmarc", group: "mail", title: "DMARC", state: "bad", text: `The record has no readable p= policy (${tags.p ?? "missing"}); receivers ignore it.`, quoted };
}

/** HSTS as the front page sent it: a year or more and includeSubDomains is the bar. */
export function judgeHsts(headers: Record<string, string>, reached: boolean): Finding {
  const value = headers["strict-transport-security"];
  if (!reached) return { id: "hsts", group: "web", title: "HSTS", state: "na", text: "The front page did not answer over HTTPS, so there was no header to read.", quoted: [] };
  if (!value) return { id: "hsts", group: "web", title: "HSTS", state: "bad", text: "No Strict-Transport-Security header: a browser that once reaches this domain over plain HTTP can be kept there.", quoted: [] };
  const maxAge = Number(/max-age=(\d+)/i.exec(value)?.[1] ?? 0);
  const subs = /includeSubDomains/i.test(value);
  const preload = /preload/i.test(value);
  const quoted = [`Strict-Transport-Security: ${value}`];
  if (maxAge >= 31_536_000 && subs) return { id: "hsts", group: "web", title: "HSTS", state: "ok", text: `A year or more (${maxAge} s), subdomains included${preload ? ", preload asked for" : ""}.`, quoted };
  if (maxAge >= 31_536_000) return { id: "hsts", group: "web", title: "HSTS", state: "warn", text: `A year or more (${maxAge} s), but without includeSubDomains a subdomain can still be reached over HTTP.`, quoted };
  return { id: "hsts", group: "web", title: "HSTS", state: "warn", text: `max-age ${maxAge} s is under a year; the preload list and most guidance want 31536000 or more.`, quoted };
}

const headerNames: [string, string][] = [
  ["content-security-policy", "Content-Security-Policy"],
  ["x-content-type-options", "X-Content-Type-Options"],
  ["x-frame-options", "X-Frame-Options"],
  ["referrer-policy", "Referrer-Policy"],
  ["permissions-policy", "Permissions-Policy"],
  ["cross-origin-opener-policy", "Cross-Origin-Opener-Policy"],
];

/** The other security headers the front page sent, each quoted; CSP, nosniff and a frame rule are the bar. */
export function judgeHeaders(headers: Record<string, string>, reached: boolean): Finding {
  if (!reached) return { id: "headers", group: "web", title: "Security headers", state: "na", text: "The front page did not answer over HTTPS.", quoted: [] };
  const quoted = headerNames.filter(([k]) => headers[k]).map(([k, label]) => `${label}: ${headers[k]!.length > 300 ? `${headers[k]!.slice(0, 299)}…` : headers[k]}`);
  const csp = headers["content-security-policy"] ?? "";
  const framed = /x-frame-options/i.test(Object.keys(headers).join(" ")) || /frame-ancestors/i.test(csp);
  const nosniff = /nosniff/i.test(headers["x-content-type-options"] ?? "");
  const missing = [!csp ? "Content-Security-Policy" : null, !nosniff ? "X-Content-Type-Options: nosniff" : null, !framed ? "a frame rule (X-Frame-Options or CSP frame-ancestors)" : null].filter((s) => s !== null);
  if (missing.length === 0) return { id: "headers", group: "web", title: "Security headers", state: "ok", text: `CSP, nosniff and a frame rule are all sent${headers["referrer-policy"] ? ", with a referrer policy" : ""}.`, quoted };
  return { id: "headers", group: "web", title: "Security headers", state: missing.length === 3 ? "bad" : "warn", text: `Missing: ${missing.join("; ")}.`, quoted };
}

/** The certificate and the handshake: TLS 1.3, a trusted chain, the name covered, not about to expire. */
export function judgeTls(facts: TlsFacts | { error: string }, domain: string, now: Date): Finding {
  if ("error" in facts && facts.error === privateAddressError) return { id: "tls", group: "web", title: "TLS", state: "na", text: "The name points at a private address, which this check does not touch.", quoted: [] };
  if ("error" in facts) return { id: "tls", group: "web", title: "TLS", state: facts.error === "ECONNREFUSED" || facts.error === "ENOTFOUND" ? "na" : "bad", text: `No TLS handshake on 443: ${facts.error}.`, quoted: [] };
  const quoted = [`${facts.protocol ?? "?"} · ${facts.cipher ?? "?"}`, `Issuer: ${facts.issuer ?? "?"} · Subject: ${facts.subject ?? "?"}`, `Valid to: ${facts.validTo?.slice(0, 10) ?? "?"}`, `Names: ${facts.names.slice(0, 8).join(", ")}${facts.names.length > 8 ? ` and ${facts.names.length - 8} more` : ""}`];
  const covers = facts.names.some((n) => n === domain || (n.startsWith("*.") && domain.endsWith(n.slice(1)) && domain.split(".").length === n.split(".").length));
  const days = facts.validTo ? Math.floor((new Date(facts.validTo).getTime() - now.getTime()) / 86_400_000) : null;
  if (!facts.authorized) return { id: "tls", group: "web", title: "TLS", state: "bad", text: `The chain is not trusted: ${facts.authorizationError ?? "unknown reason"}.`, quoted };
  if (!covers) return { id: "tls", group: "web", title: "TLS", state: "bad", text: `The certificate does not name ${domain}.`, quoted };
  if (days !== null && days < 0) return { id: "tls", group: "web", title: "TLS", state: "bad", text: "The certificate has expired.", quoted };
  if (days !== null && days < 14) return { id: "tls", group: "web", title: "TLS", state: "warn", text: `The certificate expires in ${counted(days, "day")}.`, quoted };
  if (facts.protocol !== "TLSv1.3") return { id: "tls", group: "web", title: "TLS", state: "warn", text: `${facts.protocol ?? "An old protocol"} was negotiated; TLS 1.3 is the current standard.`, quoted };
  return { id: "tls", group: "web", title: "TLS", state: "ok", text: `TLS 1.3, a trusted chain, the name covered, ${days !== null ? `${days} days` : "?"} left.`, quoted };
}

/** The whole report. Every lookup runs at once; a slow one costs its own timeout, not everyone's. */
export async function checkDomain(domain: string, deps: DomainDeps, options: { selectors?: string[] } = {}): Promise<DomainReport> {
  const started = deps.now();
  const selectors = options.selectors?.length ? options.selectors : commonSelectors;
  const { dns, http } = deps;
  const [a, aaaa, ns, mx, txt, caa, dmarc, stsTxt, tlsrpt, doh, home, plain, tlsFacts, security, stsPolicy, ...dkim] = await Promise.all([
    dns(domain, "A"),
    dns(domain, "AAAA"),
    dns(domain, "NS"),
    dns(domain, "MX"),
    dns(domain, "TXT"),
    dns(domain, "CAA"),
    dns(`_dmarc.${domain}`, "TXT"),
    dns(`_mta-sts.${domain}`, "TXT"),
    dns(`_smtp._tls.${domain}`, "TXT"),
    fetched(http, dohJsonUrl(domain), { text: true }),
    // The first answer, not the page a redirect ends on: HSTS sent on the apex's redirect is the
    // one that binds this name, and a header on www's page says nothing about it.
    fetched(http, `https://${domain}/`, { manual: true }),
    fetched(http, `http://${domain}/`, { manual: true }),
    deps.tls(domain),
    fetched(http, `https://${domain}/.well-known/security.txt`, { text: true }),
    fetched(http, `https://mta-sts.${domain}/.well-known/mta-sts.txt`, { text: true }),
    ...selectors.map((s) => dns(`${s}._domainkey.${domain}`, "TXT")),
  ]);
  const findings: Finding[] = [];
  const push = (f: Finding): number => findings.push(f);
  // The lookups SPF costs, counted through its includes; asked only once the record is known.
  const ownSpf = spfRecord(txt.records);
  const spfCount = ownSpf ? await spfLookups(ownSpf, dns) : undefined;
  // A front page that redirects: the security headers belong to the page it reaches, read by
  // following; HSTS stays judged on the first answer.
  const redirected = home.status !== null && home.status >= 300 && home.status < 400;
  const homeLocation = redirected ? (home.headers.location ?? "") : "";
  const page = redirected ? await fetched(http, `https://${domain}/`) : home;

  // Names and addresses.
  if (a.code === "nxdomain" && aaaa.code === "nxdomain") push({ id: "addresses", group: "names", title: "Addresses", state: "bad", text: "The name does not exist (NXDOMAIN).", quoted: [] });
  else if (a.records.length === 0 && aaaa.records.length === 0) push({ id: "addresses", group: "names", title: "Addresses", state: "warn", text: "No A or AAAA record at the apex; the name exists but points nowhere itself.", quoted: [] });
  else push({ id: "addresses", group: "names", title: "Addresses", state: aaaa.records.length ? "ok" : "warn", text: aaaa.records.length ? `${counted(a.records.length, "IPv4 address", "IPv4 addresses")} and ${counted(aaaa.records.length, "IPv6 address", "IPv6 addresses")}.` : `${counted(a.records.length, "IPv4 address", "IPv4 addresses")} and no IPv6: a growing share of networks reach it through translation.`, quoted: [...a.records.map((r) => `A ${r}`), ...aaaa.records.map((r) => `AAAA ${r}`)] });
  push({ id: "ns", group: "names", title: "Name servers", state: ns.records.length >= 2 ? "ok" : ns.records.length === 1 ? "warn" : "bad", text: ns.records.length >= 2 ? `${ns.records.length} name servers.` : ns.records.length === 1 ? "One name server: no redundancy." : "No NS records answered.", quoted: ns.records.map((r) => `NS ${r}`) });
  const dohAnswer = parseJson<{ AD?: boolean; Status?: number }>(doh.text, {});
  push(
    doh.status === 200 && typeof dohAnswer.AD === "boolean"
      ? { id: "dnssec", group: "names", title: "DNSSEC", state: dohAnswer.AD ? "ok" : "warn", text: dohAnswer.AD ? "Signed and validated: a validating resolver sets the AD flag on this name." : "Not signed, or not validated: a resolver that validates cannot tell a forged answer for this name from a real one.", quoted: [`Cloudflare DoH: AD=${dohAnswer.AD} Status=${dohAnswer.Status ?? "?"}`] }
      : { id: "dnssec", group: "names", title: "DNSSEC", state: "na", text: `The validating resolver did not answer (${doh.error ?? doh.status}).`, quoted: [] },
  );
  // Only an issue or issuewild property restricts issuance (RFC 8659 §4); iodef or contactemail alone names a contact and nothing else.
  const restricts = caa.records.some((r) => /^\d+\s+(?:issue|issuewild)\s/i.test(r.trim()));
  push({ id: "caa", group: "names", title: "CAA", state: restricts ? "ok" : "warn", text: restricts ? "CAA names which authorities may issue certificates for the domain." : caa.records.length ? "CAA published, but no issue property: any authority may still issue a certificate for this domain." : "No CAA record: any public authority may issue a certificate for this domain.", quoted: caa.records.map((r) => `CAA ${r}`) });

  // Mail.
  const nullMx = mx.records.length === 1 && /^0 \.?$/.test(mx.records[0]!);
  const mail = mx.records.length > 0 && !nullMx;
  push({ id: "mx", group: "mail", title: "Mail exchangers", state: mail ? "ok" : "na", text: mail ? `${counted(mx.records.length, "exchanger")}.` : nullMx ? "A null MX (0 .): the domain declares it takes no mail." : "No MX: the domain does not receive mail.", quoted: mx.records.map((r) => `MX ${r}`) });
  push(judgeSpf(txt.records, mail, spfCount));
  push(judgeDmarc(dmarc.records, mail));
  const found = selectors.map((s, i) => ({ s, answer: dkim[i]! })).filter((d) => d.answer.records.some((r) => /v=DKIM1|p=/i.test(r)));
  push({
    id: "dkim",
    group: "mail",
    title: "DKIM",
    state: found.length ? "ok" : mail ? "warn" : "na",
    text: found.length ? `${found.length === 1 ? "1 selector publishes" : `${found.length} selectors publish`} a key: ${found.map((d) => d.s).join(", ")}.` : options.selectors?.length ? `None of the selectors named (${selectors.join(", ")}) publishes a key.` : `None of the common selectors (${selectors.join(", ")}) publishes a key; name yours to check it.`,
    quoted: found.map((d) => `${d.s}._domainkey TXT "${d.answer.records[0]!.length > 120 ? `${d.answer.records[0]!.slice(0, 119)}…` : d.answer.records[0]}"`),
  });
  const sts = stsTxt.records.find((r) => /^v=STSv1/i.test(r.trim()));
  const mode = /^mode:\s*(\w+)/im.exec(stsPolicy.text ?? "")?.[1]?.toLowerCase() ?? null;
  push({
    id: "mta-sts",
    group: "mail",
    title: "MTA-STS",
    state: !mail ? "na" : sts && mode === "enforce" ? "ok" : sts && mode ? "warn" : "warn",
    text: !mail ? "Not applicable without mail." : sts && mode === "enforce" ? "Published and enforced: sending servers must use TLS to a listed MX or not deliver." : sts && mode ? `Published in mode ${mode}; enforce is the point.` : sts ? "The DNS record is there but the policy file did not answer at https://mta-sts." + domain + "/.well-known/mta-sts.txt." : "No MTA-STS: mail in transit to this domain can be downgraded to plain text by anyone in the path.",
    quoted: [...(sts ? [`_mta-sts TXT "${sts}"`] : []), ...stsPolicyQuote(stsPolicy.text)],
    ...(stsPolicyLineCount(stsPolicy.text) > stsPolicyLines ? { policyCut: true } : {}),
  });
  const rpt = tlsrpt.records.find((r) => /^v=TLSRPTv1/i.test(r.trim()));
  push({ id: "tls-rpt", group: "mail", title: "TLS-RPT", state: !mail ? "na" : rpt ? "ok" : "warn", text: !mail ? "Not applicable without mail." : rpt ? "Reports on failed TLS deliveries will arrive." : "No TLS-RPT: a sender that could not use TLS tells no one.", quoted: rpt ? [`_smtp._tls TXT "${rpt}"`] : [] });

  // Web.
  const reached = home.status !== null && home.status < 500;
  push({
    id: "https",
    group: "web",
    title: "HTTPS front page",
    state: redirected ? (/^https:\/\//i.test(homeLocation) || homeLocation.startsWith("/") ? "ok" : "warn") : home.status !== null && home.status < 400 ? "ok" : reached ? "warn" : "bad",
    text: redirected ? `https://${domain}/ answered ${home.status}, redirecting to ${homeLocation || "nowhere (no Location header)"}${page.status !== null ? `, which answered ${page.status}` : ""}.` : home.status !== null ? `https://${domain}/ answered ${home.status}.` : `https://${domain}/ did not answer: ${home.error}.`,
    quoted: [...(redirected ? [`Location: ${homeLocation}`] : []), ...(home.headers.server ? [`Server: ${home.headers.server}`] : [])],
  });
  const location = plain.headers.location ?? "";
  push(
    plain.status !== null && plain.status >= 300 && plain.status < 400
      ? { id: "http", group: "web", title: "Plain HTTP", state: /^https:\/\//i.test(location) ? "ok" : "warn", text: /^https:\/\//i.test(location) ? `http://${domain}/ redirects to HTTPS (${plain.status}).` : `http://${domain}/ redirects (${plain.status}) but not to HTTPS.`, quoted: [`Location: ${location}`] }
      : plain.status !== null && plain.status < 300
        ? { id: "http", group: "web", title: "Plain HTTP", state: "bad", text: `http://${domain}/ serves a page over plain HTTP (${plain.status}) instead of redirecting.`, quoted: [] }
        : plain.status === null
          ? { id: "http", group: "web", title: "Plain HTTP", state: "ok", text: `Nothing answers on plain HTTP (${plain.error}); fine, as long as HSTS is preloaded or everyone types https.`, quoted: [] }
          : { id: "http", group: "web", title: "Plain HTTP", state: "warn", text: `http://${domain}/ answered ${plain.status}.`, quoted: [] },
  );
  const hsts = judgeHsts(home.headers, reached);
  push(redirected && hsts.state !== "na" ? { ...hsts, text: `${hsts.text} Read on the ${home.status} that https://${domain}/ answers with, which is what binds this name.` } : hsts);
  const pageReached = page.status !== null && page.status < 500;
  const headers = judgeHeaders(page.headers, pageReached);
  push(redirected && headers.state !== "na" ? { ...headers, text: `${headers.text} Read on the page the redirect reaches (${homeLocation}).` } : headers);
  push(judgeTls(tlsFacts, domain, started));
  const contact = /^Contact:\s*(.+)$/im.exec(security.text ?? "")?.[1]?.trim();
  const expires = /^Expires:\s*(.+)$/im.exec(security.text ?? "")?.[1]?.trim();
  const expiresAt = expires ? new Date(expires) : null;
  const expiry = !expires ? "missing" : !expiresAt || Number.isNaN(expiresAt.getTime()) ? "unreadable" : expiresAt.getTime() < started.getTime() ? "past" : "ok";
  push({
    id: "security-txt",
    group: "web",
    title: "security.txt",
    state: contact && expiry === "ok" ? "ok" : "warn",
    text: !contact
      ? security.status === 200
        ? "A file answered but has no Contact line."
        : "No /.well-known/security.txt: a researcher who finds something has to guess whom to tell."
      : expiry === "missing"
        ? "Published with a Contact, but without the Expires line RFC 9116 requires, so a reader cannot tell whether it is still kept."
        : expiry === "unreadable"
          ? "Published with a Contact, but the Expires line is not a date; RFC 9116 wants RFC 3339 form."
          : expiry === "past"
            ? `Published with a Contact, but it expired on ${expires}: RFC 9116 says a file past its Expires is to be treated as stale.`
            : "Published (RFC 9116): a researcher knows whom to tell.", quoted: [...(contact ? [`Contact: ${contact}`] : []), ...(expires ? [`Expires: ${expires}`] : [])] });

  const counts: Record<FindingState, number> = { ok: 0, warn: 0, bad: 0, na: 0 };
  for (const f of findings) counts[f.state] += 1;
  return { domain, checkedAt: started.toISOString(), durationMs: deps.now().getTime() - started.getTime(), mail, findings, counts };
}
