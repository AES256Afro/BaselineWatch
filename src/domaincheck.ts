import { Resolver } from "node:dns/promises";
import tls from "node:tls";
import { HttpError, type HttpGet } from "./http.ts";
import { parseJson } from "./json.ts";

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

const reservedTlds = new Set(["local", "localhost", "internal", "lan", "home", "test", "invalid", "onion", "arpa"]);

/** A public host name as a person types it (with or without a scheme or path), lowercased, or null. */
export function validDomain(input: string): string | null {
  const name = input.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/[/?#].*$/, "").replace(/\.$/, "");
  if (name.length === 0 || name.length > 253) return null;
  if (!/^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/.test(name)) return null;
  const tld = name.split(".").pop()!;
  if (/^\d+$/.test(tld) || reservedTlds.has(tld)) return null;
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
          return { records: (await resolver.resolveCaa(name)).map((c) => `${c.critical} ${c.issue !== undefined ? `issue "${c.issue}"` : c.issuewild !== undefined ? `issuewild "${c.issuewild}"` : c.iodef !== undefined ? `iodef "${c.iodef}"` : ""}`.trim()), code: "ok" };
      }
    } catch (error) {
      const code = (error as { code?: string }).code ?? "";
      return { records: [], code: code === "ENOTFOUND" ? "nxdomain" : code === "ENODATA" ? "nodata" : "error", detail: code || String(error) };
    }
  };
}

/** A certificate field, which Node types as one string or several. */
const one = (value: string | string[] | undefined): string | null => (Array.isArray(value) ? (value[0] ?? null) : (value ?? null));

/** One TLS handshake with the domain's own name, reading the protocol, the cipher and the certificate; nothing is sent after. */
export function nodeTls(): TlsProbe {
  return (host) =>
    new Promise((resolve) => {
      let settled = false;
      const done = (facts: TlsFacts | { error: string }): void => {
        if (settled) return;
        settled = true;
        resolve(facts);
      };
      const socket = tls.connect({ host, port: 443, servername: host, timeout: 8000, rejectUnauthorized: false }, () => {
        const cert = socket.getPeerCertificate(false);
        const names = (cert.subjectaltname ?? "").split(",").map((s) => s.trim().replace(/^DNS:/, "")).filter((s) => s);
        done({
          protocol: socket.getProtocol(),
          cipher: socket.getCipher()?.name ?? null,
          issuer: one(cert.issuer?.O) ?? one(cert.issuer?.CN),
          subject: one(cert.subject?.CN),
          validTo: cert.valid_to ? new Date(cert.valid_to).toISOString() : null,
          names,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        });
        socket.end();
      });
      socket.on("timeout", () => {
        socket.destroy();
        done({ error: "timeout" });
      });
      socket.on("error", (error: NodeJS.ErrnoException) => done({ error: error.code ?? error.message }));
    });
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
    const response = await http(url, { timeoutMs: 8000, maxBytes: 512 * 1024, publicOnly: true, headers: { accept: "text/html, text/plain;q=0.9, */*;q=0.5" }, ...(options.manual ? { redirect: "manual" as const } : {}) });
    return { status: response.status, headers: response.headers ?? {}, text: options.text ? new TextDecoder("utf-8", { fatal: false }).decode(response.bytes).slice(0, 4000) : null, error: null };
  } catch (error) {
    if (error instanceof HttpError) return { status: error.status, headers: error.headers, text: null, error: null };
    const code = (error as { code?: string; cause?: { code?: string } }).cause?.code ?? (error as { code?: string }).code;
    return { status: null, headers: {}, text: null, error: code ?? (error instanceof Error ? error.message : String(error)) };
  }
}

const spfLookupTerms = /(?:^|\s)[+\-~?]?(?:include:|a(?::|\s|$)|mx(?::|\s|$)|ptr(?::|\s|$)|exists:|redirect=)/gi;

/** Reads the SPF record as a receiver would: one record, how it ends, and how many lookups it costs. */
export function judgeSpf(records: string[], mail: boolean): Finding {
  const spf = records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  if (spf.length === 0) return { id: "spf", group: "mail", title: "SPF", state: mail ? "bad" : "warn", text: mail ? "No SPF record: receivers cannot tell forged mail from this domain's own." : "No SPF record. A domain that sends no mail should still say so (v=spf1 -all), or anyone can send as it.", quoted: [] };
  if (spf.length > 1) return { id: "spf", group: "mail", title: "SPF", state: "bad", text: `${spf.length} SPF records: receivers treat more than one as a permanent error and ignore them all.`, quoted: spf };
  const record = spf[0]!.trim();
  const lookups = (record.match(spfLookupTerms) ?? []).length;
  const all = /([+\-~?]?)all\s*$/i.exec(record)?.[1] ?? null;
  const quoted = [`TXT "${record}"`];
  if (lookups > 10) return { id: "spf", group: "mail", title: "SPF", state: "bad", text: `${lookups} DNS lookups in the record; the limit is 10, past which receivers give a permanent error.`, quoted };
  if (all === "-") return { id: "spf", group: "mail", title: "SPF", state: "ok", text: `One record ending -all (hard fail), ${lookups} of 10 lookups.`, quoted };
  if (all === "~") return { id: "spf", group: "mail", title: "SPF", state: "ok", text: `One record ending ~all (soft fail), ${lookups} of 10 lookups; with DMARC at reject that is enough.`, quoted };
  if (all === "?" || all === "+" || all === "") return { id: "spf", group: "mail", title: "SPF", state: "bad", text: `The record ends ${all}all: it names senders and then permits everyone, which protects nothing.`, quoted };
  return { id: "spf", group: "mail", title: "SPF", state: "warn", text: `The record has no all term, so a sender it does not name is neither passed nor failed.`, quoted };
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
  if ("error" in facts) return { id: "tls", group: "web", title: "TLS", state: facts.error === "ECONNREFUSED" || facts.error === "ENOTFOUND" ? "na" : "bad", text: `No TLS handshake on 443: ${facts.error}.`, quoted: [] };
  const quoted = [`${facts.protocol ?? "?"} · ${facts.cipher ?? "?"}`, `Issuer: ${facts.issuer ?? "?"} · Subject: ${facts.subject ?? "?"}`, `Valid to: ${facts.validTo?.slice(0, 10) ?? "?"}`, `Names: ${facts.names.slice(0, 8).join(", ")}${facts.names.length > 8 ? ` and ${facts.names.length - 8} more` : ""}`];
  const covers = facts.names.some((n) => n === domain || (n.startsWith("*.") && domain.endsWith(n.slice(1)) && domain.split(".").length === n.split(".").length));
  const days = facts.validTo ? Math.floor((new Date(facts.validTo).getTime() - now.getTime()) / 86_400_000) : null;
  if (!facts.authorized) return { id: "tls", group: "web", title: "TLS", state: "bad", text: `The chain is not trusted: ${facts.authorizationError ?? "unknown reason"}.`, quoted };
  if (!covers) return { id: "tls", group: "web", title: "TLS", state: "bad", text: `The certificate does not name ${domain}.`, quoted };
  if (days !== null && days < 0) return { id: "tls", group: "web", title: "TLS", state: "bad", text: "The certificate has expired.", quoted };
  if (days !== null && days < 14) return { id: "tls", group: "web", title: "TLS", state: "warn", text: `The certificate expires in ${days} day(s).`, quoted };
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
    fetched(http, `https://${domain}/`),
    fetched(http, `http://${domain}/`, { manual: true }),
    deps.tls(domain),
    fetched(http, `https://${domain}/.well-known/security.txt`, { text: true }),
    fetched(http, `https://mta-sts.${domain}/.well-known/mta-sts.txt`, { text: true }),
    ...selectors.map((s) => dns(`${s}._domainkey.${domain}`, "TXT")),
  ]);
  const findings: Finding[] = [];
  const push = (f: Finding): number => findings.push(f);

  // Names and addresses.
  if (a.code === "nxdomain" && aaaa.code === "nxdomain") push({ id: "addresses", group: "names", title: "Addresses", state: "bad", text: "The name does not exist (NXDOMAIN).", quoted: [] });
  else if (a.records.length === 0 && aaaa.records.length === 0) push({ id: "addresses", group: "names", title: "Addresses", state: "warn", text: "No A or AAAA record at the apex; the name exists but points nowhere itself.", quoted: [] });
  else push({ id: "addresses", group: "names", title: "Addresses", state: aaaa.records.length ? "ok" : "warn", text: aaaa.records.length ? `${a.records.length} IPv4 and ${aaaa.records.length} IPv6 address(es).` : `${a.records.length} IPv4 address(es) and no IPv6: a growing share of networks reach it through translation.`, quoted: [...a.records.map((r) => `A ${r}`), ...aaaa.records.map((r) => `AAAA ${r}`)] });
  push({ id: "ns", group: "names", title: "Name servers", state: ns.records.length >= 2 ? "ok" : ns.records.length === 1 ? "warn" : "bad", text: ns.records.length >= 2 ? `${ns.records.length} name servers.` : ns.records.length === 1 ? "One name server: no redundancy." : "No NS records answered.", quoted: ns.records.map((r) => `NS ${r}`) });
  const dohAnswer = parseJson<{ AD?: boolean; Status?: number }>(doh.text, {});
  push(
    doh.status === 200 && typeof dohAnswer.AD === "boolean"
      ? { id: "dnssec", group: "names", title: "DNSSEC", state: dohAnswer.AD ? "ok" : "warn", text: dohAnswer.AD ? "Signed and validated: a validating resolver sets the AD flag on this name." : "Not signed, or not validated: a resolver that validates cannot tell a forged answer for this name from a real one.", quoted: [`Cloudflare DoH: AD=${dohAnswer.AD} Status=${dohAnswer.Status ?? "?"}`] }
      : { id: "dnssec", group: "names", title: "DNSSEC", state: "na", text: `The validating resolver did not answer (${doh.error ?? doh.status}).`, quoted: [] },
  );
  push({ id: "caa", group: "names", title: "CAA", state: caa.records.length ? "ok" : "warn", text: caa.records.length ? "CAA names which authorities may issue certificates for the domain." : "No CAA record: any public authority may issue a certificate for this domain.", quoted: caa.records.map((r) => `CAA ${r}`) });

  // Mail.
  const nullMx = mx.records.length === 1 && /^0 \.?$/.test(mx.records[0]!);
  const mail = mx.records.length > 0 && !nullMx;
  push({ id: "mx", group: "mail", title: "Mail exchangers", state: mail ? "ok" : "na", text: mail ? `${mx.records.length} exchanger(s).` : nullMx ? "A null MX (0 .): the domain declares it takes no mail." : "No MX: the domain does not receive mail.", quoted: mx.records.map((r) => `MX ${r}`) });
  push(judgeSpf(txt.records, mail));
  push(judgeDmarc(dmarc.records, mail));
  const found = selectors.map((s, i) => ({ s, answer: dkim[i]! })).filter((d) => d.answer.records.some((r) => /v=DKIM1|p=/i.test(r)));
  push({
    id: "dkim",
    group: "mail",
    title: "DKIM",
    state: found.length ? "ok" : mail ? "warn" : "na",
    text: found.length ? `${found.length} selector(s) publish a key: ${found.map((d) => d.s).join(", ")}.` : options.selectors?.length ? `None of the selectors named (${selectors.join(", ")}) publishes a key.` : `None of the common selectors (${selectors.join(", ")}) publishes a key; name yours to check it.`,
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
    quoted: [...(sts ? [`_mta-sts TXT "${sts}"`] : []), ...(stsPolicy.text ? stsPolicy.text.split("\n").slice(0, 6).map((l) => `policy: ${l.trim()}`).filter((l) => l !== "policy: ") : [])],
  });
  const rpt = tlsrpt.records.find((r) => /^v=TLSRPTv1/i.test(r.trim()));
  push({ id: "tls-rpt", group: "mail", title: "TLS-RPT", state: !mail ? "na" : rpt ? "ok" : "warn", text: !mail ? "Not applicable without mail." : rpt ? "Reports on failed TLS deliveries will arrive." : "No TLS-RPT: a sender that could not use TLS tells no one.", quoted: rpt ? [`_smtp._tls TXT "${rpt}"`] : [] });

  // Web.
  const reached = home.status !== null && home.status < 500;
  push({ id: "https", group: "web", title: "HTTPS front page", state: home.status !== null && home.status < 400 ? "ok" : reached ? "warn" : "bad", text: home.status !== null ? `https://${domain}/ answered ${home.status}.` : `https://${domain}/ did not answer: ${home.error}.`, quoted: home.headers.server ? [`Server: ${home.headers.server}`] : [] });
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
  push(judgeHsts(home.headers, reached));
  push(judgeHeaders(home.headers, reached));
  push(judgeTls(tlsFacts, domain, started));
  const contact = /^Contact:\s*(.+)$/im.exec(security.text ?? "")?.[1]?.trim();
  const expires = /^Expires:\s*(.+)$/im.exec(security.text ?? "")?.[1]?.trim();
  push({ id: "security-txt", group: "web", title: "security.txt", state: contact ? "ok" : "warn", text: contact ? "Published (RFC 9116): a researcher knows whom to tell." : security.status === 200 ? "A file answered but has no Contact line." : "No /.well-known/security.txt: a researcher who finds something has to guess whom to tell.", quoted: [...(contact ? [`Contact: ${contact}`] : []), ...(expires ? [`Expires: ${expires}`] : [])] });

  const counts: Record<FindingState, number> = { ok: 0, warn: 0, bad: 0, na: 0 };
  for (const f of findings) counts[f.state] += 1;
  return { domain, checkedAt: started.toISOString(), durationMs: deps.now().getTime() - started.getTime(), mail, findings, counts };
}
