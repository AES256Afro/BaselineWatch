import { isIP } from "node:net";
import type { DatabaseSync } from "node:sqlite";
import { privateAddress, type HttpGet } from "./http.ts";
import { parseJson } from "./json.ts";

/**
 * What this page learned about you (Scan 2.0, S2): the server's side of the browser check on one
 * honest panel — the address the request came from and what kind it is, whether it is a Tor
 * exit, the headers the browser volunteered, the protocol and the transport as this server saw
 * them. A teaching panel, not a tracker: it is computed from the request and nothing is kept.
 * The InternetDB lookup is the one outbound call, made only when the visitor asks for it.
 */

/** The request's facts a route hands over, shaped so a test can hand the same. */
export interface RequestFacts {
  ip: string | null;
  headers: Record<string, string | string[] | undefined>;
  /** "http" or "https" as the app resolves it (the edge's X-Forwarded-Proto when trusted). */
  protocol: string;
  httpVersion: string;
  /** The TLS protocol when this process terminated TLS itself; null when the edge did. */
  tlsProtocol: string | null;
}

export interface Seen {
  ip: string | null;
  /** "public", "private" (the LAN this server sits on), "loopback", or "unknown". */
  kind: "public" | "private" | "loopback" | "unknown";
  family: "IPv4" | "IPv6" | null;
  torExit: boolean;
  protocol: string;
  httpVersion: string;
  tlsProtocol: string | null;
  /** The headers worth showing, in a fixed order, only the ones that were sent. */
  headers: { name: string; value: string }[];
  /** Global Privacy Control and Do Not Track, as sent. */
  gpc: boolean;
  dnt: boolean;
  /** Where the browser said it came from, if it said. */
  referer: string | null;
}

const shown: [string, string][] = [
  ["user-agent", "User-Agent"],
  ["accept-language", "Accept-Language"],
  ["sec-ch-ua", "Sec-CH-UA"],
  ["sec-ch-ua-platform", "Sec-CH-UA-Platform"],
  ["sec-ch-ua-mobile", "Sec-CH-UA-Mobile"],
  ["sec-fetch-site", "Sec-Fetch-Site"],
  ["sec-gpc", "Sec-GPC"],
  ["dnt", "DNT"],
  ["referer", "Referer"],
  ["accept", "Accept"],
  ["accept-encoding", "Accept-Encoding"],
  ["save-data", "Save-Data"],
];

const first = (value: string | string[] | undefined): string | null => (Array.isArray(value) ? (value[0] ?? null) : (value ?? null));

export function isTorExit(db: DatabaseSync, ip: string | null): boolean {
  if (!ip) return false;
  return db.prepare("SELECT 1 FROM tor_exits WHERE ip = ?").get(ip) !== undefined;
}

export function whatWasSeen(db: DatabaseSync, facts: RequestFacts): Seen {
  const ip = facts.ip ? facts.ip.replace(/^::ffff:/, "") : null;
  const version = ip ? isIP(ip) : 0;
  const kind: Seen["kind"] = !ip || version === 0 ? "unknown" : ip === "127.0.0.1" || ip === "::1" ? "loopback" : privateAddress(ip) ? "private" : "public";
  const headers = shown.flatMap(([key, name]) => {
    const value = first(facts.headers[key]);
    return value ? [{ name, value: value.length > 300 ? `${value.slice(0, 299)}…` : value }] : [];
  });
  return {
    ip,
    kind,
    family: version === 4 ? "IPv4" : version === 6 ? "IPv6" : null,
    torExit: kind === "public" && isTorExit(db, ip),
    protocol: facts.protocol,
    httpVersion: facts.httpVersion,
    tlsProtocol: facts.tlsProtocol,
    headers,
    gpc: first(facts.headers["sec-gpc"]) === "1",
    dnt: first(facts.headers.dnt) === "1",
    referer: first(facts.headers.referer),
  };
}

export interface Exposure {
  ip: string;
  ports: number[];
  hostnames: string[];
  cpes: string[];
  vulns: string[];
  tags: string[];
  /** True when Shodan has nothing on the address, which is the good answer. */
  nothing: boolean;
}

export const internetDbUrl = (ip: string): string => `https://internetdb.shodan.io/${ip}`;

/** What Shodan last saw of a public address: ports, names, software, CVEs. A 404 is "nothing", which is the good answer. */
export async function lookUpExposure(http: HttpGet, ip: string): Promise<Exposure> {
  const empty: Exposure = { ip, ports: [], hostnames: [], cpes: [], vulns: [], tags: [], nothing: true };
  try {
    const response = await http(internetDbUrl(ip), { headers: { accept: "application/json" }, timeoutMs: 15_000, maxBytes: 1024 * 1024 });
    const data = parseJson<Partial<Exposure>>(new TextDecoder().decode(response.bytes), {});
    const list = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").slice(0, 100) : []);
    const ports = Array.isArray(data.ports) ? data.ports.filter((p): p is number => typeof p === "number").slice(0, 200) : [];
    return { ip, ports, hostnames: list(data.hostnames), cpes: list(data.cpes), vulns: list(data.vulns).map((v) => v.toUpperCase()), tags: list(data.tags), nothing: ports.length === 0 && list(data.vulns).length === 0 };
  } catch (error) {
    if ((error as { status?: number }).status === 404) return empty;
    throw error;
  }
}
