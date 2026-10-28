import { lookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";
import { productVersion } from "./version.ts";

/** Every outbound request identifies itself; feed publishers and Reddit require it. */
export const userAgent = `BaselineWatch/${productVersion} (+https://cybercard.net; security news and baseline change tracker)`;

export interface HttpOptions {
  /** Sent as If-None-Match when set. */
  etag?: string | null;
  /** Sent as If-Modified-Since when set. */
  lastModified?: string | null;
  timeoutMs?: number;
  headers?: Record<string, string>;
  /** Responses larger than this are refused, while they stream: the cap holds for chunked and compressed bodies too. */
  maxBytes?: number;
  /** GET unless a body is given; the few listing endpoints that need a POST send JSON. */
  method?: "GET" | "POST";
  body?: string;
  /** Follow redirects (the default), or refuse them: a 3xx then fails as an HttpError. */
  redirect?: "follow" | "manual";
  /**
   * The URL came from a feed, a page or a user's post rather than from a publisher the owner
   * chose: only public hosts are allowed. Loopback, LAN, link-local and other reserved
   * addresses are refused, and every redirect hop is checked again before it is followed.
   */
  publicOnly?: boolean;
}

export interface HttpResponse {
  url: string;
  status: number;
  /** True for a 304; `bytes` is then empty. */
  notModified: boolean;
  bytes: Uint8Array;
  etag: string | null;
  lastModified: string | null;
  contentType: string | null;
  /** Every response header, names lowercased; the security headers a domain check reads come from here. Absent from a hand-made fake. */
  headers?: Record<string, string>;
}

export type HttpGet = (url: string, options?: HttpOptions) => Promise<HttpResponse>;

export class HttpError extends Error {
  readonly status: number;
  /** The refused response's headers, so a 3xx's Location or a 403's HSTS can still be read. */
  readonly headers: Record<string, string>;
  constructor(url: string, status: number, headers: Record<string, string> = {}) {
    super(`HTTP ${status} from ${url}`);
    this.status = status;
    this.headers = headers;
  }
}

/** A response's headers as a plain object, names lowercased. */
export function headersOf(response: Response): Record<string, string> {
  const out: Record<string, string> = {};
  response.headers.forEach((value, name) => {
    out[name.toLowerCase()] = value;
  });
  return out;
}

const maxRedirects = 5;

/** An IPv6 address as its eight hextets, however it was written (compressed, with a dotted quad, bracketed, with a zone), or null. */
export function hextets(ip: string): number[] | null {
  const bare = ip.replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  const halves = bare.split("::");
  if (halves.length > 2) return null;
  const groups = (s: string): number[] =>
    (s ? s.split(":") : []).flatMap((g) => {
      if (g.includes(".")) {
        const quad = g.split(".").map(Number);
        if (quad.length !== 4 || quad.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return [Number.NaN];
        return [(quad[0]! << 8) | quad[1]!, (quad[2]! << 8) | quad[3]!];
      }
      return [/^[0-9a-f]{1,4}$/i.test(g) ? Number.parseInt(g, 16) : Number.NaN];
    });
  const head = groups(halves[0]!);
  const tail = halves.length === 2 ? groups(halves[1]!) : [];
  const fill = 8 - head.length - tail.length;
  if (fill < 0 || (halves.length === 1 && fill !== 0)) return null;
  const all = [...head, ...Array<number>(fill).fill(0), ...tail];
  return all.every((n) => Number.isInteger(n)) ? all : null;
}

/** Whether an address is loopback, private, link-local, multicast or otherwise not a public host. */
export function privateAddress(ip: string): boolean {
  const bare = ip.replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  const kind = isIP(bare);
  if (kind === 4) {
    const [a = 0, b = 0, c = 0] = bare.split(".").map(Number);
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      // Two more of IANA's special-purpose ranges that a network really can carry a host on, and
      // that a publisher is never on: protocol assignments (192.0.0.0/24, which holds the DS-Lite
      // and NAT64 well-known addresses) and benchmarking (198.18.0.0/15, routed inside some
      // networks). The three documentation ranges — 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
      // — are deliberately *not* here: they route nowhere, so refusing them stops nothing, and
      // they are this project's own stand-in for a public address in tests, fixtures and the
      // guides. Blocking the placeholder would cost every one of those a special case.
      (a === 192 && b === 0 && c === 0) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }
  if (kind !== 6) return true;
  const g = hextets(bare);
  if (!g) return true;
  const quad = (hi: number, lo: number): string => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  // ::/8 holds the unspecified and loopback addresses and the IPv4-mapped and -compatible forms
  // (::ffff:a.b.c.d is also written ::ffff:XXXX:XXXX): the embedded IPv4 decides, the rest is private.
  if (g[0] === 0) return g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff ? privateAddress(quad(g[6]!, g[7]!)) : true;
  if ((g[0]! & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((g[0]! & 0xffc0) === 0xfe80) return true; // fe80::/10 link local
  if ((g[0]! & 0xffc0) === 0xfec0) return true; // fec0::/10 site local (deprecated, still routed on old networks)
  if ((g[0]! & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (g[0] === 0x100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return true; // 100::/64 discard-only
  if (g[0] === 0x64 && g[1] === 0xff9b) return privateAddress(quad(g[6]!, g[7]!)); // 64:ff9b::/96 NAT64
  if (g[0] === 0x2002) return privateAddress(quad(g[1]!, g[2]!)); // 2002::/16 6to4
  // 2001::/32 is Teredo: the address embeds an obfuscated IPv4 and the tunnel is not a
  // publisher's host. 2001:db8::/32, the documentation range, is left public for the same reason
  // the IPv4 ones above are: it is the placeholder this project writes examples with.
  if (g[0] === 0x2001 && g[1] === 0) return true;
  return false;
}

/**
 * Refuses a URL that is not http(s) to a public host; the host is resolved and every address
 * checked. Answers the addresses, so the request can go to one of them rather than resolve the
 * name again: a name with a short TTL that answers public once and private the next time would
 * otherwise slip a LAN address past the check (DNS rebinding).
 */
export async function assertPublicUrl(url: string): Promise<string[]> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`refusing ${url}: not a URL`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error(`refusing ${parsed.protocol} URL`);
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) throw new Error(`refusing ${host}: not a public host`);
  const addresses = isIP(host) ? [host] : (await lookup(host, { all: true })).map((a) => a.address);
  if (addresses.length === 0 || addresses.some(privateAddress)) throw new Error(`refusing ${host}: not a public host`);
  return addresses;
}

/** What one hop answered, from either transport: the status, the headers, and the body on request, capped. */
interface Reply {
  status: number;
  headers: Record<string, string>;
  header(name: string): string | null;
  body(maxBytes: number, url: string): Promise<Uint8Array>;
  discard(): Promise<void>;
}

/** fetch, for a publisher the owner chose: it follows redirects itself when asked and decompresses. */
async function viaFetch(target: string, init: { method: string; headers: Record<string, string>; body?: string; redirect: "follow" | "manual"; signal: AbortSignal }): Promise<Reply> {
  const response = await fetch(target, { method: init.method, headers: init.headers, ...(init.body !== undefined ? { body: init.body } : {}), redirect: init.redirect, signal: init.signal });
  return {
    status: response.status,
    headers: headersOf(response),
    header: (name) => response.headers.get(name),
    body: (maxBytes, url) => readCapped(response, maxBytes, url),
    discard: async () => {
      await response.body?.cancel().catch(() => {});
    },
  };
}

/**
 * One request to a host whose address was already vetted: the socket goes to that address and
 * the name stays on the wire — the Host header, the SNI and the certificate check all use it —
 * so the bytes come from the host the check approved and not from a second resolution. Used for
 * every `publicOnly` hop; a test hands in a loopback address under a name that resolves nowhere.
 */
export function pinnedRequest(target: string, address: string, init: { method: string; headers: Record<string, string>; body?: string; timeoutMs: number }): Promise<Reply> {
  const parsed = new URL(target);
  const family = isIP(address);
  // net.connect asks for one address or, with `all`, a list; both forms answer the vetted one.
  const pinned = (_hostname: string, options: { all?: boolean }, callback: (error: Error | null, address: string | { address: string; family: number }[], family?: number) => void): void => {
    if (options.all) callback(null, [{ address, family }]);
    else callback(null, address, family);
  };
  const transport = parsed.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const request = transport.request(parsed, { method: init.method, headers: init.headers, lookup: pinned as never, timeout: init.timeoutMs }, (response) => {
      // The deadline runs on through the body, as AbortSignal.timeout does on the other path: a
      // server that answers its headers at once and then drips a byte inside every idle window
      // would otherwise hold the request, and the scheduler slot waiting on it, for as long as it liked.
      response.on("close", () => clearTimeout(deadline));
      const headers: Record<string, string> = {};
      for (const [name, value] of Object.entries(response.headers)) {
        if (value !== undefined) headers[name.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
      }
      resolve({
        status: response.statusCode ?? 0,
        headers,
        header: (name) => headers[name.toLowerCase()] ?? null,
        body: (maxBytes, url) =>
          new Promise((ok, fail) => {
            const chunks: Buffer[] = [];
            let total = 0;
            response.on("data", (chunk: Buffer) => {
              total += chunk.length;
              if (total > maxBytes) {
                request.destroy();
                fail(new Error(`response from ${url} exceeds the ${maxBytes} byte limit`));
                return;
              }
              chunks.push(chunk);
            });
            response.on("end", () => ok(Buffer.concat(chunks)));
            response.on("error", fail);
            // Destroyed by the deadline before the end: a body cut short is a failure, not a short answer.
            response.on("close", () => {
              if (!response.complete) fail(new Error(`no complete answer from ${parsed.host} within ${init.timeoutMs} ms`));
            });
          }),
        discard: async () => {
          response.resume();
        },
      });
    });
    const fail = (): void => {
      request.destroy(Object.assign(new Error(`no answer from ${parsed.host} within ${init.timeoutMs} ms`), { code: "timeout" }));
    };
    // `timeout` is the socket's idle limit; the deadline bounds the whole request, body included.
    const deadline = setTimeout(fail, init.timeoutMs);
    request.on("timeout", fail);
    request.on("error", (error) => {
      clearTimeout(deadline);
      reject(error);
    });
    if (init.body !== undefined) request.write(init.body);
    request.end();
  });
}

/** Reads a body while counting, so a chunked or compressed reply cannot grow past the cap in memory. */
async function readCapped(response: Response, maxBytes: number, url: string): Promise<Uint8Array> {
  if (!response.body) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new Error(`response from ${url} exceeds the ${maxBytes} byte limit`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.byteLength;
  }
  return out;
}

const redirectStatus = new Set([301, 302, 303, 307, 308]);

/** GET with a timeout, conditional headers, a size cap and the product's User-Agent. */
export const httpGet: HttpGet = async (url, options = {}) => {
  const headers: Record<string, string> = {
    "user-agent": userAgent,
    accept: "application/rss+xml, application/atom+xml, application/xml, text/xml, application/json;q=0.9, */*;q=0.5",
    ...options.headers,
  };
  if (options.etag) headers["if-none-match"] = options.etag;
  if (options.lastModified) headers["if-modified-since"] = options.lastModified;
  let method = options.method ?? (options.body !== undefined ? "POST" : "GET");
  let body = options.body;
  // Redirects are followed by hand when each hop must be vetted, or refused when asked; fetch follows the rest itself.
  const byHand = options.publicOnly === true || options.redirect === "manual";
  const signal = AbortSignal.timeout(options.timeoutMs ?? 30_000);
  const maxBytes = options.maxBytes ?? 25 * 1024 * 1024;

  let target = url;
  for (let hop = 0; ; hop += 1) {
    let response: Reply;
    if (options.publicOnly) {
      const addresses = await assertPublicUrl(target);
      response = await pinnedRequest(target, addresses[0]!, { method, headers, ...(body !== undefined ? { body } : {}), timeoutMs: options.timeoutMs ?? 30_000 });
    } else {
      response = await viaFetch(target, { method, headers, ...(body !== undefined ? { body } : {}), redirect: byHand ? "manual" : "follow", signal });
    }

    if (byHand && redirectStatus.has(response.status)) {
      const location = response.header("location");
      await response.discard();
      if (options.redirect === "manual" || !location || hop >= maxRedirects) throw new HttpError(target, response.status, response.headers);
      target = new URL(location, target).toString();
      // A 303, or a 301/302 answered to a POST, continues as a GET without the body, as browsers do.
      if (response.status === 303 || (method === "POST" && response.status !== 307 && response.status !== 308)) {
        method = "GET";
        body = undefined;
      }
      continue;
    }

    const etag = response.header("etag");
    const lastModified = response.header("last-modified");
    const contentType = response.header("content-type");

    if (response.status === 304) {
      await response.discard();
      return { url, status: 304, notModified: true, bytes: new Uint8Array(0), etag, lastModified, contentType, headers: response.headers };
    }
    if (response.status < 200 || response.status >= 300) {
      await response.discard();
      throw new HttpError(target, response.status, response.headers);
    }
    const declared = Number(response.header("content-length") ?? 0);
    if (declared > maxBytes) {
      await response.discard();
      throw new Error(`response from ${target} declares ${declared} bytes, over the ${maxBytes} limit`);
    }
    const bytes = await response.body(maxBytes, target);
    return { url, status: response.status, notModified: false, bytes, etag, lastModified, contentType, headers: response.headers };
  }
};
