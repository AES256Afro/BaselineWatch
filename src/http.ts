import { lookup } from "node:dns/promises";
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
}

export type HttpGet = (url: string, options?: HttpOptions) => Promise<HttpResponse>;

export class HttpError extends Error {
  readonly status: number;
  constructor(url: string, status: number) {
    super(`HTTP ${status} from ${url}`);
    this.status = status;
  }
}

const maxRedirects = 5;

/** Whether an address is loopback, private, link-local, multicast or otherwise not a public host. */
export function privateAddress(ip: string): boolean {
  const v6 = ip.toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v6);
  if (mapped) return privateAddress(mapped[1]!);
  if (isIP(ip) === 4) {
    const [a = 0, b = 0] = ip.split(".").map(Number);
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224
    );
  }
  if (isIP(ip) === 6) {
    const head = v6.replace(/^\[|\]$/g, "");
    if (head === "::" || head === "::1") return true;
    const first = Number.parseInt(head.split(":")[0] || "0", 16);
    return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80 || (first & 0xff00) === 0xff00 || head.startsWith("64:ff9b:");
  }
  return true;
}

/** Refuses a URL that is not http(s) to a public host; the host is resolved and every address checked. */
export async function assertPublicUrl(url: string): Promise<void> {
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

/** GET with a timeout, conditional headers, a size cap and the product's User-Agent. */
export const httpGet: HttpGet = async (url, options = {}) => {
  const headers: Record<string, string> = {
    "user-agent": userAgent,
    accept: "application/rss+xml, application/atom+xml, application/xml, text/xml, application/json;q=0.9, */*;q=0.5",
    ...options.headers,
  };
  if (options.etag) headers["if-none-match"] = options.etag;
  if (options.lastModified) headers["if-modified-since"] = options.lastModified;
  const method = options.method ?? (options.body !== undefined ? "POST" : "GET");
  // Redirects are followed by hand when each hop must be vetted, or refused when asked; fetch follows the rest itself.
  const byHand = options.publicOnly === true || options.redirect === "manual";
  const signal = AbortSignal.timeout(options.timeoutMs ?? 30_000);
  const maxBytes = options.maxBytes ?? 25 * 1024 * 1024;

  let target = url;
  for (let hop = 0; ; hop += 1) {
    if (options.publicOnly) await assertPublicUrl(target);
    const response = await fetch(target, {
      method,
      headers,
      ...(options.body !== undefined ? { body: options.body } : {}),
      redirect: byHand ? "manual" : "follow",
      signal,
    });

    if (byHand && response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      await response.body?.cancel().catch(() => {});
      if (options.redirect === "manual" || !location || hop >= maxRedirects) throw new HttpError(target, response.status);
      target = new URL(location, target).toString();
      continue;
    }

    const etag = response.headers.get("etag");
    const lastModified = response.headers.get("last-modified");
    const contentType = response.headers.get("content-type");

    if (response.status === 304) {
      await response.body?.cancel().catch(() => {});
      return { url, status: 304, notModified: true, bytes: new Uint8Array(0), etag, lastModified, contentType };
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      throw new HttpError(target, response.status);
    }
    const declared = Number(response.headers.get("content-length") ?? 0);
    if (declared > maxBytes) {
      await response.body?.cancel().catch(() => {});
      throw new Error(`response from ${target} declares ${declared} bytes, over the ${maxBytes} limit`);
    }
    const bytes = await readCapped(response, maxBytes, target);
    return { url, status: response.status, notModified: false, bytes, etag, lastModified, contentType };
  }
};
