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
  /** Responses larger than this are refused. */
  maxBytes?: number;
  /** GET unless a body is given; the few listing endpoints that need a POST send JSON. */
  method?: "GET" | "POST";
  body?: string;
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

/** GET with a timeout, conditional headers, a size cap and the product's User-Agent. */
export const httpGet: HttpGet = async (url, options = {}) => {
  const headers: Record<string, string> = {
    "user-agent": userAgent,
    accept: "application/rss+xml, application/atom+xml, application/xml, text/xml, application/json;q=0.9, */*;q=0.5",
    ...options.headers,
  };
  if (options.etag) headers["if-none-match"] = options.etag;
  if (options.lastModified) headers["if-modified-since"] = options.lastModified;

  const response = await fetch(url, {
    method: options.method ?? (options.body !== undefined ? "POST" : "GET"),
    headers,
    ...(options.body !== undefined ? { body: options.body } : {}),
    redirect: "follow",
    signal: AbortSignal.timeout(options.timeoutMs ?? 30_000),
  });

  const etag = response.headers.get("etag");
  const lastModified = response.headers.get("last-modified");
  const contentType = response.headers.get("content-type");

  if (response.status === 304) {
    return { url, status: 304, notModified: true, bytes: new Uint8Array(0), etag, lastModified, contentType };
  }
  if (!response.ok) {
    throw new HttpError(url, response.status);
  }
  const maxBytes = options.maxBytes ?? 25 * 1024 * 1024;
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (declared > maxBytes) throw new Error(`response from ${url} declares ${declared} bytes, over the ${maxBytes} limit`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > maxBytes) throw new Error(`response from ${url} is ${bytes.byteLength} bytes, over the ${maxBytes} limit`);
  return { url, status: response.status, notModified: false, bytes, etag, lastModified, contentType };
};
