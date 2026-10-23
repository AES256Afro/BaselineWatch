import { randomBytes } from "node:crypto";
import { looks, schemes, type Look, type Scheme } from "./look.ts";

/**
 * Runtime configuration, read once from the environment.
 *
 * Every variable is prefixed BW_. Secrets are never logged and never rendered;
 * pages only say whether one is set.
 */
export interface Config {
  /** Interface to bind. 127.0.0.1 when run by hand, 0.0.0.0 in the container. */
  host: string;
  port: number;
  /** Holds the SQLite database and the content-addressed snapshot blobs. */
  dataDir: string;
  /** The address people use, for links in digests and notifications. */
  baseUrl: string;
  timeZone: string;
  /** When true anyone who can reach the page may read it; writes still need the owner. */
  publicRead: boolean;
  /**
   * Whose X-Forwarded-For is believed, in Express's `trust proxy` words: addresses, CIDRs, or
   * loopback, linklocal, uniquelocal. The default believes every private address, which is what
   * lets a tunnel published through Docker's bridge be believed; where LAN visitors also connect
   * directly, narrow it to the proxy's own address, since a believed peer can forge the header.
   */
  trustedProxies: string;
  /** The owner's password. Unset means single-user mode: no sign-in, writes open. */
  adminPassword: string | null;
  /** Signs session cookies. Unset means a fresh secret per start, so sessions end on restart. */
  sessionSecret: string;
  /** False stops the in-process scheduler (tests, or when a cron job runs the CLI instead). */
  scheduler: boolean;
  nvdApiKey: string | null;
  /** How many days of NVD modifications the first pull loads. */
  nvdBackfillDays: number;
  notifyUrl: string | null;
  /** When true (the default) new articles get their lead image cached from the feed or og:image. */
  newsImages: boolean;
  llmUrl: string | null;
  /** The Ollama model name used for generated summaries. */
  llmModel: string;
  /** How often the digest is written and sent. */
  digest: "daily" | "weekly" | "off";
  /** Local hour (in `timeZone`) at which the digest runs. */
  digestHour: number;
  /** How pages are drawn unless a browser chose otherwise: the dense "console" or the paper "register". */
  look: Look;
  /** Light, dark, or "system" for whatever the device says. A browser may choose its own. */
  scheme: Scheme;
  /**
   * A second origin serving the same probe images (another BaselineWatch instance, or this one on
   * another hostname), so the Scan page can test a cross-site request beside the same-site one.
   * Unset means the same-site set alone.
   */
  probeOrigin: string | null;
}

function choice<T extends string>(env: Env, key: string, allowed: readonly T[], fallback: T): T {
  const value = env[key]?.trim().toLowerCase();
  if (!value) return fallback;
  if (!(allowed as readonly string[]).includes(value)) throw new Error(`${key} must be one of ${allowed.join(", ")}, got "${value}"`);
  return value as T;
}

function hour(env: Env, key: string, fallback: number): number {
  const value = env[key];
  if (value === undefined || value.trim() === "") return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0 || n > 23) throw new Error(`${key} must be an hour from 0 to 23, got "${value}"`);
  return n;
}

function days(env: Env, key: string, fallback: number): number {
  const value = env[key];
  if (value === undefined || value.trim() === "") return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 3650) throw new Error(`${key} must be a whole number of days between 1 and 3650, got "${value}"`);
  return n;
}

type Env = Record<string, string | undefined>;

function text(env: Env, key: string, fallback: string): string {
  const value = env[key];
  return value === undefined || value.trim() === "" ? fallback : value.trim();
}

function optional(env: Env, key: string): string | null {
  const value = env[key];
  return value === undefined || value.trim() === "" ? null : value.trim();
}

/** An http(s) origin and nothing more: scheme, host and port, no path, query or credentials. */
function origin(env: Env, key: string): string | null {
  const value = optional(env, key);
  if (value === null) return null;
  const problem = new Error(`${key} must be an http(s) origin such as https://probe.example.net, got "${value}"`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw problem;
  }
  if (!/^https?:$/.test(url.protocol) || url.username || url.password || url.origin !== value.replace(/\/+$/, "")) throw problem;
  return url.origin;
}

/** An http(s) URL to a service (a path is fine, credentials are not), or nothing. */
function httpUrl(env: Env, key: string): string | null {
  const value = optional(env, key);
  if (value === null) return null;
  const problem = new Error(`${key} must be an http(s) URL such as http://ollama:11434, got "${value}"`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw problem;
  }
  if (!/^https?:$/.test(url.protocol) || url.username || url.password) throw problem;
  return value;
}

function flag(env: Env, key: string, fallback: boolean): boolean {
  const value = env[key];
  if (value === undefined || value.trim() === "") return fallback;
  const word = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(word)) return true;
  if (["0", "false", "no", "off"].includes(word)) return false;
  // A typo must not quietly turn a flag off (close the site, stop the scheduler); it is refused at start-up.
  throw new Error(`${key} must be true or false (1/0, yes/no, on/off), got "${value}"`);
}

function port(env: Env, key: string, fallback: number): number {
  const value = env[key];
  if (value === undefined || value.trim() === "") return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    throw new Error(`${key} must be a port number between 1 and 65535, got "${value}"`);
  }
  return n;
}

export function loadConfig(env: Env = process.env): Config {
  const portNumber = port(env, "BW_PORT", 8790);
  return {
    host: text(env, "BW_HOST", "127.0.0.1"),
    port: portNumber,
    dataDir: text(env, "BW_DATA_DIR", "./data"),
    baseUrl: text(env, "BW_BASE_URL", `http://localhost:${portNumber}`).replace(/\/+$/, ""),
    timeZone: text(env, "TZ", "Etc/UTC"),
    publicRead: flag(env, "BW_PUBLIC_READ", true),
    trustedProxies: text(env, "BW_TRUSTED_PROXIES", "loopback, linklocal, uniquelocal"),
    adminPassword: optional(env, "BW_ADMIN_PASSWORD"),
    sessionSecret: optional(env, "BW_SESSION_SECRET") ?? randomBytes(32).toString("hex"),
    scheduler: flag(env, "BW_SCHEDULER", true),
    nvdApiKey: optional(env, "BW_NVD_API_KEY"),
    nvdBackfillDays: days(env, "BW_NVD_BACKFILL_DAYS", 7),
    notifyUrl: optional(env, "BW_NOTIFY_URL"),
    newsImages: flag(env, "BW_NEWS_IMAGES", true),
    llmUrl: httpUrl(env, "BW_LLM_URL"),
    llmModel: text(env, "BW_LLM_MODEL", "llama3.2:3b"),
    digest: choice(env, "BW_DIGEST", ["daily", "weekly", "off"] as const, "daily"),
    digestHour: hour(env, "BW_DIGEST_HOUR", 7),
    look: choice(env, "BW_LOOK", looks, "console"),
    scheme: choice(env, "BW_SCHEME", schemes, "system"),
    probeOrigin: origin(env, "BW_PROBE_ORIGIN"),
  };
}
