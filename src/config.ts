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
  /** When true anyone who can reach the page may read it; writes still need the owner (M7). */
  publicRead: boolean;
  nvdApiKey: string | null;
  notifyUrl: string | null;
  llmUrl: string | null;
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

function flag(env: Env, key: string, fallback: boolean): boolean {
  const value = env[key];
  if (value === undefined || value.trim() === "") return fallback;
  return ["1", "true", "yes", "on"].includes(value.trim().toLowerCase());
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
    nvdApiKey: optional(env, "BW_NVD_API_KEY"),
    notifyUrl: optional(env, "BW_NOTIFY_URL"),
    llmUrl: optional(env, "BW_LLM_URL"),
  };
}
