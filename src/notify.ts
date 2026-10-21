import type { DatabaseSync } from "node:sqlite";
import { HttpError, httpGet, type HttpGet } from "./http.ts";

/**
 * One notification URL, Apprise-style, three transports:
 *   ntfy://host[:port]/topic     (ntfys:// for TLS)
 *   gotify://host[:port]/token   (gotifys:// for TLS)
 *   https://... or http://...    a webhook that receives {title, body, url, kind} as JSON
 * Email goes through one of these (ntfy and Apprise both forward to mail) rather than SMTP here.
 */
export interface Notification {
  kind: "kev" | "release" | "watch" | "directive" | "digest" | "network" | "source" | "test";
  title: string;
  body: string;
  url?: string | null;
}

export interface Transport {
  scheme: "ntfy" | "gotify" | "webhook";
  endpoint: string;
  token?: string;
}

export function parseNotifyUrl(value: string | null): Transport | null {
  if (!value) return null;
  const m = /^(ntfys?|gotifys?|https?):\/\/(.+)$/i.exec(value.trim());
  if (!m) return null;
  const scheme = m[1]!.toLowerCase();
  const rest = m[2]!;
  if (scheme.startsWith("ntfy")) {
    const slash = rest.indexOf("/");
    if (slash < 0) return null;
    const host = rest.slice(0, slash);
    const topic = rest.slice(slash + 1).replace(/\/+$/, "");
    if (!topic) return null;
    return { scheme: "ntfy", endpoint: `${scheme === "ntfys" ? "https" : "http"}://${host}/${topic}` };
  }
  if (scheme.startsWith("gotify")) {
    const slash = rest.indexOf("/");
    if (slash < 0) return null;
    const host = rest.slice(0, slash);
    const token = rest.slice(slash + 1).replace(/\/+$/, "");
    if (!token) return null;
    return { scheme: "gotify", endpoint: `${scheme === "gotifys" ? "https" : "http"}://${host}/message`, token };
  }
  return { scheme: "webhook", endpoint: value.trim() };
}

/** An HTTP header value: ASCII as is, anything else RFC 2047-encoded, which ntfy decodes (a raw em dash would make fetch refuse the header). */
export function headerValue(value: string): string {
  return /^[\x20-\x7e]*$/.test(value) ? value : `=?UTF-8?B?${Buffer.from(value, "utf8").toString("base64")}?=`;
}

/**
 * What the alerts log keeps of a failure: the status or the kind of error, never the message,
 * because an HttpError's message names the endpoint and the endpoint is the credential (a
 * webhook URL, an ntfy topic) and the log is shown on the Digest page.
 */
export function failureText(error: unknown): string {
  if (error instanceof HttpError) return `HTTP ${error.status}`;
  if (error instanceof Error) return error.name === "TimeoutError" || error.name === "AbortError" ? "timed out" : `send failed (${error.name})`;
  return "send failed";
}

/** Sends one notification; never throws. Returns what happened for the alerts log. */
export async function send(transport: Transport | null, n: Notification, http: HttpGet = httpGet): Promise<{ status: "sent" | "failed" | "unconfigured"; error: string | null }> {
  if (!transport) return { status: "unconfigured", error: null };
  // A redirect is refused: the token or the body must not be re-sent to wherever a 3xx points.
  const post = { method: "POST" as const, timeoutMs: 20_000, redirect: "manual" as const };
  try {
    if (transport.scheme === "ntfy") {
      const headers: Record<string, string> = { title: headerValue(n.title), tags: n.kind === "kev" || n.kind === "network" ? "rotating_light" : n.kind === "directive" ? "warning" : n.kind === "release" ? "page_facing_up" : "bell", "content-type": "text/plain; charset=utf-8" };
      if (n.url) headers.click = headerValue(n.url);
      await http(transport.endpoint, { ...post, body: n.body, headers });
    } else if (transport.scheme === "gotify") {
      const body = JSON.stringify({ title: n.title, message: n.url ? `${n.body}\n${n.url}` : n.body, priority: n.kind === "kev" || n.kind === "directive" || n.kind === "network" ? 7 : 4 });
      await http(transport.endpoint, { ...post, body, headers: { "content-type": "application/json", "x-gotify-key": transport.token ?? "" } });
    } else {
      await http(transport.endpoint, { ...post, body: JSON.stringify({ kind: n.kind, title: n.title, body: n.body, url: n.url ?? null }), headers: { "content-type": "application/json" } });
    }
    return { status: "sent", error: null };
  } catch (error) {
    return { status: "failed", error: failureText(error) };
  }
}

/** Sends and records. The alerts table is the audit trail the Today view and the Sources page show. */
export async function notify(db: DatabaseSync, transport: Transport | null, n: Notification, http: HttpGet = httpGet, now: () => Date = () => new Date()): Promise<void> {
  const result = await send(transport, n, http);
  db.prepare("INSERT INTO alerts (kind, title, body, url, sent_at, status, error) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
    n.kind,
    n.title,
    n.body,
    n.url ?? null,
    now().toISOString(),
    result.status,
    result.error,
  );
}

export interface AlertRow {
  id: number;
  kind: string;
  title: string;
  body: string | null;
  url: string | null;
  sent_at: string;
  status: string;
  error: string | null;
}

export function recentAlerts(db: DatabaseSync, limit = 20): AlertRow[] {
  return db.prepare("SELECT * FROM alerts ORDER BY sent_at DESC, id DESC LIMIT ?").all(limit) as unknown as AlertRow[];
}
