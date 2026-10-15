import type { DatabaseSync } from "node:sqlite";
import { httpGet, type HttpGet } from "./http.ts";

/**
 * One notification URL, Apprise-style, three transports:
 *   ntfy://host[:port]/topic     (ntfys:// for TLS)
 *   gotify://host[:port]/token   (gotifys:// for TLS)
 *   https://... or http://...    a webhook that receives {title, body, url, kind} as JSON
 * Email goes through one of these (ntfy and Apprise both forward to mail) rather than SMTP here.
 */
export interface Notification {
  kind: "kev" | "release" | "watch" | "digest" | "test";
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

/** Sends one notification; never throws. Returns what happened for the alerts log. */
export async function send(transport: Transport | null, n: Notification, http: HttpGet = httpGet): Promise<{ status: "sent" | "failed" | "unconfigured"; error: string | null }> {
  if (!transport) return { status: "unconfigured", error: null };
  try {
    if (transport.scheme === "ntfy") {
      const headers: Record<string, string> = { title: n.title, tags: n.kind === "kev" ? "rotating_light" : n.kind === "release" ? "page_facing_up" : "bell", "content-type": "text/plain; charset=utf-8" };
      if (n.url) headers.click = n.url;
      await http(transport.endpoint, { method: "POST", body: n.body, headers, timeoutMs: 20_000 });
    } else if (transport.scheme === "gotify") {
      const body = JSON.stringify({ title: n.title, message: n.url ? `${n.body}\n${n.url}` : n.body, priority: n.kind === "kev" ? 7 : 4 });
      await http(transport.endpoint, { method: "POST", body, headers: { "content-type": "application/json", "x-gotify-key": transport.token ?? "" }, timeoutMs: 20_000 });
    } else {
      await http(transport.endpoint, { method: "POST", body: JSON.stringify({ kind: n.kind, title: n.title, body: n.body, url: n.url ?? null }), headers: { "content-type": "application/json" }, timeoutMs: 20_000 });
    }
    return { status: "sent", error: null };
  } catch (error) {
    return { status: "failed", error: error instanceof Error ? error.message : String(error) };
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
