import type { DatabaseSync } from "node:sqlite";
import { HttpError, httpGet, type HttpGet } from "./http.ts";
import { parseMailUrl, sendMail, SmtpError, type MailDeps, type MailTransport } from "./smtp.ts";

/**
 * One notification URL, Apprise-style, four transports:
 *   ntfy://host[:port]/topic                       (ntfys:// for TLS)
 *   gotify://host[:port]/token                     (gotifys:// for TLS)
 *   https://... or http://...                      a webhook that receives {title, body, url, kind} as JSON
 *   mailto://user:pass@host[:port]/to@example.org  (mailtos:// for TLS from the first byte; ?from= to set the sender)
 * Mail goes by the small SMTP client in src/smtp.ts: STARTTLS when offered, AUTH PLAIN when a
 * password is given, never a password in the clear.
 */
export interface Notification {
  kind: "kev" | "release" | "watch" | "directive" | "digest" | "network" | "source" | "test";
  title: string;
  body: string;
  url?: string | null;
}

export interface Transport {
  scheme: "ntfy" | "gotify" | "webhook" | "mail";
  /** Where it goes; for mail, the recipient's address (the host and credentials sit in `mail`). */
  endpoint: string;
  token?: string;
  mail?: MailTransport;
}

export function parseNotifyUrl(value: string | null): Transport | null {
  if (!value) return null;
  const mail = parseMailUrl(value);
  if (mail) return { scheme: "mail", endpoint: mail.to, mail };
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
function headerValue(value: string): string {
  return /^[\x20-\x7e]*$/.test(value) ? value : `=?UTF-8?B?${Buffer.from(value, "utf8").toString("base64")}?=`;
}

/**
 * What the alerts log keeps of a failure: the status or the kind of error, never the message,
 * because an HttpError's message names the endpoint and the endpoint is the credential (a
 * webhook URL, an ntfy topic) and the log is shown on the Digest page.
 */
function failureText(error: unknown): string {
  if (error instanceof HttpError) return `HTTP ${error.status}`;
  if (error instanceof SmtpError) return `SMTP ${error.code}`;
  if (error instanceof Error) return error.name === "TimeoutError" || error.name === "AbortError" ? "timed out" : `send failed (${error.name})`;
  return "send failed";
}

/** Sends one notification; never throws. Returns what happened for the alerts log. */
export async function send(transport: Transport | null, n: Notification, http: HttpGet = httpGet, mailDeps: MailDeps = {}): Promise<{ status: "sent" | "failed" | "unconfigured"; error: string | null }> {
  if (!transport) return { status: "unconfigured", error: null };
  if (transport.scheme === "mail" && transport.mail) {
    try {
      await sendMail(transport.mail, { subject: n.title, text: n.url ? `${n.body}\n\n${n.url}` : n.body }, mailDeps);
      return { status: "sent", error: null };
    } catch (error) {
      return { status: "failed", error: failureText(error) };
    }
  }
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
