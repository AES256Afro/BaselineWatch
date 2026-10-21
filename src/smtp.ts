import net from "node:net";
import tls from "node:tls";

/**
 * A small SMTP client for the notifier (N6): one message to one address, over implicit TLS or
 * STARTTLS, with AUTH PLAIN when the owner gave a user and password. Enough for a digest or an
 * alert to reach an inbox at any ordinary provider; not a mail library. The dialogue is the
 * plain one — greeting, EHLO, STARTTLS, EHLO again, AUTH, MAIL FROM, RCPT TO, DATA, QUIT — each
 * answer read whole (a 250- continuation line is one answer) and judged by its code. The socket
 * is injectable so the tests speak the server's side.
 */

export interface MailTransport {
  host: string;
  port: number;
  /** TLS from the first byte (465); otherwise STARTTLS is used when the server offers it. */
  secure: boolean;
  user: string | null;
  pass: string | null;
  from: string;
  to: string;
}

export interface MailMessage {
  subject: string;
  text: string;
}

export class SmtpError extends Error {
  readonly code: number;
  constructor(step: string, code: number, line: string) {
    super(`SMTP ${step}: ${code} ${line.slice(0, 120)}`);
    this.name = "SmtpError";
    this.code = code;
  }
}

/** Either kind of socket, as the client reads and writes it. */
export type MailSocket = net.Socket | tls.TLSSocket;

export interface MailDeps {
  connect?: (t: MailTransport) => MailSocket;
  upgrade?: (socket: MailSocket, host: string) => Promise<MailSocket>;
  now?: () => Date;
  timeoutMs?: number;
}

/** The client's name in EHLO, and the domain of its Message-ID: the local host as the OS names it, else a fixed word. */
const clientName = (): string => {
  try {
    return (process.env.HOSTNAME || "baselinewatch").replace(/[^A-Za-z0-9.-]/g, "") || "baselinewatch";
  } catch {
    return "baselinewatch";
  }
};

/** RFC 2047 for a subject that is not plain ASCII. */
function headerText(value: string): string {
  return /^[\x20-\x7e]*$/.test(value) ? value : `=?UTF-8?B?${Buffer.from(value, "utf8").toString("base64")}?=`;
}

/** The message as the wire wants it: CRLF line ends, a leading dot doubled, headers first. */
export function wireMessage(t: MailTransport, m: MailMessage, now: Date, id: string): string {
  const body = m.text.replace(/\r?\n/g, "\r\n").replace(/^\./gm, "..");
  const headers = [
    `From: ${t.from}`,
    `To: ${t.to}`,
    `Subject: ${headerText(m.subject)}`,
    `Date: ${now.toUTCString()}`,
    `Message-ID: <${id}@${clientName()}>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: 8bit",
    "Auto-Submitted: auto-generated",
  ];
  return `${headers.join("\r\n")}\r\n\r\n${body}\r\n.\r\n`;
}

/** Reads one SMTP answer: lines until one whose fourth character is a space. */
class Reader {
  private buffer = "";
  private waiting: { resolve: (lines: string[]) => void; reject: (e: Error) => void } | null = null;
  private closed: Error | null = null;
  constructor(socket: MailSocket, timeoutMs: number) {
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      this.buffer += chunk;
      this.deliver();
    });
    socket.on("error", (error: Error) => this.fail(error));
    socket.on("close", () => this.fail(new Error("the server closed the connection")));
    socket.setTimeout(timeoutMs, () => this.fail(new Error("the server went quiet")));
  }
  private fail(error: Error): void {
    this.closed = error;
    if (this.waiting) {
      this.waiting.reject(error);
      this.waiting = null;
    }
  }
  private deliver(): void {
    if (!this.waiting) return;
    const lines = this.buffer.split("\r\n");
    const end = lines.findIndex((l) => /^\d{3}(\s|$)/.test(l));
    if (end < 0) return;
    const answer = lines.slice(0, end + 1);
    this.buffer = lines.slice(end + 1).join("\r\n");
    const w = this.waiting;
    this.waiting = null;
    w.resolve(answer);
  }
  answer(): Promise<string[]> {
    return new Promise((resolve, reject) => {
      if (this.closed) return reject(this.closed);
      this.waiting = { resolve, reject };
      this.deliver();
    });
  }
}

const defaultConnect = (t: MailTransport): MailSocket => (t.secure ? tls.connect({ host: t.host, port: t.port, servername: t.host }) : net.connect({ host: t.host, port: t.port }));
const defaultUpgrade = (socket: MailSocket, host: string): Promise<MailSocket> =>
  new Promise((resolve, reject) => {
    const secure = tls.connect({ socket: socket as net.Socket, servername: host }, () => resolve(secure));
    secure.on("error", reject);
  });

/** Sends one message, or throws an SmtpError with the step and code (never the credentials). */
export async function sendMail(t: MailTransport, m: MailMessage, deps: MailDeps = {}): Promise<void> {
  const timeoutMs = deps.timeoutMs ?? 20_000;
  const now = deps.now ?? (() => new Date());
  let socket = (deps.connect ?? defaultConnect)(t);
  let reader = new Reader(socket, timeoutMs);
  const expect = async (step: string, ok: number[]): Promise<string[]> => {
    const lines = await reader.answer();
    const code = Number(lines[lines.length - 1]!.slice(0, 3));
    if (!ok.includes(code)) throw new SmtpError(step, code, lines[lines.length - 1]!);
    return lines;
  };
  const say = async (line: string, step: string, ok: number[]): Promise<string[]> => {
    socket.write(`${line}\r\n`);
    return expect(step, ok);
  };
  try {
    await expect("greeting", [220]);
    let ehlo = await say(`EHLO ${clientName()}`, "EHLO", [250]);
    if (!t.secure && ehlo.some((l) => /^250[- ]STARTTLS/i.test(l))) {
      await say("STARTTLS", "STARTTLS", [220]);
      socket = await (deps.upgrade ?? defaultUpgrade)(socket, t.host);
      reader = new Reader(socket, timeoutMs);
      ehlo = await say(`EHLO ${clientName()}`, "EHLO after STARTTLS", [250]);
    } else if (!t.secure && t.pass) {
      throw new SmtpError("STARTTLS", 0, "the server offers no STARTTLS, and a password is not sent in the clear");
    }
    if (t.user && t.pass) {
      const plain = Buffer.from(`\0${t.user}\0${t.pass}`, "utf8").toString("base64");
      await say(`AUTH PLAIN ${plain}`, "AUTH", [235]);
    }
    await say(`MAIL FROM:<${t.from}>`, "MAIL FROM", [250]);
    await say(`RCPT TO:<${t.to}>`, "RCPT TO", [250, 251]);
    await say("DATA", "DATA", [354]);
    const id = `${now().getTime().toString(36)}.${Math.random().toString(36).slice(2, 10)}`;
    socket.write(wireMessage(t, m, now(), id));
    await expect("message", [250]);
    // The message is accepted; a QUIT the server never answers is not a failure.
    await say("QUIT", "QUIT", [221]).catch(() => undefined);
  } finally {
    socket.end();
    socket.destroy();
  }
}

/**
 * mailto://user:pass@host:587/to@example.org?from=bw@example.org — the notifier's mail form,
 * Apprise-style: mailtos:// for TLS from the first byte (465), otherwise STARTTLS. The user and
 * password are percent-decoded; from defaults to the user when it looks like an address, else
 * to baselinewatch@host.
 */
export function parseMailUrl(value: string): MailTransport | null {
  const m = /^(mailtos?):\/\/(?:([^:@/]*)(?::([^@/]*))?@)?([^/:?#]+)(?::(\d+))?\/([^?#]+)(?:\?(.*))?$/i.exec(value.trim());
  if (!m) return null;
  const secure = m[1]!.toLowerCase() === "mailtos";
  const user = m[2] ? decodeURIComponent(m[2]) : null;
  const pass = m[3] ? decodeURIComponent(m[3]) : null;
  const host = m[4]!;
  const port = m[5] ? Number(m[5]) : secure ? 465 : 587;
  const to = decodeURIComponent(m[6]!);
  const query = new URLSearchParams(m[7] ?? "");
  if (!/^[^\s@]+@[^\s@]+$/.test(to) || !Number.isInteger(port) || port <= 0 || port > 65535) return null;
  const from = query.get("from") ?? (user && user.includes("@") ? user : `baselinewatch@${host}`);
  if (!/^[^\s@]+@[^\s@]+$/.test(from)) return null;
  return { host, port, secure, user: user || null, pass: pass || null, from, to };
}
