import net from "node:net";
import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { notify, parseNotifyUrl, send } from "../src/notify.ts";
import { parseMailUrl, sendMail, SmtpError, wireMessage } from "../src/smtp.ts";

/**
 * The notifier's mail transport (N6): a fake SMTP server in this process speaks the server's
 * side, so the dialogue, the authentication and the message on the wire are checked as sent.
 */

const now = new Date("2026-10-21T22:00:00Z");

interface FakeServer {
  port: number;
  received: string[];
  commands: string[];
  close(): Promise<void>;
}

/** A plain SMTP server: greets, answers EHLO with AUTH PLAIN, accepts one message, keeps every command and the message. */
function fakeSmtp(options: { auth?: string | null; starttls?: boolean; rejectRcpt?: boolean } = {}): Promise<FakeServer> {
  const received: string[] = [];
  const commands: string[] = [];
  const server = net.createServer((socket) => {
    let data = false;
    let message = "";
    socket.write("220 fake.example ESMTP\r\n");
    socket.on("data", (chunk) => {
      const text = chunk.toString("utf8");
      if (data) {
        message += text;
        const end = message.indexOf("\r\n.\r\n");
        if (end >= 0) {
          received.push(message.slice(0, end + 2));
          data = false;
          socket.write("250 queued\r\n");
        }
        return;
      }
      for (const line of text.split("\r\n").filter((l) => l)) {
        commands.push(line);
        if (/^EHLO /i.test(line)) socket.write(`250-fake.example\r\n${options.starttls ? "250-STARTTLS\r\n" : ""}250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n`);
        else if (/^STARTTLS$/i.test(line)) socket.write("220 go ahead\r\n");
        else if (/^AUTH PLAIN /i.test(line)) socket.write(options.auth && line === `AUTH PLAIN ${options.auth}` ? "235 ok\r\n" : "535 no\r\n");
        else if (/^MAIL FROM:/i.test(line)) socket.write("250 ok\r\n");
        else if (/^RCPT TO:/i.test(line)) socket.write(options.rejectRcpt ? "550 no such user\r\n" : "250 ok\r\n");
        else if (/^DATA$/i.test(line)) {
          data = true;
          socket.write("354 go\r\n");
        } else if (/^QUIT$/i.test(line)) {
          socket.write("221 bye\r\n");
          socket.end();
        } else socket.write("500 what\r\n");
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ port: (server.address() as net.AddressInfo).port, received, commands, close: () => new Promise((r) => server.close(() => r())) }));
  });
}

describe("the mail URL", () => {
  it("reads host, port, credentials, recipient and sender, with the defaults a provider expects", () => {
    expect(parseMailUrl("mailto://bw%40example.org:p%40ss@smtp.example.org:587/you@example.org")).toEqual({ host: "smtp.example.org", port: 587, secure: false, user: "bw@example.org", pass: "p@ss", from: "bw@example.org", to: "you@example.org" });
    expect(parseMailUrl("mailtos://smtp.example.org/you@example.org?from=alerts@example.org")).toMatchObject({ port: 465, secure: true, user: null, pass: null, from: "alerts@example.org" });
    expect(parseMailUrl("mailto://smtp.example.org/you@example.org")).toMatchObject({ port: 587, from: "baselinewatch@smtp.example.org" });
    expect(parseMailUrl("mailto://smtp.example.org/not-an-address")).toBeNull();
    expect(parseMailUrl("ntfy://x/y")).toBeNull();
    expect(parseNotifyUrl("mailto://smtp.example.org/you@example.org")).toMatchObject({ scheme: "mail", endpoint: "you@example.org" });
  });
});

describe("the message on the wire", () => {
  it("has the headers a receiver wants, CRLF line ends, a doubled leading dot and a terminating dot", () => {
    const t = { host: "h", port: 25, secure: false, user: null, pass: null, from: "a@x", to: "b@y" };
    const wire = wireMessage(t, { subject: "Digest — today", text: "line one\n.starts with a dot\nend" }, now, "id1", "news.example");
    expect(wire).toContain("Subject: =?UTF-8?B?");
    expect(wire).toContain("Message-ID: <id1@news.example>\r\n");
    expect(wire).toContain("From: a@x\r\nTo: b@y\r\n");
    expect(wire).toContain("Date: Wed, 21 Oct 2026 22:00:00 GMT\r\n");
    expect(wire).toContain("\r\n\r\nline one\r\n..starts with a dot\r\nend\r\n.\r\n");
    expect(wire.endsWith("\r\n.\r\n")).toBe(true);
  });
});

describe("sending", () => {
  it("speaks the dialogue, authenticates, and the server gets the message", async () => {
    const auth = Buffer.from("\0bw@example.org\0secret", "utf8").toString("base64");
    const server = await fakeSmtp({ auth });
    try {
      const t = { host: "127.0.0.1", port: server.port, secure: false, user: "bw@example.org", pass: "secret", from: "bw@example.org", to: "you@example.org" };
      // Without STARTTLS on offer, a password is not sent in the clear: refused before AUTH.
      await expect(sendMail(t, { subject: "s", text: "b" }, { now: () => now })).rejects.toThrow(/offers no STARTTLS/);
      expect(server.commands.some((c) => c.startsWith("AUTH"))).toBe(false);
    } finally {
      await server.close();
    }
    // With STARTTLS on offer, the test upgrade keeps the same socket (no certificates in a unit test) and the rest follows.
    const tls = await fakeSmtp({ auth, starttls: true });
    try {
      const t = { host: "127.0.0.1", port: tls.port, secure: false, user: "bw@example.org", pass: "secret", from: "bw@example.org", to: "you@example.org" };
      await sendMail(t, { subject: "KEV: CVE-2026-1", text: "Added today.\n.hidden line" }, { now: () => now, upgrade: async (socket) => socket, clientName: "news.example" });
      expect(tls.commands.map((c) => c.split(" ")[0])).toEqual(["EHLO", "STARTTLS", "EHLO", "AUTH", "MAIL", "RCPT", "DATA", "QUIT"]);
      // The site's own host names the client, not the container's id.
      expect(tls.commands[0]).toBe("EHLO news.example");
      expect(tls.commands[2]).toBe("EHLO news.example");
      expect(tls.received[0]).toMatch(/Message-ID: <[^>]+@news\.example>/);
      expect(tls.commands).toContain(`AUTH PLAIN ${auth}`);
      expect(tls.commands).toContain("MAIL FROM:<bw@example.org>");
      expect(tls.commands).toContain("RCPT TO:<you@example.org>");
      expect(tls.received[0]).toContain("Subject: KEV: CVE-2026-1\r\n");
      expect(tls.received[0]).toContain("\r\n\r\nAdded today.\r\n..hidden line\r\n");
    } finally {
      await tls.close();
    }
  });

  it("names the step and the code when the server refuses, never the credentials, and the alerts log keeps only the code", async () => {
    const server = await fakeSmtp({ rejectRcpt: true });
    try {
      const t = { host: "127.0.0.1", port: server.port, secure: false, user: null, pass: null, from: "bw@example.org", to: "nobody@example.org" };
      const error = await sendMail(t, { subject: "s", text: "b" }, { now: () => now }).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(SmtpError);
      expect((error as SmtpError).message).toBe("SMTP RCPT TO: 550 550 no such user");
      const result = await send({ scheme: "mail", endpoint: t.to, mail: t }, { kind: "test", title: "t", body: "b" }, undefined, { now: () => now });
      expect(result).toEqual({ status: "failed", error: "SMTP 550" });
      const db = openDatabase(":memory:");
      migrate(db);
      await notify(db, { scheme: "mail", endpoint: t.to, mail: t }, { kind: "test", title: "t", body: "b", url: "https://x" }, undefined, () => now);
      expect(db.prepare("SELECT status, error FROM alerts").get()).toEqual({ status: "failed", error: "SMTP 550" });
      db.close();
    } finally {
      await server.close();
    }
  });
});
