import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { parseExitList } from "../src/adapters/tor-exits.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { internetDbUrl, lookUpExposure, whatWasSeen } from "../src/seen.ts";
import { fakeHttp, fixture, startTestApp } from "./helpers.ts";

/** What this page learned about you (Scan 2.0, S2): the request's facts, the Tor list, the lookup on request. */

const now = new Date("2026-10-21T22:00:00Z");
const text = (name: string) => new TextDecoder().decode(fixture(`scan/${name}`));

describe("the Tor exit list", () => {
  it("is one address per line, and is swapped in whole", async () => {
    const ips = parseExitList(`${text("torbulkexitlist.txt")}\n# a comment\nnot-an-ip\n171.25.193.25\n`);
    expect(ips.length).toBe(60);
    expect(ips[0]).toBe("171.25.193.25");
    const db = openDatabase(":memory:");
    migrate(db);
    const dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-tor-"));
    try {
      const source = getSource(db, "tor-exits")!;
      expect(source.schedule).toBe("daily");
      // A list this short is refused as not the real one; the real one has over a thousand.
      const short = await ingestSource(db, dataDir, source, { http: fakeHttp({ [source.url]: { bytes: fixture("scan/torbulkexitlist.txt") } }), now: () => now });
      expect(short.status).toBe("error");
      expect(short.error).toMatch(/60 address/);
      const long = Array.from({ length: 1200 }, (_, i) => `10.${Math.floor(i / 256)}.${i % 256}.1`).join("\n");
      const first = await ingestSource(db, dataDir, source, { http: fakeHttp({ [source.url]: { text: long } }), now: () => now });
      expect(first.status).toBe("ok");
      expect(first.detail).toBe("1200 exit addresses");
      const again = await ingestSource(db, dataDir, source, { http: fakeHttp({ [source.url]: { text: `${long}\n10.9.9.9` } }), now: () => now });
      expect(again.inserted).toBe(1);
      expect((db.prepare("SELECT COUNT(*) AS n FROM tor_exits").get() as { n: number }).n).toBe(1201);
    } finally {
      db.close();
      rmSync(dataDir, { recursive: true, force: true });
    }
  });
});

describe("what was seen", () => {
  it("reads the address's kind, the Tor mark, the privacy signals and the headers worth showing", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    db.prepare("INSERT INTO tor_exits (ip, seen_at) VALUES ('203.0.113.9', ?)").run(now.toISOString());
    const base = { protocol: "https", httpVersion: "1.1", tlsProtocol: null };
    const tor = whatWasSeen(db, { ...base, ip: "::ffff:203.0.113.9", headers: { "user-agent": "UA", "sec-gpc": "1", dnt: "1", referer: "https://x/", "x-nope": "hidden" } });
    expect(tor).toMatchObject({ ip: "203.0.113.9", kind: "public", family: "IPv4", torExit: true, gpc: true, dnt: true, referer: "https://x/" });
    expect(tor.headers.map((h) => h.name)).toEqual(["User-Agent", "Sec-GPC", "DNT", "Referer"]);
    expect(whatWasSeen(db, { ...base, ip: "192.168.1.20", headers: {} })).toMatchObject({ kind: "private", torExit: false, gpc: false });
    expect(whatWasSeen(db, { ...base, ip: "127.0.0.1", headers: {} }).kind).toBe("loopback");
    expect(whatWasSeen(db, { ...base, ip: "2001:db8::1", headers: {} })).toMatchObject({ kind: "public", family: "IPv6" });
    expect(whatWasSeen(db, { ...base, ip: null, headers: {} }).kind).toBe("unknown");
    db.close();
  });
});

describe("the InternetDB lookup", () => {
  it("reads ports, names, software and CVEs, and a 404 as the good answer", async () => {
    const http = fakeHttp({ [internetDbUrl("1.1.1.1")]: { bytes: fixture("scan/internetdb-1.1.1.1.json") }, [internetDbUrl("203.0.113.9")]: { status: 404 } });
    const seen = await lookUpExposure(http, "1.1.1.1");
    expect(seen.ports).toContain(443);
    expect(seen.hostnames).toContain("one.one.one.one");
    expect(seen.cpes).toEqual(["cpe:/a:cloudflare:cloudflare"]);
    expect(seen.nothing).toBe(false);
    expect(await lookUpExposure(http, "203.0.113.9")).toMatchObject({ nothing: true, ports: [] });
  });
});

describe("on the Scan page", () => {
  it("draws the panel from the request, and looks an address up only when asked", async () => {
    const app = await startTestApp({ now: () => now, http: fakeHttp({ [internetDbUrl("1.1.1.1")]: { bytes: fixture("scan/internetdb-1.1.1.1.json") } }) });
    try {
      const page = await (await fetch(`${app.base}/scan`, { headers: { "user-agent": "TestBrowser/1", "sec-gpc": "1", "accept-language": "en-GB" } })).text();
      expect(page).toContain("What this page learned about you");
      expect(page).toContain("<code>127.0.0.1</code> — this machine itself (IPv4)");
      expect(page).toContain("Global Privacy Control sent");
      expect(page).toContain("<dt>Accept-Language</dt><dd><code>en-GB</code></dd>");
      expect(page).toContain("The internet-facing lookup needs a public address");
      expect(page).not.toContain("What Shodan last saw");
      const headers = { "content-type": "application/x-www-form-urlencoded", origin: app.base, "sec-fetch-site": "same-origin" };
      const looked = await (await fetch(`${app.base}/scan/exposure`, { method: "POST", headers, body: "ip=1.1.1.1" })).text();
      expect(looked).toContain("What Shodan last saw of 1.1.1.1");
      expect(looked).toContain("<dt>Open ports</dt><dd>53, 69, 80, 443");
      expect((await fetch(`${app.base}/scan/exposure`, { method: "POST", headers, body: "ip=192.168.1.1" })).status).toBe(400);
      expect((await fetch(`${app.base}/scan/exposure`, { method: "POST", headers, body: "ip=nonsense" })).status).toBe(400);
    } finally {
      await app.close();
    }
  });
});
