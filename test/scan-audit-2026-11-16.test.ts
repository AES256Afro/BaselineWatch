import { describe, expect, it } from "vitest";
import { caaLine, checkDomain, judgeSpf, spfLookups, type DnsLookup } from "../src/domaincheck.ts";
import { fixFor } from "../src/domainfix.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { HttpError, type HttpGet } from "../src/http.ts";
import { netSettingKeys, piholeV6Clients, runNetworkScan, setSetting, resolvConfPath, type ReadText } from "../src/netscan.ts";
import { scanTile } from "../src/scanhistory.ts";
import { fakeHttp, startTestApp } from "./helpers.ts";

/**
 * The scan area's audit of 16 November: the network check reading silence as a block, the domain
 * check judging HSTS on the page a redirect reaches, SPF lookups counted on the top record alone,
 * the MTA-STS advice blind to the finding, and Pi-hole v6's API.
 */

const now = new Date("2026-11-16T12:00:00Z");

function seedRun(db: ReturnType<typeof openDatabase>, outcomes: ("sinkholed" | "resolved" | "timeout")[], doh = "blocked"): void {
  const id = db.prepare("INSERT INTO net_scans (started_at, finished_at, resolver, resolver_source, upstream, doh) VALUES (?, ?, '192.0.2.53', 'resolv.conf', NULL, ?)").run(now.toISOString(), now.toISOString(), doh).lastInsertRowid;
  const canary = db.prepare("INSERT INTO net_canaries (scan_id, category, source_id, name, outcome, answer) VALUES (?, 'ads', 'canary-ads', ?, ?, ?)");
  outcomes.forEach((o, i) => canary.run(id, `c${i}.example.net`, o, o === "timeout" ? "ETIMEOUT" : o === "sinkholed" ? "0.0.0.0" : "198.51.100.7"));
}

describe("a network run the resolver did not answer", () => {
  it("is not shown as every canary sinkholed, on Today's tile", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    seedRun(db, ["timeout", "timeout", "timeout"]);
    expect(scanTile(db)).toMatchObject({ state: "warn", figure: "0/3", text: "the resolver did not answer" });
    seedRun(db, ["sinkholed", "sinkholed", "timeout"]);
    expect(scanTile(db)).toMatchObject({ state: "warn", figure: "2/3", text: "1 canary unanswered" });
    seedRun(db, ["sinkholed", "sinkholed", "sinkholed"]);
    expect(scanTile(db)).toMatchObject({ state: "ok", figure: "3/3", text: "every canary sinkholed" });
    db.close();
  });

  it("is not shown as enforced on the page, and its DoH row is not green", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      seedRun(app.db, ["timeout", "timeout"]);
      const page = await (await fetch(`${app.base}/scan/network`)).text();
      expect(page).not.toContain("Every canary the resolver was asked for came back sinkholed");
      expect(page).toContain("The resolver did not answer for any of the 2 canaries");
      expect(page).not.toContain('<span class="ok-t">blocked or unreachable</span>');
      seedRun(app.db, ["sinkholed", "sinkholed"]);
      const good = await (await fetch(`${app.base}/scan/network`)).text();
      expect(good).toContain("Every canary the resolver was asked for came back sinkholed");
      expect(good).toContain('<span class="ok-t">blocked or unreachable</span>');
    } finally {
      await app.close();
    }
  });
});

describe("Pi-hole v6", () => {
  /** A Pi-hole v6: POST /api/auth for a sid, the summary only with it. */
  function v6(calls: { url: string; method?: string; body?: string; sid?: string }[]): HttpGet {
    return async (url, options = {}) => {
      calls.push({ url, ...(options.method ? { method: options.method } : {}), ...(options.body ? { body: options.body } : {}), ...(options.headers?.sid ? { sid: options.headers.sid } : {}) });
      expect(options.redirect).toBe("manual");
      const reply = (text: string) => ({ url, status: 200, notModified: false, bytes: new TextEncoder().encode(text), etag: null, lastModified: null, contentType: "application/json" });
      if (url === "http://192.0.2.10/api/auth" && options.method === "POST") {
        const password = (JSON.parse(options.body ?? "{}") as { password?: string }).password;
        if (password !== "pw") throw new HttpError(url, 401);
        return reply('{"session":{"valid":true,"totp":false,"sid":"sid-123","validity":1800}}');
      }
      if (url === "http://192.0.2.10/api/stats/summary" && options.headers?.sid === "sid-123") return reply('{"queries":{"total":100},"clients":{"active":17,"total":31}}');
      if (url.startsWith("http://192.0.2.10/api/")) throw new HttpError(url, 401);
      if (url === "https://cloudflare-dns.com/dns-query?name=example.com&type=A") throw new Error("blocked");
      throw new HttpError(url, 404);
    };
  }

  it("signs in with the password and reads the clients active in the last day", async () => {
    const calls: { url: string; method?: string; body?: string; sid?: string }[] = [];
    expect(await piholeV6Clients("http://192.0.2.10", "pw", v6(calls))).toBe(17);
    expect(calls).toEqual([
      { url: "http://192.0.2.10/api/auth", method: "POST", body: '{"password":"pw"}' },
      { url: "http://192.0.2.10/api/stats/summary", sid: "sid-123" },
    ]);
  });

  it("is what the network run counts from, and a refused password is reported as v6's answer", async () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const readLan: ReadText = (file) => (file === resolvConfPath ? "nameserver 192.0.2.53\n" : null);
    setSetting(db, netSettingKeys.piholeUrl, "http://192.0.2.10/", now.toISOString());
    setSetting(db, netSettingKeys.piholeToken, "pw", now.toISOString());
    const scan = await runNetworkScan(db, { now: () => now, resolve: async () => ["0.0.0.0"], readFile: readLan, http: v6([]) });
    expect(scan).toMatchObject({ clients_seen: 17, clients_source: "pihole", error: null });
    setSetting(db, netSettingKeys.piholeToken, "wrong", now.toISOString());
    const refused = await runNetworkScan(db, { now: () => new Date("2026-11-17T12:00:00Z"), resolve: async () => ["0.0.0.0"], readFile: readLan, http: v6([]) });
    expect(refused).toMatchObject({ clients_seen: null, error: "pihole: HTTP 401" });
    db.close();
  });

  it("falls back to v5's API when /api is not there", async () => {
    const db = openDatabase(":memory:");
    migrate(db);
    setSetting(db, netSettingKeys.piholeUrl, "http://192.0.2.10", now.toISOString());
    setSetting(db, netSettingKeys.piholeToken, "token-abc", now.toISOString());
    const http = fakeHttp({ "http://192.0.2.10/api/auth": { status: 404 }, "http://192.0.2.10/admin/api.php?summaryRaw&auth=token-abc": { text: '{"unique_clients": 23}' } });
    const scan = await runNetworkScan(db, { now: () => now, resolve: async () => ["0.0.0.0"], readFile: (f) => (f === resolvConfPath ? "nameserver 192.0.2.53\n" : null), http });
    expect(scan.clients_seen).toBe(23);
    db.close();
  });
});

/** A domain whose apex redirects to www, the way microsoft.com does. */
function redirectingDomain(): { dns: DnsLookup; http: HttpGet } {
  const dns: DnsLookup = async (name, type) => {
    const table: Record<string, string[]> = {
      "A redir.example.net": ["203.0.113.30"],
      "TXT redir.example.net": ["v=spf1 include:a.redir.example.net include:b.redir.example.net -all"],
      "TXT a.redir.example.net": ["v=spf1 include:c.redir.example.net a mx -all"],
      "TXT b.redir.example.net": ["v=spf1 redirect=d.redir.example.net"],
      "TXT c.redir.example.net": ["v=spf1 ip4:203.0.113.0/24 exists:%{i}.x.redir.example.net -all"],
      "TXT d.redir.example.net": ["v=spf1 mx ptr ~all"],
    };
    const records = table[`${type} ${name}`];
    return records ? { records, code: "ok" } : { records: [], code: "nodata" };
  };
  const http = fakeHttp({
    "https://cloudflare-dns.com/dns-query?name=redir.example.net&type=A": { text: '{"Status":0,"AD":false}' },
    "https://redir.example.net/": { status: 301, headers: { location: "https://www.redir.example.net/", "strict-transport-security": "max-age=31536000" } },
    "http://redir.example.net/": { status: 301, headers: { location: "https://redir.example.net/" } },
    "https://redir.example.net/.well-known/security.txt": { text: "Contact: mailto:security@redir.example.net\n" },
    "https://mta-sts.redir.example.net/.well-known/mta-sts.txt": { status: 404 },
  });
  // The followed request reaches www, whose page sends the stronger header.
  const followed: HttpGet = async (url, options = {}) => {
    if (url === "https://redir.example.net/" && options.redirect !== "manual") return { url, status: 200, notModified: false, bytes: new Uint8Array(0), etag: null, lastModified: null, contentType: "text/html", headers: { "strict-transport-security": "max-age=31536000; includeSubDomains", "content-security-policy": "frame-ancestors 'none'", "x-content-type-options": "nosniff" } };
    return http(url, options);
  };
  return { dns, http: followed };
}

describe("a domain whose front page redirects", () => {
  it("has HSTS judged on the apex's own answer, with the hop named, and the headers on the page reached", async () => {
    const { dns, http } = redirectingDomain();
    const report = await checkDomain("redir.example.net", { dns, http, tls: async () => ({ error: "ECONNREFUSED" }), now: () => now });
    const by = Object.fromEntries(report.findings.map((f) => [f.id, f]));
    expect(by.https).toMatchObject({ state: "ok", text: "https://redir.example.net/ answered 301, redirecting to https://www.redir.example.net/, which answered 200.", quoted: ["Location: https://www.redir.example.net/"] });
    expect(by.hsts).toMatchObject({ state: "warn", quoted: ["Strict-Transport-Security: max-age=31536000"] });
    expect(by.hsts?.text).toContain("without includeSubDomains");
    expect(by.hsts?.text).toContain("Read on the 301 that https://redir.example.net/ answers with");
    expect(by.headers).toMatchObject({ state: "ok" });
    expect(by.headers?.text).toContain("(https://www.redir.example.net/)");
    // security.txt with a Contact but no Expires is not a clean pass (RFC 9116 §2.5.5).
    expect(by["security-txt"]).toMatchObject({ state: "warn", text: expect.stringContaining("without the Expires line") });
  });

  it("counts SPF lookups through includes and redirects, as RFC 7208 §4.6.4 does", async () => {
    const { dns } = redirectingDomain();
    // Top: 2 includes. a: include, a, mx. c: exists (macro, not followed). b: redirect. d: mx, ptr.
    expect(await spfLookups("v=spf1 include:a.redir.example.net include:b.redir.example.net -all", dns)).toEqual({ count: 9, missing: [], multiple: [], capped: false });
    const finding = judgeSpf(["v=spf1 include:a.redir.example.net include:b.redir.example.net -all"], true, await spfLookups("v=spf1 include:a.redir.example.net include:b.redir.example.net -all", dns));
    expect(finding).toMatchObject({ state: "ok", text: "One record ending -all (hard fail), 9 of 10 lookups counted through its includes." });
    // A redirect beside an all term is never followed, so it costs nothing.
    expect((await spfLookups("v=spf1 redirect=d.redir.example.net -all", dns)).count).toBe(0);
    // Past ten through the includes is a permanent error even when the top record has two terms.
    const deep: DnsLookup = async (name) => ({ records: [name === "x.example.net" ? "v=spf1 a mx ptr exists:e.example.net include:y.example.net -all" : "v=spf1 a mx ptr exists:f.example.net a:g.example.net mx:h.example.net -all"], code: "ok" });
    const lots = await spfLookups("v=spf1 include:x.example.net -all", deep);
    expect(lots.count).toBe(12);
    expect(judgeSpf(["v=spf1 include:x.example.net -all"], true, lots)).toMatchObject({ state: "bad", text: expect.stringContaining("12 DNS lookups counted through its includes") });
    // An include naming a domain with no SPF record is a permanent error too.
    const missing = await spfLookups("v=spf1 include:gone.redir.example.net -all", dns);
    expect(missing).toMatchObject({ count: 1, missing: ["gone.redir.example.net"] });
    expect(fixFor(judgeSpf(["v=spf1 include:gone.redir.example.net -all"], true, missing), "redir.example.net")!.text).toMatch(/Correct or remove the include/);
    // A loop is stopped by the depth cap rather than followed forever.
    const loop: DnsLookup = async () => ({ records: ["v=spf1 include:loop.example.net -all"], code: "ok" });
    expect(await spfLookups("v=spf1 include:loop.example.net -all", loop)).toMatchObject({ capped: true });
  });
});

describe("the smaller findings", () => {
  it("quotes every CAA tag, not only issue, issuewild and iodef", () => {
    expect(caaLine({ critical: 0, issue: "letsencrypt.org" })).toBe('0 issue "letsencrypt.org"');
    expect(caaLine({ critical: 0, contactemail: "dns@example.com" })).toBe('0 contactemail "dns@example.com"');
    expect(caaLine({ critical: 128, tbs: "x" })).toBe('128 tbs "x"');
  });

  it("warns on a security.txt past its Expires", async () => {
    const { dns } = redirectingDomain();
    const http = fakeHttp({
      "https://cloudflare-dns.com/dns-query?name=redir.example.net&type=A": { text: '{"Status":0,"AD":false}' },
      "https://redir.example.net/": { text: "", headers: {} },
      "http://redir.example.net/": { status: 301, headers: { location: "https://redir.example.net/" } },
      "https://redir.example.net/.well-known/security.txt": { text: "Contact: mailto:s@redir.example.net\nExpires: 2026-01-01T00:00:00.000Z\n" },
      "https://mta-sts.redir.example.net/.well-known/mta-sts.txt": { status: 404 },
    });
    const report = await checkDomain("redir.example.net", { dns, http, tls: async () => ({ error: "ECONNREFUSED" }), now: () => now });
    expect(report.findings.find((f) => f.id === "security-txt")).toMatchObject({ state: "warn", text: expect.stringContaining("expired on 2026-01-01T00:00:00.000Z") });
    expect(report.findings.find((f) => f.id === "addresses")?.text).toBe("1 IPv4 address and no IPv6: a growing share of networks reach it through translation.");
  });

  it("gives MTA-STS advice for what was found", () => {
    const base = { id: "mta-sts", group: "mail" as const, title: "MTA-STS", state: "warn" as const };
    const testing = fixFor({ ...base, text: "Published in mode testing; enforce is the point.", quoted: ['_mta-sts TXT "v=STSv1; id=1"', "policy: version: STSv1", "policy: mode: testing", "policy: mx: mx1.example.net", "policy: max_age: 604800"] }, "example.net")!;
    expect(testing.text).toMatch(/serve it with mode: enforce/);
    expect(testing.lines).toContain("mode: enforce");
    expect(testing.lines).not.toContain("mode: testing");
    expect(testing.lines).toContain("mx: mx1.example.net");
    const noFile = fixFor({ ...base, text: "The DNS record is there but the policy file did not answer at https://mta-sts.example.net/.well-known/mta-sts.txt.", quoted: ['_mta-sts TXT "v=STSv1; id=1"'] }, "example.net")!;
    expect(noFile.lines.some((l) => l.startsWith("_mta-sts."))).toBe(false);
    expect(noFile.text).toMatch(/Serve the file there/);
    const none = fixFor({ ...base, text: "No MTA-STS: mail in transit…", quoted: [] }, "example.net")!;
    expect(none.lines[0]).toContain("_mta-sts.example.net. IN TXT");
  });

  it("writes the CAA record with a placeholder, naming the issuer the handshake saw", () => {
    const caa = { id: "caa", group: "names" as const, title: "CAA", state: "warn" as const, text: "No CAA record", quoted: [] };
    const tls = { id: "tls", group: "web" as const, title: "TLS", state: "ok" as const, text: "", quoted: ["TLSv1.3 · x", "Issuer: Google Trust Services · Subject: example.net", "Valid to: 2027-01-01"] };
    const fix = fixFor(caa, "example.net", [caa, tls])!;
    expect(fix.lines[0]).toContain('issue "<CA-DOMAIN>"');
    expect(fix.lines.join(" ")).not.toContain("letsencrypt.org");
    expect(fix.text).toContain("from Google Trust Services");
  });
});
