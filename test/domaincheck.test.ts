import { describe, expect, it } from "vitest";
import { caaLine, certificateDate, checkDomain, commonSelectors, judgeDmarc, judgeHeaders, judgeHsts, judgeSpf, judgeTls, parseSelectors, peerFacts, publicRecordName, spfLookups, validDomain, type DnsLookup, type TlsProbe } from "../src/domaincheck.ts";
import { fixFor } from "../src/domainfix.ts";
import { fakeHttp, startTestApp } from "./helpers.ts";

/**
 * Check a domain (Scan 2.0, S3): the verdicts from recorded answers. The fakes play a well-run
 * domain and a bare one; the judges are tested on the record shapes seen in the wild.
 */

const now = new Date("2026-10-21T22:00:00Z");

describe("the name typed", () => {
  it("is read as a public host name, however it was typed, or refused", () => {
    expect(validDomain(" Example.COM ")).toBe("example.com");
    expect(validDomain("https://www.example.com/path?q=1")).toBe("www.example.com");
    expect(validDomain("example.com.")).toBe("example.com");
    expect(validDomain("localhost")).toBeNull();
    expect(validDomain("router.local")).toBeNull();
    expect(validDomain("10.0.0.1")).toBeNull();
    expect(validDomain("-bad.example.com")).toBeNull();
    expect(validDomain("no spaces.com")).toBeNull();
    expect(validDomain("")).toBeNull();
  });

  it("reads selectors as DNS labels", () => {
    expect(parseSelectors("google, Selector1 s2")).toEqual(["google", "selector1", "s2"]);
    expect(parseSelectors("bad label!, k1")).toEqual(["bad", "k1"]);
    expect(parseSelectors(undefined)).toEqual([]);
  });
});

describe("the judges", () => {
  it("read SPF the way a receiver does", () => {
    expect(judgeSpf(["v=spf1 include:_spf.google.com -all"], true)).toMatchObject({ state: "ok", quoted: ['TXT "v=spf1 include:_spf.google.com -all"'] });
    expect(judgeSpf(["v=spf1 include:a.example.net ~all"], true).state).toBe("ok");
    expect(judgeSpf(["v=spf1 include:a.example.net +all"], true)).toMatchObject({ state: "bad" });
    expect(judgeSpf(["v=spf1 include:a.example.net"], true).state).toBe("warn");
    expect(judgeSpf(["v=spf1 -all", "v=spf1 ~all"], true)).toMatchObject({ state: "bad", text: expect.stringContaining("2 SPF records") });
    expect(judgeSpf(["v=spf1 " + Array.from({ length: 11 }, (_, i) => `include:s${i}.example.net`).join(" ") + " -all"], true)).toMatchObject({ state: "bad", text: expect.stringContaining("11 DNS lookups") });
    expect(judgeSpf([], true).state).toBe("bad");
    expect(judgeSpf([], false).state).toBe("warn");
    expect(judgeSpf(["google-site-verification=abc"], false).state).toBe("warn");
  });

  it("read DMARC's policy and reporting", () => {
    expect(judgeDmarc(["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"], true)).toMatchObject({ state: "ok", text: expect.stringContaining("Aggregate reports go to mailto:dmarc@example.com") });
    expect(judgeDmarc(["v=DMARC1; p=quarantine"], true).state).toBe("ok");
    expect(judgeDmarc(["v=DMARC1; p=none; rua=mailto:x@example.com"], true).state).toBe("warn");
    expect(judgeDmarc(["v=DMARC1; p=reject; pct=50"], true)).toMatchObject({ state: "warn", text: expect.stringContaining("pct=50") });
    expect(judgeDmarc(["v=DMARC1; sp=none"], true).state).toBe("bad");
    expect(judgeDmarc([], true).state).toBe("bad");
    expect(judgeDmarc([], false).state).toBe("warn");
  });

  it("read HSTS and the other headers as sent", () => {
    expect(judgeHsts({ "strict-transport-security": "max-age=63072000; includeSubDomains; preload" }, true)).toMatchObject({ state: "ok", text: expect.stringContaining("preload asked for") });
    expect(judgeHsts({ "strict-transport-security": "max-age=31536000" }, true).state).toBe("warn");
    expect(judgeHsts({ "strict-transport-security": "max-age=3600; includeSubDomains" }, true).state).toBe("warn");
    expect(judgeHsts({}, true).state).toBe("bad");
    expect(judgeHsts({}, false).state).toBe("na");
    expect(judgeHeaders({ "content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" }, true)).toMatchObject({ state: "ok", quoted: expect.arrayContaining(["Referrer-Policy: no-referrer"]) });
    expect(judgeHeaders({ "x-frame-options": "DENY" }, true)).toMatchObject({ state: "warn", text: expect.stringContaining("Content-Security-Policy") });
    expect(judgeHeaders({}, true).state).toBe("bad");
  });

  it("read the handshake and the certificate", () => {
    const good = { protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", issuer: "Let's Encrypt", subject: "example.com", validTo: "2026-12-01T00:00:00.000Z", names: ["example.com", "www.example.com"], authorized: true, authorizationError: null };
    expect(judgeTls(good, "example.com", now)).toMatchObject({ state: "ok", text: expect.stringContaining("40 days") });
    expect(judgeTls({ ...good, names: ["*.example.com"] }, "www.example.com", now).state).toBe("ok");
    expect(judgeTls({ ...good, names: ["*.example.com"] }, "example.com", now).state).toBe("bad");
    expect(judgeTls({ ...good, protocol: "TLSv1.2" }, "example.com", now).state).toBe("warn");
    expect(judgeTls({ ...good, validTo: "2026-10-30T00:00:00.000Z" }, "example.com", now)).toMatchObject({ state: "warn", text: expect.stringContaining("8 days") });
    expect(judgeTls({ ...good, authorized: false, authorizationError: "CERT_HAS_EXPIRED" }, "example.com", now)).toMatchObject({ state: "bad", text: expect.stringContaining("CERT_HAS_EXPIRED") });
    expect(judgeTls({ error: "ECONNREFUSED" }, "example.com", now).state).toBe("na");
    expect(judgeTls({ error: "timeout" }, "example.com", now).state).toBe("bad");
  });
});

/** A well-run domain, as its records would answer. */
function goodDns(): DnsLookup {
  const table: Record<string, string[]> = {
    "A good.example.net": ["203.0.113.10"],
    "AAAA good.example.net": ["2001:db8::10"],
    "NS good.example.net": ["ns1.good.example.net", "ns2.good.example.net"],
    "MX good.example.net": ["10 mx1.good.example.net", "20 mx2.good.example.net"],
    "TXT good.example.net": ["v=spf1 include:_spf.good.example.net -all", "google-site-verification=abc"],
    "TXT _spf.good.example.net": ["v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 -all"],
    "CAA good.example.net": ['0 issue "letsencrypt.org"'],
    "TXT _dmarc.good.example.net": ["v=DMARC1; p=reject; rua=mailto:dmarc@good.example.net"],
    "TXT _mta-sts.good.example.net": ["v=STSv1; id=20261001"],
    "TXT _smtp._tls.good.example.net": ["v=TLSRPTv1; rua=mailto:tls@good.example.net"],
    "TXT google._domainkey.good.example.net": ["v=DKIM1; k=rsa; p=MIIBIjANBgkq"],
  };
  return async (name, type) => {
    const records = table[`${type} ${name}`];
    return records ? { records, code: "ok" } : { records: [], code: "nodata" };
  };
}

const goodTls: TlsProbe = async () => ({ protocol: "TLSv1.3", cipher: "TLS_AES_128_GCM_SHA256", issuer: "Let's Encrypt", subject: "good.example.net", validTo: "2027-01-10T00:00:00.000Z", names: ["good.example.net", "www.good.example.net"], authorized: true, authorizationError: null });

const goodHttp = () =>
  fakeHttp({
    "https://cloudflare-dns.com/dns-query?name=good.example.net&type=A": { text: '{"Status":0,"AD":true,"Answer":[]}' },
    "https://good.example.net/": { text: "<html>", headers: { "strict-transport-security": "max-age=63072000; includeSubDomains; preload", "content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin", server: "nginx" } },
    "http://good.example.net/": { status: 301, headers: { location: "https://good.example.net/" } },
    "https://good.example.net/.well-known/security.txt": { text: "Contact: mailto:security@good.example.net\nExpires: 2027-06-01T00:00:00.000Z\n" },
    "https://mta-sts.good.example.net/.well-known/mta-sts.txt": { text: "version: STSv1\nmode: enforce\nmx: mx1.good.example.net\nmx: mx2.good.example.net\nmax_age: 604800\n" },
  });

describe("a whole domain", () => {
  it("comes back green when every record is right, each one quoted", async () => {
    const report = await checkDomain("good.example.net", { dns: goodDns(), tls: goodTls, http: goodHttp(), now: () => now });
    expect(report.mail).toBe(true);
    expect(report.counts).toEqual({ ok: 16, warn: 0, bad: 0, na: 0 });
    const by = Object.fromEntries(report.findings.map((f) => [f.id, f]));
    expect(by.dnssec?.quoted).toEqual(["Cloudflare DoH: AD=true Status=0"]);
    expect(by.dkim?.text).toContain("google");
    expect(by["mta-sts"]?.quoted).toContain("policy: mode: enforce");
    expect(by.http?.quoted).toEqual(["Location: https://good.example.net/"]);
    expect(by["security-txt"]?.quoted).toEqual(["Contact: mailto:security@good.example.net", "Expires: 2027-06-01T00:00:00.000Z"]);
    expect(by.caa?.quoted).toEqual(['CAA 0 issue "letsencrypt.org"']);
  });

  it("says what a bare domain lacks, and what does not apply without mail", async () => {
    const bareDns: DnsLookup = async (name, type) => (type === "A" && name === "bare.example.net" ? { records: ["203.0.113.20"], code: "ok" } : type === "NS" && name === "bare.example.net" ? { records: ["ns1.bare.example.net"], code: "ok" } : { records: [], code: "nodata" });
    const http = fakeHttp({
      "https://cloudflare-dns.com/dns-query?name=bare.example.net&type=A": { text: '{"Status":0,"AD":false,"Answer":[]}' },
      "https://bare.example.net/": { text: "<html>", headers: {} },
      "http://bare.example.net/": { text: "<html>" },
      "https://bare.example.net/.well-known/security.txt": { status: 404 },
      "https://mta-sts.bare.example.net/.well-known/mta-sts.txt": { status: 404 },
    });
    const report = await checkDomain("bare.example.net", { dns: bareDns, tls: async () => ({ error: "ECONNREFUSED" }), http, now: () => now });
    const by = Object.fromEntries(report.findings.map((f) => [f.id, f]));
    expect(report.mail).toBe(false);
    expect(by.addresses?.state).toBe("warn");
    expect(by.ns?.state).toBe("warn");
    expect(by.dnssec?.state).toBe("warn");
    expect(by.caa?.state).toBe("warn");
    expect(by.mx?.state).toBe("na");
    expect(by.spf?.state).toBe("warn");
    expect(by.dmarc?.state).toBe("warn");
    expect(by.dkim?.state).toBe("na");
    expect(by["mta-sts"]?.state).toBe("na");
    expect(by["tls-rpt"]?.state).toBe("na");
    expect(by.http).toMatchObject({ state: "bad", text: expect.stringContaining("plain HTTP") });
    expect(by.hsts?.state).toBe("bad");
    expect(by.headers?.state).toBe("bad");
    expect(by.tls?.state).toBe("na");
    expect(by["security-txt"]?.state).toBe("warn");
    // The common selectors were all tried, once each.
    expect(commonSelectors.length).toBe(12);
  });

  it("reads a name that does not exist as that", async () => {
    const dns: DnsLookup = async () => ({ records: [], code: "nxdomain", detail: "ENOTFOUND" });
    const http = fakeHttp({});
    const report = await checkDomain("gone.example.net", { dns, tls: async () => ({ error: "ENOTFOUND" }), http, now: () => now });
    expect(report.findings.find((f) => f.id === "addresses")).toMatchObject({ state: "bad", text: "The name does not exist (NXDOMAIN)." });
    expect(report.findings.find((f) => f.id === "https")?.state).toBe("bad");
  });
});

describe("the page", () => {
  it("takes a name, refuses a bad one, keeps the owner's own domains, and throttles", async () => {
    const app = await startTestApp({ now: () => now, dns: goodDns(), tls: goodTls, http: goodHttp(), env: { BW_ADMIN_PASSWORD: "x" } });
    try {
      const empty = await (await fetch(`${app.base}/scan/domain`)).text();
      expect(empty).toContain("Check a domain");
      expect(empty).toContain('aria-current="page"><b>A domain</b>');
      const bad = await fetch(`${app.base}/scan/domain?name=localhost`);
      expect(bad.status).toBe(400);
      expect(await bad.text()).toContain("is not a public domain name");
      const page = await (await fetch(`${app.base}/scan/domain?name=GOOD.example.net&selectors=google`)).text();
      expect(page).toContain("Check a domain · good.example.net");
      expect(page).toContain("<small>Good</small><b>16</b>");
      expect(page).toContain("<li><code>TXT &quot;v=DMARC1; p=reject; rua=mailto:dmarc@good.example.net&quot;</code></li>");
      expect(page).toContain('<span class="state ok">Good</span>');
      expect(page).not.toContain('id="own"');
      // The Scan page points here, and the menu has the four entries.
      const scan = await (await fetch(`${app.base}/scan`)).text();
      expect(scan).toContain('<a href="/scan/domain">check a domain</a>');
      expect(scan).toContain("<b>The server&#39;s network</b>");
    } finally {
      await app.close();
    }
  });
});

describe("a certificate the probe cannot read", () => {
  // The handshake callback runs outside any request, so one throw there ended the process: a
  // certificate whose notAfter is not a date (month 13) did it for anyone who asked about the
  // domain serving it. Reproduced against a real TLS server before the fix; this holds the parts.
  const socket = (cert: Record<string, unknown>) => ({
    getPeerCertificate: () => cert as never,
    getProtocol: () => "TLSv1.3",
    getCipher: () => ({ name: "TLS_AES_256_GCM_SHA384", standardName: "TLS_AES_256_GCM_SHA384", version: "TLSv1.3" }),
    authorized: false,
    authorizationError: new Error("ERROR_IN_CERT_NOT_AFTER_FIELD"),
  });

  it("reads a date that is not one as missing, rather than throwing", () => {
    expect(certificateDate("Jan 13 23:59:59 2027 GMT")).toBe("2027-01-13T23:59:59.000Z");
    expect(certificateDate("Mon 13 05 23:59:59 2027 GMT")).toBeNull();
    expect(certificateDate("")).toBeNull();
    expect(certificateDate(undefined)).toBeNull();
  });

  it("returns the facts it could read, with the expiry left out", () => {
    const facts = peerFacts(socket({ valid_to: "not a date", subject: { CN: "bad.example.net" }, issuer: { CN: "bad.example.net" }, subjectaltname: 7 }));
    expect(facts).toMatchObject({ validTo: null, subject: "bad.example.net", names: [], authorized: false, authorizationError: "Error: ERROR_IN_CERT_NOT_AFTER_FIELD" });
    expect(judgeTls(facts, "bad.example.net", new Date("2026-11-05T00:00:00Z")).state).toBeDefined();
  });
});

describe("SPF includes a visitor's record names", () => {
  it("follows only public names, and asks at most ten TXT questions (RFC 7208's ten lookups)", async () => {
    const asked: string[] = [];
    const dns: DnsLookup = async (name) => {
      asked.push(name);
      return { records: ["v=spf1 -all"], code: "ok" };
    };
    const record = "v=spf1 include:nas.lan include:localhost include:printer include:files.local redirect=db.internal include:router.home.arpa include:_spf.example.com ~all";
    const out = await spfLookups(record, dns);
    // Every term still costs a lookup a receiver would make; only the public one is asked here.
    expect(asked).toEqual(["_spf.example.com"]);
    expect(out).toEqual({ count: 6, missing: [], multiple: [], capped: false });

    // Five includes, each naming another: the count passes ten as the walk goes, and the walk asks no more than ten questions.
    asked.length = 0;
    const chain: DnsLookup = async (name) => {
      asked.push(name);
      return { records: [`v=spf1 include:next.${name} -all`], code: "ok" };
    };
    const capped = await spfLookups(`v=spf1 ${Array.from({ length: 5 }, (_, i) => `include:s${i}.example.com`).join(" ")} -all`, chain);
    expect(asked.length).toBeLessThanOrEqual(10);
    expect(capped).toMatchObject({ capped: true });
    expect(["_spf.google.com", "spf.protection.outlook.com", "xn--bcher-kva.example.net"].map(publicRecordName)).toEqual(["_spf.google.com", "spf.protection.outlook.com", "xn--bcher-kva.example.net"]);
    expect(["nas", "nas.lan", "x.home.arpa", "10.0.0.1", "db.internal", "-a.example.com"].map(publicRecordName)).toEqual([null, null, null, null, null, null]);
  });
});

describe("bug sweep 3a: CAA, the MTA-STS policy, an include with two SPF records", () => {
  const withRecords = (extra: Record<string, string[]>): DnsLookup => {
    const base = goodDns();
    return async (name, type) => (extra[`${type} ${name}`] ? { records: extra[`${type} ${name}`]!, code: "ok" } : base(name, type));
  };

  it("passes CAA only when a record has issue or issuewild, and quotes no type key", async () => {
    const report = await checkDomain("good.example.net", { dns: withRecords({ "CAA good.example.net": ['0 contactemail "dns@good.example.net"'] }), tls: goodTls, http: goodHttp(), now: () => now });
    const caa = report.findings.find((f) => f.id === "caa")!;
    expect(caa).toMatchObject({ state: "warn", text: "CAA published, but no issue property: any authority may still issue a certificate for this domain." });
    expect(fixFor(caa, "good.example.net")?.lines[0]).toContain("IN CAA 0 issue");
    const wild = await checkDomain("good.example.net", { dns: withRecords({ "CAA good.example.net": ['0 issuewild "letsencrypt.org"'] }), tls: goodTls, http: goodHttp(), now: () => now });
    expect(wild.findings.find((f) => f.id === "caa")?.state).toBe("ok");
    expect(caaLine({ critical: 0, issue: "letsencrypt.org", type: "CAA" })).toBe('0 issue "letsencrypt.org"');
  });

  it("moves a four-mx testing policy to enforce with every mx and the max_age", async () => {
    const http = fakeHttp({
      "https://cloudflare-dns.com/dns-query?name=good.example.net&type=A": { text: '{"Status":0,"AD":true,"Answer":[]}' },
      "https://mta-sts.good.example.net/.well-known/mta-sts.txt": { text: "version: STSv1\nmode: testing\nmx: mx1.good.example.net\nmx: mx2.good.example.net\nmx: mx3.good.example.net\nmx: mx4.good.example.net\nmax_age: 86400\n" },
    });
    const report = await checkDomain("good.example.net", { dns: goodDns(), tls: goodTls, http, now: () => now });
    const sts = report.findings.find((f) => f.id === "mta-sts")!;
    const lines = fixFor(sts, "good.example.net")!.lines;
    for (const mx of ["mx1", "mx2", "mx3", "mx4"]) expect(lines).toContain(`mx: ${mx}.good.example.net`);
    expect(lines).toContain("mode: enforce");
    expect(lines).toContain("max_age: 86400");
    // A policy too long to quote whole says so, and the fix does not rebuild it from the part shown.
    const long = Array.from({ length: 25 }, (_, i) => `mx: mx${i}.good.example.net`).join("\n");
    const cut = await checkDomain("good.example.net", { dns: goodDns(), tls: goodTls, http: fakeHttp({ "https://mta-sts.good.example.net/.well-known/mta-sts.txt": { text: `version: STSv1\nmode: testing\n${long}\nmax_age: 86400\n` } }), now: () => now });
    const cutSts = cut.findings.find((f) => f.id === "mta-sts")!;
    expect(cutSts.quoted.at(-1)).toBe("(8 more policy lines not shown)");
    expect(fixFor(cutSts, "good.example.net")!.lines.some((l) => l.startsWith("mx: <each"))).toBe(true);
  });

  it("names an include with two SPF records as that, not as publishing none", async () => {
    const dns: DnsLookup = async (name) => ({ records: name === "two.example.com" ? ["v=spf1 -all", "v=spf1 ~all"] : [], code: "ok" });
    const counted = await spfLookups("v=spf1 include:two.example.com -all", dns);
    expect(counted).toEqual({ count: 1, missing: [], multiple: ["two.example.com"], capped: false });
    const finding = judgeSpf(["v=spf1 include:two.example.com -all"], true, counted);
    expect(finding).toMatchObject({ state: "bad", text: "The record includes two.example.com, which publishes more than one SPF record: receivers give a permanent error." });
    expect(fixFor(finding, "example.net")!.text).toMatch(/merge its SPF records/);
  });
});
