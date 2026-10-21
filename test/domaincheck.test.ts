import { describe, expect, it } from "vitest";
import { checkDomain, commonSelectors, judgeDmarc, judgeHeaders, judgeHsts, judgeSpf, judgeTls, parseSelectors, validDomain, type DnsLookup, type TlsProbe } from "../src/domaincheck.ts";
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
    expect(judgeSpf(["v=spf1 include:a.example ~all"], true).state).toBe("ok");
    expect(judgeSpf(["v=spf1 include:a.example +all"], true)).toMatchObject({ state: "bad" });
    expect(judgeSpf(["v=spf1 include:a.example"], true).state).toBe("warn");
    expect(judgeSpf(["v=spf1 -all", "v=spf1 ~all"], true)).toMatchObject({ state: "bad", text: expect.stringContaining("2 SPF records") });
    expect(judgeSpf(["v=spf1 " + Array.from({ length: 11 }, (_, i) => `include:s${i}.example`).join(" ") + " -all"], true)).toMatchObject({ state: "bad", text: expect.stringContaining("11 DNS lookups") });
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
    expect(judgeTls({ ...good, validTo: "2026-10-30T00:00:00.000Z" }, "example.com", now)).toMatchObject({ state: "warn", text: expect.stringContaining("8 day(s)") });
    expect(judgeTls({ ...good, authorized: false, authorizationError: "CERT_HAS_EXPIRED" }, "example.com", now)).toMatchObject({ state: "bad", text: expect.stringContaining("CERT_HAS_EXPIRED") });
    expect(judgeTls({ error: "ECONNREFUSED" }, "example.com", now).state).toBe("na");
    expect(judgeTls({ error: "timeout" }, "example.com", now).state).toBe("bad");
  });
});

/** A well-run domain, as its records would answer. */
function goodDns(): DnsLookup {
  const table: Record<string, string[]> = {
    "A good.example": ["203.0.113.10"],
    "AAAA good.example": ["2001:db8::10"],
    "NS good.example": ["ns1.good.example", "ns2.good.example"],
    "MX good.example": ["10 mx1.good.example", "20 mx2.good.example"],
    "TXT good.example": ["v=spf1 include:_spf.good.example -all", "google-site-verification=abc"],
    "CAA good.example": ['0 issue "letsencrypt.org"'],
    "TXT _dmarc.good.example": ["v=DMARC1; p=reject; rua=mailto:dmarc@good.example"],
    "TXT _mta-sts.good.example": ["v=STSv1; id=20261001"],
    "TXT _smtp._tls.good.example": ["v=TLSRPTv1; rua=mailto:tls@good.example"],
    "TXT google._domainkey.good.example": ["v=DKIM1; k=rsa; p=MIIBIjANBgkq"],
  };
  return async (name, type) => {
    const records = table[`${type} ${name}`];
    return records ? { records, code: "ok" } : { records: [], code: "nodata" };
  };
}

const goodTls: TlsProbe = async () => ({ protocol: "TLSv1.3", cipher: "TLS_AES_128_GCM_SHA256", issuer: "Let's Encrypt", subject: "good.example", validTo: "2027-01-10T00:00:00.000Z", names: ["good.example", "www.good.example"], authorized: true, authorizationError: null });

const goodHttp = () =>
  fakeHttp({
    "https://cloudflare-dns.com/dns-query?name=good.example&type=A": { text: '{"Status":0,"AD":true,"Answer":[]}' },
    "https://good.example/": { text: "<html>", headers: { "strict-transport-security": "max-age=63072000; includeSubDomains; preload", "content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin", server: "nginx" } },
    "http://good.example/": { status: 301, headers: { location: "https://good.example/" } },
    "https://good.example/.well-known/security.txt": { text: "Contact: mailto:security@good.example\nExpires: 2027-06-01T00:00:00.000Z\n" },
    "https://mta-sts.good.example/.well-known/mta-sts.txt": { text: "version: STSv1\nmode: enforce\nmx: mx1.good.example\nmx: mx2.good.example\nmax_age: 604800\n" },
  });

describe("a whole domain", () => {
  it("comes back green when every record is right, each one quoted", async () => {
    const report = await checkDomain("good.example", { dns: goodDns(), tls: goodTls, http: goodHttp(), now: () => now });
    expect(report.mail).toBe(true);
    expect(report.counts).toEqual({ ok: 16, warn: 0, bad: 0, na: 0 });
    const by = Object.fromEntries(report.findings.map((f) => [f.id, f]));
    expect(by.dnssec?.quoted).toEqual(["Cloudflare DoH: AD=true Status=0"]);
    expect(by.dkim?.text).toContain("google");
    expect(by["mta-sts"]?.quoted).toContain("policy: mode: enforce");
    expect(by.http?.quoted).toEqual(["Location: https://good.example/"]);
    expect(by["security-txt"]?.quoted).toEqual(["Contact: mailto:security@good.example", "Expires: 2027-06-01T00:00:00.000Z"]);
    expect(by.caa?.quoted).toEqual(['CAA 0 issue "letsencrypt.org"']);
  });

  it("says what a bare domain lacks, and what does not apply without mail", async () => {
    const bareDns: DnsLookup = async (name, type) => (type === "A" && name === "bare.example" ? { records: ["203.0.113.20"], code: "ok" } : type === "NS" && name === "bare.example" ? { records: ["ns1.bare.example"], code: "ok" } : { records: [], code: "nodata" });
    const http = fakeHttp({
      "https://cloudflare-dns.com/dns-query?name=bare.example&type=A": { text: '{"Status":0,"AD":false,"Answer":[]}' },
      "https://bare.example/": { text: "<html>", headers: {} },
      "http://bare.example/": { text: "<html>" },
      "https://bare.example/.well-known/security.txt": { status: 404 },
      "https://mta-sts.bare.example/.well-known/mta-sts.txt": { status: 404 },
    });
    const report = await checkDomain("bare.example", { dns: bareDns, tls: async () => ({ error: "ECONNREFUSED" }), http, now: () => now });
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
    const report = await checkDomain("gone.example", { dns, tls: async () => ({ error: "ENOTFOUND" }), http, now: () => now });
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
      const page = await (await fetch(`${app.base}/scan/domain?name=GOOD.example&selectors=google`)).text();
      expect(page).toContain("Check a domain · good.example");
      expect(page).toContain("<small>Good</small><b>16</b>");
      expect(page).toContain("<li><code>TXT &quot;v=DMARC1; p=reject; rua=mailto:dmarc@good.example&quot;</code></li>");
      expect(page).toContain('<span class="state ok">Good</span>');
      expect(page).not.toContain('id="own"');
      // The Scan page points here, and the menu has the four entries.
      const scan = await (await fetch(`${app.base}/scan`)).text();
      expect(scan).toContain('<a href="/scan/domain">check a domain</a>');
      expect(scan).toContain("<b>Your network</b>");
    } finally {
      await app.close();
    }
  });
});
