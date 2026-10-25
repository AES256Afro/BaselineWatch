import { describe, expect, it } from "vitest";
import type { Finding } from "../src/domaincheck.ts";
import { fixFor, fixKindLabel } from "../src/domainfix.ts";

/**
 * What to do about a domain finding. The check said what was wrong and quoted the record; this is
 * the half that was missing — the record to publish or the header to send — and the rules it
 * follows matter more than the text, because a wrong record here costs a reader their mail.
 */

const finding = (id: string, state: Finding["state"], text = "x"): Finding => ({ id, group: "web", title: id, state, text, quoted: [] });
const domain = "example.net";

describe("the fix for a finding", () => {
  it("has nothing to say about a finding that is already good or does not apply", () => {
    for (const id of ["caa", "spf", "dmarc", "hsts", "headers", "security-txt", "mta-sts", "tls-rpt", "http", "tls", "dnssec", "dkim"]) {
      expect(fixFor(finding(id, "ok"), domain), id).toBeNull();
      expect(fixFor(finding(id, "na"), domain), id).toBeNull();
    }
  });

  it("has nothing to say about the rows that report rather than judge", () => {
    for (const id of ["addresses", "ns", "mx", "https"]) {
      expect(fixFor(finding(id, "bad"), domain), id).toBeNull();
    }
  });

  it("covers every check that can be wrong, so no finding is left without a next step", () => {
    for (const id of ["caa", "dnssec", "spf", "dmarc", "dkim", "mta-sts", "tls-rpt", "http", "hsts", "headers", "security-txt", "tls"]) {
      const fix = fixFor(finding(id, "bad"), domain);
      expect(fix, id).not.toBeNull();
      expect(fix!.text.length, id).toBeGreaterThan(40);
      expect(fixKindLabel[fix!.kind], id).toBeTruthy();
      expect(fix!.source.url, id).toMatch(/^https:\/\//);
    }
  });

  it("writes the records for the domain that was checked, not for an example", () => {
    expect(fixFor(finding("dmarc", "bad", "No DMARC record"), domain)!.lines[0]).toBe(`_dmarc.${domain}. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@${domain}; fo=1"`);
    expect(fixFor(finding("tls-rpt", "bad"), domain)!.lines[0]).toContain(`_smtp._tls.${domain}.`);
    expect(fixFor(finding("caa", "warn"), domain)!.lines[0]).toContain(`${domain}. IN CAA`);
    expect(fixFor(finding("security-txt", "bad"), domain)!.lines[0]).toContain(`https://${domain}/.well-known/security.txt`);
  });

  it("never hands over a finished record that would refuse the reader's own mail", () => {
    // SPF and DKIM are the two where a confident answer is a wrong answer: an SPF record that
    // does not name a sender refuses it, and a DKIM key comes from the provider, not from here.
    const spf = fixFor(finding("spf", "bad", "No SPF record"), domain)!;
    expect(spf.lines.join(" ")).toContain("YOUR-PROVIDER");
    expect(spf.caution).toMatch(/every service that sends as you/);
    const dkim = fixFor(finding("dkim", "bad"), domain)!;
    expect(dkim.kind).toBe("setting");
    expect(dkim.lines.join(" ")).toContain("<the public key your provider gives you>");
    expect(dkim.caution).toMatch(/does not prove there is no DKIM/);
  });

  it("says plainly when there is no record to publish at all", () => {
    for (const id of ["dnssec", "dkim", "http", "tls"]) {
      expect(fixFor(finding(id, "bad"), domain)!.kind, id).toBe("setting");
    }
  });

  it("carries a caution wherever pasting it blind would cost something", () => {
    for (const id of ["caa", "dnssec", "spf", "dmarc", "dkim", "mta-sts", "http", "hsts", "headers", "security-txt", "tls"]) {
      expect(fixFor(finding(id, "bad"), domain)!.caution, id).toBeTruthy();
    }
    // TLS-RPT is the one that cannot break anything: it only asks for reports.
    expect(fixFor(finding("tls-rpt", "bad"), domain)!.caution).toBeUndefined();
  });

  it("starts DMARC and MTA-STS where they are safe to start", () => {
    expect(fixFor(finding("dmarc", "bad", "No DMARC record"), domain)!.lines[0]).toContain("p=none");
    expect(fixFor(finding("mta-sts", "bad"), domain)!.lines.join("\n")).toContain("mode: testing");
  });

  it("reads the finding's own words, so a missing record and a weak one get different advice", () => {
    expect(fixFor(finding("spf", "bad", "No SPF record found."), domain)!.text).toMatch(/Publish one SPF record/);
    expect(fixFor(finding("spf", "warn", "One record ending ~all (soft fail)."), domain)!.text).toMatch(/Tighten the record/);
    expect(fixFor(finding("dmarc", "bad", "No DMARC record."), domain)!.text).toMatch(/Publish a DMARC record/);
    expect(fixFor(finding("dmarc", "warn", "Policy none."), domain)!.text).toMatch(/Move the policy on/);
  });
});
