import type { Finding } from "./domaincheck.ts";

/**
 * What to do about a domain finding.
 *
 * The check (domaincheck.ts) says what is wrong and quotes the record it read. Until now it
 * stopped there: a reader learned their domain publishes no CAA record and was left to go and
 * find out what one looks like. This says the next thing — the record to publish or the header to
 * send — as text they can copy, beside the body that defines it.
 *
 * Three rules this follows, because a wrong record here costs more than no record:
 *
 * - **Nothing is generated that could break something silently.** An SPF record that does not
 *   name every sender refuses that sender's mail, so the SPF fix is a shape with the senders
 *   marked as the reader's to fill, never a finished record.
 * - **A setting that is not a record says so.** DNSSEC and DKIM are turned on at the registrar or
 *   the mail provider; there is nothing to paste, and pretending otherwise would waste the
 *   reader's afternoon.
 * - **Every fix cites the body that defines it**, so a reader can check this page's homework.
 */
export interface DomainFix {
  /** What to do, in a sentence. */
  text: string;
  /** Lines to copy: a DNS record in zone-file form, a header, or the contents of a file. */
  lines: string[];
  /** What the lines are, so the reader knows where they go. */
  kind: "dns" | "header" | "file" | "setting";
  /** The caution that goes with it, when pasting it blind would cost something. */
  caution?: string;
  /** Where the rule comes from. */
  source: { label: string; url: string };
}

const rfc = (number: number, label: string): { label: string; url: string } => ({ label: `RFC ${number}: ${label}`, url: `https://www.rfc-editor.org/rfc/rfc${number}.html` });

/**
 * The fix for a finding, or nothing when there is none to give — a finding that is already good,
 * one that does not apply, and the purely descriptive rows (the addresses, the name servers, the
 * mail exchangers) which report what is there rather than judge it.
 */
export function fixFor(finding: Finding, domain: string): DomainFix | null {
  if (finding.state === "ok" || finding.state === "na") return null;
  switch (finding.id) {
    case "caa":
      return {
        kind: "dns",
        text: "Name the certificate authorities allowed to issue for this domain, so no other one may.",
        lines: [`${domain}. IN CAA 0 issue "letsencrypt.org"`, `${domain}. IN CAA 0 iodef "mailto:security@${domain}"`],
        caution: "List every authority that issues for you — the one your host or CDN uses as well as your own. A CAA record that leaves one out stops it renewing, and the certificate expires rather than failing loudly.",
        source: rfc(8659, "DNS Certification Authority Authorization"),
      };
    case "dnssec":
      return {
        kind: "setting",
        text: "DNSSEC is switched on where the domain is registered, not in a record you publish: the DNS host signs the zone and the registrar publishes the DS record that vouches for the key. Most hosts have it as one switch.",
        lines: [],
        caution: "A signed zone whose DS record does not match makes the domain disappear for validating resolvers. Change the two together, and check with a validator before you walk away.",
        source: rfc(9364, "DNS Security Introduction and Requirements"),
      };
    case "spf":
      return {
        kind: "dns",
        text: finding.text.includes("no SPF") || finding.text.includes("No SPF")
          ? "Publish one SPF record saying who may send as this domain. A domain that sends no mail says so with a bare hard fail."
          : "Tighten the record: end it in -all so a receiver refuses mail from anywhere the record does not name.",
        lines: [`${domain}. IN TXT "v=spf1 -all"    ; a domain that sends no mail`, `${domain}. IN TXT "v=spf1 include:YOUR-PROVIDER -all"    ; one that does`],
        caution: "Replace YOUR-PROVIDER with every service that sends as you — the mail host, the newsletter, the ticketing system, the monitoring that mails you. Anything missing from the record has its mail refused, and ten DNS lookups is the limit a receiver will follow.",
        source: rfc(7208, "Sender Policy Framework"),
      };
    case "dmarc":
      return {
        kind: "dns",
        text: finding.text.includes("No DMARC") || finding.text.includes("no DMARC")
          ? "Publish a DMARC record. Start at p=none with reports coming back, read them for a few weeks, then move to quarantine and reject once nothing legitimate is failing."
          : "Move the policy on, once the reports show nothing legitimate failing: none, then quarantine, then reject.",
        lines: [`_dmarc.${domain}. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@${domain}; fo=1"`],
        caution: "p=reject before the reports are clean refuses your own mail. The rua address receives a daily XML report from every large receiver, so point it somewhere a person or a parser will actually read.",
        source: rfc(7489, "Domain-based Message Authentication, Reporting and Conformance"),
      };
    case "dkim":
      return {
        kind: "setting",
        text: "DKIM keys come from whoever sends your mail: the provider generates the pair, you publish the public half at the selector it names. There is nothing to write here until it has given you one.",
        lines: [`<selector>._domainkey.${domain}. IN TXT "v=DKIM1; k=rsa; p=<the public key your provider gives you>"`],
        caution: "This check tries the selectors the common providers use. Finding none does not prove there is no DKIM — a provider using a selector of its own would not be found — so check with your provider before concluding anything.",
        source: rfc(6376, "DomainKeys Identified Mail"),
      };
    case "mta-sts":
      return {
        kind: "file",
        text: "MTA-STS is a DNS record pointing at a policy file, so a sending server knows to insist on TLS to your mail exchangers rather than accept a downgrade.",
        lines: [
          `_mta-sts.${domain}. IN TXT "v=STSv1; id=$(date +%Y%m%d%H%M%S)"`,
          `# then, at https://mta-sts.${domain}/.well-known/mta-sts.txt, served over valid HTTPS:`,
          "version: STSv1",
          "mode: testing",
          `mx: <each of your MX host names, one "mx:" line each>`,
          "max_age: 604800",
        ],
        caution: "Start in testing mode, which reports without refusing. mode: enforce with an mx list that misses one of your exchangers makes mail to it fail, and the id must change whenever the policy does or senders keep the old one.",
        source: rfc(8461, "SMTP MTA Strict Transport Security"),
      };
    case "tls-rpt":
      return {
        kind: "dns",
        text: "TLS-RPT asks sending servers to report when TLS to your mail exchangers fails, which is how you find out that MTA-STS is breaking something before your correspondents tell you.",
        lines: [`_smtp._tls.${domain}. IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@${domain}"`],
        source: rfc(8460, "SMTP TLS Reporting"),
      };
    case "http":
      return {
        kind: "setting",
        text: "Answer plain HTTP with a permanent redirect to the same path over HTTPS, and nothing else: a page served over plain HTTP can be rewritten in transit before the reader ever reaches the secure one.",
        lines: ["HTTP/1.1 301 Moved Permanently", `Location: https://${domain}/`],
        caution: "Redirect to the same path, not to the front page: a link to /a/b that lands on / is a broken link, and people stop following them.",
        source: { label: "MDN: redirections in HTTP", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections" },
      };
    case "hsts":
      return {
        kind: "header",
        text: "Send Strict-Transport-Security, so a browser that has been here once refuses plain HTTP afterwards without being asked.",
        lines: [`Strict-Transport-Security: max-age=31536000; includeSubDomains`],
        caution: "includeSubDomains binds every subdomain for the whole max-age, including any that is still HTTP-only — check them first. Begin with a short max-age (300) and raise it once nothing breaks; the header cannot be taken back early.",
        source: rfc(6797, "HTTP Strict Transport Security"),
      };
    case "headers":
      return {
        kind: "header",
        text: "Send the headers this answer is missing. These are a starting point that breaks nothing on a site that serves its own scripts and styles.",
        lines: [
          "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
          "X-Content-Type-Options: nosniff",
          "Referrer-Policy: strict-origin-when-cross-origin",
        ],
        caution: "A Content-Security-Policy is the one to test rather than paste: a site loading scripts, fonts or images from elsewhere needs those origins named, and a policy that forgets one silently stops the page working. Report-Only first says what it would have blocked.",
        source: { label: "MDN: Content-Security-Policy", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy" },
      };
    case "security-txt":
      return {
        kind: "file",
        text: "Say where to report a flaw, so someone who finds one in your site can tell you instead of giving up or going public.",
        lines: [
          `# at https://${domain}/.well-known/security.txt`,
          `Contact: mailto:security@${domain}`,
          "Expires: <a date within a year, in RFC 3339 form, e.g. 2027-01-01T00:00:00.000Z>",
          "Preferred-Languages: en",
        ],
        caution: "Expires is required and the file is stale once it passes, so put a reminder wherever you keep them. Point Contact at something a person reads.",
        source: rfc(9116, "A File Format to Aid in Security Vulnerability Disclosure"),
      };
    case "tls":
      return {
        kind: "setting",
        text: "The certificate needs attention: renew it before it expires, and make sure the chain it serves includes the intermediate certificates, which is the usual cause of a chain a browser will not accept.",
        lines: [],
        caution: "A certificate that validates in a browser can still fail elsewhere: browsers fill in a missing intermediate from their own cache, and a command-line client or another language's TLS stack will not.",
        source: { label: "Mozilla: server-side TLS configuration", url: "https://wiki.mozilla.org/Security/Server_Side_TLS" },
      };
    default:
      return null;
  }
}

/** The label for each kind, as the page introduces the lines. */
export const fixKindLabel: Record<DomainFix["kind"], string> = {
  dns: "Publish this record",
  header: "Send this header",
  file: "Serve this",
  setting: "Change this setting",
};
