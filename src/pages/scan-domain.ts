import { html, newTab, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import type { CtCertRow } from "../ct.ts";
import type { DomainReport, Finding } from "../domaincheck.ts";
import { fixFor, fixKindLabel } from "../domainfix.ts";
import { page } from "./layout.ts";

/**
 * Check a domain (Scan 2.0, S3): the form, and the report as rows in the Scan area's own shape —
 * a verdict per check with the record it rests on quoted, grouped as names, mail and web. A
 * teaching page: each row says what the record means, and — for a row that is not already good —
 * what to publish or send to put it right, with the caution that goes with it (domainfix.ts).
 * Server-rendered from one check; no script.
 */

export interface ScanDomainOptions {
  owner: boolean;
  open: boolean;
  look: LookState;
  /** What was typed, cleaned, or nothing yet. */
  domain: string | null;
  selectors: string;
  report: DomainReport | null;
  /** Why there is no report: a bad name, a throttle, nothing typed. */
  problem: string | null;
  /** The owner's own domains, each a link, so the page opens on them. */
  own: string[];
  /** The certificates the transparency logs hold for a listed domain, newest first; empty for any other. */
  certs?: CtCertRow[];
}

const groups: { id: Finding["group"]; title: string; blurb: string }[] = [
  { id: "names", title: "Names and addresses", blurb: "What the DNS says about the domain itself: where it points, who serves it, whether answers are signed, who may issue certificates." },
  { id: "mail", title: "Mail", blurb: "Whether mail claiming to come from this domain can be told from forgery, and whether mail to it travels encrypted." },
  { id: "web", title: "Web", blurb: "What the front page sends with itself: the transport, the headers that bind a browser, and whom to tell about a flaw." },
];

const stateWord: Record<Finding["state"], string> = { ok: "Good", warn: "Could be better", bad: "Missing or wrong", na: "Not applicable" };

function row(n: number, f: Finding, domain: string): Html {
  // What to do about it, for a row that is not already good. The check used to stop at the
  // verdict, which left a reader who learns their domain publishes no CAA record to go and find
  // out what one looks like; this is the record, beside the body that defines it.
  const fix = fixFor(f, domain);
  return html`<article class="check" id="check-${f.id}">
  <span class="n">${String(n).padStart(2, "0")}</span>
  <div>
    <div class="t">${f.title}</div>
    <p class="d">${f.text}</p>
    ${f.quoted.length ? html`<ul class="ev">${f.quoted.map((q) => html`<li><code>${q}</code></li>`)}</ul>` : ""}
    ${fix
      ? html`<details class="fix">
          <summary>What to do</summary>
          <p class="d">${fix.text}</p>
          ${fix.lines.length ? html`<p class="small lab">${fixKindLabel[fix.kind]}</p><pre class="fix-lines">${fix.lines.join("\n")}</pre>` : ""}
          ${fix.caution ? html`<p class="small caution"><b>Before you do:</b> ${fix.caution}</p>` : ""}
          <p class="small">The rule: <a href="${fix.source.url}" ${newTab}>${fix.source.label}</a>. These lines are a starting point for this domain, not a finished configuration — read the caution and check them against what you actually run.</p>
        </details>`
      : ""}
  </div>
  <span class="state ${f.state}">${stateWord[f.state]}</span>
</article>`;
}

export function renderScanDomain(options: ScanDomainOptions): string {
  const { owner, open, look, domain, selectors, report, problem, own } = options;
  const certs = options.certs ?? [];
  const form = html`<form method="get" action="/scan/domain" class="search stack-sm" role="search">
    <label for="name">Domain</label>
    <input type="text" id="name" name="name" value="${domain ?? ""}" placeholder="example.com" required maxlength="253" inputmode="url" autocapitalize="none" spellcheck="false">
    <label for="selectors">DKIM selectors <span class="small">(optional, comma-separated)</span></label>
    <input type="text" id="selectors" name="selectors" value="${selectors}" placeholder="google, selector1" maxlength="200">
    <button type="submit" class="primary">Check</button>
  </form>`;
  let n = 0;
  const body = report
    ? html`
      <div class="stats" aria-label="Summary">
        <div class="${report.counts.bad ? "bad" : ""}"><small>Missing or wrong</small><b>${report.counts.bad}</b></div>
        <div class="${report.counts.warn ? "warn" : ""}"><small>Could be better</small><b>${report.counts.warn}</b></div>
        <div><small>Good</small><b>${report.counts.ok}</b></div>
        <div><small>Receives mail</small><b class="date">${report.mail ? "yes" : "no"}</b></div>
        <div><small>Checked</small><b class="date">${report.checkedAt.slice(11, 16)} UTC</b></div>
      </div>
      ${groups.map(
        (g) => html`<section class="box wide" id="${g.id}">
          <h2>${g.title}</h2>
          <p class="small">${g.blurb}</p>
          <div class="checks">${report.findings.filter((f) => f.group === g.id).map((f) => row(++n, f, report.domain))}</div>
        </section>`,
      )}
      <p class="small">Read in ${report.durationMs} ms by DNS questions to this server's resolver, one question to Cloudflare's validating resolver for the DNSSEC flag, and GETs of the domain's own front page and well-known files. No port was probed beyond 443, and 80 to see whether it redirects. Nothing was stored.</p>`
    : html`<section class="box wide"><p class="small">${problem ?? "Type a domain. The check reads it by DNS and HTTPS alone — the way internet.nl, Hardenize and MXToolbox do — and quotes every record beside its verdict."}</p></section>`;
  const content = html`<section class="scan">
  <p class="crumbs"><a href="/">Home</a><span>›</span><a href="/scan">Scan</a><span>›</span><b>A domain</b></p>
  <h1>Check a domain <span class="arrow">its mail, DNS and web posture, each record quoted</span></h1>
  <p class="lede">
    SPF, DMARC and DKIM say whether forged mail from the domain is refused; MTA-STS and TLS-RPT whether mail to it travels encrypted; DNSSEC and CAA who may answer for it and certify it; HSTS, the security headers, the certificate and <code>security.txt</code> what the front page binds a browser to and whom to tell about a flaw. Lookups only, from this server; nothing is sent to the domain beyond a GET of its front page.
  </p>
  <div class="cols">
    <div class="main">
      ${form}
      ${own.length ? html`<p class="small">Your domains: ${own.map((d, i) => html`${i ? " · " : ""}<a href="/scan/domain?name=${encodeURIComponent(d)}">${d}</a>`)}</p>` : ""}
      ${body}
      ${certs.length
        ? html`<section class="box wide" id="certificates">
            <h2>Certificates in the transparency logs <span class="count">${certs.length} newest</span></h2>
            <ul class="refs">${certs.map((c) => html`<li><a href="https://crt.sh/?id=${c.id}" ${newTab}>${c.names.split("\n").join(", ")}</a> <span class="small">${c.issuer ?? "unknown issuer"}${c.not_before ? ` · from ${c.not_before.slice(0, 10)}` : ""}${c.not_after ? ` to ${c.not_after.slice(0, 10)}` : ""}</span></li>`)}</ul>
            <p class="small">From crt.sh, read once a day for the domains you listed; a certificate logged since the last read is a News item. One you did not expect means someone else holds a certificate for a name of yours.</p>
          </section>`
        : ""}
    </div>
    <aside class="side">
      <div class="box">
        <h2>What each row rests on</h2>
        <ul class="small plan">
          <li><a href="https://www.rfc-editor.org/rfc/rfc7208" ${newTab}>RFC 7208</a> SPF · <a href="https://www.rfc-editor.org/rfc/rfc7489" ${newTab}>RFC 7489</a> DMARC · <a href="https://www.rfc-editor.org/rfc/rfc6376" ${newTab}>RFC 6376</a> DKIM</li>
          <li><a href="https://www.rfc-editor.org/rfc/rfc8461" ${newTab}>RFC 8461</a> MTA-STS · <a href="https://www.rfc-editor.org/rfc/rfc8460" ${newTab}>RFC 8460</a> TLS-RPT</li>
          <li><a href="https://www.rfc-editor.org/rfc/rfc8659" ${newTab}>RFC 8659</a> CAA · <a href="https://www.rfc-editor.org/rfc/rfc6797" ${newTab}>RFC 6797</a> HSTS · <a href="https://www.rfc-editor.org/rfc/rfc9116" ${newTab}>RFC 9116</a> security.txt</li>
          <li>NIST SP 800-177 Rev. 1, <em>Trustworthy Email</em>, for the order to do them in; CISA BOD 18-01 for what the US government requires of its own domains (DMARC reject, HSTS, no weak TLS).</li>
        </ul>
      </div>
      <div class="box">
        <h2>Limits</h2>
        <ul class="small plan">
          <li>DKIM can only be read at a selector; the common ones are tried, yours may differ.</li>
          <li>The DNSSEC flag is Cloudflare's resolver's word; the chain itself is not walked here.</li>
          <li>HSTS preload status is not looked up; the <code>preload</code> directive is reported as sent.</li>
          <li>A front page that refuses non-browser clients (403) still shows its headers; one behind a bot wall may not.</li>
        </ul>
      </div>
      ${owner
        ? html`<div class="box" id="own">
            <h2>Your domains</h2>
            <form method="post" action="/scan/domain/own" class="stack">
              <label for="own-domains">Comma-separated</label>
              <input type="text" id="own-domains" name="domains" value="${own.join(", ")}" maxlength="500" placeholder="example.com, example.org">
              <button type="submit">Save</button>
            </form>
            <p class="small">Listed on this page as links; nothing is checked until you open one.</p>
          </div>`
        : ""}
    </aside>
  </div>
</section>`;
  return page({ title: domain ? `Check a domain · ${domain}` : "Check a domain", active: "scan-domain", content, owner, open, look, canonical: "/scan/domain", description: "A domain's mail, DNS and web posture read by lookups alone: SPF, DMARC, DKIM, MTA-STS, DNSSEC, CAA, HSTS, the certificate, security.txt, each record quoted." });
}
