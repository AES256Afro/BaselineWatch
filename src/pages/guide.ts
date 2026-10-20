import { html } from "../html.ts";
import type { LookState } from "../look.ts";
import { page } from "./layout.ts";

/**
 * The teaching page: what the Register is, what the scores and severities mean, and how the
 * reading areas relate. Written for cybercard.net's learning audience, so every term links to
 * the page that shows it in use. Plain prose, no data: it renders the same for everyone.
 */
export function renderGuide(options: { owner: boolean; open: boolean; look: LookState }): string {
  const content = html`
    <h1>How to read this site</h1>
    <p class="lede">
      This site does two jobs: it gathers security news in one timeline, and it keeps a change
      register for the security standards themselves. The terms below appear all over both; each
      one links to the page where you can see it in use.
    </p>
    <div class="guide">
      <section class="box" id="areas">
        <h2>The three reading areas</h2>
        <p>
          <a href="/">News</a> is the home page: articles from the sources the site follows, plus
          the vulnerabilities worth an entry of their own. <a href="/today">Today</a> is the same
          material rolled up into one glance at the last day. <a href="/vulnerabilities">Vulnerabilities</a>
          is the full table — every CVE the pipeline has seen, searchable and filterable. Only
          notable CVEs make the News timeline: ones in KEV, new criticals, EPSS over 50%, or
          active exploitation; the table keeps the rest.
        </p>
      </section>
      <section class="box" id="register">
        <h2>The Register</h2>
        <p>
          <a href="/register">The Register</a> tracks changes to the standards themselves: NIST
          SP 800-53 controls, DISA <a href="/stigs">STIGs</a>, Microsoft security
          <a href="/baselines">baselines</a>, and CIS Benchmarks from your own copy. When a
          publisher releases a new version, the Register shows each requirement before and after,
          what changed, and the publisher's stated reason. Where a summary is machine-generated
          rather than the publisher's own words, it carries a label saying so.
        </p>
      </section>
      <section class="box" id="kev">
        <h2>KEV — known to be exploited</h2>
        <p>
          <a href="/vulnerabilities?kev=1">KEV</a> is CISA's Known Exploited Vulnerabilities
          catalog: the list of CVEs with reliable evidence of exploitation in the wild. A KEV
          entry is the strongest single signal a vulnerability sends — it is no longer about
          whether someone might attack it, because someone already has. US federal agencies are
          required to remediate KEV entries by a due date; everyone else does well to treat the
          list the same way.
        </p>
      </section>
      <section class="box" id="epss">
        <h2>EPSS — how likely exploitation is</h2>
        <p>
          <a href="/vulnerabilities?min_epss=0.5">EPSS</a>, the Exploit Prediction Scoring System
          from FIRST, estimates the probability that a CVE will be exploited in the next thirty
          days, from 0 to 1. It answers a different question than severity: a flaw can be grave
          but unlikely to be attacked, or modest but attacked everywhere. This site surfaces a
          CVE as news when its EPSS passes 50%.
        </p>
      </section>
      <section class="box" id="cvss">
        <h2>CVSS — how bad the flaw itself is</h2>
        <p>
          <a href="/vulnerabilities?min_cvss=9">CVSS</a>, the Common Vulnerability Scoring
          System, rates the technical severity of a flaw from 0 to 10 — what an attacker gets and
          how easily, regardless of whether anyone is attacking it. 9.0 and above is critical.
          Read CVSS and EPSS together: CVSS for the blast radius, EPSS for the odds, KEV for the
          certainty.
        </p>
      </section>
      <section class="box" id="cat">
        <h2>CAT I, II and III — STIG severities</h2>
        <p>
          DISA grades every <a href="/stigs">STIG</a> rule by what ignoring it costs. CAT I means
          exploitation directly and immediately loses confidentiality, availability or integrity
          — fix first. CAT II means exploitation has the potential to cause that loss. CAT III
          means the weakness degrades the measures protecting against it. The STIG pages count
          each release's rules by category and show what changed against the previous version.
        </p>
      </section>
    </div>`;

  return page({ title: "How to read this site", active: "guide", content, ...options });
}
