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
      register for the security standards themselves. The ladder below is the frame for all of
      it — standard, baseline, control, setting — and the terms after it appear all over both
      jobs; each one links to the page where you can see it in use. Where those rulebooks come from
      in the first place — the law, the policy and the publishers behind each one — is
      <a href="/learn">Learn</a>.
    </p>
    <div class="guide">
      <section class="box wide" id="ladder">
        <h2>Standard, baseline, control, setting</h2>
        <p>
          Four words do most of the work in this field, and they are used loosely nearly
          everywhere. On this site they mean exactly one thing each, and the menus are built from
          them: <a href="/standards">Standards</a>, <a href="/baselines">Baselines</a>,
          <a href="/controls">Controls</a>.
        </p>
        <ol class="ladder">
          <li>
            <b>Standard</b> <span class="rung">the rulebook</span>
            <p>
              A publisher's document saying how things are to be done: NIST SP 800-53, SP 800-171,
              a DISA STIG, a CIS Benchmark, FedRAMP's rules, NASA's policy set. It is written for
              everyone, not for your machine. <a href="/standards">Standards</a> lists the ones
              this instance tracks, and <a href="/register">what changed</a> in each release.
            </p>
          </li>
          <li>
            <b>Baseline</b> <span class="rung">the set of rules chosen for your kind of system</span>
            <p>
              A standard is too large to apply whole, so a baseline selects from it: SP 800-53's
              Low, Moderate and High sets, the DISA STIG baseline for a platform, Microsoft's
              security baseline for a Windows release. <a href="/baselines">Baselines</a> builds
              the strictest published one for a platform and lets you trim it.
            </p>
          </li>
          <li>
            <b>Control</b> <span class="rung">one specific rule in that set</span>
            <p>
              AC-2 Account Management, IA-2 Multi-Factor Authentication, CM-6 Secure
              Configuration. A control says what must be true, not how to make it true on a Mac.
              <a href="/controls">Controls</a> is one rule at a time: its text, the rules that
              implement it, and how it has changed.
            </p>
          </li>
          <li>
            <b>Configuration setting</b> <span class="rung">how the control is enforced on a device or service</span>
            <p>
              The registry value, the mobileconfig payload key, the Intune settings-catalog
              definition, the shell command in a STIG's fix text. One control usually becomes
              several settings, and they differ per platform — which is why a
              <a href="/baselines">baseline export</a> comes in a Jamf, Intune or Linux flavour.
            </p>
          </li>
        </ol>
        <h3>The same ladder, twice</h3>
        <div class="ladder-pair">
          <div>
            <h4>A house</h4>
            <p><b>Standard</b>: build houses this way.<br>
              <b>Baseline</b>: for this kind of house, these requirements.<br>
              <b>Controls</b>: a lock on the door, a smoke detector, an alarm.<br>
              <b>Setting</b>: this lock, fitted this way, on this door.</p>
          </div>
          <div>
            <h4>A federal system</h4>
            <p><b>Standard</b>: NIST SP 800-53, and the agency's own policy above it.<br>
              <b>Baseline</b>: the Moderate set, plus the agency's tailoring.<br>
              <b>Control</b>: IA-2, multi-factor authentication.<br>
              <b>Setting</b>: Intune requires a PIV-derived certificate for every user.</p>
          </div>
        </div>
        <p class="small">
          An agency's own layer sits between the standard and the baseline: NASA's OCIO
          Cybersecurity Standards and Engineering Team takes NIST checklists, CIS Benchmarks, DoD
          STIGs and vendor guidance and issues NASA-approved configuration specifications from
          them. Those specifications are internal, so this site tracks the public layer instead —
          the quarterly <a href="/standards/nasa-cyber-ref">NASA Cybersecurity Policy Reference</a>,
          which lists every NASA cybersecurity document with its dates and status, and diffs like
          any other standard.
        </p>
        <h3>Where the rulebook itself came from</h3>
        <p>
          The ladder starts at the standard, but the standard did not start there. A law obliges
          somebody to act, a policy says what acting looks like, a framework structures the work,
          and only then is there a catalogue to pick a baseline out of — and below the setting there
          is a check that proves it. <a href="/learn">Learn</a> draws that whole chain, names every
          publisher on it (NIST, CISA, DISA, CNSS, NASA, CIS, Microsoft, the NSA, the ACSC, the
          NCSC), links each one's own address with what it takes to read it, and traces the same
          control three ways: down a federal system's ladder, a DoD system's, and a private
          company's.
        </p>
      </section>
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
      <section class="box" id="exploits">
        <h2>Public exploits — and Microsoft's own word</h2>
        <p>
          A score says how bad a flaw could be; an <span class="chip exploit">exploit</span> chip
          says someone has already written the code. The table reads three free indexes once a day
          — Exploit-DB, Metasploit's modules and the PoC-in-GitHub list — and the CVE page lists
          each entry under <b>Fix</b>, linking to the index, never to the code. <i>Verified</i> is
          Exploit-DB's own flag or a Metasploit module ranked good or better; a GitHub repository
          is a claim. For Microsoft's products the CVE page also carries <b>Microsoft's update</b>:
          the KB per product from the Security Update Guide, and whether Microsoft itself says the
          flaw is <span class="chip kev">exploited</span> or publicly disclosed.
          <a href="/vulnerabilities/microsoft">Patch Tuesday</a> lays each month out by update
          and product, your own Windows releases first.
        </p>
      </section>
      <section class="box" id="news-chip">
        <h2>What the News is talking about</h2>
        <p>
          A <span class="chip news">news ×3</span> chip means three sources named the CVE this
          week, whatever its score; the CVE page lists the stories under <b>In the news</b>, and
          <a href="/today">Today</a> names the most talked-about. It is the one signal that comes
          from the News itself rather than from NVD, CISA or FIRST.
        </p>
      </section>
      <section class="box" id="feeds">
        <h2>Feeds, the calendar, search</h2>
        <p>
          Everything the pages show can leave with you: the News and the table as RSS under any
          filter, every source as OPML, CISA's KEV due dates as a calendar you subscribe to, the
          same facts as JSON under <code>/api/v1/</code>. The <a href="/feeds">Feeds</a> page
          writes every address out in full. The box in the masthead searches CVEs, the News,
          every standard's controls, Microsoft's updates and the sources in one go; a CVE id typed
          whole opens its page.
        </p>
      </section>
      <section class="box" id="scan">
        <h2>The Scan area — what each check can prove</h2>
        <p>
          <a href="/scan">This browser</a> runs in your tab and uploads nothing: whether a blocker
          hides and stops ads, whether a filtering resolver answers, and what the browser gives
          away — privacy signals, WebRTC addresses, the fingerprint surface, the referrer. The
          same page shows what this server learned from your request. <a href="/scan/domain">A
          domain</a> reads any domain by lookups alone — SPF, DMARC, DKIM, MTA-STS, DNSSEC, CAA,
          HSTS, the certificate — and quotes every record beside its verdict.
          <a href="/scan/network">Your network</a> is the owner's: the LAN resolver tested with
          canary names from this server, and once a day what the internet sees of the public
          address and what the router gives away. <a href="/scan/history">History</a> keeps every
          run. <a href="/scan/devices">A device</a> reads what a computer runs from a script's
          report you paste — the Windows build, the browsers, the packages — and says which CVEs
          apply to those versions. Signals, not certificates: each row says what it saw, and nothing here contacts an
          advertising or malware host or sends a packet to a device that did not ask.
        </p>
      </section>
      <section class="box" id="devices">
        <h2>Is this device affected? — what a reading can say</h2>
        <p>
          No web page can see what a computer runs, and this site installs nothing, so
          <a href="/scan/devices">a device</a> is read by a script you run on it —
          <code>bw-inventory.ps1</code> on Windows, <code>bw-inventory.sh</code> on macOS and Linux,
          served with their sums beside the check scripts — and the script prints version numbers
          and nothing else: the Windows build, the macOS or distribution release, each browser's
          version, a Linux distribution's packages. You paste that report. What the owner pastes is
          kept as verdicts and CVE ids under the device's name, never the report itself.
        </p>
        <p>
          Each line is read against a source that can answer it. A Windows build is compared with
          the fixed build Microsoft's Security Update Guide names for each update on that Windows
          version, so a missing update is listed with the CVEs it fixes and which of them Microsoft
          says are exploited. A browser and macOS are compared with the vendor's newest announced
          release, a release with endoflife.date, and a Linux distribution's packages go to OSV in
          one question, where versions are compared by the distribution's own rules — a Debian
          package whose number reads older than the upstream fix can still be fixed, because the
          distribution backported it and OSV knows the version that did.
        </p>
        <p>
          What a reading cannot say: whether an application outside those lists is current, whether
          a setting is wrong, or whether anything is running. "Up to date" means no newer release
          is known to the sources this instance reads, as of their last read — not that nothing is
          wrong with the machine. Read it again after patching; the page says what moved.
        </p>
      </section>
      <section class="box" id="watchlist">
        <h2>The watchlist, and an SBOM</h2>
        <p>
          The <a href="/watchlist">watchlist</a> is how the table knows your stack: products,
          packages, platforms, keywords. A software bill of materials (CycloneDX or SPDX JSON)
          turns into package entries in one upload, so the advisories for what a system actually
          ships mark it as yours. Versions are not kept — the advisory says which — and nothing
          else from the file is stored.
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
