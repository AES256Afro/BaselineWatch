import { html, newTab, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import type { NetworkSummary } from "../netscan.ts";
import type { Exposure, Seen } from "../seen.ts";
import { page } from "./layout.ts";

/**
 * The Scan area (M12.1): the browser check. Three rows a script in this tab can fill (ad hiding,
 * ad requests, filtering DNS), two rows no page can test, a Run button, and the limits and privacy
 * of the test beside them. The page renders complete with every row at "not run"; the one script
 * this site serves, /assets/scan.js, draws the results in and uploads nothing. docs/mockups/scan
 * 01 and 02 are the drawings this follows.
 */
export interface ScanPageOptions {
  owner: boolean;
  open: boolean;
  look: LookState;
  /** A second origin serving the same probe images, for the cross-site set; null for same-site only. */
  probeOrigin: string | null;
  /** The network check's latest run (M12.3), for row 05; null when none has run. */
  network: NetworkSummary | null;
  /** The server's side of the check: what this request told it (S2). */
  seen: Seen;
  /** The InternetDB answer for the address the visitor asked about, when they asked; an error text when the lookup failed. */
  exposure?: Exposure | null;
  exposureError?: string | null;
}

/** What this page learned about you: the request's facts on one honest panel, each with what it means. */
function seenPanel(seen: Seen, exposure: Exposure | null | undefined, exposureError: string | null | undefined): Html {
  const where = seen.kind === "public" ? "a public address: the one your network shows the internet" : seen.kind === "private" ? "a private address: this server is on your LAN with you, so the internet-facing address is not visible here" : seen.kind === "loopback" ? "this machine itself" : "unknown";
  const exposureBox = exposure
    ? html`<div class="exposure">
        <h3 class="small">What Shodan last saw of ${exposure.ip}</h3>
        ${exposure.nothing
          ? html`<p class="small">Nothing: no open port and no known flaw on record for this address. That is the good answer.</p>`
          : html`<dl class="kv">
              <dt>Open ports</dt><dd>${exposure.ports.length ? exposure.ports.join(", ") : "none on record"}</dd>
              <dt>Hostnames</dt><dd>${exposure.hostnames.length ? exposure.hostnames.slice(0, 6).join(", ") : "none"}</dd>
              <dt>Software (CPE)</dt><dd>${exposure.cpes.length ? exposure.cpes.slice(0, 6).join(", ") : "none"}</dd>
              <dt>CVEs</dt><dd>${exposure.vulns.length ? exposure.vulns.slice(0, 12).map((v, i) => html`${i ? ", " : ""}<a href="/vulnerabilities/${v}">${v}</a>`) : "none"}${exposure.vulns.length > 12 ? html` and ${exposure.vulns.length - 12} more` : ""}</dd>
              ${exposure.tags.length ? html`<dt>Tags</dt><dd>${exposure.tags.join(", ")}</dd>` : ""}
            </dl>`}
        <p class="small">From Shodan's InternetDB, as it last scanned the address — not a scan from here. An open port here is a service your router or ISP exposes; see <a href="/scan/why#exposure">what the internet sees</a>.</p>
      </div>`
    : exposureError
      ? html`<p class="small">The lookup did not answer: ${exposureError}.</p>`
      : "";
  return html`<section class="box seen" id="seen">
    <h2>What this page learned about you</h2>
    <p class="small">The server's side of the check: what this request carried, drawn here and kept nowhere.</p>
    <dl class="kv">
      <dt>Address</dt><dd><code>${seen.ip ?? "?"}</code> — ${where}${seen.family ? html` (${seen.family})` : ""}${seen.torExit ? html` · <b>a Tor exit</b>: this request came through Tor` : ""}</dd>
      <dt>Transport</dt><dd>${seen.protocol.toUpperCase()}, HTTP/${seen.httpVersion}${seen.tlsProtocol ? html`, ${seen.tlsProtocol}` : seen.protocol === "https" ? html`, TLS ended at the edge in front of this server` : ""}</dd>
      <dt>Privacy signals</dt><dd>${seen.gpc ? "Global Privacy Control sent" : "no Global Privacy Control"}${seen.dnt ? " · Do Not Track sent" : " · no Do Not Track"}</dd>
      <dt>Referrer</dt><dd>${seen.referer ? html`<code>${seen.referer}</code>` : "none sent: this browser told the page nothing about where you came from"}</dd>
    </dl>
    <details class="how"><summary>Every header the browser volunteered (${seen.headers.length})</summary>
      <dl class="kv">${seen.headers.map((h) => html`<dt>${h.name}</dt><dd><code>${h.value}</code></dd>`)}</dl>
    </details>
    ${seen.kind === "public"
      ? html`<form method="post" action="/scan/exposure" class="inline"><input type="hidden" name="ip" value="${seen.ip ?? ""}"><button type="submit">What does the internet see of ${seen.ip}?</button> <span class="small">one lookup of Shodan's InternetDB, on your say-so</span></form>`
      : html`<p class="small">The internet-facing lookup needs a public address; from the LAN this page sees only your private one.</p>`}
    ${exposureBox}
  </section>`;
}

interface CheckRow {
  id: string;
  n: string;
  title: string;
  chip: string;
  what: Html;
  why: Html;
  /** The fix panel the script unfolds when this row comes back open; absent for rows with nothing to fix. */
  fix?: Html;
}

/**
 * The fix for the requests row: one line per browser family, every line server-rendered and
 * hidden; the script unfolds the panel when the row reads "No difference" and shows the line for
 * the browser it detected ("other" when it detected none). The depth lives in the guide; the
 * data-guide link is retargeted to the detected platform's page.
 */
function requestsFix(): Html {
  return html`<div class="fix" id="fix-requests" hidden>
    <h3>Close this gap</h3>
    <ul class="fixways">
      <li data-for="firefox">In Firefox: install <a href="https://addons.mozilla.org/firefox/addon/ublock-origin/" ${newTab}>uBlock Origin</a> from Mozilla's add-ons site and leave the default lists on.</li>
      <li data-for="chrome">In Chrome: install <a href="https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh" ${newTab}>uBlock Origin Lite</a> from the Chrome Web Store, the build written for Chrome's newer extension interface, and leave the default lists on.</li>
      <li data-for="edge">In Edge: install <a href="https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh" ${newTab}>uBlock Origin Lite</a> (Edge installs from the Chrome Web Store) and leave the default lists on.</li>
      <li data-for="safari">In Safari: content blockers come from the App Store (AdGuard, 1Blocker, Wipr use Apple's content-blocker interface); after installing one, turn it on under Safari › Settings › Extensions.</li>
      <li data-for="brave">This is Brave: its shields block requests without hiding by class names, so check Shields is up for this site (the lion icon) rather than installing anything.</li>
      <li data-for="inapp">This is an app's in-app view, which carries no blocker at all. Open this page in Safari, Chrome or Firefox and close the gap there.</li>
      <li data-for="other">Install uBlock Origin, or uBlock Origin Lite where the browser requires it; the guide names the right build per browser.</li>
    </ul>
    <p class="proof">About two minutes. Then reload this page and re-run: this row should turn to <b>Load difference</b>, and the hiding row should climb.</p>
    <p class="small">The full step, with what a clean result looks like and the vendor pages it follows: <a data-guide data-anchor="blocker" href="/scan/guide">a content blocker in the browser</a>.</p>
  </div>`;
}

/** The fix for the DNS row: one line per platform, unfolded the same way. */
function dnsFix(): Html {
  return html`<div class="fix" id="fix-dns" hidden>
    <h3>Close this gap</h3>
    <ul class="fixways">
      <li data-for="macos">On this Mac: install <a href="https://adguard-dns.io/en/public-dns.html" ${newTab}>AdGuard DNS's configuration profile</a> or make a free <a href="https://nextdns.io" ${newTab}>NextDNS</a> profile, then System Settings › Privacy &amp; Security › Profiles › Install. NextDNS names its profile to the re-run, so the fix proves itself.</li>
      <li data-for="ios">On this iPhone or iPad: install the resolver's configuration profile (<a href="https://adguard-dns.io/en/public-dns.html" ${newTab}>AdGuard DNS</a> or <a href="https://nextdns.io" ${newTab}>NextDNS</a>), then Settings › General › VPN &amp; Device Management › Install.</li>
      <li data-for="windows">On this PC: Settings › Network &amp; internet › your adapter › DNS server assignment › Edit, and enter a filtering resolver's addresses (<a href="https://adguard-dns.io/en/public-dns.html" ${newTab}>AdGuard DNS</a> or <a href="https://nextdns.io" ${newTab}>NextDNS</a>), with DNS over HTTPS on where offered.</li>
      <li data-for="android">On this phone: Settings › Network &amp; internet › Private DNS, and enter the filtering resolver's hostname (AdGuard DNS's <code>dns.adguard-dns.com</code>, or your NextDNS profile's name). It covers every app, including Chrome.</li>
      <li data-for="linux">On this computer: point systemd-resolved or NetworkManager at a filtering resolver; the guide has the exact lines and the command that proves each.</li>
      <li data-for="other">Set this device's DNS to a filtering resolver (AdGuard DNS, NextDNS); the guide has the steps, one platform at a time.</li>
    </ul>
    <p class="proof">Re-run after: this row should name the resolver that answered, for every app on this device, not just this browser.</p>
    <p class="small">Already behind a Pi-hole, or on a VPN with its own filter? This row cannot see those from a browser, so "none seen" may be wrong in your favour; the network check is their eye. Full steps: <a data-guide data-anchor="dns" href="/scan/guide">filter DNS for every app</a>.</p>
  </div>`;
}

function checkRows(probeOrigin: string | null): CheckRow[] {
  return [
    {
      id: "hiding",
      n: "01",
      title: "Ad hiding",
      chip: "20 baits, 2 controls",
      what: html`Twenty invisible elements named the way ad slots are named (<code>adsbox</code>, <code>ad-banner</code>, <code>adsbygoogle</code>, <code>#ad</code>, …) and two with neutral names. A filter list's generic cosmetic rules hide the baits and leave the controls alone; the script reads them back after two frames.`,
      why: html`Cosmetic filtering is the cheapest sign a content blocker is on in this browser. Some blockers hide nothing here and still block requests, so a zero is "not seen", never "unprotected".`,
    },
    {
      id: "requests",
      n: "02",
      title: "Ad requests",
      fix: requestsFix(),
      chip: probeOrigin ? "6 test images, 4 controls" : "3 test images, 2 controls",
      what: html`Images on paths that match EasyList's request rules (<code>/ad_images/</code>, <code>/adsbanner-</code>, <code>/ad_skyscraper.gif</code>) on this server${probeOrigin ? html` and on one cross-site host` : ""}, each between two control images with identical bytes. No cookies, no referrer, never displayed. The test is a load difference, not a verdict: a timeout is unknown, a failure this page's own policy caused is reported as such, and a failed test image is tried once more before it counts.`,
      why: html`Hiding a slot is not the same as stopping the request; the request is what carries the payload. A blocker that fails this test but passes the first is hiding ads it still fetched.`,
    },
    {
      id: "dns",
      n: "03",
      title: "Filtering DNS for this browser",
      fix: dnsFix(),
      chip: "AdGuard, NextDNS self-checks",
      what: html`A fresh random name under <code>-dnscheck.adguard-dns.com</code> resolves only through AdGuard's resolvers and names the server group; <code>test.nextdns.io</code> answers only through NextDNS and names the profile. Cloudflare, Quad9 and a Pi-hole have no such endpoint; the network check, which runs from this server, will cover them.`,
      why: html`A browser blocker protects one browser; a filtering resolver covers every app that uses the system DNS. This row sees the resolver this browser uses, which a VPN, iCloud Private Relay or the browser's own DNS-over-HTTPS can make different from the device's.`,
    },
  ];
}

function row(check: CheckRow): Html {
  return html`<article class="check" data-check="${check.id}" id="check-${check.id}">
  <span class="n">${check.n}</span>
  <div>
    <div class="t">${check.title} <span class="chip">${check.chip}</span></div>
    <details class="how"><summary>How this row is tested</summary><p class="d">${check.what}</p></details>
    <ul class="ev" hidden></ul>
    <p class="matters"><b>Why it matters.</b> ${check.why} <a href="/scan/why#${check.id}">More</a></p>
    ${check.fix ?? ""}
  </div>
  <span class="state na">Not run</span>
</article>`;
}

export function renderScan({ owner, open, look, probeOrigin, network, seen, exposure, exposureError }: ScanPageOptions): string {
  const rows = checkRows(probeOrigin).map(row);
  const content = html`<section class="scan" id="scan" data-probe-origin="${probeOrigin ?? ""}">
  <p class="crumbs"><a href="/">Home</a><span>›</span><b>Scan</b></p>
  <h1>Scan <span class="arrow">this browser: ads and filtering DNS</span></h1>
  <p class="lede">
    Three short checks that run in this tab and see this browser only: whether a content blocker
    hides ad slots, whether it stops ad requests, and whether this browser's DNS is a filtering
    resolver. Signals, not a certificate: a positive row names what was observed; no row can say
    whether ad code was stopped elsewhere or whether this device was ever reached. Results are drawn
    into this page and never uploaded.
  </p>
  <div class="verdict" id="scan-verdict" hidden>
    <p class="tally"><b id="scan-verdict-count">0</b><span>of 3 protections seen</span></p>
    <h2 id="scan-verdict-title"></h2>
    <p id="scan-verdict-text"></p>
  </div>
  <div class="cols">
    <div class="main">
      <div class="checks">
        ${rows}
        <article class="check off" data-check="apps">
          <span class="n">04</span>
          <div>
            <div class="t">Other apps on this device</div>
            <p class="d">Not measured by a browser. The <a href="/scan/guide">manual guide</a> says how to read the system resolver, the hosts file and the firewall by hand on <a href="/scan/guide/windows">Windows</a>, <a href="/scan/guide/macos">macOS</a>, <a href="/scan/guide/linux">Linux</a>, <a href="/scan/guide/ios">iPhone and iPad</a> and <a href="/scan/guide/android">Android</a>, and one plain script per computer reads them in one go, uploading nothing.</p>
          </div>
          <span class="state na">Not a page's to test</span>
        </article>
        <article class="check${network ? "" : " off"}" data-check="network">
          <span class="n">05</span>
          <div>
            <div class="t">Every device on your network</div>
            ${network
              ? html`<p class="d">No web page can test this; this server can, because it sits on the LAN. The <a href="/scan/network">network check</a> resolved ${network.total} canary names through the resolver this network hands out${network.scan.resolver ? html` (<code>${network.scan.resolver}</code>)` : ""}: ${network.sinkholed} sinkholed, ${network.resolved} resolved. A sinkholed canary is blocked for every device using that resolver.</p>`
              : html`<p class="d">No web page can test this. This server can, because it sits on the LAN: the <a href="/scan/network">network check</a> resolves canary names through the resolver the router hands out, daily, once the owner turns it on. The guide's <a href="/scan/guide/windows#router">router</a> and <a href="/scan/guide/windows#network">network</a> sections say what to set on the router and how to prove each setting from any device.</p>`}
          </div>
          ${network
            ? html`<span class="state ${network.resolved === 0 && network.sinkholed > 0 ? "ok" : "warn"}">${network.sinkholed} / ${network.total} sinkholed</span>`
            : html`<span class="state na">Not run from this server</span>`}
        </article>
      </div>
      <div class="scan-run">
        <button type="button" class="primary" id="scan-run" disabled>Run the check</button>
        <span class="small" id="scan-status" role="status" aria-live="polite">Waiting for the script.</span>
        <span class="small open-count" id="scan-open" hidden></span>
        <noscript><span class="small">The check is a script in this tab; with scripts off it cannot run. Nothing else on this site needs one.</span></noscript>
      </div>
      ${seenPanel(seen, exposure, exposureError)}
      <p class="small">After changing a blocker's settings, reload first. In-app browsers (Instagram, Facebook, TikTok) have no blockers and cannot install a DNS profile; open this page in Safari, Chrome or Firefox instead.</p>
    </div>
    <aside class="side">
      <div class="box">
        <h2>Why scan for ads at all</h2>
        <p class="small">Advertising networks deliver code to a device the way any other content arrives, and that path has been used to deliver spyware: Citizen Lab documented an ad-tech pipeline that placed Candiru's spyware through targeted ads. Blocking ad delivery closes one road in; it is not proof of safety, and ads served from the same domain as the content are not blocked by any of this. <a href="/scan/why">The whole argument, with the sources</a>.</p>
      </div>
      <div class="box">
        <h2>Check a domain</h2>
        <p class="small">Your own domain's mail, DNS and web posture — SPF, DMARC, DKIM, MTA-STS, DNSSEC, CAA, HSTS, the certificate, <code>security.txt</code> — read by lookups from this server, each record quoted: <a href="/scan/domain">check a domain</a>.</p>
      </div>
      <div class="box">
        <h2>Do it by hand</h2>
        <p class="small">Everything this area checks, done yourself, one platform at a time, with the command that proves each step and the vendor page it follows: <a href="/scan/guide/windows">Windows</a> · <a href="/scan/guide/macos">macOS</a> · <a href="/scan/guide/linux">Linux</a> · <a href="/scan/guide/ios">iPhone and iPad</a> · <a href="/scan/guide/android">Android</a>. The <a href="/scan/guide">guide index</a> carries the two scripts that do the computer checks in one go, with their checksums.</p>
      </div>
      <div class="box">
        <h2>Limits of this check</h2>
        <ul class="small plan">
          <li>Signals, not a safety certificate. Element hiding and failed requests cannot prove ad code was stopped.</li>
          <li>It sees this browser only; the resolver row reports this browser's resolver, not the device's.</li>
          <li>Effective filters can be missed: a Pi-hole, a VPN's filter and most browser filters have no self-check. The network check is the better eye for those.</li>
          <li>Blocking ads reduces exposure; ads served from the content's own domain are not blocked by any of this.</li>
        </ul>
      </div>
      <div class="box">
        <h2>Privacy of the test</h2>
        <p class="small">Test images carry no cookies and no referrer and are never shown. The only outside hosts contacted are the two resolvers' self-check endpoints, each learning what any site you visit learns: your address. No advertising domain is contacted, and nothing you see here leaves this page.</p>
      </div>
      <div class="box">
        <h2>Environment</h2>
        <dl class="kv" id="scan-env">
          <dt>Browser</dt><dd data-env="browser">read when the check runs</dd>
          <dt>Platform</dt><dd data-env="platform">—</dd>
          <dt>In-app view</dt><dd data-env="inapp">—</dd>
          <dt>Brave shields</dt><dd data-env="brave">—</dd>
          <dt>VPN</dt><dd>not something a page can see</dd>
        </dl>
      </div>
      <div class="box">
        <h2>The one page with a script</h2>
        <p class="small">The browser check needs a few lines of script in this tab. Every other page on this site runs with <code>script-src 'none'</code>; this page alone carries its own policy allowing one self-hosted file, the probe images and the two self-check hosts. No inline script anywhere, ever. <a href="/assets/scan.js" ${newTab}>Read the script</a>.</p>
      </div>
    </aside>
  </div>
</section>`;
  return page({ title: "Scan", active: "scan", content, owner, open, look, script: "/assets/scan.js" });
}

/**
 * The page every "Why it matters" link lands on: one section per check, each saying why the thing
 * is worth finding, what the check can and cannot prove, and the primary document it rests on.
 * Prose written for this product; nothing generated by a model; the sources carry the attribution.
 */
export function renderScanWhy(options: { owner: boolean; open: boolean; look: LookState }): string {
  const source = (href: string, text: string, note?: string): Html => html`<li><a href="${href}" ${newTab}>${text}</a>${note ? html`, ${note}` : ""}</li>`;
  const sections: [string, string][] = [
    ["ads", "Ads as a delivery path"],
    ["hiding", "Ad hiding"],
    ["requests", "Ad requests"],
    ["dns", "Filtering DNS"],
    ["router", "The router"],
    ["upnp", "UPnP port mappings"],
    ["exposure", "What the internet sees"],
    ["bypass", "DNS bypass and interception"],
    ["device", "Reading the device itself"],
    ["harden", "Hardening, in order"],
  ];
  const content = html`<section class="scan-why">
  <p class="crumbs"><a href="/">Home</a><span>›</span><a href="/scan">Scan</a><span>›</span><b>Why these checks</b></p>
  <h1>Why these checks <span class="arrow">and what each can prove</span></h1>
  <p class="lede">
    Ads are a delivery path. The same auction that places a shoe advertisement can place code, and it
    has. Filtering ad delivery closes that road; it is one road, and the checks in this area say
    which roads are closed on this browser, this device, this network and this router, nothing more.
    The <a href="/scan">browser check</a> runs in this tab; the <a href="/scan/guide">manual guide</a>
    does the rest by hand, and its steps lead back here.
  </p>
  <p class="small">On this page: ${sections.map(([id, title], i) => html`${i > 0 ? " · " : ""}<a href="#${id}">${title}</a>`)}</p>
  <div class="guide">
    <section class="box" id="ads">
      <h2>Ads as a delivery path</h2>
      <p>An ad is content fetched from a third party at the moment the page loads, chosen for you by an auction that knows your identifier, your location and your device. That is also a description of a targeted exploit delivery system, and Citizen Lab's research shows it being used as one: an advertising-technology pipeline that delivered Candiru's spyware through targeted ads. Blocking the request means the code never arrives; hiding the slot means it arrived and was not shown. Ads served from the same domain as the content (Instagram, YouTube, TikTok) are not blocked by any of this, because the content and the ad are the same server.</p>
      <ul class="sources">
        ${source("https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/", "Citizen Lab, “How Discover-Tech turned targeted ads into a pipeline for spyware”")}
        ${source("https://citizenlab.ca/research/", "Citizen Lab research index", "the earlier Candiru reports")}
      </ul>
    </section>
    <section class="box" id="hiding">
      <h2>Ad hiding</h2>
      <p>Content blockers carry generic cosmetic rules that hide any element named like an ad slot. The check plants twenty such names and two neutral ones and reads back which were hidden. It proves a blocker with cosmetic rules is active in this browser. It does not prove requests were stopped (that is the next check), and a blocker that hides nothing here may still block everything, so a zero is "not observed", never "unprotected".</p>
      <ul class="sources">
        ${source("https://ublockorigin.com/", "uBlock Origin", "the blocker whose generic rules these names come from")}
        ${source("https://easylist.to/", "EasyList", "the filter list most blockers carry")}
      </ul>
    </section>
    <section class="box" id="requests">
      <h2>Ad requests</h2>
      <p>Request filtering is the control that matters, because the request is what carries a payload. The check loads images whose paths match three of EasyList's request rules, <code>/ad_images/*$image</code>, <code>/adsbanner-$image</code> and <code>/ad_skyscraper.gif$image</code> as the list read on 2026-10-19, between control images with identical bytes, on this server and, when the owner has named one, on one cross-site host. A load difference is evidence of request filtering; a timeout is unknown; a failure this page's own policy caused is reported as such. No advertising domain is contacted, so the test leaks nothing to an ad network.</p>
      <ul class="sources">
        ${source("https://easylist.to/easylist/easylist.txt", "EasyList, the list itself", "the three rules are in its general block section")}
      </ul>
    </section>
    <section class="box" id="dns">
      <h2>Filtering DNS</h2>
      <p>A browser blocker protects one browser. A filtering resolver answers "no such name" for ad, tracker and malware domains for every app that uses the system DNS, which is most apps on a phone and most on a computer. The browser check can confirm two resolvers by their own self-check endpoints; the network check planned for this server will confirm any resolver by resolving canaries through it. A VPN, iCloud Private Relay or a browser's own DNS-over-HTTPS replaces the system resolver and must be checked where it is set.</p>
      <ul class="sources">
        ${source("https://adguard-dns.io/en/public-dns.html", "AdGuard DNS public servers", "with its own check on the page")}
        ${source("https://test.nextdns.io", "NextDNS self-check", "answers with the profile when NextDNS is the resolver")}
        ${source("https://docs.pi-hole.net/", "Pi-hole documentation", "a network-wide resolver that has no self-check")}
      </ul>
      <p class="small">By hand: the guide's DNS section for <a href="/scan/guide/windows#dns">Windows</a>, <a href="/scan/guide/macos#dns">macOS</a>, <a href="/scan/guide/linux#dns">Linux</a>, <a href="/scan/guide/ios#dns">iPhone and iPad</a> and <a href="/scan/guide/android#dns">Android</a>.</p>
    </section>
    <section class="box" id="router">
      <h2>The router</h2>
      <p>Every device on the network trusts the router for its address, its resolver and its path out. A router with a known exploited vulnerability on its LAN-side admin page is reachable by any device that joins the network, including a guest's phone; one with remote management open on the WAN side is reachable by everyone, and that is where routers on CISA's Known Exploited Vulnerabilities list are usually exploited. The password printed on the device, and the vendor's default, are in every list an attacker tries first. The guide's router section is the same on every platform: change the password, hand out the filtering resolver by DHCP, turn UPnP and remote management off, note the firmware and look it up in this site's <a href="/vulnerabilities">Vulnerabilities</a> table, where a KEV entry is one CISA has seen exploited. The router check planned for this server will read the model and firmware the gateway announces and do that matching by the hour.</p>
      <ul class="sources">
        ${source("https://www.cisa.gov/news-events/news/home-network-security", "CISA, Home Network Security", "default passwords, remote management, UPnP, firmware, the firewall, Wi-Fi encryption")}
        ${source("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CISA, Known Exploited Vulnerabilities catalog")}
      </ul>
      <p class="small">By hand: <a href="/scan/guide/windows#router">the router section of the guide</a>.</p>
    </section>
    <section class="box" id="upnp">
      <h2>UPnP port mappings</h2>
      <p>Universal Plug and Play lets any program on the LAN ask the router to open a port from the internet to that program, without a password: the Internet Gateway Device service's AddPortMapping call is the whole mechanism. Games use it; so does anything that wants to be reachable, and so does malware that wants a way back in. A mapping to a remote-desktop, file-sharing or SSH port is a hole in the firewall that nobody approved. CERT's note on routers that accept UPnP requests on the WAN side shows the worse case, where anyone on the internet can ask. Turning UPnP off removes the mechanism; reading the table once a month catches what it opened. The scripts list the mappings with the same GetGenericPortMappingEntry call any device on the LAN may make, and never add or remove one.</p>
      <ul class="sources">
        ${source("https://openconnectivity.org/developer/specifications/upnp-resources/upnp/internet-gateway-device-igd-v-2-0/", "Open Connectivity Foundation, UPnP Internet Gateway Device v2.0", "the specification of the mapping calls")}
        ${source("https://www.kb.cert.org/vuls/id/357851", "CERT/CC, VU#357851: UPnP requests accepted over router WAN interfaces")}
        ${source("https://www.cisa.gov/news-events/news/home-network-security", "CISA, Home Network Security", "disable UPnP when not needed")}
      </ul>
      <p class="small">By hand: <a href="/scan/guide/windows#router">the router section of the guide</a>; the scripts' <code>upnp</code> row reads the table.</p>
    </section>
    <section class="box" id="exposure">
      <h2>What the internet sees</h2>
      <p>Public indexes crawl every address and record what answered. That record is what an attacker reads before touching anything, so the first question about your address is what the index says. The guide asks Shodan's free InternetDB lookup for your public address rather than scanning from here, which keeps this product from being the thing that scans you; it is a record of what the crawlers last saw, not a live scan, and a port that UPnP opened yesterday may not be in it yet. The firewall check planned for this server will ask the same lookup once a day and treat a change as news.</p>
      <ul class="sources">
        ${source("https://internetdb.shodan.io/", "Shodan, InternetDB")}
      </ul>
      <p class="small">By hand: <a href="/scan/guide/windows#network">the network section of the guide</a>.</p>
    </section>
    <section class="box" id="bypass">
      <h2>DNS bypass and interception</h2>
      <p>Network-wide filtering only covers devices that use the network's resolver. A device with a hard-coded resolver, or an app or browser using DNS over HTTPS, walks past it unless the router redirects port 53 to the filter and blocks the known public DoH endpoints. The guide's test is one lookup of an ad domain sent straight to a public resolver: a real address means the bypass is open, a sinkholed answer or a timeout means the router caught it. The opposite failure exists too: an ISP or a router that silently answers every DNS query itself, which the same lookup shows when a resolver you did not choose answers. DNS over HTTPS and DNS over TLS are the encrypted forms, worth having on the resolver you chose and worth blocking for the ones you did not.</p>
      <ul class="sources">
        ${source("https://discourse.pi-hole.net/t/how-do-i-configure-my-devices-to-use-pi-hole-as-their-dns-server/245", "Pi-hole FAQ, configuring devices to use the Pi-hole", "including the router redirect")}
        ${source("https://www.rfc-editor.org/rfc/rfc8484", "RFC 8484, DNS queries over HTTPS")}
        ${source("https://www.rfc-editor.org/rfc/rfc7858", "RFC 7858, DNS over TLS")}
      </ul>
      <p class="small">By hand: <a href="/scan/guide/windows#network">the network section of the guide</a>; the scripts' <code>bypass</code> rows run the same lookups.</p>
    </section>
    <section class="box" id="device">
      <h2>Reading the device itself</h2>
      <p>A browser test sees one browser. The device scripts read what every app on the device uses: the system resolver, the hosts file, the firewall's state, what listens, and the settings that change how a target is picked. Where an ad leaves a trace, history alone misses it: cookies, cache and local storage keep the hosts an ad frame touched, and that reading against an indicator list is the next step planned for the scripts. Windows does not record DNS lookups unless its DNS-Client log is turned on, so the past is usually unrecorded; turning it on is the one setting the scripts recommend. A clean result means no finding where the script could look; spyware of this grade is built to defeat exactly this kind of check, so a concrete reason to think you were targeted is a reason to use a helpline.</p>
      <ul class="sources">
        ${source("https://docs.mvt.re/en/latest/", "Amnesty International, Mobile Verification Toolkit")}
        ${source("https://www.accessnow.org/help/", "Access Now Digital Security Helpline")}
        ${source("https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil", "Microsoft, wevtutil", "turns the DNS-Client log on")}
      </ul>
      <p class="small">By hand: the scripts on the <a href="/scan/guide">guide index</a>, with their checksums.</p>
    </section>
    <section class="box" id="harden">
      <h2>Hardening, in order</h2>
      <ol class="plan">
        <li><b>Filter DNS</b> for every app on the device and, at the router, for every device. Reduces requests to known ad and tracking domains.</li>
        <li><b>Lockdown Mode</b> on iPhone, iPad and Mac for anyone likely to be targeted: limits what an attack can do if one gets through.</li>
        <li><b>Take away the advertising identifier</b>: changes how a target is picked in the first place.</li>
        <li><b>Look at the past</b> with the Mobile Verification Toolkit; none of the first three says whether anything already happened. Spyware of this grade is built to defeat exactly this kind of check, so a concrete reason to think you were targeted is a reason to use a helpline.</li>
      </ol>
      <ul class="sources">
        ${source("https://support.apple.com/en-us/105120", "Apple, About Lockdown Mode")}
        ${source("https://docs.mvt.re/en/latest/", "Amnesty International, Mobile Verification Toolkit")}
        ${source("https://www.accessnow.org/help/", "Access Now Digital Security Helpline")}
      </ul>
    </section>
    <section class="box">
      <h2>How this page is written</h2>
      <p class="small">Each section rests on a primary document and links to it. Where a sentence is this product's reading rather than the source's words, it says "the check" or "this product". Nothing here is generated by a model. The router, exposure and bypass checks this server will run itself arrive later; the <a href="/scan/guide">guide</a> does them by hand today.</p>
    </section>
  </div>
</section>`;
  return page({ title: "Why these checks", active: "scan", content, ...options });
}
