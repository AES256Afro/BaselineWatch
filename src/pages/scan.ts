import { html, newTab, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
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
}

interface CheckRow {
  id: string;
  n: string;
  title: string;
  chip: string;
  what: Html;
  why: Html;
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
      chip: probeOrigin ? "6 test images, 4 controls" : "3 test images, 2 controls",
      what: html`Images on paths that match EasyList's request rules (<code>/ad_images/</code>, <code>/adsbanner-</code>, <code>/ad_skyscraper.gif</code>) on this server${probeOrigin ? html` and on one cross-site host` : ""}, each between two control images with identical bytes. No cookies, no referrer, never displayed. The test is a load difference, not a verdict: a timeout is unknown, a failure this page's own policy caused is reported as such, and a failed test image is tried once more before it counts.`,
      why: html`Hiding a slot is not the same as stopping the request; the request is what carries the payload. A blocker that fails this test but passes the first is hiding ads it still fetched.`,
    },
    {
      id: "dns",
      n: "03",
      title: "Filtering DNS for this browser",
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
    <p class="d">${check.what}</p>
    <ul class="ev" hidden></ul>
    <p class="matters"><b>Why it matters.</b> ${check.why} <a href="/scan/why#${check.id}">More</a></p>
  </div>
  <span class="state na">Not run</span>
</article>`;
}

export function renderScan({ owner, open, look, probeOrigin }: ScanPageOptions): string {
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
  <div class="cols">
    <div class="main">
      <div class="checks">
        ${rows}
        <article class="check off" data-check="apps">
          <span class="n">04</span>
          <div>
            <div class="t">Other apps on this device</div>
            <p class="d">Not measured by a browser. The device scripts planned for this area will read the system resolver, the hosts file and the firewall state and say what the apps actually use. Until then, the device's own DNS setting is the thing to look at.</p>
          </div>
          <span class="state na">Not a page's to test</span>
        </article>
        <article class="check off" data-check="network">
          <span class="n">05</span>
          <div>
            <div class="t">Every device on your network</div>
            <p class="d">No web page can test this. This server can, because it sits on the LAN: the network check planned next resolves canary names through the resolver the router hands out. Until then, look at the router's DNS setting, or at a Pi-hole or AdGuard Home dashboard, which counts the queries it answered for every device.</p>
          </div>
          <span class="state na">Not a page's to test</span>
        </article>
      </div>
      <div class="scan-run">
        <button type="button" class="primary" id="scan-run" disabled>Run the check</button>
        <span class="small" id="scan-status" role="status" aria-live="polite">Waiting for the script.</span>
        <noscript><span class="small">The check is a script in this tab; with scripts off it cannot run. Nothing else on this site needs one.</span></noscript>
      </div>
      <p class="small">After changing a blocker's settings, reload first. In-app browsers (Instagram, Facebook, TikTok) have no blockers and cannot install a DNS profile; open this page in Safari, Chrome or Firefox instead.</p>
    </div>
    <aside class="side">
      <div class="box">
        <h2>Why scan for ads at all</h2>
        <p class="small">Advertising networks deliver code to a device the way any other content arrives, and that path has been used to deliver spyware: Citizen Lab documented an ad-tech pipeline that placed Candiru's spyware through targeted ads. Blocking ad delivery closes one road in; it is not proof of safety, and ads served from the same domain as the content are not blocked by any of this. <a href="/scan/why">The whole argument, with the sources</a>.</p>
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
  const content = html`<section class="scan-why">
  <p class="crumbs"><a href="/">Home</a><span>›</span><a href="/scan">Scan</a><span>›</span><b>Why these checks</b></p>
  <h1>Why these checks <span class="arrow">and what each can prove</span></h1>
  <p class="lede">
    Ads are a delivery path. The same auction that places a shoe advertisement can place code, and it
    has. Filtering ad delivery closes that road; it is one road, and the checks on the Scan page say
    which roads are closed on this browser, nothing more.
  </p>
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
      <p class="small">Each section rests on a primary document and links to it. Where a sentence is this product's reading rather than the source's words, it says "the check" or "this product". Nothing here is generated by a model. The router, firewall and device sections arrive with their checks.</p>
    </section>
  </div>
</section>`;
  return page({ title: "Why these checks", active: "scan", content, ...options });
}
