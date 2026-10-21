import { html, newTab, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { scriptsFor, sumsFile, type ScanScript, type ScriptPlatform } from "../scan-scripts.ts";
import { page } from "./layout.ts";
import { androidSections } from "./scan-guide/android.ts";
import { iosSections } from "./scan-guide/ios.ts";
import { linuxSections } from "./scan-guide/linux.ts";
import { macosSections } from "./scan-guide/macos.ts";
import { guidePlatforms, isGuidePlatform, src, type GuidePlatform, type GuidePlatformInfo, type Section, type Source, type Step } from "./scan-guide/shared.ts";
import { windowsSections } from "./scan-guide/windows.ts";


export function guideSections(platform: GuidePlatform): Section[] {
  switch (platform) {
    case "windows":
      return windowsSections();
    case "macos":
      return macosSections();
    case "linux":
      return linuxSections();
    case "ios":
      return iosSections();
    case "android":
      return androidSections();
  }
}

function sourceLinks(sources: Source[]): Html {
  return html`${sources.map((s, i) => html`${i > 0 ? " · " : ""}<a href="${s.href}" ${newTab}>${s.text}</a>`)}`;
}

function renderStep(step: Step): Html {
  return html`<li>
  <p><b>${step.title}.</b> ${step.do}</p>
  ${step.clean ? html`<p class="small"><b>Clean:</b> ${step.clean}</p>` : ""}
  ${step.finding ? html`<p class="small"><b>A finding:</b> ${step.finding}</p>` : ""}
  ${step.why ? html`<p class="small"><b>Why:</b> ${step.why}${step.more ? html` <a href="/scan/why#${step.more}">More</a>` : ""}</p>` : step.more ? html`<p class="small"><a href="/scan/why#${step.more}">Why this matters</a></p>` : ""}
  <p class="small src">Source${step.sources.length > 1 ? "s" : ""}: ${sourceLinks(step.sources)}</p>
</li>`;
}

function renderSection(section: Section, n: number): Html {
  return html`<section class="box guide-section" id="${section.id}">
  <h2>${n}. ${section.title}</h2>
  ${section.intro ? html`<p class="small">${section.intro}</p>` : ""}
  <ol class="steps">${section.steps.map(renderStep)}</ol>
</section>`;
}

/** The download box: each script for the platform, its sum, and how to verify and run it. */
export { guidePlatforms, isGuidePlatform, type GuidePlatform, type GuidePlatformInfo };
function scriptBox(scripts: readonly ScanScript[], platform: ScriptPlatform | null, heading = "The script"): Html {
  if (!platform) {
    return html`<div class="box">
  <h2>No script for phones</h2>
  <p class="small">A phone does not let a script read the system. For a filtering check, the browser check at <a href="/scan">/scan</a> is the phone's own view; for the past, Amnesty's Mobile Verification Toolkit reads a backup, and its documentation is the guide to follow.</p>
  <ul class="sources"><li><a href="${src.mvtIos.href}" ${newTab}>${src.mvtIos.text}</a></li><li><a href="${src.mvtAndroid.href}" ${newTab}>${src.mvtAndroid.text}</a></li></ul>
</div>`;
  }
  const mine = scriptsFor(scripts, platform);
  return html`<div class="box">
  <h2>${heading}</h2>
  <p class="small">Every check above, read from the device by one plain script and printed in the window. It uploads nothing, changes nothing and needs no administrator rights; its header says what it contacts. Check the sum, then read the file before you run it.</p>
  ${mine.map(
    (s) => html`<dl class="kv script">
  <dt>File</dt><dd><a href="/scan/scripts/${s.file}" download>${s.file}</a> (${s.bytes} bytes) · <a href="/scan/scripts/${s.file}">view</a></dd>
  <dt>SHA-256</dt><dd><code class="sum">${s.sha256}</code></dd>
  <dt>Verify</dt><dd><code>${s.verify}</code></dd>
  <dt>Run</dt><dd><code>${s.run}</code> (${s.shell})</dd>
</dl>`,
  )}
  <p class="small"><a href="/scan/scripts/${sumsFile}">${sumsFile}</a> carries the same sums for <code>sha256sum -c</code> and <code>shasum -a 256 -c</code>.</p>
</div>`;
}

function platformPicker(current: GuidePlatform | null): Html {
  return html`${guidePlatforms.map((p, i) => html`${i > 0 ? " · " : ""}${p.id === current ? html`<b>${p.label}</b>` : html`<a href="/scan/guide/${p.id}">${p.label}</a>`}`)}`;
}

export interface GuidePageOptions {
  owner: boolean;
  open: boolean;
  look: LookState;
  scripts: readonly ScanScript[];
}

export function renderScanGuide(platform: GuidePlatform, { owner, open, look, scripts }: GuidePageOptions): string {
  const info = guidePlatforms.find((p) => p.id === platform) ?? guidePlatforms[0]!;
  const sections = guideSections(platform);
  const others = guidePlatforms.filter((p) => p.id !== platform);
  const content = html`<section class="scan-guide">
  <p class="crumbs"><a href="/">Home</a><span>›</span><a href="/scan">Scan</a><span>›</span><a href="/scan/guide">Do it by hand</a><span>›</span><b>${info.label}</b></p>
  <h1>Do it by hand <span class="arrow">${info.label}</span></h1>
  <p class="lede">Pick a platform: ${platformPicker(platform)}. Each section is one thing the Scan area checks: how to do it yourself on ${info.device}, what a clean result looks like, what a finding means, and the vendor page each step follows. The router and the network are the same from every platform, so those sections are too.</p>
  <div class="cols">
    <div class="main">
      ${sections.map((s, i) => renderSection(s, i + 1))}
    </div>
    <aside class="side">
      <div class="box">
        <h2>On this page</h2>
        <ol class="small plan">${sections.map((s) => html`<li><a href="#${s.id}">${s.title}</a></li>`)}</ol>
      </div>
      ${scriptBox(scripts, info.script)}
      <div class="box">
        <h2>Prove it in the browser</h2>
        <p class="small">The <a href="/scan">browser check</a> sees this browser only: whether a blocker hides ad slots and stops ad requests, and which filtering resolver this browser uses. Run it after each DNS or blocker step. <a href="/scan/why">Why these checks</a> carries the argument for each, with its sources.</p>
      </div>
      <div class="box">
        <h2>Other platforms</h2>
        <dl class="kv">${others.map((p) => html`<dt><a href="/scan/guide/${p.id}">${p.label}</a></dt><dd>${otherPlatformNote(p.id)}</dd>`)}</dl>
      </div>
      <div class="box">
        <h2>Limits</h2>
        <p class="small">DNS filtering cannot remove ads from Instagram, Facebook, TikTok or YouTube: those come from the same servers as the content. A browser test sees one browser; a script sees one device. None of this says whether anything already happened.</p>
      </div>
    </aside>
  </div>
</section>`;
  return page({ title: `Do it by hand: ${info.label}`, active: "scan-guide", content, owner, open, look });
}

function otherPlatformNote(platform: GuidePlatform): Html {
  switch (platform) {
    case "windows":
      return html`Settings, Network &amp; internet, the adapter's DNS server assignment with DNS over HTTPS on; prove with <code>Get-DnsClientServerAddress</code> and <code>Get-NetFirewallProfile</code>.`;
    case "macos":
      return html`The resolver's profile under System Settings, General, Device Management; the firewall under Network; prove with <code>scutil --dns</code> and <code>socketfilterfw</code>.`;
    case "linux":
      return html`<code>resolvectl status</code> and resolved.conf; <code>ufw status</code>, <code>firewall-cmd</code> or <code>nft list ruleset</code>; <code>ss -ltnup</code>.`;
    case "ios":
      return html`The resolver's profile under Settings, General, VPN &amp; Device Management; Lockdown Mode under Privacy &amp; Security.`;
    case "android":
      return html`Settings, Network &amp; internet, Private DNS, the provider's hostname; the security patch level under About phone.`;
  }
}

/** The index at /scan/guide: the platforms, the scripts, and what the guides cover. */
export function renderScanGuideIndex({ owner, open, look, scripts }: GuidePageOptions): string {
  const content = html`<section class="scan-guide">
  <p class="crumbs"><a href="/">Home</a><span>›</span><a href="/scan">Scan</a><span>›</span><b>Do it by hand</b></p>
  <h1>Do it by hand <span class="arrow">every check, on every platform</span></h1>
  <p class="lede">The browser check sees one browser. These guides do the rest by hand, one platform at a time: the resolver every app uses, the blocker in the browser, the device's own firewall and what listens, the router, what the internet sees of your address and what walks past the filter, the advertising identifier, and the past. Each step names the vendor page it follows. The scripts below do the same checks on a computer in one go.</p>
  <div class="cols">
    <div class="main">
      <div class="checks">
        ${guidePlatforms.map(
          (p, i) => html`<article class="check">
  <span class="n">${String(i + 1).padStart(2, "0")}</span>
  <div>
    <div class="t"><a href="/scan/guide/${p.id}">${p.label}</a></div>
    <p class="d">${otherPlatformNote(p.id)}</p>
  </div>
  <span class="state na">${p.script ? "guide and script" : "guide"}</span>
</article>`,
        )}
      </div>
      <div class="box guide-section" id="what">
        <h2>What every guide covers</h2>
        <ol class="plan">
          <li><b>Filter DNS for every app</b>: which resolver, how to set it, how to prove it with one lookup of an ad domain, and the hosts file.</li>
          <li><b>A content blocker in the browser</b>, and what the browser's own DNS does.</li>
          <li><b>The device's firewall and what listens</b>: profiles, the inbound default, sharing and remote access, SMB leaving the device.</li>
          <li><b>The router</b>: the printed password, the resolver it hands out, UPnP and its mappings, remote management, firmware against this site's CVE table and KEV, Wi-Fi encryption.</li>
          <li><b>The network</b>: what Shodan's index says about your address, whether plain DNS and DNS over HTTPS bypass the filter, and whether IPv6 reaches the device.</li>
          <li><b>Lockdown Mode and the advertising identifier</b>, and <b>the past</b>: logging, and the Mobile Verification Toolkit for phones.</li>
        </ol>
        <p class="small"><a href="/scan/why">Why these checks</a> carries the argument for each, with its sources.</p>
      </div>
    </div>
    <aside class="side">
      ${scriptBox(scripts, "windows", "The Windows script")}
      ${scriptBox(scripts, "macos", "The macOS and Linux script")}
      <div class="box">
        <h2>Before you run anything</h2>
        <ul class="small plan">
          <li>Check the SHA-256 against the one shown here.</li>
          <li>Read the file. Every check is a few lines; nothing is obfuscated and nothing is downloaded by the script.</li>
          <li>A clean result means no finding where the script could look. It is not a clean bill of health.</li>
          <li>With a concrete reason to think you were targeted, use a helpline, not a script: <a href="${src.accessNow.href}" ${newTab}>${src.accessNow.text}</a>.</li>
        </ul>
      </div>
    </aside>
  </div>
</section>`;
  return page({ title: "Do it by hand", active: "scan-guide", content, owner, open, look });
}
