import { html, newTab, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { indicatorTally, type TraceIndicators } from "../traces.ts";
import { page } from "./layout.ts";

/**
 * Traces (S8): has this computer met the spyware's servers? The browser's half of Zero Breach's
 * local scanner — the person picks a browser profile, its cache, the hosts file, a DNS dump, a
 * registry export or the Downloads folder, and the page's script (public/traces.js) reads them in
 * the tab against the indicator list the Register tracks. The page renders whole without the
 * script: where each browser keeps its data, the commands that dump what the system holds, and
 * the rules the reading keeps. Nothing is uploaded; no form on it posts a file.
 */

export interface ScanTracesOptions {
  owner: boolean;
  open: boolean;
  look: LookState;
  list: TraceIndicators;
}

interface Place {
  browser: string;
  profile: string;
  cache?: string;
}

/** Where each browser keeps its profile, and its cache when that lives elsewhere, per system. */
const places: { os: string; id: string; tip: string; rows: Place[] }[] = [
  {
    os: "Windows",
    id: "windows",
    tip: "Type the path with its %…% part into the picker's address bar. Chromium browsers lock History and Cookies while they run, so close the browser first, or read its data from a different browser.",
    rows: [
      { browser: "Chrome", profile: "%LOCALAPPDATA%\\Google\\Chrome\\User Data" },
      { browser: "Edge", profile: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data" },
      { browser: "Brave", profile: "%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data" },
      { browser: "Vivaldi", profile: "%LOCALAPPDATA%\\Vivaldi\\User Data" },
      { browser: "Firefox", profile: "%APPDATA%\\Mozilla\\Firefox\\Profiles", cache: "%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles" },
    ],
  },
  {
    os: "macOS",
    id: "macos",
    tip: "In the picker, ⌘⇧G opens a path and ⌘⇧. shows hidden folders. Safari's History.db sits behind macOS's privacy protection, which a web page's picker cannot pass unless the browser has Full Disk Access; if it cannot be read the page says so.",
    rows: [
      { browser: "Chrome", profile: "~/Library/Application Support/Google/Chrome", cache: "~/Library/Caches/Google/Chrome" },
      { browser: "Edge", profile: "~/Library/Application Support/Microsoft Edge", cache: "~/Library/Caches/Microsoft Edge" },
      { browser: "Brave", profile: "~/Library/Application Support/BraveSoftware/Brave-Browser", cache: "~/Library/Caches/BraveSoftware/Brave-Browser" },
      { browser: "Vivaldi", profile: "~/Library/Application Support/Vivaldi", cache: "~/Library/Caches/Vivaldi" },
      { browser: "Firefox", profile: "~/Library/Application Support/Firefox/Profiles", cache: "~/Library/Caches/Firefox/Profiles" },
      { browser: "Safari", profile: "~/Library/Safari", cache: "~/Library/Caches/com.apple.Safari" },
    ],
  },
  {
    os: "Linux",
    id: "linux",
    tip: "In a GTK picker, Ctrl+L types a path and Ctrl+H shows hidden folders. A snap or Flatpak browser keeps its data under ~/snap/<name> or ~/.var/app/<id> instead.",
    rows: [
      { browser: "Chrome", profile: "~/.config/google-chrome", cache: "~/.cache/google-chrome" },
      { browser: "Chromium", profile: "~/.config/chromium", cache: "~/.cache/chromium" },
      { browser: "Edge", profile: "~/.config/microsoft-edge", cache: "~/.cache/microsoft-edge" },
      { browser: "Brave", profile: "~/.config/BraveSoftware/Brave-Browser", cache: "~/.cache/BraveSoftware/Brave-Browser" },
      { browser: "Firefox", profile: "~/.mozilla/firefox", cache: "~/.cache/mozilla/firefox" },
    ],
  },
];

interface SystemStep {
  what: string;
  why: string;
  run?: string;
  pick?: string;
}

/** What the system holds beyond the browser, and the one command that puts each in a form the page reads. */
const system: { os: string; id: string; steps: SystemStep[] }[] = [
  {
    os: "Windows",
    id: "sys-windows",
    steps: [
      { what: "The DNS cache", why: "Every name this boot has looked up, from any program. Reading it resolves nothing. Paste the output.", run: "ipconfig /displaydns" },
      { what: "The DNS log", why: "The only record of lookups before this boot, and off by default, so usually empty. Write it to a file and pick the file.", run: "wevtutil qe Microsoft-Windows-DNS-Client/Operational /c:50000 /rd:true /f:text > %TEMP%\\dns-log.txt" },
      { what: "Per-user COM registrations", why: "This chain's documented persistence is a COM hijack under HKCU. Export the key and pick the file; a registration naming an indicator is the strongest finding a text read can make.", run: "reg export HKCU\\Software\\Classes\\CLSID %TEMP%\\clsid.reg /y" },
      { what: "The hosts file", why: "A name pointed at a real address is a finding; pointed at 0.0.0.0 it is a block, which is protective.", pick: "C:\\Windows\\System32\\drivers\\etc\\hosts" },
      { what: "The abused driver's path", why: "If this file exists, pick it: its fingerprint says whether it is the build the actor brings or a legitimate driver of the same name.", pick: "C:\\Windows\\System32\\drivers\\HW.sys" },
      { what: "Turn the DNS log on for next time", why: "It cannot be turned on backwards. In an administrator prompt this keeps 64 MB of lookups, months rather than hours; the same line with /e:false turns it off. It protects nothing and changes nothing else.", run: "wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true /ms:67108864" },
    ],
  },
  {
    os: "macOS",
    id: "sys-macos",
    steps: [
      { what: "The hosts file", why: "As on Windows: a real address is a finding, a sink is a block.", pick: "/etc/hosts" },
      { what: "The DNS cache", why: "macOS keeps no cache a person can dump without administrator rights and the system log; leave it as a gap, which the reading reports." },
    ],
  },
  {
    os: "Linux",
    id: "sys-linux",
    steps: [
      { what: "The hosts file", why: "As on Windows: a real address is a finding, a sink is a block.", pick: "/etc/hosts" },
      { what: "The resolver's cache", why: "systemd-resolved 250 and later can list what it holds. Paste the output.", run: "sudo resolvectl show-cache" },
    ],
  },
];

function placesFold(group: (typeof places)[number]): Html {
  return html`<details class="fold" id="where-${group.id}">
    <summary><b>${group.os}</b><span class="fold-meta">${group.rows.length} browsers</span></summary>
    <p class="small">${group.tip}</p>
    <dl class="kv">${group.rows.map((r) => html`<dt>${r.browser}</dt><dd><code>${r.profile}</code>${r.cache ? html`<br><span class="small">cache:</span> <code>${r.cache}</code>` : ""}</dd>`)}</dl>
  </details>`;
}

function systemFold(group: (typeof system)[number]): Html {
  return html`<details class="fold" id="${group.id}">
    <summary><b>${group.os}</b><span class="fold-meta">${group.steps.length} step${group.steps.length === 1 ? "" : "s"}</span></summary>
    <dl class="kv">${group.steps.map((s) => html`<dt>${s.what}</dt><dd>${s.why}${s.run ? html`<br><code>${s.run}</code>` : ""}${s.pick ? html`<br><span class="small">pick:</span> <code>${s.pick}</code>` : ""}</dd>`)}</dl>
  </details>`;
}

export function renderScanTraces({ owner, open, look, list }: ScanTracesOptions): string {
  const tally = indicatorTally(list);
  const total = list.indicators.length;
  const listLine = total
    ? html`${total} indicators — ${tally.domains} domains, ${tally.ips} addresses, ${tally.hashes} file fingerprints${list.version ? html` — version ${list.version}` : ""}`
    : html`Not fetched yet: the Register reads it daily, and the check waits for it.`;
  const content = html`<section class="scan scan-traces" id="traces">
  <p class="crumbs"><a href="/">Home</a><span>›</span><a href="/scan">Scan</a><span>›</span><b>Traces</b></p>
  <h1>Has this computer met the spyware's servers? <span class="arrow">its saved data, read in this tab</span></h1>
  <p class="lede">
    An ad is a subresource inside a frame, so it never reaches a browser's history, but its cache, cookies, site storage and connection records keep the hosts it touched for a while. This page reads the files you pick — a browser profile, its cache, the hosts file, a DNS dump, a registry export, the Downloads folder — against the published AdFection and Candiru indicators, in this tab. Nothing is uploaded, and no indicator is ever looked up or contacted.
  </p>
  <div class="verdict" id="traces-verdict" hidden>
    <p class="tally"><b id="traces-verdict-count">0</b><span>indicators found</span></p>
    <h2 id="traces-verdict-title"></h2>
    <p id="traces-verdict-text"></p>
  </div>
  <div class="box notice-help" id="traces-help" hidden>
    <h2>Where to get help</h2>
    <p class="small">Keep the files and this page as they are. These helplines work with people who may have been targeted, free of charge: <a href="https://www.accessnow.org/help/" ${newTab}>Access Now Digital Security Helpline</a> · <a href="https://securitylab.amnesty.org/" ${newTab}>Amnesty International Security Lab</a> · <a href="https://citizenlab.ca/" ${newTab}>The Citizen Lab</a>.</p>
  </div>
  <div class="cols">
    <div class="main">
      <div class="box" id="traces-pick">
        <h2>What to read</h2>
        <label class="drop" id="traces-drop" for="traces-folder">
          <b>Drop a folder or files here</b>
          <span class="small">or choose below. A folder picker in Chrome asks to “upload” the files: that is its wording for letting this page read them; nothing leaves the tab.</span>
        </label>
        <div class="pickers">
          <label>A folder (a browser profile, its cache, Downloads) <input type="file" id="traces-folder" webkitdirectory multiple></label>
          <label>Files (hosts, a .reg export, a DNS log) <input type="file" id="traces-files" multiple></label>
        </div>
        <label for="traces-paste">Or paste text — a DNS-cache dump, a hosts file, anything</label>
        <textarea id="traces-paste" rows="5" spellcheck="false" placeholder="ipconfig /displaydns output, or resolvectl show-cache"></textarea>
        <div class="scan-run">
          <button type="button" class="primary" id="traces-run" disabled>Read them</button>
          <span class="small" id="traces-status" role="status" aria-live="polite">Waiting for the script.</span>
          <noscript><span class="small">The reading is a script in this tab; with scripts off it cannot run. The steps below still say what to look at by hand.</span></noscript>
        </div>
        <p class="small" id="traces-picked">Nothing picked yet.</p>
      </div>
      <div class="checks" id="traces-findings" hidden></div>
      <div class="box" id="traces-coverage" hidden></div>
      <h2 class="rows-head" id="where">Where each browser keeps it <span class="count">pick the whole folder; every profile in it is read</span></h2>
      ${places.map(placesFold)}
      <h2 class="rows-head" id="system">What the system holds <span class="count">one command each, nothing changed</span></h2>
      ${system.map(systemFold)}
    </div>
    <aside class="side">
      <div class="box">
        <h2>The list it reads against</h2>
        <p class="small">${listLine}.</p>
        <p class="small">Zero Breach's curated indicators from The Citizen Lab's <i>Exposing AdFection</i> and the reports it cites, each with its tier — ad delivery, validator, command-and-control, a spyware sample — <a href="/standards/adfection-indicators">tracked in the Register</a>, so a change to the list is a diff there. The data is CC0; <a href="https://github.com/interplains/zero-breach" ${newTab}>Zero Breach</a> is not affiliated with the researchers it cites, and neither is this site.</p>
      </div>
      <div class="box">
        <h2>What a finding means</h2>
        <ul class="small plan">
          <li><b>Where</b> it was found sets the grade: a fingerprint on disk or a registration to run is the strongest, then a connection record, a DNS record, a hosts mapping, and last a mention in saved content.</li>
          <li><b>The tier</b> sets the weight: an ad network's name is not infection; a command-and-control server's is serious.</li>
          <li>A file that could not be read is <b>unknown</b>, never clean, and so is every place not picked.</li>
        </ul>
      </div>
      <div class="box">
        <h2>Rules the reading keeps</h2>
        <ul class="small plan">
          <li>Text comparison only. No indicator is resolved, fetched or linked; resolving a command server's name tells its operators a possible target exists. Names on this page are shown with their dots bracketed.</li>
          <li>Nothing leaves the tab: the page has one request, for the list, and the policy it is served under allows no other.</li>
          <li>Whole names only: <code>notcontrolium.net</code> is not <code>controlium.net</code>, and a parent is not counted again for its child.</li>
        </ul>
      </div>
      <div class="box">
        <h2>What it cannot say</h2>
        <ul class="small plan">
          <li>A clean reading means no published indicator in what was read — not that the device is clean. Spyware of this grade is built to defeat exactly this kind of check.</li>
          <li>Caches and logs are short-lived; the 2024–25 window cannot usually be read back.</li>
          <li>A page cannot read the registry or the DNS log itself, or open a database a running browser holds locked; the commands above put each in a file it can.</li>
          <li>Phones: Amnesty's <a href="https://docs.mvt.re/" ${newTab}>Mobile Verification Toolkit</a> reads a backup against the same indicators, which Zero Breach publishes as STIX.</li>
        </ul>
      </div>
      <div class="box">
        <h2>The fuller check</h2>
        <p class="small">Zero Breach's own <a href="https://github.com/interplains/zero-breach/tree/main/scan" ${newTab}>adint-scan</a> runs on the machine with Python alone: it copies locked databases, walks the registry and the DNS log directly, reads each history row's host rather than its bytes, and can check files against two published Candiru detection rules. This page is its browser-sized half.</p>
      </div>
    </aside>
  </div>
</section>`;
  return page({
    title: "Traces",
    active: "scan-traces",
    content,
    owner,
    open,
    look,
    canonical: "/scan/traces",
    description: "Read a browser profile, its cache, the hosts file and a DNS dump against the published AdFection and Candiru spyware indicators, in your own tab: nothing uploaded, no indicator ever contacted.",
    script: "/assets/traces.js",
  });
}
