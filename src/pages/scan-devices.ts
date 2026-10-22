import { html, newTab, type Html } from "../html.ts";
import type { DeviceReading } from "../devices.ts";
import type { DeviceFinding, InventoryReport } from "../inventory.ts";
import { relativeTime } from "../time.ts";
import type { LookState } from "../look.ts";
import { scriptsFor, sumsFile, type ScanScript } from "../scan-scripts.ts";
import { page } from "./layout.ts";

/**
 * Is this device affected? (S7.) The page the owner pastes the inventory script's report into,
 * and the reading of it: Windows builds against the Security Update Guide, browsers against the
 * vendors' releases, the OS against Apple and endoflife.date, Linux packages against OSV. The
 * report is read and answered on this page and kept nowhere; the owner alone can post one.
 */

export interface ScanDevicesOptions {
  owner: boolean;
  open: boolean;
  look: LookState;
  scripts: readonly ScanScript[];
  report?: InventoryReport | null;
  findings?: DeviceFinding[];
  problem?: string | null;
  /** The newest reading of each device the owner has read, newest first; the owner alone sees them. */
  devices?: DeviceReading[];
  /** One device's readings when the page is opened on it. */
  history?: { device: string; readings: DeviceReading[] } | null;
  /** The name this reading was recorded under, and what moved since the device's last reading. */
  recorded?: { device: string; appeared: string[]; cleared: string[] } | null;
  now: Date;
}

const worstWord: Record<DeviceReading["worst"], string> = { ok: "Up to date", warn: "Behind", bad: "Exposed", na: "Not read" };

function devicesBox(devices: DeviceReading[], now: Date): Html {
  if (devices.length === 0) return html`<div class="box"><h2>Your devices</h2><p class="small">Each reading is kept by the device's name — its verdicts and CVE ids, never the report — so the next reading says what moved.</p></div>`;
  return html`<div class="box" id="devices">
    <h2>Your devices <span class="count">${devices.length}</span></h2>
    <ul class="refs">${devices.map((d) => html`<li><a href="/scan/devices?device=${encodeURIComponent(d.device)}"><b>${d.device}</b></a> <span class="state ${d.worst}">${worstWord[d.worst]}</span> <span class="small">${d.os_label ?? d.os} · read ${relativeTime(d.read_at, now)}</span></li>`)}</ul>
  </div>`;
}

function historyBox(history: { device: string; readings: DeviceReading[] }, owner: boolean, now: Date): Html {
  return html`<section class="box wide" id="history">
    <h2>${history.device} <span class="count">${history.readings.length} reading(s)</span></h2>
    ${history.readings.length
      ? html`<ul class="refs">${history.readings.map((r) => html`<li><span class="state ${r.worst}">${worstWord[r.worst]}</span> ${r.os_label ?? r.os} <span class="small">· ${r.read_at.slice(0, 16).replace("T", " ")} UTC · ${relativeTime(r.read_at, now)}</span>${r.findings.filter((f) => f.state === "bad" || f.state === "warn").map((f) => html`<div class="small">${f.title}: ${f.text}</div>`)}</li>`)}</ul>`
      : html`<p class="small">No reading under that name.</p>`}
    ${owner && history.readings.length ? html`<form method="post" action="/scan/devices/forget" class="inline"><input type="hidden" name="device" value="${history.device}"><button type="submit" class="link">Forget this device</button></form>` : ""}
  </section>`;
}

const stateWord: Record<DeviceFinding["state"], string> = { ok: "Up to date", warn: "Behind", bad: "Exposed", na: "Not read" };

function findingRow(n: number, f: DeviceFinding): Html {
  return html`<article class="check" id="device-${f.id}">
  <span class="n">${String(n).padStart(2, "0")}</span>
  <div>
    <div class="t">${f.title}</div>
    <p class="d">${f.text}</p>
    ${f.quoted.length ? html`<ul class="ev">${f.quoted.map((q) => html`<li><code>${q}</code></li>`)}</ul>` : ""}
    ${f.links?.length ? html`<p class="small">${f.links.map((l, i) => html`${i ? " · " : ""}<a href="${l.href}">${l.label}</a>`)}</p>` : ""}
    ${f.refs.length
      ? html`<ul class="refs device-refs">${f.refs.slice(0, 60).map((r) => html`<li>${/^https?:\/\//.test(r.href) ? html`<a href="${r.href}" ${newTab}>${r.id}</a>` : html`<a href="${r.href}">${r.id}</a>`}${r.note ? html` <span class="small">${r.note}</span>` : ""}</li>`)}${f.refs.length > 60 ? html`<li class="small">and ${f.refs.length - 60} more</li>` : ""}</ul>`
      : ""}
  </div>
  <span class="state ${f.state}">${stateWord[f.state]}</span>
</article>`;
}

function scriptBox(scripts: readonly ScanScript[]): Html {
  const mine = [...scriptsFor(scripts, "windows"), ...scriptsFor(scripts, "macos")].filter((s) => s.file.startsWith("bw-inventory"));
  return html`<div class="box">
    <h2>The inventory script</h2>
    <p class="small">Read it before you run it: it prints version numbers and package names, sends nothing anywhere, and changes nothing. Verify the sum against <a href="/scan/scripts/${sumsFile}">${sumsFile}</a>.</p>
    ${mine.map(
      (s) => html`<dl class="kv">
        <dt>${s.label.split(" — ")[0]}</dt><dd><a href="/scan/scripts/${s.file}" download>${s.file}</a> (${s.bytes} bytes) · <a href="/scan/scripts/${s.file}">view</a></dd>
        <dt>Run</dt><dd><code>${s.run}</code></dd>
        <dt>SHA-256</dt><dd><code class="sum">${s.sha256}</code></dd>
      </dl>`,
    )}
  </div>`;
}

export function renderScanDevices(options: ScanDevicesOptions): string {
  const { owner, open, look, scripts, report, findings, problem, now } = options;
  const devices = options.devices ?? [];
  const recorded = options.recorded ?? null;
  const results = findings?.length
    ? html`<section class="box wide" id="reading">
        <h2>What applies to ${recorded ? recorded.device : "this device"} <span class="count">${report?.os.name ?? report?.os.family ?? ""} ${report?.os.version ?? ""}${report?.os.build ? ` · build ${report.os.build}` : ""}</span></h2>
        ${recorded && (recorded.appeared.length || recorded.cleared.length)
          ? html`<p class="small"><b>Since the last reading:</b> ${recorded.appeared.length ? html`${recorded.appeared.length} newly applying (${recorded.appeared.slice(0, 6).join(", ")}${recorded.appeared.length > 6 ? ", …" : ""})` : ""}${recorded.appeared.length && recorded.cleared.length ? "; " : ""}${recorded.cleared.length ? html`${recorded.cleared.length} cleared (${recorded.cleared.slice(0, 6).join(", ")}${recorded.cleared.length > 6 ? ", …" : ""})` : ""}.</p>`
          : recorded
            ? html`<p class="small">Recorded under <b>${recorded.device}</b>; the next reading under that name will say what moved.</p>`
            : ""}
        <div class="checks">${findings.map((f, i) => findingRow(i + 1, f))}</div>
        <p class="small">Read once from the report you pasted and kept nowhere. Windows builds are judged against the Security Update Guide's fixed builds, browsers and macOS against the vendors' announced releases, Linux packages by OSV's own version comparison for the distribution; a row marked <i>Not read</i> says what was missing.</p>
      </section>`
    : "";
  const form = owner
    ? html`<form method="post" action="/scan/devices" class="stack" id="paste">
        <label for="device">Device name</label>
        <input type="text" id="device" name="device" maxlength="60" placeholder="laptop" value="${recorded?.device ?? ""}" required>
        <label for="report">Paste the script's whole output</label>
        <textarea id="report" name="report" rows="8" required spellcheck="false" placeholder="BW-REPORT-BEGIN&#10;{&quot;bw&quot;:1, …}&#10;BW-REPORT-END"></textarea>
        <button type="submit" class="primary">Read it</button>
        <p class="small">The reading's verdicts and CVE ids are kept under the device's name, never the report itself; a name used before continues that device's history.</p>
      </form>`
    : html`<p class="small"><a href="/login">Sign in</a> to paste a report; a device's software list is the owner's to show.</p>`;
  const content = html`<section class="scan">
  <p class="crumbs"><a href="/">Home</a><span>›</span><a href="/scan">Scan</a><span>›</span><b>A device</b></p>
  <h1>Is this device affected? <span class="arrow">what it runs, against what the sources know</span></h1>
  <p class="lede">
    No web page can see what a computer runs, and this site installs nothing on it. The inventory script reads the version numbers — the Windows build, the macOS or distribution release, the browsers, the packages — and prints one report; paste it here and this page says which CVEs apply to those versions: the Windows updates not yet on the build and which of their CVEs Microsoft says are exploited, the browser and OS releases you are behind, and for a Linux distribution the packages OSV holds open advisories for at the installed version.
  </p>
  ${problem ? html`<div class="notice">${problem}</div>` : ""}
  ${results}
  ${options.history ? historyBox(options.history, owner, now) : ""}
  <div class="cols">
    <div class="main">
      ${form}
    </div>
    <aside class="side">
      ${owner ? devicesBox(devices, now) : ""}
      ${scriptBox(scripts)}
      <div class="box">
        <h2>What it can and cannot say</h2>
        <ul class="small plan">
          <li>Windows: exact. The guide names the build each KB produces; a lower build lacks that KB's CVEs.</li>
          <li>Browsers and macOS: by release. Behind the newest announced release means its fixes are missing; the vendor's note lists them.</li>
          <li>Linux: OSV compares the installed version with each advisory's range by the distribution's own rules. A backported fix that OSV knows about is not flagged; one it does not know about is.</li>
          <li>Not read: applications other than browsers, Windows apps, Homebrew, and distributions OSV does not carry.</li>
        </ul>
        <p class="small"><a href="/guide#devices">The guide</a> says what each verdict rests on.</p>
      </div>
    </aside>
  </div>
</section>`;
  return page({ title: "Is this device affected?", active: "scan-devices", content, owner, open, look, canonical: "/scan/devices", description: "Run the inventory script, paste its report, and see which CVEs apply to the versions this device runs: Windows builds against Microsoft's guide, browsers and macOS against the vendors, Linux packages against OSV." });
}
