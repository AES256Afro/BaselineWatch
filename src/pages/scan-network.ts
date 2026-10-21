import type { DatabaseSync } from "node:sqlite";
import { html, newTab, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import {

/**
 * The network check's page: the latest run's resolver, upstream, DoH answer and canary tallies by
 * category, the owner's switches and dashboard tokens, and the day-over-day changes.
 */
  categoryTallies,
  getSetting,
  latestNetScan,
  netScanEnabled,
  netSettingKeys,
  parseChanges,
  scanCanaries,
  controlName,
  type CategoryTally,
  type NetCanaryRow,
  type NetScanRow,
} from "../netscan.ts";
import { relativeTime } from "../time.ts";
import { exposureEnabled, exposureKeys, latestExposure, type ExposureFinding } from "../exposure.ts";
import { page } from "./layout.ts";

/**
 * The network check's page (M12.3, mockup 03): the canaries as the last run resolved them through
 * the LAN resolver, one tile per category, the full table with each answer verbatim, a finding row
 * per category that is not sinkholed, and the owner's switches (the scan is opt-in, the dashboard
 * tokens are shown as set or not set and never rendered). Everything on it is server-rendered from
 * the stored scan; the page carries no script.
 */
export interface ScanNetworkOptions {
  db: DatabaseSync;
  owner: boolean;
  open: boolean;
  look: LookState;
  now: Date;
  notice?: string | undefined;
}

const tone = (tally: CategoryTally): "ok" | "warn" | "bad" | "na" => {
  if (tally.resolved === 0 && tally.sinkholed > 0) return "ok";
  if (tally.resolved > 0) return tally.category === "adfection" ? "bad" : "warn";
  return "na";
};

/** What a canary's outcome means for the network, in the table's last column. */
function meaning(row: NetCanaryRow): Html {
  if (row.outcome === "sinkholed") return html`<span class="ok-t">blocked network-wide</span>`;
  if (row.outcome === "timeout") return html`<span class="mute-t">no answer</span>`;
  const cls = row.category === "adfection" ? "bad-t" : "warn-t";
  return html`<span class="${cls}">resolved: not blocked by this resolver</span>`;
}

/** The fix per category: which list closes it, and where the Register tracks that list. */
const fixes: Record<string, { text: string; list: string }> = {
  ads: { text: "Add an ad blocklist (EasyList's domains ride most Pi-hole default lists) on the resolver, then run again.", list: "canary-ads" },
  trackers: { text: "Add a tracker blocklist (EasyPrivacy-derived lists are on most Pi-hole defaults) on the resolver, then run again.", list: "canary-trackers" },
  malware: { text: "Add a malware blocklist that carries URLhaus (the common DNS blocklists do) as an adlist on the resolver, then run again.", list: "canary-malware" },
  phishing: { text: "Add a phishing blocklist that carries OpenPhish's hosts as an adlist on the resolver, then run again.", list: "canary-phishing" },
  adfection: { text: "Add the adfection list as an adlist on the resolver (the Register holds its current version and will show when it changes), then run again.", list: "adfection-dns" },
};

function findingRow(tally: CategoryTally, index: number): Html {
  const fix = fixes[tally.category];
  const bad = tally.category === "adfection";
  return html`<article class="check" data-finding="${tally.category}">
  <span class="n">${String(index + 1).padStart(2, "0")}</span>
  <div>
    <div class="t">${tally.resolved} ${tally.label.toLowerCase()} canar${tally.resolved === 1 ? "y" : "ies"} resolved</div>
    <p class="d">The resolver answered a real address, so these names are not blocked for the devices using it. ${fix?.text ?? ""}</p>
    ${bad ? html`<p class="matters"><b>Why it matters.</b> These are the domains documented in the Citizen Lab and Confiant research on spyware delivered through targeted ads. Blocking them at the resolver closes that road for every device on the LAN, not one browser. <a href="/scan/why#ads">The research, linked</a></p>` : ""}
  </div>
  <div class="row"><span class="state ${bad ? "bad" : "warn"}">Finding</span>${fix ? html` <a class="chip" href="/standards/${fix.list}">The list in the Register</a>` : ""}</div>
</article>`;
}

function ownerForms(db: DatabaseSync, enabled: boolean): Html {
  const set = (key: string): string => (getSetting(db, key) ? "set" : "not set");
  return html`<div class="box" id="settings">
    <h2>Scan settings</h2>
    <p class="small">The scan sends DNS queries and one HTTPS request on this network, so it is off until you turn it on. Once on, it runs daily from the scheduler.</p>
    <form method="post" action="/scan/network/enable" class="row">
      <input type="hidden" name="on" value="${enabled ? "0" : "1"}">
      <button type="submit">${enabled ? "Turn the daily scan off" : "Turn the daily scan on"}</button>
    </form>
    ${enabled ? html`<form method="post" action="/scan/network/run" class="row"><button type="submit">Run now</button></form>` : ""}
    <h3>Resolver dashboards</h3>
    <p class="small">With a token, the scan also reads how many clients the resolver answered for in the last day. The token is stored on this instance, used only against the address you give, and never shown again.</p>
    <form method="post" action="/scan/network/settings" class="kv-form">
      <label>Pi-hole address <input name="pihole_url" placeholder="http://192.0.2.10" autocomplete="off"></label>
      <label>Pi-hole API token (${set(netSettingKeys.piholeToken)}) <input name="pihole_token" type="password" autocomplete="off"></label>
      <label>AdGuard Home address <input name="adguard_url" placeholder="http://192.0.2.10:3000" autocomplete="off"></label>
      <label>AdGuard Home user:password (${set(netSettingKeys.adguardToken)}) <input name="adguard_token" type="password" autocomplete="off"></label>
      <button type="submit">Save</button>
      <span class="small">Leaving a field empty keeps it; a single space clears it.</span>
    </form>
  </div>`;
}

const exposureWord: Record<ExposureFinding["state"], string> = { ok: "Good", warn: "Finding", bad: "Finding", na: "Not read" };

/**
 * Router and exposure (S4): the owner's own address and ports, so the owner alone sees it. The
 * findings of the last daily run, and the switches: on or off, the router's address, its vendor
 * and model for the firmware match.
 */
function exposureSection(db: DatabaseSync, owner: boolean, now: Date): Html {
  if (!owner) {
    return html`<section class="box" id="exposure"><h2>Router and exposure</h2><p class="small">What the internet sees of this network's public address and what the router gives away on the LAN, read once a day from this server. It names the owner's own address and ports, so the owner alone sees it.</p></section>`;
  }
  const on = exposureEnabled(db);
  const run = latestExposure(db);
  const value = (key: string): string => (db.prepare("SELECT value FROM app_settings WHERE key = ?").get(key) as { value: string } | undefined)?.value ?? "";
  const rows = run
    ? html`<div class="checks">${run.findings.map(
        (f, i) => html`<article class="check" id="exposure-${f.id}">
          <span class="n">${String(i + 1).padStart(2, "0")}</span>
          <div>
            <div class="t">${f.title}</div>
            <p class="d">${f.text}</p>
            ${f.quoted.length ? html`<ul class="ev">${f.quoted.map((q) => html`<li><code>${q}</code></li>`)}</ul>` : ""}
          </div>
          <span class="state ${f.state}">${exposureWord[f.state]}</span>
        </article>`,
      )}</div>
      <p class="small">Run ${relativeTime(run.at, now)}. The public address is Cloudflare's trace's word, the ports and CVEs Shodan's InternetDB's as it last scanned the address — not a scan from here. A new open port, a new KEV match for the firmware or a changed address is sent through the notifier the day it is seen.</p>`
    : html`<p class="small">${on ? "On; the first run happens on the scheduler's next pass, or press Run now." : "Off. Turning it on asks Cloudflare for this network's public address, Shodan's InternetDB what it sees of that address, and the router (if named) for its front page, once a day."}</p>`;
  return html`<section class="box" id="exposure">
    <h2>Router and exposure</h2>
    ${rows}
    <form method="post" action="/scan/exposure/settings" class="kv-form">
      <input type="hidden" name="on" value="${on ? "1" : "0"}">
      <label>Router address <input name="router_url" value="${value(exposureKeys.routerUrl)}" placeholder="http://192.168.1.1" autocomplete="off"></label>
      <label>Router vendor <input name="vendor" value="${value(exposureKeys.vendor)}" placeholder="netgear, tp-link, ubiquiti…" autocomplete="off"></label>
      <label>Model (optional) <input name="model" value="${value(exposureKeys.model)}" placeholder="RAX50" autocomplete="off"></label>
      <button type="submit">Save</button>
    </form>
    <form method="post" action="/scan/exposure/settings" class="row">
      <input type="hidden" name="on" value="${on ? "0" : "1"}">
      <input type="hidden" name="keep" value="1">
      <button type="submit">${on ? "Turn the daily exposure check off" : "Turn the daily exposure check on"}</button>
    </form>
    ${on ? html`<form method="post" action="/scan/exposure/run" class="row"><button type="submit">Run now</button></form>` : ""}
    <p class="small">The vendor is matched against the CVE table's vendor names (the CPE spelling: <code>netgear</code>, <code>tp-link</code>, <code>ubiquiti</code>, <code>asus</code>); a model narrows it to CVEs that name it. Nothing is sent to the router beyond a request for its front page.</p>
  </section>`;
}

function asideBoxes(db: DatabaseSync, scan: NetScanRow | null, owner: boolean, enabled: boolean): Html {
  const clients =
    scan?.clients_seen !== null && scan?.clients_seen !== undefined
      ? html`<dl class="kv"><dt>Clients seen</dt><dd>${scan.clients_seen} in the last day, per the ${scan.clients_source === "pihole" ? "Pi-hole" : "AdGuard Home"} API</dd></dl>
        <p class="small">Devices missing from the resolver's log either use another resolver (a VPN, DNS-over-HTTPS in the browser, a hard-coded public one) or were off. The browser check catches those one device at a time.</p>`
      : html`<p class="small">With a Pi-hole or AdGuard Home token saved${owner ? html` below` : html` by the owner`}, this box counts the clients the resolver answered for, so devices that bypass it stand out.${scan?.error ? html` Last read: ${scan.error}.` : ""}</p>`;
  return html`<div class="box">
      <h2>Who uses this resolver</h2>
      ${clients}
    </div>
    <div class="box">
      <h2>The canary lists</h2>
      <ul class="sources">
        <li>Ads and trackers: twelve names each, derived from <a href="https://easylist.to/" ${newTab}>EasyList and EasyPrivacy</a>, refreshed with the lists in the <a href="/standards/canary-ads">Register</a>.</li>
        <li>Malware and phishing: registrable names derived from <a href="https://urlhaus.abuse.ch/" ${newTab}>URLhaus</a> and OpenPhish the same way.</li>
        <li>Ad-delivered spyware: twelve of the adfection list's domains (reviewed indicators from the published Candiru research), <a href="/standards/adfection-dns">tracked in the Register</a>.</li>
        <li>Control: <code>${controlName}</code>, a name that always resolves and names the upstream.</li>
      </ul>
      <p class="small">Canaries are resolved by this server only; no device of yours contacts them, and nothing is ever fetched from one.</p>
    </div>
    ${scan ? html`<div class="box">
      <h2>Also tested from here</h2>
      <dl class="kv">
        <dt>Resolver</dt><dd>${scan.resolver ?? "none found"}${scan.resolver_source ? html` (${scan.resolver_source})` : ""}</dd>
        <dt>Upstream seen</dt><dd>${scan.upstream ?? "no answer from the control name"}</dd>
        <dt>DoH from this LAN</dt><dd>${scan.doh === "reachable" ? html`<span class="warn-t">reachable: a browser can bypass this resolver</span>` : scan.doh === "blocked" ? html`<span class="ok-t">blocked or unreachable</span>` : "not tested"}</dd>
      </dl>
    </div>` : ""}
    ${owner ? ownerForms(db, enabled) : ""}`;
}

export function renderScanNetwork({ db, owner, open, look, now, notice }: ScanNetworkOptions): string {
  const scan = latestNetScan(db);
  const enabled = netScanEnabled(db);
  const rows = scan ? scanCanaries(db, scan.id) : [];
  const tallies = categoryTallies(rows);
  const findings = tallies.filter((t) => t.resolved > 0);
  const changes = parseChanges(scan?.changes_json ?? null);

  const tiles = html`<div class="stats net-tiles">${tallies.map(
    (t) => html`<div><small>${t.label}</small><b class="${tone(t)}-t">${t.sinkholed} / ${t.total}</b><span class="small">sinkholed${t.resolved > 0 ? html` · ${t.resolved} resolved` : ""}${t.timeout > 0 ? html` · ${t.timeout} no answer` : ""}</span></div>`,
  )}</div>`;

  const table = html`<div class="table-wrap"><table><caption class="visually-hidden">Canary names and their answers</caption>
    <thead><tr><th scope="col">Canary</th><th scope="col">List</th><th scope="col">Answer</th><th scope="col">Means</th></tr></thead>
    <tbody>${rows.map((r) => html`<tr><td class="mono">${r.name}</td><td>${r.category}</td><td class="mono">${r.answer ?? ""}</td><td>${meaning(r)}</td></tr>`)}</tbody>
  </table></div>
  <p class="small">All ${rows.length} canaries of the last run, with the list each came from and the answer verbatim. The upstream the resolver forwards to is read from the control name, so a resolver forwarding to an unfiltered upstream is caught.</p>`;

  const changesBox =
    changes && (changes.resolverChanged || changes.newlyResolving.length > 0 || changes.newlySinkholed.length > 0)
      ? html`<div class="box">
      <h2>Since the previous run</h2>
      <ul class="small plan">
        ${changes.resolverChanged ? html`<li>The resolver changed: <code>${changes.resolverChanged.from ?? "none"}</code> → <code>${changes.resolverChanged.to ?? "none"}</code>.</li>` : ""}
        ${changes.newlyResolving.map((c) => html`<li><code>${c.name}</code> (${c.category}) now resolves; it was sinkholed.</li>`)}
        ${changes.newlySinkholed.map((c) => html`<li><code>${c.name}</code> (${c.category}) is now sinkholed.</li>`)}
      </ul>
      <p class="small">A canary newly resolving or a changed resolver is sent through the notifier the moment the run sees it; the rest rides the digest.</p>
    </div>`
      : "";

  const body = scan
    ? html`${scan.error && rows.length === 0 ? html`<div class="notice">The last run found nothing to resolve: ${scan.error}.</div>` : ""}
  ${tiles}
  <div class="cols">
    <div class="main">
      ${findings.length > 0 ? html`<div class="checks">${findings.map((t, i) => findingRow(t, i))}</div>` : html`<p class="small">Every canary the resolver was asked for came back sinkholed: the lists behind these categories are enforced for every device that uses it.</p>`}
      ${rows.length > 0 ? table : ""}
    </div>
    <aside class="side">
      ${changesBox}
      ${asideBoxes(db, scan, owner, enabled)}
    </aside>
  </div>
  ${exposureSection(db, owner, now)}`
    : html`<div class="cols">
    <div class="main">
      <article class="check off">
        <span class="n">—</span>
        <div>
          <div class="t">No run yet</div>
          <p class="d">${enabled ? "The scan is on; the first run happens on the scheduler's next pass (or press Run now)." : owner ? "The scan is off. It sends DNS queries on this network, so it waits for you to turn it on." : "The scan is off; the owner has not turned the LAN checks on."}</p>
        </div>
        <span class="state na">Not run</span>
      </article>
    </div>
    <aside class="side">${asideBoxes(db, null, owner, enabled)}</aside>
  </div>
  ${exposureSection(db, owner, now)}`;

  const content = html`<section class="scan-network">
  <p class="crumbs"><a href="/">Home</a><span>›</span><a href="/scan">Scan</a><span>›</span><b>This network</b></p>
  <h1>This network <span class="arrow">canaries through the LAN resolver</span></h1>
  ${notice ? html`<div class="notice">${notice}</div>` : ""}
  <p class="lede">
    ${scan?.resolver
      ? html`The resolver this network hands out is <code>${scan.resolver}</code> (read from ${scan.resolver_source ?? "this server"}). The canary names below were resolved through it from this server${scan.finished_at ? html` ${relativeTime(scan.finished_at, now)}` : ""}; a name that returns <code>0.0.0.0</code>, a loopback address or NXDOMAIN is blocked for every device using that resolver.`
      : html`This server sits on the LAN, so it can test the row no web page can: it resolves canary names through the resolver the router hands out, and a sinkholed answer covers every device that uses it.`}
    A phone on a VPN, or a browser with its own DNS-over-HTTPS, does not use that resolver; the <a href="/scan">browser check</a> catches those.
  </p>
  ${body}
</section>`;
  return page({ title: "This network", active: "scan-network", content, owner, open, look });
}
