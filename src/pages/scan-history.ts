import type { DatabaseSync } from "node:sqlite";
import { html, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { exposureHistory, listNetScans } from "../scanhistory.ts";
import { relativeTime } from "../time.ts";
import { page } from "./layout.ts";

/**
 * The scans over time (S6): every network run with its tallies and what changed since the one
 * before, and for the owner the last two exposure runs side by side. Server-rendered from the
 * stored runs; no script.
 */

export function renderScanHistory(options: { db: DatabaseSync; owner: boolean; open: boolean; now: Date; look: LookState }): string {
  const { db, owner, open, now, look } = options;
  const scans = listNetScans(db, 60);
  const exposure = owner ? exposureHistory(db) : { last: null, previous: null };
  const changeWords = (s: (typeof scans)[number]): Html => {
    const c = s.changes;
    if (!c) return html`<span class="small">first run</span>`;
    const parts: Html[] = [];
    if (c.resolverChanged) parts.push(html`resolver <code>${c.resolverChanged.from ?? "none"}</code> → <code>${c.resolverChanged.to ?? "none"}</code>`);
    if (c.newlyResolving.length) parts.push(html`<b>${c.newlyResolving.length} newly resolving</b> (${c.newlyResolving.slice(0, 3).map((n) => n.name).join(", ")}${c.newlyResolving.length > 3 ? ", …" : ""})`);
    if (c.newlySinkholed.length) parts.push(html`${c.newlySinkholed.length} newly sinkholed`);
    return parts.length ? html`${parts.map((p, i) => html`${i ? "; " : ""}${p}`)}` : html`<span class="small">no change</span>`;
  };
  const table = scans.length
    ? html`<div class="table-wrap"><table class="vulns history"><caption class="visually-hidden">Network check runs</caption>
        <thead><tr><th scope="col">Run</th><th scope="col">Resolver</th><th scope="col" class="n">Sinkholed</th><th scope="col" class="n">Resolved</th><th scope="col">Since the run before</th><th scope="col" class="n">Clients</th></tr></thead>
        <tbody>${scans.map(
          (s) => html`<tr class="${s.resolved > 0 ? "hit" : ""}">
            <td class="id" title="${s.started_at}">${s.started_at.slice(0, 10)} <span class="small">${relativeTime(s.started_at, now)}</span>${owner && s.error ? html`<div class="small">${s.error}</div>` : ""}</td>
            <td class="who">${owner ? html`<code>${s.resolver ?? "—"}</code>${s.upstream ? html` <span class="small">via ${s.upstream}</span>` : ""}` : s.resolver ? "the LAN's" : "—"}${s.doh ? html` <span class="small">· DoH ${s.doh}</span>` : ""}</td>
            <td class="n">${s.sinkholed}<span class="small">/${s.total}</span></td>
            <td class="n">${s.resolved ? html`<b>${s.resolved}</b>` : "0"}${s.timeout ? html` <span class="small">+${s.timeout} silent</span>` : ""}</td>
            <td class="desc">${changeWords(s)}</td>
            <td class="n">${s.clients_seen ?? "—"}</td>
          </tr>`,
        )}</tbody>
      </table></div>`
    : html`<p class="small">No network run yet. The <a href="/scan/network">network check</a> is off until the owner turns it on; once on, it runs daily and every run lands here.</p>`;
  const run = (r: NonNullable<typeof exposure.last>, label: string): Html => html`<div class="box">
    <h2>${label} <span class="count">${relativeTime(r.at, now)}</span></h2>
    <dl class="kv">
      <dt>Public address</dt><dd><code>${r.publicIp ?? "unknown"}</code></dd>
      <dt>Open ports</dt><dd>${r.internet ? (r.internet.ports.length ? r.internet.ports.join(", ") : "none on record") : "not read"}</dd>
      <dt>Known flaws</dt><dd>${r.internet?.vulns.length ? r.internet.vulns.slice(0, 8).join(", ") : "none"}</dd>
      <dt>Router</dt><dd>${r.router ? (r.router.redirectsToHttps ? "admin page over HTTPS" : r.router.plainStatus !== null && r.router.plainStatus < 400 ? "admin page over plain HTTP" : r.router.plainStatus === null && r.router.tlsStatus === null ? "did not answer" : "answered without a page") : "not named"}</dd>
      <dt>Firmware</dt><dd>${r.firmware ? (r.firmware.kev.length ? html`<b>${r.firmware.kev.length} on the KEV</b>` : `${r.firmware.cves.length} CVE(s) named, none on the KEV`) : "vendor not named"}</dd>
    </dl>
  </div>`;
  const content = html`<section class="scan-network">
  <p class="crumbs"><a href="/">Home</a><span>›</span><a href="/scan">Scan</a><span>›</span><b>History</b></p>
  <h1>Scan history <span class="arrow">every run, and what changed between them</span></h1>
  <p class="lede">The network check's daily runs, newest first: the resolver each used, how many canaries it sinkholed, and what moved since the run before — the facts behind the notifications. ${owner ? "Your exposure runs, the last two, sit below." : "The owner's exposure runs are theirs alone to see."}</p>
  <section class="box wide"><h2>Network check <span class="count">${scans.length} run(s)</span></h2>${table}</section>
  ${owner
    ? html`<div class="cols"><section class="main">${exposure.last ? run(exposure.last, "Exposure, last run") : html`<div class="box"><h2>Exposure</h2><p class="small">No exposure run yet; turn it on under <a href="/scan/network#exposure">the network page</a>.</p></div>`}</section><aside class="side">${exposure.previous ? run(exposure.previous, "The run before") : ""}</aside></div>`
    : ""}
</section>`;
  return page({ title: "Scan history", active: "scan-history", content, owner, open, look, canonical: "/scan/history", description: "Every network check run, newest first, with what changed between them." });
}
