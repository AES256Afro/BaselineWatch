import { counted, figure, html, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { relativeTime } from "../time.ts";
import { visitWindows, type AgentKind, type Counted, type VisitReport, type VisitWindow } from "../visits.ts";
import { page } from "./layout.ts";

/**
 * Visitors (owner only): who read this site in a window, from what the server counted as it
 * answered (src/visits.ts). People first, by day and by page, where they came from and on what;
 * then every program that is not a person's browser, by the name it gave and the network it came
 * from; then the paths asked for that do not exist, and the latest visits one by one.
 */
export interface VisitorsOptions {
  report: VisitReport;
  now: Date;
  timeZone: string;
  /** Whether this instance is counting (BW_VISITS); off still shows what was counted before. */
  counting: boolean;
  owner: boolean;
  open: boolean;
  look: LookState;
}

const kindWords: Record<Exclude<AgentKind, "person">, { title: string; line: string }> = {
  assistant: { title: "AI assistants", line: "fetching a page because a person asked it to" },
  crawler: { title: "Crawlers", line: "search engines, AI crawlers, link previews, scanners and monitors" },
  reader: { title: "Feed readers", line: "polling the RSS for their readers" },
  tool: { title: "Tools and scripts", line: "libraries and command-line clients, by the name they send" },
  unknown: { title: "Unnamed", line: "no User-Agent, or a browser's name without the Accept-Language every browser sends" },
};

const regions = new Intl.DisplayNames(["en"], { type: "region" });

function countryName(code: string): string {
  if (code === "T1") return "Tor";
  if (code === "XX") return "Unknown";
  try {
    return regions.of(code) ?? code;
  } catch {
    return code;
  }
}

function shownPath(path: string): string {
  try {
    return decodeURIComponent(path);
  } catch {
    return path;
  }
}

function network(name: string | null, confirmed: boolean): Html {
  if (!name) return html`<span class="note">no name</span>`;
  return confirmed ? html`${name}` : html`${name} <span class="note" title="The address's reverse DNS names this domain, but the name does not resolve back to the address.">unconfirmed</span>`;
}

function countedTable(id: string, title: string, line: string, rows: Counted[], name: (n: string) => Html | string = (n) => n, open = false): Html {
  if (rows.length === 0) return html``;
  return html`<details class="fold" id="${id}"${open ? html` open` : ""}><summary><b>${title}</b> <span class="fold-meta">${line}</span></summary>
    <div class="table-wrap"><table class="compact"><thead><tr><th>${title}</th><th class="num">Visits</th></tr></thead><tbody>
      ${rows.map((r) => html`<tr><td>${name(r.name)}</td><td class="num">${figure(r.visits)}</td></tr>`)}
    </tbody></table></div></details>`;
}

export function renderVisitors(options: VisitorsOptions): string {
  const r = options.report;
  const t = r.totals;
  const link = (days: VisitWindow, host: string | null): string => `/visitors?days=${days}${host ? `&host=${encodeURIComponent(host)}` : ""}`;
  const when = new Intl.DateTimeFormat("en-GB", { timeZone: options.timeZone, day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  const windowWord = r.days === 1 ? "today" : `the last ${r.days} days`;
  const nothing = t.visits + t.assistants + t.crawlers + t.readers + t.tools + t.unknown + t.missing + t.api === 0;
  const automated = (Object.keys(kindWords) as (keyof typeof kindWords)[]).map((kind) => ({ kind, rows: r.automated.filter((a) => a.kind === kind) })).filter((g) => g.rows.length > 0);

  const content = html`
    <div class="wire-top"><h1>Visitors <small>${r.from === r.to ? r.to : html`${r.from} to ${r.to}`} · ${r.host ?? "every address"}</small></h1></div>
    ${options.counting ? "" : html`<p class="small"><b>Counting is off</b> on this instance (<code>BW_VISITS=false</code>); what is below was counted before it was turned off.</p>`}
    <p class="small">Counted on the server as each answer was sent: no script, no cookie, no address kept, and your own visits left out. A visit is one browser on one day. Programs that are not a person's browser are counted by request. <a href="/guide#visits">What is kept</a>.</p>
    <div class="filters"><span class="lab">Window</span>${visitWindows.map((d) => html`<a class="${d === r.days ? "on" : ""}" href="${link(d, r.host)}">${d === 1 ? "Today" : `${d} days`}</a>`)}</div>
    ${r.hosts.length > 1 || r.host
      ? html`<div class="filters"><span class="lab">Address</span><a class="${r.host ? "" : "on"}" href="${link(r.days, null)}">Every address</a>${r.hosts.map((h) => html`<a class="${h.host === r.host ? "on" : ""}" href="${link(r.days, h.host)}">${h.host} <b>${figure(h.visits)}</b></a>`)}</div>`
      : ""}
    ${nothing
      ? html`<section class="box"><h2>No visits in ${windowWord}</h2><p>Nothing has been counted${r.host ? html` for ${r.host}` : ""} in this window. Counting starts with the first answer this version gives; your own visits, and any from this server's own network, are never counted.</p></section>`
      : html`
    <div class="stats today">
      <a class="tile" href="#days"><small>Visits</small><b>${figure(t.visits)}</b><span>one browser on one day</span></a>
      <a class="tile" href="#pages"><small>Page views</small><b>${figure(t.views)}</b><span>by those browsers</span></a>
      <a class="tile" href="#assistant"><small>AI assistants</small><b>${figure(t.assistants)}</b><span>requests made for a person</span></a>
      <a class="tile" href="#crawler"><small>Crawlers</small><b>${figure(t.crawlers)}</b><span>requests</span></a>
      <a class="tile" href="#reader"><small>Readers, tools, unnamed</small><b>${figure(t.readers + t.tools + t.unknown)}</b><span>${counted(t.api, "request")} to the API</span></a>
    </div>

    <section id="days">
      <h2>By day</h2>
      <div class="table-wrap"><table class="compact"><thead><tr><th>Day</th><th class="num">Visits</th><th class="num">Page views</th><th class="num">AI assistants</th><th class="num">Crawlers</th><th class="num">Readers, tools, unnamed</th></tr></thead><tbody>
        ${r.byDay.map((d) => html`<tr${d.visits + d.assistants + d.crawlers + d.others === 0 ? html` class="off"` : ""}><td class="day">${d.day}</td><td class="num">${figure(d.visits)}</td><td class="num">${figure(d.views)}</td><td class="num">${figure(d.assistants)}</td><td class="num">${figure(d.crawlers)}</td><td class="num">${figure(d.others)}</td></tr>`)}
      </tbody></table></div>
    </section>

    <section>
      <h2>People</h2>
      ${r.pages.length > 0
        ? html`<details class="fold" id="pages" open><summary><b>Pages</b> <span class="fold-meta">the pages people read, by visits</span></summary>
        <div class="table-wrap"><table class="compact"><thead><tr><th>Page</th><th class="num">Visits</th><th class="num">Views</th></tr></thead><tbody>
          ${r.pages.map((p) => html`<tr><td><a href="${p.path}">${shownPath(p.path)}</a></td><td class="num">${figure(p.visits)}</td><td class="num">${figure(p.views)}</td></tr>`)}
        </tbody></table></div></details>`
        : html`<p class="small">No person's browser read a page in this window.</p>`}
      ${countedTable("referrers", "Came from", "the site a link was followed from; most browsers send it", r.referrers, (n) => n, true)}
      ${countedTable("countries", "Countries", "as Cloudflare's edge reads the address", r.countries, countryName)}
      ${r.networks.length > 0
        ? html`<details class="fold" id="networks"><summary><b>Networks</b> <span class="fold-meta">the domain each address's reverse DNS names: a provider's, or an employer's</span></summary>
        <div class="table-wrap"><table class="compact"><thead><tr><th>Network</th><th class="num">Visits</th></tr></thead><tbody>
          ${r.networks.map((n) => html`<tr><td>${network(n.name, n.confirmed)}</td><td class="num">${figure(n.visits)}</td></tr>`)}
        </tbody></table></div></details>`
        : ""}
      ${countedTable("browsers", "Browsers", "by the family the User-Agent names", r.browsers)}
      ${countedTable("systems", "Systems", "the operating system the browser reports", r.systems)}
      ${countedTable("devices", "Devices", "desktop, phone or tablet", r.devices)}
    </section>

    ${automated.length > 0
      ? html`<section>
      <h2>Programs</h2>
      ${automated.map((g) => html`<details class="fold" id="${g.kind}"><summary><b>${kindWords[g.kind].title}</b> <span class="fold-meta">${kindWords[g.kind].line} · ${counted(g.rows.reduce((n, a) => n + a.requests, 0), "request")}</span></summary>
        <div class="table-wrap"><table class="compact"><thead><tr><th>Name</th><th>Network</th><th class="num">Requests</th><th>Last</th></tr></thead><tbody>
          ${g.rows.map((a) => html`<tr><td>${a.name}</td><td>${network(a.network, a.confirmed)}</td><td class="num">${figure(a.requests)}</td><td>${relativeTime(a.last, options.now)}</td></tr>`)}
        </tbody></table></div></details>`)}
    </section>`
      : ""}

    ${r.missing.length > 0
      ? html`<section>
      <h2>Not found</h2>
      <details class="fold" id="missing"><summary><b>Paths that do not exist</b> <span class="fold-meta">a broken link, or a scanner trying paths · ${counted(t.missing, "request")}</span></summary>
        <div class="table-wrap"><table class="compact"><thead><tr><th>Path</th><th class="num">Requests</th><th>Last</th></tr></thead><tbody>
          ${r.missing.map((m) => html`<tr><td><code>${shownPath(m.path)}</code></td><td class="num">${figure(m.requests)}</td><td>${relativeTime(m.last, options.now)}</td></tr>`)}
        </tbody></table></div></details>
    </section>`
      : ""}

    ${r.recent.length > 0
      ? html`<section id="recent">
      <h2>Latest page views</h2>
      <div class="table-wrap"><table><thead><tr><th>When</th><th>Page</th><th>Country</th><th>Network</th><th>Browser</th><th>Came from</th></tr></thead><tbody>
        ${r.recent.map(
          (v) => html`<tr><td>${when.format(new Date(v.at))}</td><td><a href="${v.path}">${shownPath(v.path)}</a>${r.host || r.hosts.length < 2 ? "" : html`<div class="note">${v.host}</div>`}</td><td>${v.country ? countryName(v.country) : ""}</td><td>${network(v.network, v.confirmed)}</td><td>${v.browser ?? ""}<div class="note">${[v.os, v.device].filter(Boolean).join(", ")}</div></td><td>${v.referrer ?? ""}</td></tr>`,
        )}
      </tbody></table></div>
    </section>`
      : ""}`}`;

  return page({ title: "Visitors", active: "visitors", content, meta: r.lastAt ? html`last ${relativeTime(r.lastAt, options.now)}` : html`none yet`, owner: options.owner, open: options.open, look: options.look });
}
