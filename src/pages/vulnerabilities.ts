import type { DatabaseSync } from "node:sqlite";
import { exploitSourceLabel, exploitTallies, exploitWording, type ExploitTally } from "../exploits.ts";
import { fixContext, fixesFor, whoseWord, type Fix } from "../fix.ts";
import { figure, html, newTab, newTabIf, type Html } from "../html.ts";
import { relativeTime, shortStamp } from "../time.ts";
import { cveMentions, newsFor } from "../trending.ts";
import { getTriage } from "../triage.ts";
import { cweOf, getVuln, kevPairUsable, listVulns, loadWatchlist, squash, platformFigures, vulnChanges, vulnStats, type AffectedPackage, type PlatformFigures, type VulnFilters, type VulnRow } from "../vulns.ts";
import { platformChoiceName } from "../platforms.ts";
import { kevChip } from "../wire.ts";
import { platformPicker } from "./platform-pick.ts";
import type { LookState } from "../look.ts";
import { page, staleNotice } from "./layout.ts";
import { saveSearchForm } from "./saved.ts";
import { triageForm } from "./triage.ts";
import { parseJson } from "../json.ts";
import { counted, epssPercent } from "../words.ts";
import { isRepublished, msrcFlags, releaseNoteUrl } from "../msrc.ts";

/**
 * The Vulnerabilities pages: the table with its filters and search, and one CVE with its scores,
 * history, affected platforms, the watchlist's marks and the Fix panel.
 */
function severityChip(row: VulnRow): Html {
  if (row.cvss_score === null) return html`<span class="chip">unscored</span>`;
  const level = (row.cvss_severity ?? "").toLowerCase() || (row.cvss_score >= 9 ? "critical" : row.cvss_score >= 7 ? "high" : row.cvss_score >= 4 ? "medium" : "low");
  return html`<span class="chip sev ${level}" title="CVSS ${row.cvss_version ?? ""} ${row.cvss_vector ?? ""}">${row.cvss_score.toFixed(1)} ${level}</span>`;
}

/** The table narrowed to the CVE's own CVSS band, the way the Today page bands them. */
function severityHref(row: VulnRow): string {
  if (row.cvss_score === null) return "/vulnerabilities?severity=unscored";
  const level = (row.cvss_severity ?? "").toLowerCase();
  return level === "critical" || level === "high" || level === "medium" || level === "low" ? `/vulnerabilities?severity=${level}` : `/vulnerabilities?min_cvss=${row.cvss_score}`;
}

/** "exploit", or "exploit ×3": a public exploit is known, with the title saying where and whether any is verified. */
function exploitChip(t: ExploitTally | undefined): Html {
  if (!t) return html``;
  return html`<span class="chip exploit${t.verified ? " verified" : ""}" title="${exploitWording(t)}">exploit${t.count > 1 ? ` ×${t.count}` : ""}</span>`;
}

/**
 * One platform's card: what is affecting it, and the worst of it by the table's risk order. Every
 * figure is a link to the list it counts, so "45 exploited" opens those 45.
 */
function platformCard(f: PlatformFigures): Html {
  const base = f.id === "danger" ? "/vulnerabilities?danger=1" : `/vulnerabilities?platform=${f.id}`;
  const worst = f.worst;
  // "microsoft windows 11 24h2": the one product that put the CVE on this card, as words.
  const who = f.worstProduct ?? "";
  return html`<div class="pcard${f.id === "danger" ? " danger" : ""}">
    <a class="pcard-head" href="${base}"><small>${f.label}</small><b>${figure(f.total)}</b></a>
    <p class="pcard-blurb">${f.blurb}</p>
    <p class="pcard-stats">${f.kev ? html`<a class="kev" href="${base}&amp;kev=1">${figure(f.kev)} known exploited (KEV)</a>` : html`<span>none known exploited (KEV)</span>`} · <a href="${base}&amp;exploit=1">${figure(f.exploit)} public exploit</a> · <a href="${base}&amp;new=168">${figure(f.recent)} new this week</a></p>
    ${worst
      ? html`<p class="pcard-worst"><span>Worst now</span> <a href="/vulnerabilities/${worst.cve_id}">${worst.cve_id}</a>${worst.kev ? html` <span class="chip kev">KEV</span>` : ""}${worst.cvss_score !== null ? html` <span class="small">${worst.cvss_score.toFixed(1)}</span>` : ""}${who ? html` <span class="small">${who}</span>` : ""}</p>`
      : ""}
  </div>`;
}

/** CISA's SSVC exploitation value in words: "none" is "no exploitation reported", not a reading of none. */
export function ssvcExploitation(value: string): string {
  return value === "none" ? "CISA SSVC: no exploitation reported" : value === "poc" ? "CISA SSVC: proof of concept public" : value === "active" ? "CISA SSVC: exploited" : `CISA SSVC: exploitation ${value}`;
}

function epssText(row: VulnRow): string {
  return row.epss === null ? "—" : epssPercent(row.epss);
}

function query(filters: VulnFilters, overrides: Partial<VulnFilters>): string {
  const f = { ...filters, ...overrides };
  const p = new URLSearchParams();
  if (f.watch) p.set("watch", "1");
  if (f.platform) p.set("platform", f.platform);
  if (f.danger) p.set("danger", "1");
  if (f.kev) p.set("kev", "1");
  if (f.ransomware) p.set("ransomware", "1");
  if (f.cwe) p.set("cwe", f.cwe);
  if (f.exploit) p.set("exploit", "1");
  if (f.dueFrom && f.dueTo) p.set("due", "7");
  if (f.minCvss !== undefined) p.set("min_cvss", String(f.minCvss));
  if (f.severity) p.set("severity", f.severity);
  if (f.minEpss !== undefined) p.set("min_epss", String(f.minEpss));
  if (f.maxEpss !== undefined) p.set("max_epss", String(f.maxEpss));
  if (f.noEpss) p.set("epss", "none");
  // A 24 h window is the "1" the links have always carried; a wider one (the Today page's 3 or 7 days) names its hours.
  if (f.changedSince) p.set("changed", f.changedHours && f.changedHours !== 24 ? String(f.changedHours) : "1");
  if (f.newSince) p.set("new", f.newHours && f.newHours !== 24 ? String(f.newHours) : "1");
  if (f.movedSince) p.set("moved", f.movedHours && f.movedHours !== 24 ? String(f.movedHours) : "1");
  if (f.label) p.set("label", f.label);
  if (f.q) p.set("q", f.q);
  // The default is left out, so an unfiltered list keeps the bare /vulnerabilities address
  // — which is what tells the Save box, the feed link and a saved search that nothing is filtered.
  if (f.sort && f.sort !== "risk") p.set("sort", f.sort);
  if (f.offset) p.set("offset", String(f.offset));
  const s = p.toString();
  return s ? `/vulnerabilities?${s}` : "/vulnerabilities";
}

/** The window a chip names: the Today page's 3 or 7 days read as such, so the figure clicked and the list shown agree. */
const windowWord = (h: number | undefined): string => (h === undefined || h === 24 ? "24 h" : h % 24 === 0 ? `${h / 24} days` : `${h} h`);
const pct = (n: number): string => `${Math.round(n * 100)}%`;
/** An EPSS band the Today page sent the list into, in words, or null. */
const epssBandWords = (filters: VulnFilters): string | null =>
  filters.noEpss ? "no score" : filters.maxEpss !== undefined ? `${filters.minEpss !== undefined ? `${pct(filters.minEpss)} to ` : "under "}${pct(filters.maxEpss)}` : null;

/**
 * The filters in force, each in the words the table's filter line uses and with the address that
 * takes it off: the heading, the empty list and the RSS feed's title all name them this way.
 */
export function activeVulnFilters(filters: VulnFilters): { label: string; off: string }[] {
  const epssBand = epssBandWords(filters);
  // On a phone they stand outside the folded list of every filter.
  const active: { label: string; off: string }[] = [];
  const on = (cond: unknown, label: string, off: Partial<VulnFilters>): void => {
    if (cond) active.push({ label, off: query(filters, { ...off, offset: 0 }) });
  };
  on(filters.platform, filters.platform ? platformChoiceName(filters.platform) : "", { platform: undefined });
  on(filters.danger, "Most dangerous", { danger: false });
  on(filters.watch, "My stack", { watch: false });
  on(filters.label, `Watch: ${filters.label ?? ""}`, { label: undefined });
  on(filters.kev, "Known exploited (KEV)", { kev: false });
  on(filters.ransomware, "Ransomware (KEV)", { ransomware: false });
  on(filters.exploit, "Public exploit", { exploit: false });
  on(filters.dueFrom, "Due this week (KEV)", { dueFrom: undefined, dueTo: undefined });
  on(filters.cwe, filters.cwe ?? "", { cwe: undefined });
  on(filters.minCvss !== undefined, filters.minCvss === 9 ? "Critical (9+)" : `CVSS ${filters.minCvss ?? ""}+`, { minCvss: undefined });
  on(filters.severity, `CVSS ${filters.severity ?? ""}`, { severity: undefined });
  on(epssBand, `EPSS ${epssBand ?? ""}`, { minEpss: undefined, maxEpss: undefined, noEpss: false });
  on(!epssBand && filters.minEpss !== undefined, `EPSS ≥ ${pct(filters.minEpss ?? 0)}`, { minEpss: undefined });
  on(filters.changedSince, `Changed, ${windowWord(filters.changedHours)}`, { changedSince: undefined, changedHours: undefined });
  on(filters.newSince, `New, ${windowWord(filters.newHours)}`, { newSince: undefined, newHours: undefined });
  on(filters.movedSince, `Moved, ${windowWord(filters.movedHours)}`, { movedSince: undefined, movedHours: undefined });
  on(filters.q, `“${filters.q ?? ""}”`, { q: undefined });

  return active;
}

export interface VulnListOptions {
  db: DatabaseSync;
  filters: VulnFilters;
  owner: boolean;
  open: boolean;
  now: Date;
  look: LookState;
  /** Query values the table read as no filter ("due=30"), named in a notice above it (src/routes/query.ts#ignoredVulnParams). */
  ignored?: string[];
}

export function renderVulnList({ db, filters, owner, open, now, look, ignored = [] }: VulnListOptions): string {
  const limit = 50;
  const { rows, total } = listVulns(db, { ...filters, limit });
  const since = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
  const stats = vulnStats(db, since);
  const epssDate = (db.prepare("SELECT value FROM app_settings WHERE key = 'epss.date'").get() as { value: string } | undefined)?.value;
  const cursor = (db.prepare("SELECT value FROM app_settings WHERE key = 'nvd.cursor'").get() as { value: string } | undefined)?.value;
  const offset = filters.offset ?? 0;
  const none = !filters.watch && !filters.kev && !filters.ransomware && !filters.cwe && !filters.exploit && !filters.dueFrom && filters.minCvss === undefined && !filters.severity && filters.minEpss === undefined && filters.maxEpss === undefined && !filters.noEpss && !filters.changedSince && !filters.newSince && !filters.movedSince && !filters.label;
  // A band the Today page sent us into, shown as a chip that takes it off again.
  const epssBand = epssBandWords(filters);

  // The landing view opens on what is affecting each platform; a list already narrowed to one does not need the cards.
  const landing = none && !filters.platform && !filters.danger && !filters.q && offset === 0;
  const cards = landing ? platformFigures(db, new Date(now.getTime() - 7 * 86_400_000).toISOString()) : [];
  const exploits = exploitTallies(db, rows.map((r) => r.cve_id));
  const microsoft = msrcFlags(db, rows.map((r) => r.cve_id));
  // Named by two or more sources this week: being talked about, whatever the score.
  const mentions = cveMentions(db, rows.map((r) => r.cve_id), new Date(now.getTime() - 7 * 86_400_000).toISOString());
  const tableRows = rows.map((r) => {
    const vendors = parseJson<string[]>(r.vendors_json, []);
    const products = parseJson<string[]>(r.products_json, []);
    const packages = parseJson<AffectedPackage[]>(r.packages_json, []);
    const who = [...new Set([...vendors.slice(0, 2), ...products.slice(0, 3)])].join(", ") || packages.slice(0, 3).map((p) => `${p.ecosystem}:${p.name}`).join(", ");
    const watch = owner ? parseJson<string[]>(r.watch_labels_json, []) : [];
    return html`<tr class="${owner && r.watch_hit ? "hit" : ""}">
      <td class="id"><a href="/vulnerabilities/${r.cve_id}">${r.cve_id}</a>${r.kev ? kevChip(r.kev_due_date, now) : ""}${exploitChip(exploits.get(r.cve_id))}${microsoft.get(r.cve_id)?.exploited ? html`<span class="chip kev" title="Microsoft reports this CVE exploited">exploited</span>` : ""}${(mentions.get(r.cve_id)?.sources ?? 0) >= 2 ? html`<span class="chip news" title="Named by ${mentions.get(r.cve_id)?.sources} sources in the last 7 days">news ×${mentions.get(r.cve_id)?.sources}</span>` : ""}${watch.length ? html`<span class="chip mine">${watch.join(", ")}</span>` : ""}</td>
      <td>${severityChip(r)}</td>
      <td class="n" title="EPSS ${r.epss ?? ""} · percentile ${r.epss_percentile ?? ""}">${epssText(r)}</td>
      <td class="who">${who || html`<span class="small">no CPE yet</span>`}</td>
      <td class="desc"><span>${r.description ?? ""}</span></td>
      <td class="n when" title="${shortStamp(r.last_modified_at)}">${relativeTime(r.last_modified_at, now)}</td>
    </tr>`;
  });

  const active = activeVulnFilters(filters);

  // Every filter as a chip, and the sort: in a row on a wide screen, folded on a phone (CSS picks one).
  const filterChips = html`
      <a class="${none ? "on" : ""}" href="${query(filters, { watch: false, kev: false, ransomware: false, cwe: undefined, exploit: false, dueFrom: undefined, dueTo: undefined, minCvss: undefined, severity: undefined, minEpss: undefined, maxEpss: undefined, noEpss: false, changedSince: undefined, newSince: undefined, movedSince: undefined, movedHours: undefined, label: undefined, offset: 0 })}">All</a>
      ${owner ? html`<a class="${filters.watch ? "on" : ""}" href="${query(filters, { watch: !filters.watch, offset: 0 })}">My stack</a>` : ""}
      <a class="${filters.kev ? "on" : ""}" href="${query(filters, { kev: !filters.kev, offset: 0 })}">Known exploited (KEV)</a>
      <a class="${filters.ransomware ? "on" : ""}" href="${query(filters, { ransomware: !filters.ransomware, offset: 0 })}" title="KEV entries CISA marks as known to be used in ransomware campaigns">Ransomware (KEV)</a>
      <a class="${filters.dueFrom ? "on" : ""}" href="${query(filters, filters.dueFrom ? { dueFrom: undefined, dueTo: undefined, offset: 0 } : { dueFrom: "from", dueTo: "to", offset: 0 })}" title="KEV entries whose CISA due date falls in the seven days starting today">Due this week (KEV)</a>
      <a class="${filters.exploit ? "on" : ""}" href="${query(filters, { exploit: !filters.exploit, offset: 0 })}">Public exploit</a>
      <a class="${filters.minCvss === 9 ? "on" : ""}" href="${query(filters, { minCvss: filters.minCvss === 9 ? undefined : 9, offset: 0 })}">Critical (9+)</a>
      <a class="${filters.minEpss === 0.5 ? "on" : ""}" href="${query(filters, { minEpss: filters.minEpss === 0.5 ? undefined : 0.5, offset: 0 })}">Likely exploited (EPSS ≥ 50%)</a>
      <a class="${filters.changedSince ? "on" : ""}" href="${query(filters, { changedSince: filters.changedSince ? undefined : since, changedHours: undefined, offset: 0 })}">Changed, ${windowWord(filters.changedSince ? filters.changedHours : undefined)}</a>
      <a class="${filters.newSince ? "on" : ""}" href="${query(filters, { newSince: filters.newSince ? undefined : since, newHours: undefined, offset: 0 })}">New, ${windowWord(filters.newSince ? filters.newHours : undefined)}</a>
      ${filters.movedSince ? html`<a class="on" href="${query(filters, { movedSince: undefined, movedHours: undefined, offset: 0 })}" title="Published or really changed, as Today counts them">Moved, ${windowWord(filters.movedHours)} ×</a>` : ""}
      ${filters.label ? html`<a class="on" href="${query(filters, { label: undefined, offset: 0 })}">Watch: ${filters.label} ×</a>` : ""}
      ${filters.cwe ? html`<a class="on" href="${query(filters, { cwe: undefined, offset: 0 })}" title="NVD's weakness for the CVE">Weakness: ${filters.cwe} ×</a>` : ""}
      ${filters.severity ? html`<a class="on" href="${query(filters, { severity: undefined, offset: 0 })}">CVSS ${filters.severity} ×</a>` : ""}
      ${epssBand ? html`<a class="on" href="${query(filters, { minEpss: undefined, maxEpss: undefined, noEpss: false, offset: 0 })}">EPSS ${epssBand} ×</a>` : ""}
      <span class="sort">Sort:
        <a class="${(filters.sort ?? "risk") === "risk" ? "on" : ""}" href="${query(filters, { sort: "risk", offset: 0 })}" title="Known exploited first, then a public exploit, then EPSS, then CVSS, then how recently it changed">risk</a>
        <a class="${filters.sort === "modified" ? "on" : ""}" href="${query(filters, { sort: "modified", offset: 0 })}">modified</a>
        <a class="${filters.sort === "published" ? "on" : ""}" href="${query(filters, { sort: "published", offset: 0 })}">published</a>
        <a class="${filters.sort === "cvss" ? "on" : ""}" href="${query(filters, { sort: "cvss", offset: 0 })}">CVSS</a>
        <a class="${filters.sort === "epss" ? "on" : ""}" href="${query(filters, { sort: "epss", offset: 0 })}">EPSS</a>
      </span>`;

  const feedQuery = query(filters, { offset: 0 });
  const feed = { href: `/vulnerabilities/feed.xml${feedQuery.slice("/vulnerabilities".length)}`, title: "Vulnerabilities" };
  // The same rows, in the same order, as a file: into a ticket or a spreadsheet.
  const csvHref = `/vulnerabilities.csv${feedQuery.slice("/vulnerabilities".length)}`;
  const content = html`
    ${staleNotice(db, now)}
    ${ignored.length ? html`<p class="notice warn" role="status">${ignored.map((w, i) => html`${i ? "; " : ""}<code>${w}</code>`)} ${ignored.length === 1 ? "is not a filter" : "are not filters"} this table takes; ${active.length ? "showing the rest" : "showing all"}.</p>` : ""}
    <div class="stats vstats" aria-label="Totals">
      <a href="/vulnerabilities"><small>CVEs known</small><b>${figure(stats.total)}</b></a>
      <a href="/vulnerabilities?new=1"><small>New, 24 h</small><b>${figure(stats.newSince)}</b></a>
      <a href="/vulnerabilities?changed=1"><small>Changed, 24 h</small><b>${figure(stats.changedSince)}</b></a>
      <a href="/vulnerabilities?kev=1"><small>Known exploited (KEV)</small><b>${figure(stats.kev)}</b></a>
      <a href="/vulnerabilities?exploit=1"><small>Public exploit</small><b>${figure(stats.exploit)}</b></a>
      ${owner ? html`<a href="/vulnerabilities?watch=1"><small>Match watchlist</small><b>${figure(stats.watch)}</b></a>` : ""}
    </div>
    <div class="wire-top">
      <h1>Vulnerabilities${filters.platform ? html` <small class="motto">· ${platformChoiceName(filters.platform)}</small>` : filters.danger ? html` <small class="motto">· the most dangerous</small>` : ""}</h1>
      ${saveSearchForm(db, query(filters, { offset: 0 }), owner)}
      <form method="get" action="/vulnerabilities" class="search" role="search">
        ${filters.watch ? html`<input type="hidden" name="watch" value="1">` : ""}
        ${filters.platform ? html`<input type="hidden" name="platform" value="${filters.platform}">` : ""}
        ${filters.danger ? html`<input type="hidden" name="danger" value="1">` : ""}
        ${filters.kev ? html`<input type="hidden" name="kev" value="1">` : ""}
        ${filters.ransomware ? html`<input type="hidden" name="ransomware" value="1">` : ""}
        ${filters.exploit ? html`<input type="hidden" name="exploit" value="1">` : ""}
        ${filters.dueFrom ? html`<input type="hidden" name="due" value="7">` : ""}
        <label class="visually-hidden" for="q">Search CVEs</label>
        <input type="search" id="q" name="q" value="${filters.q ?? ""}" placeholder="CVE id, vendor, product or words in the description">
        <label class="cwe-field" for="cwe">Weakness <input type="text" id="cwe" name="cwe" value="${filters.cwe ?? ""}" placeholder="CWE-79" size="9" maxlength="20" title="A weakness id, such as CWE-79 or 79"></label>
        <button type="submit">Search</button>
      </form>
    </div>
    ${cards.length
      ? html`<section class="platforms" aria-labelledby="affecting">
          <h2 id="affecting">By platform</h2>
          <p class="small lede-line">The CVEs this site holds for each platform, how many are known exploited (KEV) or have a public exploit, and the worst of them now by the table's risk order.</p>
          <div class="pcards">${cards.map(platformCard)}</div>
        </section>`
      : ""}
    ${platformPicker(filters, (next) => query(filters, { platform: next.platform, danger: next.danger === true, offset: 0 }))}
    <div class="filters vf-wide">${filterChips}</div>
    <div class="vf-narrow">
      ${active.length ? html`<div class="filters">${active.map((a) => html`<a class="on" href="${a.off}">${a.label} ×</a>`)}</div>` : ""}
      <details class="vf-fold"><summary>Filters${active.length ? ` (${active.length} on)` : ""}</summary>
        <div class="filters">${filterChips}</div>
      </details>
    </div>
    ${rows.length === 0
      ? html`<div class="empty"><b>${total === 0 && stats.total === 0 ? "No CVEs yet." : "No CVEs match."}</b><p>${stats.total === 0 ? "The NVD source pulls every CVE modified in its backfill window (seven days unless BW_NVD_BACKFILL_DAYS says otherwise) on its first run; the owner can start it now from the Sources page." : active.length ? html`Nothing matches ${active.map((a, i) => html`${i ? (i === active.length - 1 ? " and " : ", ") : ""}<a href="${a.off}" title="Take this filter off">${a.label}</a>`)}${active.length > 1 ? " together" : ""}. Loosen a filter or search differently.` : "Loosen a filter or search differently."}</p></div>`
      : html`<h2 class="list-count" id="list">${figure(total)} ${total === 1 ? "CVE" : "CVEs"}${active.length ? html` · ${active.map((a) => a.label).join(" · ")}` : ""}</h2>
        <div class="table-wrap"><table class="vulns"><caption class="visually-hidden">CVEs</caption>
          <thead><tr><th scope="col">CVE</th><th scope="col">CVSS</th><th scope="col">EPSS</th><th scope="col">Vendor, product</th><th scope="col">Description</th><th scope="col">Modified</th></tr></thead>
          <tbody>${tableRows}</tbody>
        </table></div>
        <p class="more">${figure(offset + rows.length)} of ${figure(total)}${offset + rows.length < total ? html` · <a href="${query(filters, { offset: offset + limit })}">Next</a>` : ""}${offset > 0 ? html` · <a href="${query(filters, { offset: Math.max(0, offset - limit) })}">Previous</a>` : ""}</p>`}
    <p class="small"><a href="${csvHref}">Download these ${figure(Math.min(total, 1000))} as CSV</a>${total > 1000 ? " (the first thousand in this order)" : ""} · <a href="${feed.href}">subscribe to this list</a>.</p>
    <p class="small">EPSS scores: ${epssDate ? html`<a href="/sources#src-first-epss">${epssDate}</a>` : html`none pulled yet — <a href="/sources#src-first-epss">Sources</a>`}. NVD cursor: ${cursor ? html`<a href="/sources#src-nvd-cves">${shortStamp(cursor)}</a>` : html`no pull yet — <a href="/sources#src-nvd-cves">Sources</a> shows each feed's state and what to do when one fails`}. The <a href="/?kind=vulnerability">News page</a> shows only notable CVEs (KEV, your stack, new criticals, EPSS over 50%, or active exploitation per SSVC); this table has all of them.</p>`;

  return page({ title: "Vulnerabilities", active: "vulnerabilities", content, meta: html`${figure(stats.total)} CVEs · ${figure(stats.kev)} known exploited (KEV)`, owner, open, look, feed, canonical: "/vulnerabilities", description: "Every CVE as NVD, CISA and FIRST describe it: CVSS, EPSS, KEV, public exploits, and the fix published for each." });
}

/**
 * Public exploits, in a box of their own below the Fix panel: a reader looking for the patch is
 * not handed the attack first. Each line links to where the exploit is published: an Exploit-DB
 * entry, a Metasploit module's source, or a GitHub repository.
 */
function exploitsBox(fix: Fix): Html {
  return fix.exploits.length
    ? html`<section class="box" id="exploits"><h2>Public exploits ${countOf(fix.exploits.length)}</h2>
        <ul class="refs">${fix.exploits.slice(0, 20).map((e) => html`<li><a href="${e.url}" ${newTab}>${e.title}</a> <span class="small">${exploitSourceLabel[e.source_id] ?? e.source_id}${e.verified ? " · verified" : ""}${e.published_at ? html` · ${e.published_at.slice(0, 10)}` : ""}</span></li>`)}${fix.exploits.length > 20 ? html`<li class="small">and ${fix.exploits.length - 20} more</li>` : ""}</ul>
        <p class="small">Each line links to where the exploit is published: the Exploit-DB entry, the Metasploit module's source on GitHub, or the GitHub repository that claims a proof of concept. These pages hold working exploit code. Exploit-DB's "verified" and a Metasploit rank of good or better count as verified; a PoC-in-GitHub entry is a repository's claim.</p>
</section>`
    : html``;
}

/** "github.com", "msrc.microsoft.com": where a reference lives, which says more than its full address. */
export function refHost(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url.slice(0, 60);
  }
}

/** NVD lists one address several times, once per tag set; a reader wants each address once with all its tags. */
export function uniqueRefs(refs: { url: string; tags: string[] }[]): { url: string; tags: string[] }[] {
  const byUrl = new Map<string, { url: string; tags: string[] }>();
  for (const r of refs) {
    const seen = byUrl.get(r.url);
    if (seen) for (const t of r.tags) {
      if (!seen.tags.includes(t)) seen.tags.push(t);
    }
    else byUrl.set(r.url, { url: r.url, tags: [...r.tags] });
  }
  return [...byUrl.values()];
}

/**
 * What tells one reference from another on the same host: a commit's short id (twelve characters,
 * as the kernel's own references write it) where the address names a commit, else the address's
 * last path segment. git.kernel.org writes a commit as /c/<sha> or ?id=<sha>.
 */
function refTail(url: string): string {
  try {
    const u = new URL(url);
    const sha = /\/(?:commits?|c)\/([0-9a-f]{7,40})\b/i.exec(u.pathname)?.[1] ?? /\/([0-9a-f]{12,40})\/?$/i.exec(u.pathname)?.[1] ?? (/^[0-9a-f]{7,40}$/i.test(u.searchParams.get("id") ?? "") ? u.searchParams.get("id")! : undefined) ?? (/^[0-9a-f]{7,40}$/i.test(u.searchParams.get("h") ?? "") ? u.searchParams.get("h")! : undefined);
    if (sha) return sha.slice(0, 12).toLowerCase();
    const segments = u.pathname.split("/").filter(Boolean);
    const last = segments.at(-1);
    return last ? decodeURIComponent(last).replace(/\.(s?html?|php|aspx?)$/i, "").slice(0, 48) : u.search.slice(0, 48);
  } catch {
    return "";
  }
}

/** Each reference's link words: the host alone, or the host and its tail where two references share the host. */
export function refLabels(refs: { url: string }[]): Map<string, string> {
  const hosts = new Map<string, number>();
  for (const r of refs) hosts.set(refHost(r.url), (hosts.get(refHost(r.url)) ?? 0) + 1);
  return new Map(refs.map((r) => {
    const host = refHost(r.url);
    const tail = (hosts.get(host) ?? 0) > 1 ? refTail(r.url) : "";
    return [r.url, tail ? `${host} · ${tail}` : host];
  }));
}

/** One reference line: the host as the link's words (with its tail when the host repeats), NVD's tags beside it, the full address on hover. */
function refLine(r: { url: string; tags: string[] }, labels?: Map<string, string>): Html {
  return /^https?:\/\//i.test(r.url)
    ? html`<li><a href="${r.url}" title="${r.url}" ${newTabIf(r.url)}>${labels?.get(r.url) ?? refHost(r.url)}</a>${r.tags.length ? html` <span class="small">${r.tags.join(", ")}</span>` : ""}</li>`
    : html`<li>${r.url}${r.tags.length ? html` <span class="small">${r.tags.join(", ")}</span>` : ""}</li>`;
}

/** A box's count in brackets, "(4)", so it does not read as part of the heading. */
const countOf = (n: number): Html => html`<span class="count">(${figure(n)})</span>`;

/**
 * Microsoft's guide also carries products that are not Microsoft's own: Azure Linux (family
 * "Mariner") ships Linux kernel fixes, Edge republishes Chromium's. Such a row is headed by the
 * product it is, never "Microsoft's update" on a Linux kernel CVE.
 */
function msrcHeading(ms: NonNullable<Fix["microsoft"]>): Html {
  if (!isRepublished(ms)) return html`Microsoft's update`;
  const product = ms.family === "Mariner" ? "Azure Linux" : (ms.family ?? "Microsoft product");
  return html`${product} update (Microsoft Security Update Guide)`;
}

/** The Fix panel: what has been published that fixes or mitigates the CVE, quoted and linked, or an honest empty. */
function fixPanel(fix: Fix, windows = false): Html {
  const ms = fix.microsoft;
  // A Windows CVE whose KB is not held here: say where this month's KB is, rather than nothing.
  const noKb = windows && !ms?.fixes.some((f) => f.kb)
    ? html`<p class="small msrc-missing">Microsoft's KB data for this CVE is not loaded here: this instance holds only the Security Update Guide months it has read. <a href="https://msrc.microsoft.com/update-guide/vulnerability/${fix.cveId}" ${newTab}>Microsoft's page for ${fix.cveId}</a> names the KB per Windows release.</p>`
    : html``;
  const microsoft = ms?.fixes.length
    ? html`<h3 class="small">${msrcHeading(ms)}${ms.severity ? html` · ${ms.severity}` : ""}${ms.exploited ? html` · exploited` : ""}${ms.disclosed ? html` · publicly disclosed` : ""}</h3>
        <ul class="refs">${ms.fixes.map((f) => html`<li>${f.url ? html`<a href="${f.url}" ${newTab}>${f.kb ? `KB${f.kb}` : (f.label ?? f.url)}</a>` : (f.label ?? "")}${f.products.length ? html` — ${f.products.join(", ")}` : ""}${f.fixedBuild ? html` <span class="small">· build ${f.fixedBuild}</span>` : ""}${f.restart ? html` <span class="small">· restart required</span>` : ""}</li>`)}</ul>
        <p class="small">From the <a href="${releaseNoteUrl(ms.release_id)}" ${newTab}>${ms.release_id} release note</a> of Microsoft's Security Update Guide${ms.revised_at ? html`, revised ${ms.revised_at.slice(0, 10)}` : ""}${ms.exploitability ? html` · ${ms.exploitability}` : ""}.</p>`
    : html``;
  if (fix.empty) {
    const u = fix.untagged;
    if (u.count) {
      const whose = whoseWord(u.lead);
      return html`<section class="box fix empty-fix"><h2>Fix</h2><p>NVD has not tagged its ${u.count === 1 ? "1 reference" : html`${figure(u.count)} references`} yet${u.lead ? html`; ${whose}: <a href="${u.lead.url}" ${newTab}>${u.lead.host}</a>` : ""}.</p><p class="small">An untagged reference is often the vendor's own bulletin, waiting for NVD's analysis; every reference is listed under References below. Nothing else is published here: no vendor advisory in the News for this CVE, not in CISA's KEV, no fixed package version.</p>${noKb}</section>`;
    }
    return html`<section class="box fix empty-fix"><h2>Fix</h2><p class="small">Nothing published yet: no patch, vendor advisory or mitigation reference on NVD, no vendor advisory in the News for this CVE, not in CISA's KEV, no fixed package version. BaselineWatch does not guess at one.</p>${noKb}</section>`;
  }
  const references = uniqueRefs(fix.references);
  return html`<section class="box fix">
    <h2>Fix</h2>
    ${microsoft}
    ${noKb}
    ${fix.kev?.requiredAction
      ? html`<div class="fix-kev"><h3 class="small">CISA KEV required action${fix.kev.dueDate ? html` · due ${fix.kev.dueDate}` : ""}</h3><p>${fix.kev.requiredAction}</p>${fix.kev.notes?.length ? html`<p class="small">CISA's notes: ${fix.kev.notes.map((n, i) => html`${i ? " · " : ""}<a href="${n.url}" ${newTab}>${n.label ?? n.url.replace(/^https?:\/\//, "").slice(0, 70)}</a>`)}</p>` : ""}${fix.kev.dateAdded ? html`<p class="small">Added to the catalog ${fix.kev.dateAdded}. <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${fix.cveId}" ${newTab}>CISA KEV</a></p>` : ""}</div>`
      : ""}
    ${references.length
      ? html`<h3 class="small">Patch, vendor advisory and mitigation references on NVD ${countOf(references.length)}</h3>
          <ul class="refs">${(() => { const labels = refLabels(references); return references.slice(0, 20).map((r) => refLine(r, labels)); })()}</ul>`
      : ""}
    ${fix.advisories.length
      ? html`<h3 class="small">Vendor advisories in the News ${countOf(fix.advisories.length)}</h3>
          <ul class="refs">${fix.advisories.map((a) => html`<li><a href="${a.url ?? "/"}" ${newTabIf(a.url)}>${a.title}</a> <span class="small">${a.source}${a.publishedAt ? html` · ${a.publishedAt.slice(0, 10)}` : ""}</span></li>`)}</ul>`
      : ""}
    ${fix.packages.length
      ? html`<h3 class="small">Fixed package versions</h3>
          <ul class="refs">${fix.packages.map((p) => html`<li><code>${p.ecosystem}:${p.name}</code> fixed in ${p.fixed.join(", ")} <span class="small">${p.advisory}</span></li>`)}</ul>`
      : ""}
    ${fix.mitigations.length
      ? html`<h3 class="small">STIG rules that mitigate this class</h3>
          ${fix.mitigations.map(
            (m) => html`<div class="fix-mitigation">
              <p>${m.note} ${m.source ? html`<cite><a href="${m.source.url}" ${newTab}>${m.source.title}</a></cite>` : ""} <span class="small">(the owner's mapping, <code>data/mitigations.yaml</code>: ${m.id})</span></p>
              <ul class="change-list">${m.rules.slice(0, 8).map((r) => html`<li><a href="/standards/disa-stigs/${r.stig.latest.id}/${r.rule.ref}"><b>${r.rule.label}</b></a> <span class="chip sev ${r.rule.family === "CAT I" ? "critical" : r.rule.family === "CAT II" ? "high" : "medium"}">${r.rule.family ?? ""}</span> ${r.rule.title} <span class="small">${r.stig.product}</span></li>`)}${m.rules.length > 8 ? html`<li class="small">and ${m.rules.length - 8} more</li>` : ""}</ul>
            </div>`,
          )}`
      : ""}
    <p class="small">Every line above is quoted from NVD, CISA, Microsoft, the vendor's own advisory or DISA; nothing is generated.</p>
  </section>`;
}

/** A CVE's CPE criteria by vendor, then product, each with how many criteria name it, in the order of the most named. */
export function cpeGroups(cpes: string[]): { vendor: string; total: number; products: { product: string; cpes: string[] }[] }[] {
  const vendors = new Map<string, Map<string, string[]>>();
  for (const cpe of cpes) {
    const parts = cpe.split(":");
    const vendor = parts[3] && parts[3] !== "*" ? parts[3] : "(any vendor)";
    const product = parts[4] && parts[4] !== "*" ? parts[4] : "(any product)";
    const byProduct = vendors.get(vendor) ?? new Map<string, string[]>();
    vendors.set(vendor, byProduct);
    byProduct.set(product, [...(byProduct.get(product) ?? []), cpe]);
  }
  return [...vendors.entries()]
    .map(([vendor, byProduct]) => {
      const products = [...byProduct.entries()].map(([product, list]) => ({ product, cpes: list })).sort((a, b) => b.cpes.length - a.cpes.length || a.product.localeCompare(b.product));
      return { vendor, total: products.reduce((n, p) => n + p.cpes.length, 0), products };
    })
    .sort((a, b) => b.total - a.total || a.vendor.localeCompare(b.vendor));
}

/** The CPE box: one folded line per vendor with its products and counts; the first five vendors open and the rest folded, and within a vendor the products after the fifth folded too. */
function cpeBlock(cpes: string[]): Html {
  const groups = cpeGroups(cpes);
  const product = (p: (typeof groups)[number]["products"][number]): Html =>
    html`<li><code>${p.product}</code> <span class="small">${figure(p.cpes.length)}</span><ul class="cpes">${p.cpes.slice(0, 10).map((c) => html`<li><code>${c}</code></li>`)}${p.cpes.length > 10 ? html`<li class="small">and ${p.cpes.length - 10} more</li>` : ""}</ul></li>`;
  const one = (g: (typeof groups)[number], open: boolean): Html => html`<details class="fold"${open ? html` open` : ""}>
      <summary><b>${g.vendor}</b><span class="fold-meta">${counted(g.products.length, "product")} · ${counted(g.total, "criterion", "criteria")}</span></summary>
      <ul class="cpes">${g.products.slice(0, 5).map(product)}</ul>
      ${g.products.length > 5 ? html`<details class="more-cpes"><summary class="small">${counted(g.products.length - 5, "more product")}</summary><ul class="cpes">${g.products.slice(5).map(product)}</ul></details>` : ""}
    </details>`;
  return html`${groups.map((g, i) => one(g, i < 5))}`;
}

/**
 * The vendors and products a CVE names, as watchlist entries the owner can add from here: each
 * vendor alone, and each vendor:product pair its CPE criteria name (NVD keeps vendors and
 * products as two lists, so a pair is read from a CPE), plus CISA's own pair when the KEV entry
 * names one product, which matchWatch reads from kev_vendor and kev_product and so keeps matching
 * after NVD's record replaces the vendors and products. A row with neither offers vendors alone.
 */
export function watchCandidates(cpes: string[], vendors: string[], _products: string[], kev?: { vendor: string | null; product: string | null }): string[] {
  const pairs = new Set<string>();
  for (const cpe of cpes) {
    const parts = cpe.split(":");
    if (parts[0] === "cpe" && parts[3] && parts[4] && parts[3] !== "*" && parts[4] !== "*") pairs.add(`${parts[3]}:${parts[4]}`.toLowerCase());
  }
  if (kev && kevPairUsable(kev.vendor, kev.product)) pairs.add(`${kev.vendor}:${kev.product}`.toLowerCase());
  const out = [...new Set([...vendors, ...(kev?.vendor ? [kev.vendor] : [])].map((v) => v.toLowerCase()))];
  for (const p of [...pairs].sort()) out.push(p);
  return out.slice(0, 16);
}

function watchBox(db: DatabaseSync, cveId: string, cpes: string[], vendors: string[], products: string[], kev: { vendor: string | null; product: string | null }): Html {
  const candidates = watchCandidates(cpes, vendors, products, kev);
  if (!candidates.length) return html``;
  // Held by the watchlist's own rule (squash: case, spaces and punctuation ignored, per side of a pair),
  // so a pair already matched is not offered again under another spelling.
  const key = (v: string): string => v.split(":").map(squash).join(":");
  const held = new Set(loadWatchlist(db).filter((e) => e.kind === "product").map((e) => key(e.value)));
  const back = `/vulnerabilities/${cveId}#watch`;
  return html`<section class="box" id="watch">
    <h2><a href="/watchlist">Watch</a></h2>
    <p class="small">Add a vendor, or a vendor:product pair from the CPE criteria or CISA's catalogue entry, to the watchlist: every CVE that names it is then marked as your stack.</p>
    <ul class="watch-add">${candidates.map((value) =>
      held.has(key(value))
        ? html`<li><code>${value}</code> <span class="small">watched</span></li>`
        : html`<li><form method="post" action="/watchlist" class="inline"><input type="hidden" name="kind" value="product"><input type="hidden" name="value" value="${value}"><input type="hidden" name="back" value="${back}"><button type="submit">Watch <code>${value}</code></button></form></li>`,
    )}</ul>
  </section>`;
}

export function renderVulnDetail(options: { db: DatabaseSync; cveId: string; owner: boolean; open: boolean; now: Date; look: LookState }): string | null {
  const { db, cveId, owner, open, now, look } = options;
  const row = getVuln(db, cveId);
  if (!row) return null;
  const vendors = parseJson<string[]>(row.vendors_json, []);
  const products = parseJson<string[]>(row.products_json, []);
  const packages = parseJson<AffectedPackage[]>(row.packages_json, []);
  const aliases = parseJson<string[]>(row.aliases_json, []);
  const isCve = /^CVE-/.test(row.cve_id);
  const ghsa = [row.cve_id, ...aliases].find((id) => /^GHSA-/.test(id));
  const osvId = [row.cve_id, ...aliases].find((id) => !/^CVE-/.test(id));
  const cpes = parseJson<string[]>(row.cpes_json, []);
  const cwes = parseJson<string[]>(row.cwes_json, []);
  // Only web links are drawn as links; a reference that is not http(s) is not one to follow.
  const references = uniqueRefs(parseJson<{ url: string; tags: string[] }[]>(row.references_json, []).filter((r) => /^https?:\/\//i.test(r.url)));
  const ssvc = parseJson<Record<string, string>>(row.ssvc_json, {});
  // The watchlist is the owner's: a visitor sees the CVE, not whether the owner runs it.
  const watch = owner ? parseJson<string[]>(row.watch_labels_json, []) : [];
  const msrc = msrcFlags(db, [row.cve_id]).get(row.cve_id);
  const news = newsFor(db, row.cve_id, 10);
  const changes = vulnChanges(db, row.cve_id);
  const fix = fixesFor(db, fixContext(db), row);

  const content = html`
    ${row.vuln_status === "Rejected" ? html`<p class="notice error" role="note"><b>Rejected.</b> The body that assigned this id has withdrawn it, usually as a duplicate or as not a vulnerability. It is left out of the table, the counts and Today; what follows is kept as history. <a href="/vulnerabilities?rejected=1">Other rejected ids</a>.</p>` : ""}
    <div class="vuln-head">
      <div>
        <h1>${row.cve_id}</h1>
        <div class="chips">
          ${severityChip(row)}
          ${row.epss !== null ? html`<span class="chip${row.epss >= 0.5 ? " kev" : ""}" title="FIRST EPSS: the estimated probability of exploitation in the next 30 days${row.epss_percentile !== null ? `, percentile ${((row.epss_percentile ?? 0) * 100).toFixed(0)}%` : ""}">EPSS ${epssText(row)}</span>` : ""}
          ${row.kev ? kevChip(row.kev_due_date, now) : ""}
          ${row.kev_ransomware ? html`<a class="chip kev" href="/vulnerabilities?ransomware=1" title="CISA marks this KEV entry as known to be used in ransomware campaigns">ransomware</a>` : ""}
          ${exploitChip(exploitTallies(db, [row.cve_id]).get(row.cve_id))}
          ${msrc?.exploited ? html`<span class="chip kev">Microsoft: exploited</span>` : ""}${msrc?.disclosed ? html`<span class="chip exploit">publicly disclosed</span>` : ""}
          ${watch.length ? html`<span class="chip mine">your stack: ${watch.join(", ")}</span>` : ""}
          ${ssvc.exploitation ? html`<span class="chip ${ssvc.exploitation === "active" ? "kev" : ""}">${ssvcExploitation(ssvc.exploitation)}</span>` : ""}
          <span class="chip">${row.vuln_status ?? "status unknown"}</span>
        </div>
        ${row.vuln_status === "KEV only" ? html`<p class="notice warn">CISA lists this CVE as exploited in the wild, but NVD's record of it is not loaded here yet, so the scores, products and history below are empty rather than unknown to NVD. <a href="https://nvd.nist.gov/vuln/detail/${row.cve_id}" ${newTab}>Read it at NVD</a>.</p>` : ""}
      </div>
      <div class="links">${isCve ? html`<a href="https://nvd.nist.gov/vuln/detail/${row.cve_id}" ${newTab}>NVD</a> · <a href="https://www.cve.org/CVERecord?id=${row.cve_id}" ${newTab}>CVE.org</a>` : ""}${row.kev ? html` · <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${row.cve_id}" ${newTab}>CISA KEV</a>` : ""}${ghsa ? html`${isCve ? " · " : ""}<a href="https://github.com/advisories/${ghsa}" ${newTab}>GitHub advisory</a>` : ""}${osvId ? html` · <a href="https://osv.dev/vulnerability/${osvId}" ${newTab}>OSV</a>` : ""}</div>
    </div>
    <div class="cols">
      <section class="main">
        <p class="lede">${row.description ?? "No description."}</p>
        ${fixPanel(fix, parseJson<string[]>(row.platforms_json, []).includes("windows"))}
        ${exploitsBox(fix)}
        ${news.length
          ? html`<section class="box" id="news"><h2>In the news ${countOf(news.length)}</h2>
              <ul class="refs">${news.map((n) => html`<li>${n.url ? html`<a href="${n.url}" ${newTabIf(n.url)}>${n.title}</a>` : n.title} <span class="small"><a href="/?source=${n.source_id}">${n.source_name}</a>${n.published_at ? html` · ${n.published_at.slice(0, 10)}` : ""}</span></li>`)}</ul>
            </section>`
          : ""}
        <section class="box" id="history">
          <h2><a href="#history">Change history</a> ${countOf(changes.length)}</h2>
          ${changes.length
            ? html`<ol class="hist">${changes.map(
                (c) => html`<li><time>${shortStamp(c.observed_at)}</time><b>${c.field === "new" ? "First seen" : c.field === "cvss" ? "CVSS" : c.field === "kev" ? "CISA KEV" : c.field === "epss" ? "EPSS" : c.field.charAt(0).toUpperCase() + c.field.slice(1)}</b>${
                  c.field === "description" ? html`<div class="redline"><del>${c.before_text ?? ""}</del><ins>${c.after_text ?? ""}</ins></div>` : html`<span>${c.before_text ? html`${c.before_text} → ` : ""}${c.after_text ?? ""}</span>`
                }${c.nvd_modified_at ? html`<small>NVD modified ${shortStamp(c.nvd_modified_at)}</small>` : ""}</li>`,
              )}</ol>`
            : html`<p class="small">Nothing recorded yet.</p>`}
        </section>
        <section class="box" id="cpes">
          <h2><a href="#cpes">Affected (CPE criteria)</a> ${countOf(cpes.length)}</h2>
          ${cpes.length ? cpeBlock(cpes) : html`<p class="small">NVD has not attached CPE configurations yet.</p>`}
        </section>
        ${packages.length
          ? html`<section class="box" id="packages">
          <h2><a href="#packages">Affected packages</a> ${countOf(packages.length)}</h2>
          <ul class="cpes">${packages.map(
            (p) => html`<li><code>${p.ecosystem}:${p.name}</code>${p.fixed.length ? html` · fixed in ${p.fixed.join(", ")}` : p.lastAffected.length ? html` · affected through ${p.lastAffected.join(", ")}` : html` · no fix listed`}<span class="small"> · ${p.advisory}</span></li>`,
          )}</ul>
        </section>`
          : ""}
        <section class="box" id="references">
          <h2><a href="#references">References</a> ${countOf(references.length)}</h2>
          <ul class="refs">${(() => { const labels = refLabels(references); return references.slice(0, 60).map((r) => refLine(r, labels)); })()}</ul>${references.length > 60 ? html`<p class="small">and ${references.length - 60} more on <a href="https://nvd.nist.gov/vuln/detail/${row.cve_id}" ${newTab}>NVD</a></p>` : ""}
        </section>
      </section>
      <aside class="side">
        ${(() => {
            const t = getTriage(db, "vuln", row.id);
            const board = t ? `/triage#${t.state}` : "/triage";
            if (owner) return html`<section class="box" id="triage"><h2><a href="${board}">Triage</a></h2>${triageForm({ kind: "vuln", id: row.id }, t, `/vulnerabilities/${row.cve_id}#triage`)}</section>`;
            return t ? html`<section class="box" id="triage"><h2><a href="${board}">Triage</a></h2><p><a class="chip" href="${board}">${t.state}</a>${t.due_at ? html` due ${t.due_at}` : ""}</p></section>` : "";
          })()}
        <section class="box" id="scores">
          <h2><a href="#scores">Scores</a></h2>
          <dl class="kv">
            <dt>CVSS</dt><dd>${row.cvss_score !== null ? html`<a href="${severityHref(row)}">${row.cvss_score.toFixed(1)} ${row.cvss_severity ?? ""}</a> (v${row.cvss_version})<br><code class="small">${row.cvss_vector ?? ""}</code><br><span class="small">scored by ${row.cvss_source ?? "unknown"}</span>` : html`<a href="/vulnerabilities?severity=unscored">not yet scored</a>`}</dd>
            <dt>EPSS</dt><dd>${row.epss !== null ? html`<a href="/vulnerabilities?sort=epss">${epssText(row)}</a> (percentile ${((row.epss_percentile ?? 0) * 100).toFixed(0)}%, <a href="/sources#src-first-epss">${row.epss_date ?? ""}</a>)` : html`<a href="/vulnerabilities?epss=none">no score</a>`}</dd>
            <dt>KEV</dt><dd>${row.kev ? html`<a href="/vulnerabilities?kev=1">added ${row.kev_date_added ?? "?"}, due ${row.kev_due_date ?? "?"}</a>` : "not listed"}</dd>
            ${Object.keys(ssvc).length ? html`<dt>SSVC</dt><dd>${Object.entries(ssvc).map(([k, v]) => html`${k}: ${v}<br>`)}</dd>` : ""}
            <dt>CWE</dt><dd>${cwes.length ? cwes.map((c, i) => html`${i ? ", " : ""}${cweOf(c) ? html`<a href="/vulnerabilities?cwe=${encodeURIComponent(c)}" title="Every CVE NVD files under ${c}">${c}</a>` : c}`) : "—"}</dd>
            <dt>Published</dt><dd>${row.published_at ? html`<a href="/vulnerabilities?sort=published">${shortStamp(row.published_at)}</a>` : "not yet: CISA lists it, NVD's record has not arrived"}</dd>
            <dt>Modified</dt><dd><a href="/vulnerabilities">${shortStamp(row.last_modified_at)}</a> (${relativeTime(row.last_modified_at, now)})</dd>
            <dt>Source</dt><dd>${row.source_identifier ?? "—"}</dd>
            <dt>Vendors</dt><dd>${vendors.length ? vendors.map((v, i) => html`${i ? ", " : ""}<a href="/vulnerabilities?q=${encodeURIComponent(v)}">${v}</a>`) : "—"}</dd>
            <dt>Products</dt><dd>${products.length ? products.map((p, i) => html`${i ? ", " : ""}<a href="/vulnerabilities?q=${encodeURIComponent(p)}">${p}</a>`) : "—"}</dd>
            ${aliases.length ? html`<dt>Also known as</dt><dd>${aliases.join(", ")}</dd>` : ""}
          </dl>
        </section>
        ${owner ? watchBox(db, row.cve_id, cpes, vendors, products, { vendor: row.kev_vendor ?? null, product: row.kev_product ?? null }) : ""}
      </aside>
    </div>`;

  return page({ title: row.cve_id, active: "vulnerabilities", content, owner, open, look, canonical: `/vulnerabilities/${row.cve_id}`, description: `${row.cve_id}: ${(row.description ?? "no description yet").slice(0, 150)}` });
}

/**
 * A CVE id that is well formed but has no row here. It is a real question with a real answer
 * elsewhere, so the page says where to read it, and what this instance does know: whether CISA's
 * KEV catalogue lists it (that feed is stored whole, a row in the table is not) and whether the
 * News has mentioned it. Nothing on it is a verdict about the CVE.
 */
export function renderVulnNotHeld(options: { db: DatabaseSync; cveId: string; owner: boolean; open: boolean; look: LookState }): string {
  const { db, cveId, owner, open, look } = options;
  const kev = db
    .prepare("SELECT title, url, published_at FROM items WHERE kind = 'kev' AND external_id = ? ORDER BY id DESC LIMIT 1")
    .get(cveId) as { title: string; url: string | null; published_at: string | null } | undefined;
  const news = newsFor(db, cveId, 5);
  const q = encodeURIComponent(cveId);
  const content = html`
    <nav class="crumbs small" aria-label="Breadcrumb"><a href="/vulnerabilities">Vulnerabilities</a> › ${cveId}</nav>
    <h1>${cveId} is not loaded here</h1>
    <p class="lede">This site has not loaded this CVE's details. That says nothing about the CVE: the list holds what NVD and the other feeds published or changed since this site began reading them, so an older CVE that has not changed since is missing. Read the full record where it is kept:</p>
    <ul class="read-at">
      ${[
        { href: `https://www.cve.org/CVERecord?id=${q}`, name: "CVE.org record", line: "the authoritative entry, in the words of the body that assigned it", host: "cve.org" },
        { href: `https://nvd.nist.gov/vuln/detail/${q}`, name: "NVD", line: "CVSS, CWE and affected configurations as NIST analysed them", host: "nvd.nist.gov" },
        { href: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${q}`, name: "CISA KEV catalogue", line: "listed means exploited in the wild; US federal agencies have a due date", host: "cisa.gov" },
        { href: `https://api.first.org/data/v1/epss?cve=${q}`, name: "FIRST EPSS", line: "the estimated probability of exploitation in the next 30 days", host: "first.org" },
      ].map((r) => html`<li><a href="${r.href}" ${newTab}><b>${r.name}</b><span class="small">${r.line}</span><em>${r.host} ↗</em></a></li>`)}
    </ul>
    ${kev ? html`<section class="box"><h2>In CISA's KEV catalogue</h2><p>${kev.title}${kev.published_at ? html` <span class="small">added ${kev.published_at.slice(0, 10)}</span>` : ""}</p><p class="small">It is on CISA's list of vulnerabilities exploited in the wild; NVD's details for it have not been loaded here yet.</p></section>` : ""}
    ${news.length ? html`<section class="box"><h2>In the News</h2><ul>${news.map((n) => html`<li><a href="${n.url ?? "#"}" ${newTab}>${n.title}</a> <span class="small">${n.source_name}</span></li>`)}</ul></section>` : ""}
    <p class="small">Looking for something else? <a href="/search?q=${q}">Search for ${cveId}</a> or <a href="/vulnerabilities">open the table</a>.</p>`;
  return page({ title: `${cveId} not held`, active: "vulnerabilities", content, owner, open, look });
}
