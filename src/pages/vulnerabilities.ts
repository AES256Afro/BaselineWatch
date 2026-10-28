import type { DatabaseSync } from "node:sqlite";
import { exploitSourceLabel, exploitTallies, exploitWording, type ExploitTally } from "../exploits.ts";
import { fixContext, fixesFor, type Fix } from "../fix.ts";
import { figure, html, newTab, newTabIf, type Html } from "../html.ts";
import { relativeTime, shortStamp } from "../time.ts";
import { cveMentions, newsFor } from "../trending.ts";
import { getTriage } from "../triage.ts";
import { getVuln, listVulns, vulnChanges, vulnStats, type AffectedPackage, type VulnFilters, type VulnRow } from "../vulns.ts";
import type { LookState } from "../look.ts";
import { page } from "./layout.ts";
import { saveSearchForm } from "./saved.ts";
import { triageForm } from "./triage.ts";
import { parseJson } from "../json.ts";
import { msrcFlags, releaseNoteUrl } from "../msrc.ts";

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

function epssText(row: VulnRow): string {
  if (row.epss === null) return "—";
  return `${(row.epss * 100).toFixed(row.epss < 0.01 ? 2 : 1)}%`;
}

function query(filters: VulnFilters, overrides: Partial<VulnFilters>): string {
  const f = { ...filters, ...overrides };
  const p = new URLSearchParams();
  if (f.watch) p.set("watch", "1");
  if (f.kev) p.set("kev", "1");
  if (f.exploit) p.set("exploit", "1");
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

export interface VulnListOptions {
  db: DatabaseSync;
  filters: VulnFilters;
  owner: boolean;
  open: boolean;
  now: Date;
  look: LookState;
}

export function renderVulnList({ db, filters, owner, open, now, look }: VulnListOptions): string {
  const limit = 50;
  const { rows, total } = listVulns(db, { ...filters, limit });
  const since = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
  const stats = vulnStats(db, since);
  const epssDate = (db.prepare("SELECT value FROM app_settings WHERE key = 'epss.date'").get() as { value: string } | undefined)?.value;
  const cursor = (db.prepare("SELECT value FROM app_settings WHERE key = 'nvd.cursor'").get() as { value: string } | undefined)?.value;
  const offset = filters.offset ?? 0;
  const none = !filters.watch && !filters.kev && !filters.exploit && filters.minCvss === undefined && !filters.severity && filters.minEpss === undefined && filters.maxEpss === undefined && !filters.noEpss && !filters.changedSince && !filters.newSince && !filters.movedSince && !filters.label;
  // A band the Today page sent us into, shown as a chip that takes it off again.
  const pct = (n: number) => `${Math.round(n * 100)}%`;
  const epssBand = filters.noEpss ? "no score" : filters.maxEpss !== undefined ? `${filters.minEpss !== undefined ? `${pct(filters.minEpss)} to ` : "under "}${pct(filters.maxEpss)}` : null;
  // The window a chip names: the Today page's 3 or 7 days read as such, so the figure clicked and the list shown agree.
  const windowWord = (h: number | undefined): string => (h === undefined || h === 24 ? "24 h" : h % 24 === 0 ? `${h / 24} days` : `${h} h`);

  const exploits = exploitTallies(db, rows.map((r) => r.cve_id));
  const microsoft = msrcFlags(db, rows.map((r) => r.cve_id));
  // Named by two or more sources this week: being talked about, whatever the score.
  const mentions = cveMentions(db, rows.map((r) => r.cve_id), new Date(now.getTime() - 7 * 86_400_000).toISOString());
  const tableRows = rows.map((r) => {
    const vendors = parseJson<string[]>(r.vendors_json, []);
    const products = parseJson<string[]>(r.products_json, []);
    const packages = parseJson<AffectedPackage[]>(r.packages_json, []);
    const who = [...new Set([...vendors.slice(0, 2), ...products.slice(0, 3)])].join(", ") || packages.slice(0, 3).map((p) => `${p.ecosystem}:${p.name}`).join(", ");
    const watch = parseJson<string[]>(r.watch_labels_json, []);
    return html`<tr class="${r.watch_hit ? "hit" : ""}">
      <td class="id"><a href="/vulnerabilities/${r.cve_id}">${r.cve_id}</a>${r.kev ? html`<span class="chip kev">KEV</span>` : ""}${exploitChip(exploits.get(r.cve_id))}${microsoft.get(r.cve_id)?.exploited ? html`<span class="chip kev" title="Microsoft reports this CVE exploited">exploited</span>` : ""}${(mentions.get(r.cve_id)?.sources ?? 0) >= 2 ? html`<span class="chip news" title="Named by ${mentions.get(r.cve_id)?.sources} sources in the last 7 days">news ×${mentions.get(r.cve_id)?.sources}</span>` : ""}${watch.length ? html`<span class="chip mine">${watch.join(", ")}</span>` : ""}</td>
      <td>${severityChip(r)}</td>
      <td class="n" title="EPSS ${r.epss ?? ""} · percentile ${r.epss_percentile ?? ""}">${epssText(r)}</td>
      <td class="who">${who || html`<span class="small">no CPE yet</span>`}</td>
      <td class="desc"><span>${r.description ?? ""}</span></td>
      <td class="n when" title="${shortStamp(r.last_modified_at)}">${relativeTime(r.last_modified_at, now)}</td>
    </tr>`;
  });

  const feedQuery = query(filters, { offset: 0 });
  const feed = { href: `/vulnerabilities/feed.xml${feedQuery.slice("/vulnerabilities".length)}`, title: "Vulnerabilities" };
  // The same rows, in the same order, as a file: into a ticket or a spreadsheet.
  const csvHref = `/vulnerabilities.csv${feedQuery.slice("/vulnerabilities".length)}`;
  const content = html`
    <div class="stats" aria-label="Totals">
      <a href="/vulnerabilities"><small>CVEs known</small><b>${figure(stats.total)}</b></a>
      <a href="/vulnerabilities?new=1"><small>New, 24 h</small><b>${figure(stats.newSince)}</b></a>
      <a href="/vulnerabilities?changed=1"><small>Changed, 24 h</small><b>${figure(stats.changedSince)}</b></a>
      <a href="/vulnerabilities?kev=1"><small>In KEV</small><b>${figure(stats.kev)}</b></a>
      <a href="/vulnerabilities?exploit=1"><small>Public exploit</small><b>${figure(stats.exploit)}</b></a>
      <a href="/vulnerabilities?watch=1"><small>Match watchlist</small><b>${figure(stats.watch)}</b></a>
    </div>
    <div class="wire-top">
      <h1>Vulnerabilities</h1>
      ${saveSearchForm(db, query(filters, { offset: 0 }), owner)}
      <form method="get" action="/vulnerabilities" class="search" role="search">
        ${filters.watch ? html`<input type="hidden" name="watch" value="1">` : ""}
        ${filters.kev ? html`<input type="hidden" name="kev" value="1">` : ""}
        ${filters.exploit ? html`<input type="hidden" name="exploit" value="1">` : ""}
        <label class="visually-hidden" for="q">Search CVEs</label>
        <input type="search" id="q" name="q" value="${filters.q ?? ""}" placeholder="CVE id, vendor, product or words in the description">
        <button type="submit">Search</button>
      </form>
    </div>
    <div class="filters">
      <a class="${none ? "on" : ""}" href="${query(filters, { watch: false, kev: false, exploit: false, minCvss: undefined, severity: undefined, minEpss: undefined, maxEpss: undefined, noEpss: false, changedSince: undefined, newSince: undefined, movedSince: undefined, movedHours: undefined, label: undefined, offset: 0 })}">All</a>
      <a class="${filters.watch ? "on" : ""}" href="${query(filters, { watch: !filters.watch, offset: 0 })}">My stack</a>
      <a class="${filters.kev ? "on" : ""}" href="${query(filters, { kev: !filters.kev, offset: 0 })}">Known exploited</a>
      <a class="${filters.exploit ? "on" : ""}" href="${query(filters, { exploit: !filters.exploit, offset: 0 })}">Public exploit</a>
      <a class="${filters.minCvss === 9 ? "on" : ""}" href="${query(filters, { minCvss: filters.minCvss === 9 ? undefined : 9, offset: 0 })}">Critical (9+)</a>
      <a class="${filters.minEpss === 0.5 ? "on" : ""}" href="${query(filters, { minEpss: filters.minEpss === 0.5 ? undefined : 0.5, offset: 0 })}">Likely exploited (EPSS ≥ 50%)</a>
      <a class="${filters.changedSince ? "on" : ""}" href="${query(filters, { changedSince: filters.changedSince ? undefined : since, changedHours: undefined, offset: 0 })}">Changed, ${windowWord(filters.changedSince ? filters.changedHours : undefined)}</a>
      <a class="${filters.newSince ? "on" : ""}" href="${query(filters, { newSince: filters.newSince ? undefined : since, newHours: undefined, offset: 0 })}">New, ${windowWord(filters.newSince ? filters.newHours : undefined)}</a>
      ${filters.movedSince ? html`<a class="on" href="${query(filters, { movedSince: undefined, movedHours: undefined, offset: 0 })}" title="Published or really changed, as Today counts them">Moved, ${windowWord(filters.movedHours)} ×</a>` : ""}
      ${filters.label ? html`<a class="on" href="${query(filters, { label: undefined, offset: 0 })}">Watch: ${filters.label} ×</a>` : ""}
      ${filters.severity ? html`<a class="on" href="${query(filters, { severity: undefined, offset: 0 })}">CVSS ${filters.severity} ×</a>` : ""}
      ${epssBand ? html`<a class="on" href="${query(filters, { minEpss: undefined, maxEpss: undefined, noEpss: false, offset: 0 })}">EPSS ${epssBand} ×</a>` : ""}
      <span class="sort">Sort:
        <a class="${(filters.sort ?? "risk") === "risk" ? "on" : ""}" href="${query(filters, { sort: "risk", offset: 0 })}" title="Known exploited first, then a public exploit, then EPSS, then CVSS, then how recently it changed">risk</a>
        <a class="${filters.sort === "modified" ? "on" : ""}" href="${query(filters, { sort: "modified", offset: 0 })}">modified</a>
        <a class="${filters.sort === "published" ? "on" : ""}" href="${query(filters, { sort: "published", offset: 0 })}">published</a>
        <a class="${filters.sort === "cvss" ? "on" : ""}" href="${query(filters, { sort: "cvss", offset: 0 })}">CVSS</a>
        <a class="${filters.sort === "epss" ? "on" : ""}" href="${query(filters, { sort: "epss", offset: 0 })}">EPSS</a>
      </span>
    </div>
    ${rows.length === 0
      ? html`<div class="empty"><b>${total === 0 && stats.total === 0 ? "No CVEs yet." : "No CVEs match."}</b><p>${stats.total === 0 ? "The NVD source pulls every CVE modified in its backfill window (seven days unless BW_NVD_BACKFILL_DAYS says otherwise) on its first run; the owner can start it now from the Sources page." : "Loosen a filter or search differently."}</p></div>`
      : html`<div class="table-wrap"><table class="vulns"><caption class="visually-hidden">CVEs</caption>
          <thead><tr><th scope="col">CVE</th><th scope="col">CVSS</th><th scope="col">EPSS</th><th scope="col">Vendor, product</th><th scope="col">Description</th><th scope="col">Modified</th></tr></thead>
          <tbody>${tableRows}</tbody>
        </table></div>
        <p class="more">${offset + rows.length} of ${total}${offset + rows.length < total ? html` · <a href="${query(filters, { offset: offset + limit })}">Next</a>` : ""}${offset > 0 ? html` · <a href="${query(filters, { offset: Math.max(0, offset - limit) })}">Previous</a>` : ""}</p>`}
    <p class="small"><a href="${csvHref}">Download these ${Math.min(total, 1000)} as CSV</a>${total > 1000 ? " (the first thousand in this order)" : ""} · <a href="${feed.href}">subscribe to this list</a>.</p>
    <p class="small">EPSS scores: ${epssDate ? html`<a href="/sources#src-first-epss">${epssDate}</a>` : html`none pulled yet — <a href="/sources#src-first-epss">Sources</a>`}. NVD cursor: ${cursor ? html`<a href="/sources#src-nvd-cves">${shortStamp(cursor)}</a>` : html`no pull yet — <a href="/sources#src-nvd-cves">Sources</a> shows each feed's state and what to do when one fails`}. The <a href="/?kind=vulnerability">News page</a> shows only notable CVEs (KEV, your stack, new criticals, EPSS over 50%, or active exploitation per SSVC); this table has all of them.</p>`;

  return page({ title: "Vulnerabilities", active: "vulnerabilities", content, meta: html`${stats.total} CVEs · ${stats.kev} in KEV`, owner, open, look, feed, canonical: "/vulnerabilities", description: "Every CVE as NVD, CISA and FIRST describe it: CVSS, EPSS, KEV, public exploits, and the fix published for each." });
}

/** The Fix panel: what has been published that fixes or mitigates the CVE, quoted and linked, or an honest empty. */
function fixPanel(fix: Fix): Html {
  const exploits = fix.exploits.length
    ? html`<h3 class="small">Public exploits <span class="count">${fix.exploits.length}</span></h3>
        <ul class="refs">${fix.exploits.slice(0, 20).map((e) => html`<li><a href="${e.url}" ${newTab}>${e.title}</a> <span class="small">${exploitSourceLabel[e.source_id] ?? e.source_id}${e.verified ? " · verified" : ""}${e.published_at ? html` · ${e.published_at.slice(0, 10)}` : ""}</span></li>`)}${fix.exploits.length > 20 ? html`<li class="small">and ${fix.exploits.length - 20} more</li>` : ""}</ul>
        <p class="small">Each line links to the index that lists it, never to exploit code. Exploit-DB's "verified" and a Metasploit rank of good or better count as verified; a PoC-in-GitHub entry is a repository's claim.</p>`
    : html``;
  const ms = fix.microsoft;
  const microsoft = ms?.fixes.length
    ? html`<h3 class="small">Microsoft's update${ms.severity ? html` · ${ms.severity}` : ""}${ms.exploited ? html` · exploited` : ""}${ms.disclosed ? html` · publicly disclosed` : ""}</h3>
        <ul class="refs">${ms.fixes.map((f) => html`<li>${f.url ? html`<a href="${f.url}" ${newTab}>${f.kb ? `KB${f.kb}` : (f.label ?? f.url)}</a>` : (f.label ?? "")}${f.products.length ? html` — ${f.products.join(", ")}` : ""}${f.fixedBuild ? html` <span class="small">· build ${f.fixedBuild}</span>` : ""}${f.restart ? html` <span class="small">· restart required</span>` : ""}</li>`)}</ul>
        <p class="small">From the <a href="${releaseNoteUrl(ms.release_id)}" ${newTab}>${ms.release_id} release note</a> of Microsoft's Security Update Guide${ms.revised_at ? html`, revised ${ms.revised_at.slice(0, 10)}` : ""}${ms.exploitability ? html` · ${ms.exploitability}` : ""}.</p>`
    : html``;
  if (fix.empty) {
    return html`<section class="box fix empty-fix"><h2>Fix</h2><p class="small">Nothing published yet: no patch, vendor advisory or mitigation reference on NVD, no vendor advisory in the News for this CVE, not in CISA's KEV, no fixed package version. BaselineWatch does not guess at one.</p>${exploits}</section>`;
  }
  return html`<section class="box fix">
    <h2>Fix</h2>
    ${microsoft}
    ${exploits}
    ${fix.kev?.requiredAction
      ? html`<div class="fix-kev"><h3 class="small">CISA KEV required action${fix.kev.dueDate ? html` · due ${fix.kev.dueDate}` : ""}</h3><p>${fix.kev.requiredAction}</p>${fix.kev.dateAdded ? html`<p class="small">Added to the catalog ${fix.kev.dateAdded}. <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${fix.cveId}" ${newTab}>CISA KEV</a></p>` : ""}</div>`
      : ""}
    ${fix.references.length
      ? html`<h3 class="small">Patch, vendor advisory and mitigation references on NVD <span class="count">${fix.references.length}</span></h3>
          <ul class="refs">${fix.references.slice(0, 20).map((r) => html`<li>${/^https?:\/\//i.test(r.url) ? html`<a href="${r.url}" ${newTabIf(r.url)}>${r.url}</a>` : r.url} <span class="small">${r.tags.join(", ")}</span></li>`)}</ul>`
      : ""}
    ${fix.advisories.length
      ? html`<h3 class="small">Vendor advisories in the News <span class="count">${fix.advisories.length}</span></h3>
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
  const references = parseJson<{ url: string; tags: string[] }[]>(row.references_json, []).filter((r) => /^https?:\/\//i.test(r.url));
  const ssvc = parseJson<Record<string, string>>(row.ssvc_json, {});
  const watch = parseJson<string[]>(row.watch_labels_json, []);
  const msrc = msrcFlags(db, [row.cve_id]).get(row.cve_id);
  const news = newsFor(db, row.cve_id, 10);
  const changes = vulnChanges(db, row.cve_id);
  const fix = fixesFor(db, fixContext(db), row);

  const content = html`
    <div class="vuln-head">
      <div>
        <h1>${row.cve_id}</h1>
        <div class="chips">
          ${severityChip(row)}
          ${row.kev ? html`<span class="chip kev">KEV${row.kev_due_date ? html` · due ${row.kev_due_date}` : ""}</span>` : ""}
          ${row.kev_ransomware ? html`<span class="chip kev">ransomware</span>` : ""}
          ${exploitChip(exploitTallies(db, [row.cve_id]).get(row.cve_id))}
          ${msrc?.exploited ? html`<span class="chip kev">Microsoft: exploited</span>` : ""}${msrc?.disclosed ? html`<span class="chip exploit">publicly disclosed</span>` : ""}
          ${watch.length ? html`<span class="chip mine">your stack: ${watch.join(", ")}</span>` : ""}
          ${ssvc.exploitation ? html`<span class="chip ${ssvc.exploitation === "active" ? "kev" : ""}">SSVC exploitation: ${ssvc.exploitation}</span>` : ""}
          <span class="chip">${row.vuln_status ?? "status unknown"}</span>
        </div>
      </div>
      <div class="links">${isCve ? html`<a href="https://nvd.nist.gov/vuln/detail/${row.cve_id}" ${newTab}>NVD</a> · <a href="https://www.cve.org/CVERecord?id=${row.cve_id}" ${newTab}>CVE.org</a>` : ""}${row.kev ? html` · <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${row.cve_id}" ${newTab}>CISA KEV</a>` : ""}${ghsa ? html`${isCve ? " · " : ""}<a href="https://github.com/advisories/${ghsa}" ${newTab}>GitHub advisory</a>` : ""}${osvId ? html` · <a href="https://osv.dev/vulnerability/${osvId}" ${newTab}>OSV</a>` : ""}</div>
    </div>
    <div class="cols">
      <section class="main">
        <p class="lede">${row.description ?? "No description."}</p>
        ${fixPanel(fix)}
        ${news.length
          ? html`<section class="box" id="news"><h2>In the news <span class="count">${news.length}</span></h2>
              <ul class="refs">${news.map((n) => html`<li>${n.url ? html`<a href="${n.url}" ${newTabIf(n.url)}>${n.title}</a>` : n.title} <span class="small"><a href="/?source=${n.source_id}">${n.source_name}</a>${n.published_at ? html` · ${n.published_at.slice(0, 10)}` : ""}</span></li>`)}</ul>
            </section>`
          : ""}
        <section class="box" id="history">
          <h2><a href="#history">Change history</a> <span class="count"><a href="#history">${changes.length}</a></span></h2>
          ${changes.length
            ? html`<ol class="hist">${changes.map(
                (c) => html`<li><time>${shortStamp(c.observed_at)}</time><b>${c.field === "new" ? "First seen" : c.field === "cvss" ? "CVSS" : c.field === "kev" ? "CISA KEV" : c.field === "epss" ? "EPSS" : c.field.charAt(0).toUpperCase() + c.field.slice(1)}</b>${
                  c.field === "description" ? html`<div class="redline"><del>${c.before_text ?? ""}</del><ins>${c.after_text ?? ""}</ins></div>` : html`<span>${c.before_text ? html`${c.before_text} → ` : ""}${c.after_text ?? ""}</span>`
                }${c.nvd_modified_at ? html`<small>NVD modified ${shortStamp(c.nvd_modified_at)}</small>` : ""}</li>`,
              )}</ol>`
            : html`<p class="small">Nothing recorded yet.</p>`}
        </section>
        <section class="box" id="cpes">
          <h2><a href="#cpes">Affected (CPE criteria)</a> <span class="count"><a href="#cpes">${cpes.length}</a></span></h2>
          ${cpes.length ? html`<ul class="cpes">${cpes.slice(0, 40).map((c) => html`<li><code>${c}</code></li>`)}${cpes.length > 40 ? html`<li class="small">and ${cpes.length - 40} more</li>` : ""}</ul>` : html`<p class="small">NVD has not attached CPE configurations yet.</p>`}
        </section>
        ${packages.length
          ? html`<section class="box" id="packages">
          <h2><a href="#packages">Affected packages</a> <span class="count"><a href="#packages">${packages.length}</a></span></h2>
          <ul class="cpes">${packages.map(
            (p) => html`<li><code>${p.ecosystem}:${p.name}</code>${p.fixed.length ? html` · fixed in ${p.fixed.join(", ")}` : p.lastAffected.length ? html` · affected through ${p.lastAffected.join(", ")}` : html` · no fix listed`}<span class="small"> · ${p.advisory}</span></li>`,
          )}</ul>
        </section>`
          : ""}
        <section class="box" id="references">
          <h2><a href="#references">References</a> <span class="count"><a href="#references">${references.length}</a></span></h2>
          <ul class="refs">${references.slice(0, 60).map((r) => html`<li><a href="${r.url}" ${newTabIf(r.url)}>${r.url}</a>${r.tags.length ? html` <span class="small">${r.tags.join(", ")}</span>` : ""}</li>`)}</ul>
        </section>
      </section>
      <aside class="side">
        ${(() => {
            const t = getTriage(db, "vuln", row.id);
            const board = t ? `/triage#${t.state}` : "/triage";
            if (owner) return html`<section class="box" id="triage"><h2><a href="${board}">Triage</a></h2>${triageForm({ kind: "vuln", id: row.id }, t, `/vulnerabilities/${row.cve_id}`)}</section>`;
            return t ? html`<section class="box" id="triage"><h2><a href="${board}">Triage</a></h2><p><a class="chip" href="${board}">${t.state}</a>${t.due_at ? html` due ${t.due_at}` : ""}</p></section>` : "";
          })()}
        <section class="box" id="scores">
          <h2><a href="#scores">Scores</a></h2>
          <dl class="kv">
            <dt>CVSS</dt><dd>${row.cvss_score !== null ? html`<a href="${severityHref(row)}">${row.cvss_score.toFixed(1)} ${row.cvss_severity ?? ""}</a> (v${row.cvss_version})<br><code class="small">${row.cvss_vector ?? ""}</code><br><span class="small">scored by ${row.cvss_source ?? "unknown"}</span>` : html`<a href="/vulnerabilities?severity=unscored">not yet scored</a>`}</dd>
            <dt>EPSS</dt><dd>${row.epss !== null ? html`<a href="/vulnerabilities?sort=epss">${epssText(row)}</a> (percentile ${((row.epss_percentile ?? 0) * 100).toFixed(0)}%, <a href="/sources#src-first-epss">${row.epss_date ?? ""}</a>)` : html`<a href="/vulnerabilities?epss=none">no score</a>`}</dd>
            <dt>KEV</dt><dd>${row.kev ? html`<a href="/vulnerabilities?kev=1">added ${row.kev_date_added ?? "?"}, due ${row.kev_due_date ?? "?"}</a>` : "not listed"}</dd>
            ${Object.keys(ssvc).length ? html`<dt>SSVC</dt><dd>${Object.entries(ssvc).map(([k, v]) => html`${k}: ${v}<br>`)}</dd>` : ""}
            <dt>CWE</dt><dd>${cwes.length ? cwes.map((c, i) => html`${i ? ", " : ""}<a href="/vulnerabilities?q=${encodeURIComponent(c)}">${c}</a>`) : "—"}</dd>
            <dt>Published</dt><dd><a href="/vulnerabilities?sort=published">${shortStamp(row.published_at)}</a></dd>
            <dt>Modified</dt><dd><a href="/vulnerabilities">${shortStamp(row.last_modified_at)}</a> (${relativeTime(row.last_modified_at, now)})</dd>
            <dt>Source</dt><dd>${row.source_identifier ?? "—"}</dd>
            <dt>Vendors</dt><dd>${vendors.length ? vendors.map((v, i) => html`${i ? ", " : ""}<a href="/vulnerabilities?q=${encodeURIComponent(v)}">${v}</a>`) : "—"}</dd>
            <dt>Products</dt><dd>${products.length ? products.map((p, i) => html`${i ? ", " : ""}<a href="/vulnerabilities?q=${encodeURIComponent(p)}">${p}</a>`) : "—"}</dd>
            ${aliases.length ? html`<dt>Also known as</dt><dd>${aliases.join(", ")}</dd>` : ""}
          </dl>
        </section>
      </aside>
    </div>`;

  return page({ title: row.cve_id, active: "vulnerabilities", content, owner, open, look, canonical: `/vulnerabilities/${row.cve_id}`, description: `${row.cve_id}: ${(row.description ?? "no description yet").slice(0, 150)}` });
}
