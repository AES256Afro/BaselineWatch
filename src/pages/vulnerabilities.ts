import type { DatabaseSync } from "node:sqlite";
import { html, newTab, newTabIf, type Html } from "../html.ts";
import { relativeTime, shortStamp } from "../time.ts";
import { getTriage } from "../triage.ts";
import { getVuln, listVulns, vulnChanges, vulnStats, type AffectedPackage, type VulnFilters, type VulnRow } from "../vulns.ts";
import { page } from "./layout.ts";
import { triageForm } from "./triage.ts";

function parseJson<T>(text: string | null, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

function severityChip(row: VulnRow): Html {
  if (row.cvss_score === null) return html`<span class="chip">unscored</span>`;
  const level = (row.cvss_severity ?? "").toLowerCase() || (row.cvss_score >= 9 ? "critical" : row.cvss_score >= 7 ? "high" : row.cvss_score >= 4 ? "medium" : "low");
  return html`<span class="chip sev ${level}" title="CVSS ${row.cvss_version ?? ""} ${row.cvss_vector ?? ""}">${row.cvss_score.toFixed(1)} ${level}</span>`;
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
  if (f.minCvss !== undefined) p.set("min_cvss", String(f.minCvss));
  if (f.minEpss !== undefined) p.set("min_epss", String(f.minEpss));
  if (f.changedSince) p.set("changed", "1");
  if (f.q) p.set("q", f.q);
  if (f.sort && f.sort !== "modified") p.set("sort", f.sort);
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
}

export function renderVulnList({ db, filters, owner, open, now }: VulnListOptions): string {
  const limit = 50;
  const { rows, total } = listVulns(db, { ...filters, limit });
  const since = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
  const stats = vulnStats(db, since);
  const epssDate = (db.prepare("SELECT value FROM app_settings WHERE key = 'epss.date'").get() as { value: string } | undefined)?.value;
  const cursor = (db.prepare("SELECT value FROM app_settings WHERE key = 'nvd.cursor'").get() as { value: string } | undefined)?.value;
  const offset = filters.offset ?? 0;
  const none = !filters.watch && !filters.kev && filters.minCvss === undefined && filters.minEpss === undefined && !filters.changedSince;

  const tableRows = rows.map((r) => {
    const vendors = parseJson<string[]>(r.vendors_json, []);
    const products = parseJson<string[]>(r.products_json, []);
    const packages = parseJson<AffectedPackage[]>(r.packages_json, []);
    const who = [...new Set([...vendors.slice(0, 2), ...products.slice(0, 3)])].join(", ") || packages.slice(0, 3).map((p) => `${p.ecosystem}:${p.name}`).join(", ");
    const watch = parseJson<string[]>(r.watch_labels_json, []);
    return html`<tr class="${r.watch_hit ? "hit" : ""}">
      <td class="id"><a href="/vulnerabilities/${r.cve_id}">${r.cve_id}</a>${r.kev ? html`<span class="chip kev">KEV</span>` : ""}${watch.length ? html`<span class="chip mine">${watch.join(", ")}</span>` : ""}</td>
      <td>${severityChip(r)}</td>
      <td class="n" title="EPSS ${r.epss ?? ""} · percentile ${r.epss_percentile ?? ""}">${epssText(r)}</td>
      <td class="who">${who || html`<span class="small">no CPE yet</span>`}</td>
      <td class="desc"><span>${r.description ?? ""}</span></td>
      <td class="n when" title="${shortStamp(r.last_modified_at)}">${relativeTime(r.last_modified_at, now)}</td>
    </tr>`;
  });

  const content = html`
    <div class="stats" aria-label="Totals">
      <div><small>CVEs known</small><b>${stats.total}</b></div>
      <div><small>New, 24 h</small><b>${stats.newSince}</b></div>
      <div><small>Changed, 24 h</small><b>${stats.changedSince}</b></div>
      <div><small>In KEV</small><b>${stats.kev}</b></div>
      <div><small>Match watchlist</small><b>${stats.watch}</b></div>
      <div><small>EPSS scores</small><b>${epssDate ?? "—"}</b></div>
    </div>
    <div class="wire-top">
      <h1>Vulnerabilities</h1>
      <form method="get" action="/vulnerabilities" class="search" role="search">
        ${filters.watch ? html`<input type="hidden" name="watch" value="1">` : ""}
        ${filters.kev ? html`<input type="hidden" name="kev" value="1">` : ""}
        <label class="visually-hidden" for="q">Search CVEs</label>
        <input type="search" id="q" name="q" value="${filters.q ?? ""}" placeholder="CVE id, vendor, product or words in the description">
        <button type="submit">Search</button>
      </form>
    </div>
    <div class="filters">
      <a class="${none ? "on" : ""}" href="${query(filters, { watch: false, kev: false, minCvss: undefined, minEpss: undefined, changedSince: undefined, offset: 0 })}">All</a>
      <a class="${filters.watch ? "on" : ""}" href="${query(filters, { watch: !filters.watch, offset: 0 })}">My stack</a>
      <a class="${filters.kev ? "on" : ""}" href="${query(filters, { kev: !filters.kev, offset: 0 })}">Known exploited</a>
      <a class="${filters.minCvss === 9 ? "on" : ""}" href="${query(filters, { minCvss: filters.minCvss === 9 ? undefined : 9, offset: 0 })}">Critical (9+)</a>
      <a class="${filters.minEpss === 0.5 ? "on" : ""}" href="${query(filters, { minEpss: filters.minEpss === 0.5 ? undefined : 0.5, offset: 0 })}">Likely exploited (EPSS ≥ 50%)</a>
      <a class="${filters.changedSince ? "on" : ""}" href="${query(filters, { changedSince: filters.changedSince ? undefined : since, offset: 0 })}">Changed, 24 h</a>
      <span class="sort">Sort:
        <a class="${(filters.sort ?? "modified") === "modified" ? "on" : ""}" href="${query(filters, { sort: "modified", offset: 0 })}">modified</a>
        <a class="${filters.sort === "published" ? "on" : ""}" href="${query(filters, { sort: "published", offset: 0 })}">published</a>
        <a class="${filters.sort === "cvss" ? "on" : ""}" href="${query(filters, { sort: "cvss", offset: 0 })}">CVSS</a>
        <a class="${filters.sort === "epss" ? "on" : ""}" href="${query(filters, { sort: "epss", offset: 0 })}">EPSS</a>
      </span>
    </div>
    ${rows.length === 0
      ? html`<div class="empty"><b>${total === 0 && stats.total === 0 ? "No CVEs yet." : "No CVEs match."}</b><p>${stats.total === 0 ? "The NVD source pulls every CVE modified in the last days on its first run; the owner can start it now from the Sources page." : "Loosen a filter or search differently."}</p></div>`
      : html`<div class="table-wrap"><table class="vulns">
          <thead><tr><th>CVE</th><th>CVSS</th><th>EPSS</th><th>Vendor, product</th><th>Description</th><th>Modified</th></tr></thead>
          <tbody>${tableRows}</tbody>
        </table></div>
        <p class="more">${offset + rows.length} of ${total}${offset + rows.length < total ? html` · <a href="${query(filters, { offset: offset + limit })}">Next</a>` : ""}${offset > 0 ? html` · <a href="${query(filters, { offset: Math.max(0, offset - limit) })}">Previous</a>` : ""}</p>`}
    <p class="small">NVD cursor: ${cursor ? shortStamp(cursor) : "no pull yet"}. The Wire shows only notable CVEs (KEV, your stack, new criticals, EPSS over 50%, or active exploitation per SSVC); this table has all of them.</p>`;

  return page({ title: "Vulnerabilities", active: "vulnerabilities", content, meta: html`${stats.total} CVEs · ${stats.kev} in KEV`, owner, open });
}

export function renderVulnDetail(options: { db: DatabaseSync; cveId: string; owner: boolean; open: boolean; now: Date }): string | null {
  const { db, cveId, owner, open, now } = options;
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
  const references = parseJson<{ url: string; tags: string[] }[]>(row.references_json, []);
  const ssvc = parseJson<Record<string, string>>(row.ssvc_json, {});
  const watch = parseJson<string[]>(row.watch_labels_json, []);
  const changes = vulnChanges(db, row.cve_id);

  const content = html`
    <div class="vuln-head">
      <div>
        <h1>${row.cve_id}</h1>
        <div class="chips">
          ${severityChip(row)}
          ${row.kev ? html`<span class="chip kev">KEV${row.kev_due_date ? html` · due ${row.kev_due_date}` : ""}</span>` : ""}
          ${row.kev_ransomware ? html`<span class="chip kev">ransomware</span>` : ""}
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
        <section class="box">
          <h2>Change history <span class="count">${changes.length}</span></h2>
          ${changes.length
            ? html`<ol class="hist">${changes.map(
                (c) => html`<li><time>${shortStamp(c.observed_at)}</time><b>${c.field === "new" ? "First seen" : c.field === "cvss" ? "CVSS" : c.field === "kev" ? "CISA KEV" : c.field === "epss" ? "EPSS" : c.field.charAt(0).toUpperCase() + c.field.slice(1)}</b>${
                  c.field === "description" ? html`<div class="redline"><del>${c.before_text ?? ""}</del><ins>${c.after_text ?? ""}</ins></div>` : html`<span>${c.before_text ? html`${c.before_text} → ` : ""}${c.after_text ?? ""}</span>`
                }${c.nvd_modified_at ? html`<small>NVD modified ${shortStamp(c.nvd_modified_at)}</small>` : ""}</li>`,
              )}</ol>`
            : html`<p class="small">Nothing recorded yet.</p>`}
        </section>
        <section class="box">
          <h2>Affected (CPE criteria) <span class="count">${cpes.length}</span></h2>
          ${cpes.length ? html`<ul class="cpes">${cpes.slice(0, 40).map((c) => html`<li><code>${c}</code></li>`)}${cpes.length > 40 ? html`<li class="small">and ${cpes.length - 40} more</li>` : ""}</ul>` : html`<p class="small">NVD has not attached CPE configurations yet.</p>`}
        </section>
        ${packages.length
          ? html`<section class="box">
          <h2>Affected packages <span class="count">${packages.length}</span></h2>
          <ul class="cpes">${packages.map(
            (p) => html`<li><code>${p.ecosystem}:${p.name}</code>${p.fixed.length ? html` · fixed in ${p.fixed.join(", ")}` : p.lastAffected.length ? html` · affected through ${p.lastAffected.join(", ")}` : html` · no fix listed`}<span class="small"> · ${p.advisory}</span></li>`,
          )}</ul>
        </section>`
          : ""}
        <section class="box">
          <h2>References <span class="count">${references.length}</span></h2>
          <ul class="refs">${references.slice(0, 60).map((r) => html`<li><a href="${r.url}" ${newTabIf(r.url)}>${r.url}</a>${r.tags.length ? html` <span class="small">${r.tags.join(", ")}</span>` : ""}</li>`)}</ul>
        </section>
      </section>
      <aside class="side">
        ${owner
          ? html`<section class="box"><h2>Triage</h2>${triageForm({ kind: "vuln", id: row.id }, getTriage(db, "vuln", row.id), `/vulnerabilities/${row.cve_id}`)}</section>`
          : (() => {
              const t = getTriage(db, "vuln", row.id);
              return t ? html`<section class="box"><h2>Triage</h2><p><span class="chip">${t.state}</span>${t.due_at ? html` due ${t.due_at}` : ""}</p>${t.note ? html`<p class="small">${t.note}</p>` : ""}</section>` : "";
            })()}
        <section class="box">
          <h2>Scores</h2>
          <dl class="kv">
            <dt>CVSS</dt><dd>${row.cvss_score !== null ? html`${row.cvss_score.toFixed(1)} ${row.cvss_severity ?? ""} (v${row.cvss_version})<br><code class="small">${row.cvss_vector ?? ""}</code><br><span class="small">scored by ${row.cvss_source ?? "unknown"}</span>` : "not yet scored"}</dd>
            <dt>EPSS</dt><dd>${row.epss !== null ? html`${epssText(row)} (percentile ${((row.epss_percentile ?? 0) * 100).toFixed(0)}%, ${row.epss_date ?? ""})` : "no score"}</dd>
            <dt>KEV</dt><dd>${row.kev ? html`added ${row.kev_date_added ?? "?"}, due ${row.kev_due_date ?? "?"}` : "not listed"}</dd>
            ${Object.keys(ssvc).length ? html`<dt>SSVC</dt><dd>${Object.entries(ssvc).map(([k, v]) => html`${k}: ${v}<br>`)}</dd>` : ""}
            <dt>CWE</dt><dd>${cwes.length ? cwes.join(", ") : "—"}</dd>
            <dt>Published</dt><dd>${shortStamp(row.published_at)}</dd>
            <dt>Modified</dt><dd>${shortStamp(row.last_modified_at)} (${relativeTime(row.last_modified_at, now)})</dd>
            <dt>Source</dt><dd>${row.source_identifier ?? "—"}</dd>
            <dt>Vendors</dt><dd>${vendors.join(", ") || "—"}</dd>
            <dt>Products</dt><dd>${products.join(", ") || "—"}</dd>
            ${aliases.length ? html`<dt>Also known as</dt><dd>${aliases.join(", ")}</dd>` : ""}
          </dl>
        </section>
      </aside>
    </div>`;

  return page({ title: row.cve_id, active: "vulnerabilities", content, owner, open });
}
