import type { DatabaseSync } from "node:sqlite";
import { loadFleet, releasesOf } from "../fleet.ts";
import { figure, html, newTab, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { isRepublished, msrcReleases, msrcRows, releaseName, releaseNoteUrl, type MsrcFix, type MsrcVuln } from "../msrc.ts";
import { page } from "./layout.ts";

/**
 * Patch Tuesday: Microsoft's monthly release as the Security Update Guide states it, turned the
 * way an administrator reads it — by update (KB) and by product first, then CVE by CVE. The
 * owner's own Windows releases from the fleet come first, each with the KB that is its month's
 * update and how many CVEs it closes. Nothing here is generated; every figure is a count of
 * Microsoft's rows.
 */

export interface PatchTuesdayOptions {
  db: DatabaseSync;
  releaseId: string | undefined;
  family: string | undefined;
  q: string | undefined;
  /** Include the Chromium and Azure Linux CVEs Microsoft republishes; off by default, as in Microsoft's own count. */
  all: boolean;
  owner: boolean;
  open: boolean;
  now: Date;
  look: LookState;
}

interface KbSummary extends MsrcFix {
  cves: number;
  exploited: number;
  critical: number;
}

/** The release's updates, one line per KB (or per other fix), with what each closes. */
function byUpdate(rows: MsrcVuln[]): KbSummary[] {
  const out = new Map<string, KbSummary>();
  for (const row of rows) {
    for (const fix of row.fixes) {
      const key = fix.kb ?? fix.url ?? fix.label ?? "";
      if (!key) continue;
      const s = out.get(key) ?? { ...fix, products: [...fix.products], cves: 0, exploited: 0, critical: 0 };
      s.cves += 1;
      if (row.exploited) s.exploited += 1;
      if (row.severity === "Critical") s.critical += 1;
      for (const p of fix.products) if (!s.products.includes(p)) s.products.push(p);
      out.set(key, s);
    }
  }
  return [...out.values()].sort((a, b) => b.exploited - a.exploited || b.cves - a.cves || (a.kb ?? a.label ?? "").localeCompare(b.kb ?? b.label ?? ""));
}

const kbLink = (f: MsrcFix): Html => (f.url ? html`<a href="${f.url}" ${newTab}>${f.kb ? `KB${f.kb}` : (f.label ?? f.url)}</a>` : html`${f.label ?? ""}`);

/** The fleet's Windows label ("Windows 11, version 24H2") as the guide names the product. */
const productOf = (label: string): string => label.replace(/, version /i, " Version ");

export function renderPatchTuesday(options: PatchTuesdayOptions): string | null {
  const { db, family, q, all, owner, open, look } = options;
  const releases = msrcReleases(db);
  if (releases.length === 0) {
    const content = html`
      <div class="wire-top"><h1>Patch Tuesday<small>Microsoft's monthly security release, by update and product.</small></h1></div>
      <section class="box wide"><p class="small">Nothing read yet from the Security Update Guide: the source pulls once a day and keeps the last two monthly releases. See <a href="/sources#src-msrc">Sources</a>.</p></section>`;
    return page({ title: "Patch Tuesday", active: "patch-tuesday", content, owner, open, look });
  }
  const current = options.releaseId ? releases.find((r) => r.release_id === options.releaseId) : releases[0];
  if (!current) return null;
  const rows = msrcRows(db, current.release_id);
  const own = rows.filter((r) => !isRepublished(r));
  const republished = rows.length - own.length;
  const shown = all ? rows : own;
  const families = new Map<string, number>();
  for (const r of shown) if (r.family) families.set(r.family, (families.get(r.family) ?? 0) + 1);
  const topFamilies = [...families.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 14);
  const needle = q?.trim().toLowerCase();
  const listed = shown.filter((r) => (!family || r.family === family) && (!needle || `${r.cve_id} ${r.title} ${r.family ?? ""} ${r.fixes.map((f) => f.kb ?? "").join(" ")}`.toLowerCase().includes(needle)));
  const known = listed.length ? new Set((db.prepare(`SELECT cve_id FROM vulns WHERE cve_id IN (${listed.map(() => "?").join(", ")})`).all(...listed.map((r) => r.cve_id)) as { cve_id: string }[]).map((r) => r.cve_id)) : new Set<string>();
  const updates = byUpdate(own);
  // The owner's Windows releases, each with its month's update: the first thing to read on a Tuesday evening.
  const fleet = releasesOf(loadFleet(), "windows").filter((r) => r.status === "current" || r.status === "supported");
  const mine = fleet.map((release) => ({ release, kbs: updates.filter((u) => u.products.includes(productOf(release.label))) })).filter((m) => m.kbs.length);
  const href = (overrides: { release?: string; family?: string | undefined; q?: string | undefined; all?: boolean }): string => {
    const p = new URLSearchParams();
    const merged = { release: current.release_id, family, q, all, ...overrides };
    if (merged.release !== releases[0]?.release_id) p.set("release", merged.release);
    if (merged.family) p.set("family", merged.family);
    if (merged.q) p.set("q", merged.q);
    if (merged.all) p.set("all", "1");
    const s = p.toString();
    return s ? `/vulnerabilities/microsoft?${s}` : "/vulnerabilities/microsoft";
  };
  const sevChip = (r: MsrcVuln): Html => html`<span class="chip sev ${r.severity === "Critical" ? "critical" : r.severity === "Important" ? "high" : r.severity === "Moderate" ? "medium" : "low"}">${r.severity ?? "—"}</span>`;

  const content = html`
    <div class="wire-top">
      <h1>Patch Tuesday<small>Microsoft's monthly security release, by update and product, as the <a href="${releaseNoteUrl(current.release_id)}" ${newTab}>Security Update Guide</a> states it. Nothing is generated.</small></h1>
      <div class="filters">${releases.map((r) => html`<a class="${r.release_id === current.release_id ? "on" : ""}" href="${href({ release: r.release_id, family: undefined, q: undefined })}">${releaseName(r.release_id)}</a>`)}</div>
    </div>
    <div class="stats">
      <a href="${href({ family: undefined, q: undefined, all: false })}"><small>Microsoft CVEs</small><b>${figure(current.microsoft)}</b></a>
      <a href="${href({ family: undefined, q: "", all: false })}"><small>Critical</small><b>${figure(current.critical)}</b></a>
      <div class="${current.exploited ? "bad" : ""}"><small>Exploited</small><b>${figure(current.exploited)}</b></div>
      <div><small>Publicly disclosed</small><b>${figure(current.disclosed)}</b></div>
      <a href="${href({ all: true })}"><small>Republished</small><b>${figure(republished)}</b></a>
      <div><small>Released</small><b class="date">${current.released_at?.slice(0, 10) ?? "—"}</b></div>
    </div>
    ${mine.length
      ? html`<section class="box wide" id="mine">
          <h2>Your Windows releases <span class="count">from the <a href="/fleet">fleet</a></span></h2>
          <ul class="refs">${mine.map((m) => html`<li><b>${m.release.label}</b> — ${m.kbs.map((k, i) => html`${i ? ", " : ""}${kbLink(k)} <span class="small">(${k.cves} CVEs${k.exploited ? html`, <b>${k.exploited} exploited</b>` : ""}${k.fixedBuild ? ` · build ${k.fixedBuild}` : ""})</span>`)}</li>`)}</ul>
        </section>`
      : ""}
    <section class="box wide" id="updates">
      <h2>By update <span class="count">${updates.length} in ${releaseName(current.release_id)}</span></h2>
      <div class="table-wrap">
        <table class="vulns kbs"><caption class="visually-hidden">Updates in this release</caption>
          <th scope="col"ead><tr><th scope="col">Update</th><th scope="col">Products</th><th scope="col" class="n">CVEs</th><th scope="col" class="n">Critical</th><th scope="col" class="n">Exploited</th></tr></thead>
          <tbody>${updates.slice(0, 40).map((u) => html`<tr class="${u.exploited ? "hit" : ""}"><td class="id">${kbLink(u)}${u.fixedBuild ? html`<span class="small"> · ${u.fixedBuild}</span>` : ""}</td><td class="who">${u.products.slice(0, 6).join(", ")}${u.products.length > 6 ? html` <span class="small">and ${u.products.length - 6} more</span>` : ""}</td><td class="n">${u.cves}</td><td class="n">${u.critical || ""}</td><td class="n">${u.exploited ? html`<b>${u.exploited}</b>` : ""}</td></tr>`)}</tbody>
        </table>
      </div>
      ${updates.length > 40 ? html`<p class="small">${updates.length - 40} more updates, mostly single products; the CVE table below names each.</p>` : ""}
    </section>
    <section class="box wide" id="cves">
      <h2>CVEs <span class="count">${listed.length} of ${shown.length}${all ? "" : html`, Microsoft's own (<a href="${href({ all: true })}">include the ${republished} republished</a>)`}</span></h2>
      <div class="filters">
        <a class="${family ? "" : "on"}" href="${href({ family: undefined })}">All components</a>
        ${topFamilies.map(([f, n]) => html`<a class="${family === f ? "on" : ""}" href="${href({ family: family === f ? undefined : f })}">${f} <span class="small">${n}</span></a>`)}
      </div>
      <form method="get" action="/vulnerabilities/microsoft" class="search" role="search">
        ${current.release_id !== releases[0]?.release_id ? html`<input type="hidden" name="release" value="${current.release_id}">` : ""}
        ${family ? html`<input type="hidden" name="family" value="${family}">` : ""}
        ${all ? html`<input type="hidden" name="all" value="1">` : ""}
        <label class="visually-hidden" for="q">Search this release</label>
        <input type="search" id="q" name="q" value="${q ?? ""}" placeholder="CVE, title, component or KB">
        <button type="submit">Search</button>
      </form>
      <div class="table-wrap">
        <table class="vulns"><caption class="visually-hidden">CVEs in this release</caption>
          <th scope="col"ead><tr><th scope="col">CVE</th><th scope="col">Severity</th><th scope="col" class="n">CVSS</th><th scope="col">Component</th><th scope="col">Title</th><th scope="col">Update</th></tr></thead>
          <tbody>${listed.slice(0, 400).map(
            (r) => html`<tr class="${r.exploited ? "hit" : ""}">
              <td class="id">${known.has(r.cve_id) ? html`<a href="/vulnerabilities/${r.cve_id}">${r.cve_id}</a>` : html`<span title="Not in this instance's table yet">${r.cve_id}</span>`}${r.exploited ? html`<span class="chip kev">exploited</span>` : ""}${r.disclosed ? html`<span class="chip exploit">disclosed</span>` : ""}</td>
              <td>${sevChip(r)}</td>
              <td class="n">${r.cvss_score?.toFixed(1) ?? "—"}</td>
              <td class="who">${r.family ?? ""}${isRepublished(r) ? html` <span class="small">(${r.vendor ?? "republished"})</span>` : ""}</td>
              <td class="desc"><span>${r.title}</span></td>
              <td class="who">${r.fixes.slice(0, 3).map((f, i) => html`${i ? ", " : ""}${kbLink(f)}`)}${r.fixes.length > 3 ? html` <span class="small">+${r.fixes.length - 3}</span>` : ""}</td>
            </tr>`,
          )}</tbody>
        </table>
      </div>
      ${listed.length > 400 ? html`<p class="small">Showing 400 of ${listed.length}; narrow by component or search.</p>` : ""}
      ${listed.length === 0 ? html`<p class="small">No CVE in ${releaseName(current.release_id)} matches.</p>` : ""}
    </section>
    <p class="small">Revised by Microsoft ${current.revised_at?.slice(0, 10) ?? "—"}. "Exploited" and "disclosed" are Microsoft's own words from the guide's exploitability index; a CVE's page carries NVD's, CISA's and the public exploit indexes' besides.</p>`;
  return page({ title: `Patch Tuesday · ${releaseName(current.release_id)}`, active: "patch-tuesday", content, meta: html`${current.microsoft} CVEs · ${current.exploited} exploited`, owner, open, look, canonical: "/vulnerabilities/microsoft", description: `Microsoft's ${releaseName(current.release_id)} security release by update and product: ${current.microsoft} CVEs, ${current.exploited} exploited, ${current.critical} critical.` });
}
