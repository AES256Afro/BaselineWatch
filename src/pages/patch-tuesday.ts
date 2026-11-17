import type { DatabaseSync } from "node:sqlite";
import { loadFleet, releaseStatus, releasesOf } from "../fleet.ts";
import { csvLine } from "../csv.ts";
import { counted, figure, html, newTab, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { addProduct, fixKey, fixName, isRepublished, msrcReleases, msrcRows, releaseName, releaseNoteUrl, type MsrcFix, type MsrcVuln } from "../msrc.ts";
import { page } from "./layout.ts";
import { saveSearchForm } from "./saved.ts";

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
  /** Only the CVEs the fleet's own Windows releases' updates fix (?fleet=1). */
  fleet?: boolean;
  /** The CVE table's page, from 1 (?page=). */
  page?: number;
  owner: boolean;
  open: boolean;
  now: Date;
  look: LookState;
}

interface KbSummary extends MsrcFix {
  /** The key the entries were grouped by (fixKey of each), which a row's fix is matched against. */
  key: string;
  cves: number;
  exploited: number;
  critical: number;
  /** The build each product reaches, by product: one KB is a different build on each Windows version. */
  builds: Map<string, string>;
}

/** The release's updates, one line per KB (or per other fix), with what each closes. */
function byUpdate(rows: MsrcVuln[]): KbSummary[] {
  const out = new Map<string, KbSummary>();
  // A KB is listed once per product it ships to (24H2, 25H2, 26H2 each name KB5127648), so a CVE
  // is counted once per KB, not once per entry: 3,025 read where 1,009 CVEs were meant (B19).
  // A fix with no KB is keyed by its products and build too (fixKey), so Office LTSC 2021 and 2024
  // are two lines at their own builds, not one line at whichever build was read first.
  const counted = new Map<string, Set<string>>();
  for (const row of rows) {
    for (const fix of row.fixes) {
      if (!fix.kb && !fix.url && !fix.label) continue;
      const key = fixKey(fix);
      const s = out.get(key) ?? { ...fix, key, products: [], cves: 0, exploited: 0, critical: 0, builds: new Map<string, string>() };
      for (const product of fix.products) {
        const p = addProduct(s.products, product);
        if (fix.fixedBuild && !s.builds.has(p)) s.builds.set(p, fix.fixedBuild);
      }
      out.set(key, s);
      const seen = counted.get(key) ?? new Set<string>();
      counted.set(key, seen);
      if (seen.has(row.cve_id)) continue;
      seen.add(row.cve_id);
      s.cves += 1;
      if (row.exploited) s.exploited += 1;
      if (row.severity === "Critical") s.critical += 1;
    }
  }
  const summaries = [...out.values()];
  // The first entry's build stands for the line only when every product reaches the same one.
  for (const s of summaries) s.fixedBuild = distinctBuilds(s).length === 1 ? distinctBuilds(s)[0]! : null;
  return summaries.sort((a, b) => b.exploited - a.exploited || b.cves - a.cves || fixName(a).localeCompare(fixName(b)));
}

const distinctBuilds = (s: KbSummary): string[] => [...new Set(s.builds.values())];

/** A product's entry in a summary, matched without regard to case ("Windows 11 version 26H1" and "Version 26H1" are one product). */
const productIn = (s: KbSummary, product: string): string | undefined => s.products.find((p) => p.toLowerCase() === product.toLowerCase());

const kbLink = (f: MsrcFix): Html => (f.url ? html`<a href="${f.url}" ${newTab}>${fixName(f)}</a>` : html`${f.label ?? ""}`);

/**
 * A CVE's fixes, one link per update: KB5127648 is three entries (24H2, 25H2, 26H2) and one
 * update. A fix with no KB is keyed by its name and the page it links to, not its name alone, so
 * Microsoft 365's and Office for Mac's "Release Notes" keep their own links. fixKey would split
 * one page by product and build and draw the same link three times; the page is read by its path,
 * since the guide links the same notes on docs.microsoft.com and on learn.microsoft.com.
 */
export const distinctFixes = (fixes: MsrcFix[]): MsrcFix[] => {
  const seen = new Set<string>();
  return fixes.filter((f) => {
    const name = f.kb ? fixKey(f) : `${fixName(f)}\n${pageOf(f.url)}`;
    if (seen.has(name)) return false;
    seen.add(name);
    return true;
  });
};

/** A link's page, by path: the same notes are linked under two Microsoft hosts. */
const pageOf = (url: string | null): string => {
  if (!url) return "";
  try {
    return new URL(url).pathname.toLowerCase().replace(/\/+$/, "");
  } catch {
    return url;
  }
};

/** A search for "KB5127648" or "kb 5127648" is a search for the KB's number, which is what the rows hold. */
const searchNeedle = (q: string | undefined): string | undefined => q?.trim().toLowerCase().replace(/^kb\s*(?=\d)/, "") || undefined;

/** The fleet's Windows label ("Windows 11, version 24H2") as the guide names the product. */
const productOf = (label: string): string => label.replace(/, version /i, " Version ");

/** How many CVEs one page of the table shows. */
const tablePage = 400;

/** The release, its rows and the CVEs the filters leave, as both the page and its CSV read them. */
function selectRelease(options: PatchTuesdayOptions) {
  const { db, family, q, all } = options;
  const releases = msrcReleases(db);
  if (releases.length === 0) return { releases, current: undefined } as const;
  const current = options.releaseId ? releases.find((r) => r.release_id === options.releaseId) : releases[0];
  if (!current) return null;
  const rows = msrcRows(db, current.release_id);
  const own = rows.filter((r) => !isRepublished(r));
  const republished = rows.length - own.length;
  const shown = all ? rows : own;
  const updates = byUpdate(own);
  // The owner's Windows releases, each with its month's update: the first thing to read on a Tuesday evening.
  // A release whose every support date has passed is left out, whatever the fleet file still says.
  const fleet = releasesOf(loadFleet(), "windows").filter((r) => {
    const status = releaseStatus(r, options.now);
    return status === "current" || status === "supported";
  });
  const mine = fleet
    .map((release) => {
      const product = productOf(release.label);
      // Each KB with the build it reaches on this release, not the build of whichever release Microsoft listed first.
      return { release, kbs: updates.flatMap((u) => { const p = productIn(u, product); return p ? [{ u, build: u.builds.get(p) ?? null }] : []; }) };
    })
    .filter((m) => m.kbs.length);
  // ?fleet=1: the CVEs an update for one of those releases fixes, read by the same key the updates were grouped by.
  // The summary's own key, not fixKey of the summary: a no-KB summary's products are merged from every entry.
  const fleetKeys = new Set(mine.flatMap((m) => m.kbs.map(({ u }) => u.key)));
  // Asked for and nothing in the fleet takes an update: the table says so and lists none, rather than everything.
  const fleetOnly = options.fleet === true;
  const needle = searchNeedle(q);
  const listed = shown.filter(
    (r) =>
      (!family || r.family === family) &&
      (!needle || `${r.cve_id} ${r.title} ${r.family ?? ""} ${r.fixes.map((f) => f.kb ?? "").join(" ")}`.toLowerCase().includes(needle)) &&
      (!fleetOnly || r.fixes.some((f) => fleetKeys.has(fixKey(f)))),
  );
  return { releases, current, rows, own, republished, shown, updates, mine, fleetOnly, listed } as const;
}

/** The CVE table under the page's filters, every row of it rather than one page, as CSV. */
export function patchTuesdayCsv(options: PatchTuesdayOptions, baseUrl: string): string | null {
  const picked = selectRelease(options);
  if (!picked?.current) return null;
  const lines = [csvLine(["cve", "severity", "cvss", "component", "title", "exploited", "disclosed", "updates", "update_urls", "release", "url"])];
  for (const r of picked.listed) {
    // "; " between updates: two of Microsoft's "Release Notes" read as one name joined by a space.
    const fixes = distinctFixes(r.fixes);
    const names = fixes.map((f) => fixName(f)).join("; ");
    const urls = fixes.map((f) => f.url ?? "").join("; ");
    lines.push(csvLine([r.cve_id, r.severity ?? "", r.cvss_score?.toFixed(1) ?? "", r.family ?? "", r.title, r.exploited ? "yes" : "", r.disclosed ? "yes" : "", names, urls, picked.current.release_id, `${baseUrl}/vulnerabilities/${r.cve_id}`]));
  }
  return lines.join("\r\n") + "\r\n";
}

export function renderPatchTuesday(options: PatchTuesdayOptions): string | null {
  const { db, family, q, all, owner, open, look } = options;
  const picked = selectRelease(options);
  if (!picked) return null;
  const { releases, current } = picked;
  if (!current) {
    const content = html`
      <div class="wire-top"><h1>Patch Tuesday<small>Microsoft's monthly security release, by update and product.</small></h1></div>
      <section class="box wide"><p class="small">Nothing read yet from the Security Update Guide: the source pulls once a day and keeps the last two monthly releases. See <a href="/sources#src-msrc">Sources</a>.</p></section>`;
    return page({ title: "Patch Tuesday", active: "patch-tuesday", content, owner, open, look });
  }
  const { republished, shown, updates, mine, fleetOnly, listed } = picked;
  const families = new Map<string, number>();
  for (const r of shown) if (r.family) families.set(r.family, (families.get(r.family) ?? 0) + 1);
  const topFamilies = [...families.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 14);
  const pages = Math.max(1, Math.ceil(listed.length / tablePage));
  const pageNo = Math.min(Math.max(1, Math.floor(options.page ?? 1)), pages);
  const from = (pageNo - 1) * tablePage;
  const onPage = listed.slice(from, from + tablePage);
  const known = onPage.length ? new Set((db.prepare(`SELECT cve_id FROM vulns WHERE cve_id IN (${onPage.map(() => "?").join(", ")})`).all(...onPage.map((r) => r.cve_id)) as { cve_id: string }[]).map((r) => r.cve_id)) : new Set<string>();
  const href = (overrides: { release?: string; family?: string | undefined; q?: string | undefined; all?: boolean; fleet?: boolean; page?: number }, path = "/vulnerabilities/microsoft"): string => {
    const p = new URLSearchParams();
    // A change of filter starts the table again at its first page.
    const merged = { release: current.release_id, family, q, all, fleet: fleetOnly, page: 1, ...overrides };
    if (merged.release !== releases[0]?.release_id) p.set("release", merged.release);
    if (merged.family) p.set("family", merged.family);
    if (merged.q) p.set("q", merged.q);
    if (merged.all) p.set("all", "1");
    if (merged.fleet) p.set("fleet", "1");
    if (merged.page > 1) p.set("page", String(merged.page));
    const s = p.toString();
    return s ? `${path}?${s}` : path;
  };
  const filtered = Boolean(family || q?.trim() || fleetOnly);
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
      <a href="${href({ all: true })}"><small>Republished (Chromium, Azure Linux)</small><b>${figure(republished)}</b></a>
      <div><small>Released</small><b class="date">${current.released_at?.slice(0, 10) ?? "—"}</b></div>
    </div>
    ${mine.length
      ? html`<section class="box wide" id="mine">
          <h2>Your Windows releases <span class="count">from the <a href="/fleet">fleet</a> · <a href="${href({ fleet: !fleetOnly }, "/vulnerabilities/microsoft")}#cves">${fleetOnly ? "show every CVE in the table" : "only their CVEs in the table"}</a></span></h2>
          <ul class="refs">${mine.map((m) => html`<li><b>${m.release.label}</b> — ${m.kbs.map(({ u, build }, i) => html`${i ? ", " : ""}${kbLink(u)} <span class="small">(${counted(u.cves, "CVE")}${u.exploited ? html`, <b>${u.exploited} exploited</b>` : ""}${build ? ` · build ${build}` : ""})</span>`)}</li>`)}</ul>
        </section>`
      : ""}
    <section class="box wide" id="updates">
      <h2>By update <span class="count">${figure(updates.length)} in ${releaseName(current.release_id)}</span></h2>
      <div class="table-wrap">
        <table class="vulns kbs"><caption class="visually-hidden">Updates in this release</caption>
          <thead><tr><th scope="col">Update</th><th scope="col">Products</th><th scope="col" class="n">CVEs</th><th scope="col" class="n">Critical</th><th scope="col" class="n">Exploited</th></tr></thead>
          <tbody>${updates.slice(0, 40).map((u) => html`<tr class="${u.exploited ? "hit" : ""}"><td class="id">${kbLink(u)}${u.fixedBuild ? html`<span class="small"> · ${u.fixedBuild}</span>` : ""}</td><td class="who">${u.products.slice(0, 6).map((p, i) => html`${i ? ", " : ""}${p}${!u.fixedBuild && u.builds.get(p) ? html` <span class="small">${u.builds.get(p)}</span>` : ""}`)}${u.products.length > 6 ? html` <span class="small">and ${u.products.length - 6} more</span>` : ""}</td><td class="n">${figure(u.cves)}</td><td class="n">${u.critical || ""}</td><td class="n">${u.exploited ? html`<b>${u.exploited}</b>` : ""}</td></tr>`)}</tbody>
        </table>
      </div>
      ${updates.length > 40 ? html`<p class="small">${figure(updates.length - 40)} more updates, mostly single products; the CVE table below names each.</p>` : ""}
    </section>
    <section class="box wide" id="cves">
      <h2>CVEs <span class="count">${listed.length > tablePage ? html`${pageNo === 1 ? figure(onPage.length) : `${figure(from + 1)}–${figure(from + onPage.length)}`} shown of ${figure(listed.length)}` : figure(listed.length)}${filtered ? html` matching, of ${figure(shown.length)}` : ""}${all ? "" : html`, Microsoft's own (<a href="${href({ all: true })}">include the ${figure(republished)} republished</a>)`} · <a href="${href({ page: 1 }, "/vulnerabilities/microsoft.csv")}" download>CSV of ${listed.length === 1 ? "this CVE" : `these ${figure(listed.length)} CVEs`}</a></span></h2>
      <div class="filters">
        ${mine.length || fleetOnly ? html`<a class="${fleetOnly ? "on" : ""}" href="${href({ fleet: !fleetOnly })}#cves" title="CVEs an update for one of your fleet's Windows releases fixes">Your Windows releases</a>` : ""}
        <a class="${family ? "" : "on"}" href="${href({ family: undefined })}">All components</a>
        ${topFamilies.map(([f, n]) => html`<a class="${family === f ? "on" : ""}" href="${href({ family: family === f ? undefined : f })}">${f} <span class="small">${figure(n)}</span></a>`)}
      </div>
      ${saveSearchForm(db, href({}), owner)}
      <form method="get" action="/vulnerabilities/microsoft" class="search" role="search">
        ${current.release_id !== releases[0]?.release_id ? html`<input type="hidden" name="release" value="${current.release_id}">` : ""}
        ${family ? html`<input type="hidden" name="family" value="${family}">` : ""}
        ${all ? html`<input type="hidden" name="all" value="1">` : ""}
        ${fleetOnly ? html`<input type="hidden" name="fleet" value="1">` : ""}
        <label class="visually-hidden" for="q">Search this release</label>
        <input type="search" id="q" name="q" value="${q ?? ""}" placeholder="CVE, title, component or KB">
        <button type="submit">Search</button>
      </form>
      <div class="table-wrap">
        <table class="vulns"><caption class="visually-hidden">CVEs in this release</caption>
          <thead><tr><th scope="col">CVE</th><th scope="col">Severity</th><th scope="col" class="n">CVSS</th><th scope="col">Component</th><th scope="col">Title</th><th scope="col">Update</th></tr></thead>
          <tbody>${onPage.map(
            (r) => html`<tr class="${r.exploited ? "hit" : ""}">
              <td class="id">${known.has(r.cve_id) ? html`<a href="/vulnerabilities/${r.cve_id}">${r.cve_id}</a>` : html`<span title="Not in this instance's table yet">${r.cve_id}</span>`}${r.exploited ? html`<span class="chip kev">exploited</span>` : ""}${r.disclosed ? html`<span class="chip exploit">disclosed</span>` : ""}</td>
              <td>${sevChip(r)}</td>
              <td class="n">${r.cvss_score?.toFixed(1) ?? "—"}</td>
              <td class="who">${r.family ?? ""}${isRepublished(r) ? html` <span class="small">(${r.vendor ?? "republished"})</span>` : ""}</td>
              <td class="desc"><span>${r.title}</span></td>
              <td class="who">${(() => {
                const fixes = distinctFixes(r.fixes);
                return html`${fixes.slice(0, 3).map((f, i) => html`${i ? ", " : ""}${kbLink(f)}`)}${fixes.length > 3 ? html` <span class="small">+${fixes.length - 3}</span>` : ""}`;
              })()}</td>
            </tr>`,
          )}</tbody>
        </table>
      </div>
      ${pages > 1
        ? html`<p class="small more">Page ${pageNo} of ${pages}.${pageNo > 1 ? html` <a href="${href({ page: pageNo - 1 })}#cves">Previous ${tablePage}</a>` : ""}${pageNo < pages ? html` <a href="${href({ page: pageNo + 1 })}#cves">Next ${Math.min(tablePage, listed.length - from - onPage.length)}</a>` : ""}</p>`
        : ""}
      ${listed.length === 0 ? html`<p class="small">${fleetOnly && mine.length === 0 ? "No Windows release in your fleet has an update in this release." : `No CVE in ${releaseName(current.release_id)} matches.`}</p>` : ""}
    </section>
    <p class="small">Revised by Microsoft ${current.revised_at?.slice(0, 10) ?? "—"}. "Exploited" and "disclosed" are Microsoft's own words from the guide's exploitability index; a CVE's page carries NVD's, CISA's and the public exploit indexes' besides.</p>`;
  return page({ title: `Patch Tuesday · ${releaseName(current.release_id)}`, active: "patch-tuesday", content, meta: html`${figure(current.microsoft)} CVEs · ${figure(current.exploited)} exploited`, owner, open, look, canonical: "/vulnerabilities/microsoft", description: `Microsoft's ${releaseName(current.release_id)} security release by update and product: ${current.microsoft} CVEs, ${current.exploited} exploited, ${current.critical} critical.` });
}
