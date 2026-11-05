import type { DatabaseSync } from "node:sqlite";
import { html, newTabIf, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { withheldFrom } from "../register.ts";
import { relativeTime } from "../time.ts";
import { listVulns } from "../vulns.ts";
import { listWire } from "../wire.ts";
import { latestVersions, searchControls } from "./controls.ts";
import { page } from "./layout.ts";
import { saveSearchForm } from "./saved.ts";

/**
 * One search from the masthead across everything this instance holds: CVEs, the News, the
 * controls of every standard a visitor may read, Microsoft's rows, and the sources. Each section
 * is the first few hits with a link to the page whose own search goes further. A CVE id typed
 * whole goes straight to its page (the route does that).
 */

export function renderSearch(options: { db: DatabaseSync; q: string | undefined; owner: boolean; open: boolean; now: Date; look: LookState }): string {
  const { db, owner, open, now, look } = options;
  const query = (options.q ?? "").trim();
  const title = query ? `Search · ${query}` : "Search";
  if (!query) {
    const content = html`
      <div class="wire-top"><h1>Search<small>CVEs, the News, every standard's controls, Microsoft's updates and the sources, in one go.</small></h1>
        <form method="get" action="/search" class="search" role="search"><label class="visually-hidden" for="q">Search</label><input type="search" id="q" name="q" placeholder="A CVE id, a product, a control label, a KB, a word" autofocus><button type="submit">Search</button></form>
      </div>
      <p class="small">A CVE id typed whole opens its page. "ac-2" finds the control in every catalog that has it; "KB5127648" finds the update; a vendor's name finds its CVEs and its stories.</p>`;
    return page({ title, active: "search", content, owner, open, look });
  }
  const cves = listVulns(db, { q: query, limit: 10 });
  const news = listWire(db, { q: query, limit: 10 }, { owner });
  const versions = latestVersions(db).filter((v) => !withheldFrom({ restricted: v.restricted }, owner));
  const controls = searchControls(db, versions, query, 15);
  const like = `%${query.toLowerCase()}%`;
  const microsoft = db
    .prepare("SELECT cve_id, title, release_id, severity, exploited FROM msrc_vulns WHERE lower(title) LIKE ? OR lower(cve_id) LIKE ? OR lower(fixes_json) LIKE ? ORDER BY released_at DESC, cve_id LIMIT 10")
    .all(like, like, like) as { cve_id: string; title: string; release_id: string; severity: string | null; exploited: number }[];
  const sources = db.prepare("SELECT id, name, group_name FROM sources WHERE enabled = 1 AND lower(name) LIKE ? ORDER BY name LIMIT 10").all(like) as { id: string; name: string; group_name: string }[];
  const total = cves.total + news.length + controls.length + microsoft.length + sources.length;
  const section = (heading: string, count: number | string, more: { href: string; label: string } | null, body: Html): Html =>
    html`<section class="box"><h2>${heading} <span class="count">${count}</span></h2>${body}${more ? html`<p class="small"><a href="${more.href}">${more.label}</a></p>` : ""}</section>`;
  const content = html`
    <div class="wire-top">
      <h1>Search<small>${total ? `${total} hit(s) for “${query}”` : `Nothing for “${query}”`}</small></h1>
      <form method="get" action="/search" class="search" role="search"><label class="visually-hidden" for="q">Search</label><input type="search" id="q" name="q" value="${query}"><button type="submit">Search</button></form>
      ${saveSearchForm(db, `/search?q=${encodeURIComponent(query)}`, owner)}
    </div>
    <div class="cols">
      <section class="main">
        ${cves.total
          ? section("CVEs", cves.total, { href: `/vulnerabilities?q=${encodeURIComponent(query)}`, label: `All ${cves.total} in the table` }, html`<ul class="refs">${cves.rows.map((r) => html`<li><a href="/vulnerabilities/${r.cve_id}">${r.cve_id}</a> <span class="chip sev ${(r.cvss_severity ?? "").toLowerCase()}">${r.cvss_score?.toFixed(1) ?? "unscored"}</span>${r.kev ? html` <span class="chip kev">KEV</span>` : ""} <span class="small">${r.description ?? ""}</span></li>`)}</ul>`)
          : ""}
        ${controls.length
          ? section("Controls", controls.length === 15 ? "15+" : controls.length, { href: `/controls?q=${encodeURIComponent(query)}`, label: "All of them, on the Controls page" }, html`<ul class="refs">${controls.map((c) => html`<li><a href="/standards/${c.sourceId}/${c.documentId}/${c.ref}"><b>${c.ref}</b></a> ${c.title ?? ""} <span class="small">${c.name}${c.family ? ` · ${c.family}` : ""}</span></li>`)}</ul>`)
          : ""}
        ${news.length
          ? section("News", news.length === 10 ? "10+" : news.length, { href: `/?q=${encodeURIComponent(query)}`, label: "All of them, on the News" }, html`<ul class="refs">${news.map((i) => html`<li>${i.url ? html`<a href="${i.url}" ${newTabIf(i.url)}>${i.title}</a>` : i.title} <span class="small">${i.source_name} · ${relativeTime(i.published_at ?? i.fetched_at, now)}</span></li>`)}</ul>`)
          : ""}
      </section>
      <aside class="side">
        ${microsoft.length
          ? section("Microsoft's updates", microsoft.length === 10 ? "10+" : microsoft.length, { href: `/vulnerabilities/microsoft?q=${encodeURIComponent(query)}`, label: "On the Patch Tuesday page" }, html`<ul class="refs">${microsoft.map((m) => html`<li><a href="/vulnerabilities/microsoft?q=${encodeURIComponent(m.cve_id)}">${m.cve_id}</a>${m.exploited ? html` <span class="chip kev">exploited</span>` : ""} <span class="small">${m.title} · ${m.release_id}</span></li>`)}</ul>`)
          : ""}
        ${sources.length
          ? section("Sources", sources.length, null, html`<ul class="refs">${sources.map((s) => html`<li><a href="${s.group_name === "standards" ? `/standards/${s.id}` : `/?source=${s.id}`}">${s.name}</a> <span class="small">${s.group_name}</span></li>`)}</ul>`)
          : ""}
        ${total === 0 ? html`<section class="box"><p class="small">Try a CVE id, a vendor or product, a control label such as <code>ac-2</code> or <code>SV-2542</code>, a KB number, or a word from a headline.</p></section>` : ""}
      </aside>
    </div>`;
  return page({ title, active: "search", content, owner, open, look });
}
