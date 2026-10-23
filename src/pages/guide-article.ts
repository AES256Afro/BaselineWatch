import type { DatabaseSync } from "node:sqlite";
import { fixContext, fixesFor } from "../fix.ts";
import { html, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { relativeTime } from "../time.ts";
import { getVuln } from "../vulns.ts";
import { page } from "./layout.ts";

/**
 * A guide article at `/guide/<slug>`: the owner's prose about one subject, with the CVEs it is
 * about read live from this instance's own table rather than written into the text. The prose says
 * what a reader should understand and do; the numbers, the severities and whether a fix exists yet
 * come from the pipeline, so a page written the day a flaw broke stops saying "no patch" the day
 * one lands. Articles live in `pages/guides/`, one module each, the way the scan guide's platforms
 * do.
 */

export interface GuideSection {
  id: string;
  heading: string;
  body: Html;
}

export interface GuideArticle {
  slug: string;
  title: string;
  /** One sentence for the search result and the link preview. */
  description: string;
  /** The opening paragraph, in the page's own voice. */
  standfirst: Html;
  /** When the prose was last written. The CVE figures beside it are always current. */
  written: string;
  /** The CVEs this article is about, read from the table on every request. */
  cves: string[];
  sections: GuideSection[];
}

/** One CVE as this instance currently holds it, or the honest absence of it. */
function cveRow(db: DatabaseSync, ctx: ReturnType<typeof fixContext>, cveId: string): Html {
  const v = getVuln(db, cveId);
  if (!v) {
    return html`<tr>
      <td><a href="/vulnerabilities/${cveId}">${cveId}</a></td>
      <td colspan="4" class="small">Not in this instance's table yet — the pipeline has not seen it. <a href="/sources">Sources</a> says when NVD was last read.</td>
    </tr>`;
  }
  const fix = fixesFor(db, ctx, v);
  const sev = (v.cvss_severity ?? "").toLowerCase();
  return html`<tr>
    <td><a href="/vulnerabilities/${v.cve_id}"><b>${v.cve_id}</b></a>${v.published_at ? html`<div class="small">${v.published_at.slice(0, 10)}</div>` : ""}</td>
    <td>${v.cvss_score !== null ? html`<span class="chip sev ${sev}">${v.cvss_score.toFixed(1)}</span> <span class="small">${v.cvss_severity ?? ""}${v.cvss_version ? html` · CVSS ${v.cvss_version}` : ""}</span>` : html`<span class="small">not scored yet</span>`}</td>
    <td>${v.epss !== null ? html`<span class="chip epss">${(v.epss * 100).toFixed(1)}%</span>` : html`<span class="small">no EPSS yet</span>`}</td>
    <td>${v.kev === 1 ? html`<span class="chip kev">KEV</span>${v.kev_due_date ? html` <span class="small">due ${v.kev_due_date}</span>` : ""}` : html`<span class="small">not in KEV</span>`}</td>
    <td>${fix.empty
      ? html`<b>Nothing published yet</b><div class="small">no patch, advisory or mitigation reference on this instance</div>`
      : html`<a href="/vulnerabilities/${v.cve_id}#fix">What is published</a><div class="small">${[fix.references.length ? `${fix.references.length} reference(s)` : null, fix.advisories.length ? `${fix.advisories.length} advisory` : null, fix.packages.length ? "a fixed version" : null, fix.kev ? "a KEV action" : null].filter(Boolean).join(" · ")}</div>`}</td>
  </tr>`;
}

export function renderGuideArticle(options: { db: DatabaseSync; article: GuideArticle; owner: boolean; open: boolean; look: LookState; now?: Date }): string {
  const { db, article, owner, open, look } = options;
  const now = options.now ?? new Date();
  const ctx = fixContext(db);

  const content = html`
    <div class="cols">
      <section class="main">
        <h1>${article.title}</h1>
        <p class="lede">${article.standfirst}</p>
        <p class="small">
          Written ${article.written}. The figures below are read from this instance's own table on
          every request, so they are as current as its last fetch — the prose is not.
        </p>

        <section class="box wide" id="what-is-known">
          <h2><a href="#what-is-known">What is known right now</a></h2>
          <div class="table-wrap"><table><caption class="visually-hidden">The CVEs this article is about, as this instance holds them</caption>
            <thead><tr><th scope="col">CVE</th><th scope="col">Severity</th><th scope="col">EPSS</th><th scope="col">Exploited</th><th scope="col">Fix</th></tr></thead>
            <tbody>${article.cves.map((c) => cveRow(db, ctx, c))}</tbody>
          </table></div>
          <p class="small">
            EPSS is FIRST's estimate that a CVE will be attacked in the next thirty days; KEV is
            CISA's catalogue of flaws with evidence of exploitation. A brand-new CVE usually has
            neither yet, and their absence is not reassurance — it is silence.
            <a href="/guide#epss">What these mean</a>.
          </p>
        </section>

        ${article.sections.map(
          (s) => html`<section class="box wide" id="${s.id}">
            <h2><a href="#${s.id}">${s.heading}</a></h2>
            ${s.body}
          </section>`,
        )}
      </section>
      <aside class="side">
        <section class="box">
          <h2>On this page</h2>
          <ul class="plain">
            <li><a href="#what-is-known">What is known right now</a></li>
            ${article.sections.map((s) => html`<li><a href="#${s.id}">${s.heading}</a></li>`)}
          </ul>
        </section>
        <section class="box">
          <h2>Where this fits</h2>
          <p class="small">
            <a href="/guide">How to read this site</a> explains the areas and the scores.
            <a href="/learn">Learn</a> is where the standards themselves come from.
            <a href="/vulnerabilities">Vulnerabilities</a> is every CVE this instance has seen,
            searchable. The <a href="/">News</a> is what the sources are saying as it happens.
          </p>
        </section>
        <section class="box">
          <h2>Not advice about your systems</h2>
          <p class="small">
            No web page can see what your servers run, and this one installs nothing and probes
            nothing. Everything below is general guidance about publicly documented flaws; whether
            it applies to you is a question only someone with access to your systems can answer.
          </p>
        </section>
      </aside>
    </div>`;

  return page({
    title: article.title,
    active: "guide",
    content,
    owner,
    open,
    look,
    canonical: `/guide/${article.slug}`,
    description: article.description,
    meta: html`<span class="small">updated ${relativeTime(article.written, now)}</span>`,
  });
}
