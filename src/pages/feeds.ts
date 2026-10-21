import { html, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { platformKeys } from "../platforms.ts";
import { page } from "./layout.ts";

/**
 * The Feeds page: every address a reader or a calendar can take from this instance, written out
 * in full so it can be copied, with the filters each one understands. The page computes nothing;
 * it names what /feed.xml, /vulnerabilities/feed.xml, /sources.opml and /vulnerabilities/kev.ics do.
 */

export function renderFeeds({ baseUrl, owner, open, look }: { baseUrl: string; owner: boolean; open: boolean; look: LookState }): string {
  const row = (label: string, path: string, note?: string): Html => html`<li><b>${label}</b><code><a href="${path}">${baseUrl}${path}</a></code>${note ? html`<span class="small">${note}</span>` : ""}</li>`;
  const content = html`
    <div class="wire-top">
      <h1>Feeds<small>What a reader, a calendar or another tool can take from here. Each address keeps the filters its page takes.</small></h1>
    </div>
    <div class="cols">
      <section class="main">
        <section class="box">
          <h2>News as RSS</h2>
          <ul class="feeds">
            ${row("Everything on the News", "/feed.xml")}
            ${row("Vendor advisories only", "/feed.xml?group=vulnerabilities")}
            ${row("News only, no advisories", "/feed.xml?group=news")}
            ${row("Standard releases", "/feed.xml?kind=release")}
            ${row("KEV additions", "/feed.xml?kind=kev")}
          </ul>
          <p class="small">Also <code>source=&lt;id&gt;</code> for one source (ids are on <a href="/sources">Sources</a>) and <code>q=</code> for a search, the same words the News page takes. Fifty newest items.</p>
        </section>
        <section class="box">
          <h2>Vulnerabilities as RSS</h2>
          <ul class="feeds">
            ${row("Every CVE, newest change first", "/vulnerabilities/feed.xml")}
            ${row("Known exploited (CISA KEV)", "/vulnerabilities/feed.xml?kev=1")}
            ${row("With a public exploit", "/vulnerabilities/feed.xml?exploit=1")}
            ${row("Your stack", "/vulnerabilities/feed.xml?watch=1", "the watchlist's matches")}
            ${row("Critical, new this week", "/vulnerabilities/feed.xml?severity=critical&new=168")}
            ${row("Likely exploited", "/vulnerabilities/feed.xml?min_epss=0.5", "EPSS at or over 50%")}
          </ul>
          <p class="small">By platform: ${platformKeys.map((k, i) => html`${i ? " · " : ""}<a href="/vulnerabilities/feed.xml?platform=${k}">${k}</a>`)}. Every filter of the <a href="/vulnerabilities">table</a> works: <code>kev</code>, <code>exploit</code>, <code>watch</code>, <code>platform</code>, <code>severity</code>, <code>min_cvss</code>, <code>min_epss</code>, <code>changed</code>, <code>new</code>, <code>q</code>. A CVE comes round again when it changes, because the change is the news.</p>
        </section>
      </section>
      <aside class="side">
        <section class="box">
          <h2>Calendar</h2>
          <ul class="feeds">
            ${row("KEV due dates", "/vulnerabilities/kev.ics", "all-day events, from a month ago on")}
            ${row("KEV due dates, your stack", "/vulnerabilities/kev.ics?watch=1")}
          </ul>
          <p class="small">Subscribe to the address rather than importing the file, so a CVE added to the catalog tomorrow is on the calendar tomorrow.</p>
        </section>
        <section class="box">
          <h2>Sources as OPML</h2>
          <ul class="feeds">${row("Every feed this instance reads", "/sources.opml", "for a reader's import")}</ul>
        </section>
        <section class="box">
          <h2>Programs</h2>
          <p class="small">The same facts as JSON under <code>/api/v1/</code> and as tools at <code>/mcp</code>; the pipeline's figures at <code>/metrics</code>. See the <a href="/guide#api">guide</a>.</p>
        </section>
      </aside>
    </div>`;
  return page({ title: "Feeds", active: "feeds", content, owner, open, look, canonical: "/feeds", description: "RSS for the news and the CVE table under any filter, every source as OPML, and CISA KEV due dates as a calendar." });
}
