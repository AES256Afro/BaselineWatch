import type { DatabaseSync } from "node:sqlite";
import { donut, lines, type Series, type Slice, type Tone } from "../charts.ts";
import { latestDigest } from "../digest.ts";
import { endingSupport, loadFleet } from "../fleet.ts";
import { html, newTabIf } from "../html.ts";
import type { LookState } from "../look.ts";
import { recentAlerts } from "../notify.ts";
import { relativeTime } from "../time.ts";
import { triageCounts, triageInbox } from "../triage.ts";
import { page, registerStrip } from "./layout.ts";
import { nextActions, platformBreakdown, type Action } from "../agenda.ts";
import { scanTile } from "../scanhistory.ts";
import { trendingCves } from "../trending.ts";
import { pipelineHealth, pipelineSummary } from "../pipeline.ts";
import { triageButtons } from "./triage.ts";
import { parseJson } from "../json.ts";

/**
 * The Today page: what to do next, the window's CVEs by the platform they affect, the figures that
 * matter, two charts, and what needs a person, built for a phone first.
 */
const dayMs = 24 * 60 * 60 * 1000;
/** The day, as YYYY-MM-DD in UTC, `days` days before `now`. */
const dayOf = (now: Date, days: number): string => new Date(now.getTime() - days * dayMs).toISOString().slice(0, 10);

const vendorTones: Tone[] = ["cyan", "purple", "amber", "green", "acc"];

export interface SourceGlance {
  id: string;
  name: string;
  status: string | null;
  at: string | null;
}

/** What the glance panels draw, read in a handful of bounded queries. Exported so the figures can be tested without a page. */
export interface GlanceData {
  /** KEV additions in the last 30 days by vendor, the five largest then the rest as one. */
  vendors: Slice[];
  /** News items a day for the last 14 days, by source group. */
  days: { ticks: string[]; series: Series[] };
}

function glanceData(db: DatabaseSync, now: Date): GlanceData {
  const since30 = new Date(now.getTime() - 30 * dayMs).toISOString();
  const vendorRows = db
    .prepare(
      `SELECT COALESCE(NULLIF(TRIM(CASE WHEN json_valid(signals_json) THEN json_extract(signals_json, '$.vendor') END), ''), 'Unknown') AS vendor, COUNT(*) AS n
       FROM items WHERE kind = 'kev' AND published_at >= ? GROUP BY vendor ORDER BY n DESC, vendor LIMIT 60`,
    )
    .all(since30) as { vendor: string; n: number }[];
  // A vendor leads to its KEV entries in the News; the rest, and the unnamed, to all of them.
  const kevList = (vendor?: string) => (vendor ? `/?kind=kev&q=${encodeURIComponent(vendor)}` : "/?kind=kev");
  const top = vendorRows.slice(0, 5).map((r, i): Slice => ({ label: String(r.vendor).slice(0, 40), value: r.n, tone: vendorTones[i] ?? "mute", href: kevList(r.vendor === "Unknown" ? undefined : String(r.vendor)) }));
  const rest = vendorRows.slice(5).reduce((n, r) => n + r.n, 0);
  const vendors: Slice[] = rest > 0 ? [...top, { label: "Other", value: rest, tone: "mute", href: kevList() }] : top;

  const dayKeys = Array.from({ length: 14 }, (_, i) => dayOf(now, 13 - i));
  const perDay = db
    .prepare(
      `SELECT substr(COALESCE(i.published_at, i.fetched_at), 1, 10) AS day, s.group_name AS grp, COUNT(*) AS n
       FROM items i JOIN sources s ON s.id = i.source_id
       WHERE COALESCE(i.published_at, i.fetched_at) >= ? GROUP BY day, grp`,
    )
    .all(`${dayKeys[0]}T00:00:00.000Z`) as { day: string; grp: string; n: number }[];
  const groups: { key: string; label: string; tone: Tone }[] = [
    { key: "news", label: "News", tone: "cyan" },
    { key: "vulnerabilities", label: "Vulnerabilities", tone: "purple" },
    { key: "standards", label: "Standards", tone: "amber" },
  ];
  const series: Series[] = groups.map((g) => ({
    label: g.label,
    tone: g.tone,
    values: dayKeys.map((day) => perDay.filter((r) => r.day === day && r.grp === g.key).reduce((n, r) => n + r.n, 0)),
    href: `/?group=${g.key}`,
  }));
  const ticks = dayKeys.map((d) => d.slice(5));

  return { vendors, days: { ticks, series } };
}

/**
 * The Today page: what to do, then what changed, built for a phone first. The window is a number
 * of hours (?since=24, 72, 168), 24 by default.
 *
 * It opens on the short ordered list a person can act on (src/agenda.ts) rather than on five
 * counts, because a count says how much happened and nothing about what to do with it. Under it
 * the window's CVEs are grouped by the platform they affect, with the platforms this fleet runs
 * first, so "twelve Windows, three of them exploited" is one line rather than a table to read.
 * The counts keep their row below that, and two charts rather than six: the rest of the space
 * belongs to lists that lead somewhere.
 */
export function renderToday(options: { db: DatabaseSync; owner: boolean; open: boolean; now: Date; hours: number; look: LookState }): string {
  const { db, owner, open, now, hours, look } = options;
  const since = new Date(now.getTime() - hours * 60 * 60 * 1000).toISOString();
  const n = (sql: string, ...params: string[]) => (db.prepare(sql).get(...params) as { n: number }).n;
  // KEV entries date from when CISA added them, not from when this instance first saw the catalog.
  const kev = n("SELECT COUNT(*) AS n FROM items WHERE kind = 'kev' AND published_at >= ?", since);
  const kevMine = n("SELECT COUNT(*) AS n FROM items i JOIN vulns v ON v.cve_id = i.external_id WHERE i.kind = 'kev' AND i.published_at >= ? AND v.watch_hit = 1", since);
  const watched = n("SELECT COUNT(DISTINCT c.cve_id) AS n FROM vuln_changes c JOIN vulns v ON v.cve_id = c.cve_id WHERE c.observed_at >= ? AND v.watch_hit = 1", since);
  const releases = db
    .prepare("SELECT title, url, summary, published_at, signals_json FROM items WHERE kind = 'release' AND fetched_at >= ? ORDER BY published_at DESC LIMIT 12")
    .all(since) as { title: string; url: string | null; summary: string | null; published_at: string | null; signals_json: string | null }[];
  // A standard's first load into this instance is not a release; a version with changes is.
  const realReleases = releases.filter((r) => {
    const s = parseJson<{ added?: number; removed?: number; modified?: number }>(r.signals_json, {});
    return (s.added ?? 0) + (s.removed ?? 0) + (s.modified ?? 0) > 0;
  });
  const sinceLabel = hours === 24 ? "yesterday" : hours === 72 ? "three days ago" : "a week ago";
  const windowWord = hours === 24 ? "24 h" : hours === 72 ? "3 days" : "7 days";
  const counts = triageCounts(db);
  const inbox = triageInbox(db, 8);
  const latest = db
    .prepare("SELECT i.title, i.url, i.published_at, s.id AS source_id, s.name AS source_name FROM items i JOIN sources s ON s.id = i.source_id WHERE i.kind = 'article' ORDER BY COALESCE(i.published_at, i.fetched_at) DESC LIMIT 8")
    .all() as { title: string; url: string | null; published_at: string | null; source_id: string; source_name: string }[];
  const failing = db.prepare("SELECT id, name, last_error FROM sources WHERE enabled = 1 AND last_status = 'error' ORDER BY name").all() as { id: string; name: string; last_error: string | null }[];
  const alerts = recentAlerts(db, 5);
  const talked = trendingCves(db, new Date(now.getTime() - 7 * 86_400_000).toISOString(), 8);
  const scan = scanTile(db);
  const digest = latestDigest(db);
  const glance = glanceData(db, now);
  // The fleet's support dates, so a release about to stop getting fixes is a figure here, not a surprise.
  const fleet = loadFleet();
  const ending = endingSupport(fleet, now, 90);
  const windowLink = (h: number) => html`<a class="${hours === h ? "on" : ""}" href="/today?since=${h}">${h === 24 ? "24 h" : h === 72 ? "3 days" : "7 days"}</a>`;
  // What to act on, and what the window's CVEs are about: the fleet decides which platforms lead.
  const actions: Action[] = nextActions(db, { since, now });
  const breakdown = platformBreakdown(db, since, fleet);
  // Whether the pipeline is running at all (M13.2), from rows this instance already keeps.
  const pipeline = pipelineHealth(db, now);

  const content = html`
    <div class="wire-top">
      <h1>Since ${sinceLabel}<small>What changed in the things you watch. Everything else is in the <a href="/">News</a>.</small></h1>
      <div class="filters">${windowLink(24)}${windowLink(72)}${windowLink(168)}</div>
    </div>
    ${actions.length
      ? html`<section class="box wide" id="next">
          <h2>What to do next <span class="count">${actions.length} thing(s)</span></h2>
          <ol class="next">${actions.map(
            (a, i) => html`<li>
              <span class="rank">${i + 1}</span>
              <span class="what"><b>${a.href.startsWith("http") ? html`<a href="${a.href}" ${newTabIf(a.href)}>${a.title}</a>` : html`<a href="${a.href}">${a.title}</a>`}</b>
                <span class="why">${a.why}</span></span>
              ${owner && a.itemId !== null ? html`<span class="act">${triageButtons({ kind: "item", id: a.itemId }, null, `/today?since=${hours}`, { compact: true })}</span>` : ""}
            </li>`,
          )}</ol>
        </section>`
      : html`<section class="box wide" id="next"><h2>What to do next</h2><p class="small">Nothing in the last ${windowWord} is waiting on a decision: no overdue triage, no KEV addition, no watched CVE that got worse, no standard release with changes. The window above widens to three or seven days.</p></section>`}
    <section class="box wide" id="platforms">
      <h2>Vulnerabilities by platform <span class="count">${breakdown.total} changed in ${windowWord}</span></h2>
      ${breakdown.rows.length
        ? html`<ul class="plat-rows">${breakdown.rows.map((row) => {
            const top = breakdown.rows[0]?.total ?? 1;
            const width = Math.max(2, Math.min(100, (row.total / Math.max(1, top)) * 100));
            const kevWidth = Math.min(width, (row.kev / Math.max(1, top)) * 100);
            return html`<li>
              <span class="pname"><a href="/vulnerabilities?platform=${row.key}&amp;changed=${hours === 24 ? 1 : hours}">${row.label}</a></span>
              <span class="pn">${row.total}</span>
              <svg class="pbar" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true"><rect class="t-acc" x="0" y="0" width="${width.toFixed(1)}" height="8" rx="1"></rect><rect class="t-red" x="0" y="0" width="${kevWidth.toFixed(1)}" height="8" rx="1"></rect></svg>
              <span class="mine">${row.kev ? html`<a class="chip kev" href="/vulnerabilities?platform=${row.key}&kev=1">${row.kev} KEV</a> ` : ""}${row.mine ? html`${row.mine} on your watchlist ` : ""}${row.inFleet ? html`<span class="chip ok">in your fleet</span>` : ""}</span>
            </li>`;
          })}</ul>
          ${breakdown.unplaced ? html`<p class="small">${breakdown.unplaced} of them name no platform this site can read from their CPEs, vendor and product names or description; they are in <a href="/vulnerabilities?changed=${hours === 24 ? 1 : hours}">the table</a> with the rest.</p>` : ""}`
        : html`<p class="small">No CVE changed in the last ${windowWord}.</p>`}
    </section>
    <div class="stats today">
      <a class="tile ${kev ? "bad" : ""}" href="/?kind=kev"><small>KEV additions</small><b>${kev}</b><span>${kevMine} match your stack</span></a>
      <a class="tile" href="/vulnerabilities?watch=1&changed=${hours === 24 ? 1 : hours}"><small>Watched CVEs changed</small><b>${watched}</b><span>in the window</span></a>
      <a class="tile release" href="/"><small>Standard releases</small><b>${realReleases.length}</b><span>${realReleases[0] ? realReleases[0].title.split(":")[0] : releases.length ? `${releases.length} first load(s), no diffs yet` : "none in the window"}</span></a>
      <a class="tile ${counts.affects + counts.reviewing ? "warn" : ""}" href="/triage"><small>Needs you</small><b>${counts.affects + counts.reviewing}</b><span>${inbox.length} not yet placed</span></a>
      <a class="tile ${ending.length ? "warn" : ""}" href="/fleet"><small>Support ending</small><b>${ending.length}</b><span>${ending[0] ? `${ending[0].release.label}: ${ending[0].clause}` : "none within 90 days"}</span></a>
      <a class="tile${scan.state === "warn" ? " warn" : ""}" href="${scan.href}"><small>Network check</small><b>${scan.figure}</b><span>${scan.text}</span></a>
      <a class="tile${pipeline.state === "ok" ? "" : ` ${pipeline.state}`}" href="/sources"><small>Pipeline</small><b>${pipeline.failing.length === 0 ? "ok" : pipeline.failing.length}</b><span>${pipelineSummary(pipeline)}</span></a>
    </div>
    <div class="glance two" aria-label="At a glance">
      <section class="box"><h2><a href="/?kind=kev">Known exploited</a> <span class="count">by vendor, 30 days</span></h2>${donut(glance.vendors, { label: "Known exploited by vendor, 30 days" })}</section>
      <section class="box"><h2><a href="/">News</a> <span class="count">items a day, 14 days</span></h2>${lines(glance.days.series, { label: "News items a day, 14 days", ticks: glance.days.ticks })}</section>
    </div>
    <div class="cols">
      <section class="main">
        <section class="box">
          <h2><a href="/triage">Needs you</a> <span class="count">sorted newest first</span></h2>
          ${inbox.length
            ? html`<ul class="need">${inbox.map((i) => {
                const s = parseJson<{ dueDate?: string; cvss?: number | null; epss?: number | null; kev?: boolean; watch?: string[] }>(i.signals_json, {});
                return html`<li class="${i.kind === "kev" || s.kev ? "kev" : i.kind === "release" ? "std" : ""}">
                  <div class="need-main"><b>${i.url ? html`<a href="${i.url}" ${newTabIf(i.url)}>${i.title}</a>` : i.title}</b>
                    <span class="small"><a href="/?source=${i.source_id}">${i.source_name}</a> · ${relativeTime(i.published_at, now)}${s.dueDate ? ` · due ${s.dueDate}` : ""}${typeof s.cvss === "number" ? ` · CVSS ${s.cvss.toFixed(1)}` : ""}${typeof s.epss === "number" ? ` · EPSS ${(s.epss * 100).toFixed(0)}%` : ""}${s.watch?.length ? ` · ${s.watch.join(", ")}` : ""}</span></div>
                  ${owner ? triageButtons({ kind: "item", id: i.id }, null, `/today?since=${hours}`, { compact: true }) : ""}
                </li>`;
              })}</ul>`
            : html`<p class="small">Nothing waiting. New KEV entries, notable CVEs and standard releases appear here until placed.</p>`}
        </section>
        <section class="box">
          <h2><a href="/register">Standards</a> <span class="count">${realReleases.length} release(s) with changes in the window</span></h2>
          ${realReleases.length
            ? html`<ul class="need">${realReleases.map((r) => html`<li class="std"><div class="need-main"><b>${r.url ? html`<a href="${r.url}" ${newTabIf(r.url)}>${r.title}</a>` : r.title}</b>${r.summary ? html`<span class="small">${r.summary}</span>` : ""}</div></li>`)}</ul>`
            : html`<p class="small">No standard moved${releases.length ? ` (${releases.length} first version(s) loaded, nothing to compare yet)` : ""}. The <a href="/atlas">Atlas</a> shows the rhythm and what is due next.</p>`}
        </section>
        <section class="box">
          <h2><a href="/">News, latest</a> <span class="count"><a href="/">all</a></span></h2>
          <ul class="latest">${latest.map((a) => html`<li><a class="src" href="/?source=${a.source_id}">${a.source_name}</a>${a.url ? html`<a href="${a.url}" ${newTabIf(a.url)}>${a.title}</a>` : a.title}<span class="when">${relativeTime(a.published_at, now)}</span></li>`)}</ul>
        </section>
      </section>
      <aside class="side">
        <section class="box">
          <h2><a href="/vulnerabilities">Talked about</a> <span class="count">7 days, by sources</span></h2>
          ${talked.length
            ? html`<ul class="talked">${talked.map((c) => html`<li>${c.known ? html`<a href="/vulnerabilities/${c.cveId}">${c.cveId}</a>` : html`<span title="Not in this instance's table yet">${c.cveId}</span>`} <span class="small">${c.sources} sources · ${c.url ? html`<a href="${c.url}" ${newTabIf(c.url)}>${c.headline}</a>` : c.headline}</span></li>`)}</ul>`
            : html`<p class="small">No CVE named by two sources this week.</p>`}
        </section>
        <section class="box">
          <h2><a href="/sources">Sources</a></h2>
          ${failing.length ? html`<ul class="src-fail">${failing.map((f) => html`<li><a href="/sources#src-${f.id}"><b>${f.name}</b></a> <span class="small">${f.last_error ?? "error"}</span></li>`)}</ul>` : html`<p class="small">Every enabled source answered on its last fetch.</p>`}
        </section>
        <section class="box">
          <h2><a href="/digest">Digest and alerts</a></h2>
          <p class="small">${digest ? html`Last digest <a href="/digest">${relativeTime(digest.generated_at, now)}</a>.` : html`<a href="/digest">No digest yet.</a>`}</p>
          ${alerts.length ? html`<ul class="alerts">${alerts.map((a) => html`<li class="${a.status}"><span class="when">${relativeTime(a.sent_at, now)} · ${a.kind} · ${a.status}</span>${a.url ? html`<a href="${a.url}" ${newTabIf(a.url)}>${a.title}</a>` : a.title}</li>`)}</ul>` : ""}
        </section>
      </aside>
    </div>`;

  return page({ title: "Today", active: "today", content, meta: html`${kev} KEV · ${watched} watched · ${realReleases.length} releases`, owner, open, strip: registerStrip(db, now), look , canonical: "/today", description: "What changed in the things you watch: what to do next, CVEs by platform, KEV additions, standard releases, and the pipeline's own health." });
}
