import type { DatabaseSync } from "node:sqlite";
import { bars, donut, lines, stacked, type Series, type Slice, type Tone } from "../charts.ts";
import { latestDigest } from "../digest.ts";
import { endingSupport, loadFleet } from "../fleet.ts";
import { html, newTabIf } from "../html.ts";
import type { LookState } from "../look.ts";
import { recentAlerts } from "../notify.ts";
import { relativeTime } from "../time.ts";
import { stateLabel, triageCounts, triageInbox, triageStates, type TriageState } from "../triage.ts";
import { page, registerStrip } from "./layout.ts";
import { triageButtons } from "./triage.ts";

function parseJson<T>(text: string | null, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

const dayMs = 24 * 60 * 60 * 1000;
/** The day, as YYYY-MM-DD in UTC, `days` days before `now`. */
const dayOf = (now: Date, days: number): string => new Date(now.getTime() - days * dayMs).toISOString().slice(0, 10);

const vendorTones: Tone[] = ["cyan", "purple", "amber", "green", "acc"];
const severityOrder: { key: string; label: string; tone: Tone }[] = [
  { key: "critical", label: "Critical", tone: "red" },
  { key: "high", label: "High", tone: "amber" },
  { key: "medium", label: "Medium", tone: "cyan" },
  { key: "low", label: "Low", tone: "green" },
  { key: "unscored", label: "Unscored", tone: "mute" },
];
const triageTones: Record<TriageState, Tone> = { new: "cyan", reviewing: "purple", affects: "red", done: "green", dismissed: "mute" };
const statusTones: Record<string, Tone> = { ok: "green", unchanged: "cyan", error: "red" };

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
  /** Wire items a day for the last 14 days, by source group. */
  days: { ticks: string[]; series: Series[] };
  /** Watched CVEs that changed in the window, by CVSS severity. */
  severity: Slice[];
  /** Every CVE known, by EPSS band. */
  epss: Slice[];
  triage: Slice[];
  sources: SourceGlance[];
}

export function glanceData(db: DatabaseSync, now: Date, since: string): GlanceData {
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

  const severityRows = db
    .prepare(
      `SELECT COALESCE(LOWER(cvss_severity), 'unscored') AS sev, COUNT(*) AS n FROM vulns
       WHERE watch_hit = 1 AND cve_id IN (SELECT DISTINCT cve_id FROM vuln_changes WHERE observed_at >= ?) GROUP BY sev`,
    )
    .all(since) as { sev: string; n: number }[];
  const known = new Set(severityOrder.map((s) => s.key));
  const severity: Slice[] = severityOrder.map((s) => ({
    label: s.label,
    tone: s.tone,
    value: severityRows.filter((r) => (known.has(r.sev) ? r.sev === s.key : s.key === "unscored")).reduce((n, r) => n + r.n, 0),
    href: `/vulnerabilities?watch=1&changed=1&severity=${s.key}`,
  }));

  const epssRow = db
    .prepare(
      `SELECT SUM(CASE WHEN epss IS NULL THEN 1 ELSE 0 END) AS unscored,
              SUM(CASE WHEN epss < 0.01 THEN 1 ELSE 0 END) AS low,
              SUM(CASE WHEN epss >= 0.01 AND epss < 0.1 THEN 1 ELSE 0 END) AS mid,
              SUM(CASE WHEN epss >= 0.1 AND epss < 0.5 THEN 1 ELSE 0 END) AS high,
              SUM(CASE WHEN epss >= 0.5 THEN 1 ELSE 0 END) AS top
       FROM vulns`,
    )
    .get() as { unscored: number | null; low: number | null; mid: number | null; high: number | null; top: number | null };
  const epss: Slice[] = [
    { label: "Over 50%", value: epssRow.top ?? 0, tone: "red", href: "/vulnerabilities?min_epss=0.5&sort=epss" },
    { label: "10 to 50%", value: epssRow.high ?? 0, tone: "amber", href: "/vulnerabilities?min_epss=0.1&max_epss=0.5&sort=epss" },
    { label: "1 to 10%", value: epssRow.mid ?? 0, tone: "cyan", href: "/vulnerabilities?min_epss=0.01&max_epss=0.1&sort=epss" },
    { label: "Under 1%", value: epssRow.low ?? 0, tone: "green", href: "/vulnerabilities?max_epss=0.01&sort=epss" },
    { label: "No score", value: epssRow.unscored ?? 0, tone: "mute", href: "/vulnerabilities?epss=none" },
  ];

  const counts = triageCounts(db);
  // Dismissed cards have no column of their own; the Done column says how many were set aside.
  const triage: Slice[] = triageStates.map((state) => ({ label: stateLabel[state], value: counts[state], tone: triageTones[state], href: `/triage#${state === "dismissed" ? "done" : state}` }));

  const sources = db
    .prepare(
      `SELECT id, name, last_status AS status, last_fetch_at AS at FROM sources WHERE enabled = 1
       ORDER BY CASE WHEN last_fetch_at IS NULL THEN 1 ELSE 0 END, last_fetch_at DESC, name LIMIT 8`,
    )
    .all() as unknown as SourceGlance[];

  return { vendors, days: { ticks, series }, severity, epss, triage, sources };
}

/**
 * The Today page: what changed since you last looked, summary before detail, built for a phone
 * first. The window is a number of hours (?since=24, 72, 168), 24 by default. The tiles say the
 * four figures that matter; the glance panels under them show the shape of the week in charts
 * drawn on the server; then what needs a person, in the order it arrived.
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
  const digest = latestDigest(db);
  const glance = glanceData(db, now, since);
  // The fleet's support dates, so a release about to stop getting fixes is a figure here, not a surprise.
  const ending = endingSupport(loadFleet(), now, 90);
  const windowLink = (h: number) => html`<a class="${hours === h ? "on" : ""}" href="/today?since=${h}">${h === 24 ? "24 h" : h === 72 ? "3 days" : "7 days"}</a>`;

  const content = html`
    <div class="wire-top">
      <h1>Since ${sinceLabel}<small>What changed in the things you watch. Everything else is in the <a href="/">News</a>.</small></h1>
      <div class="filters">${windowLink(24)}${windowLink(72)}${windowLink(168)}</div>
    </div>
    <div class="stats today">
      <a class="tile ${kev ? "bad" : ""}" href="/?kind=kev"><small>KEV additions</small><b>${kev}</b><span>${kevMine} match your stack</span></a>
      <a class="tile" href="/vulnerabilities?watch=1&changed=1"><small>Watched CVEs changed</small><b>${watched}</b><span>in the window</span></a>
      <a class="tile release" href="/"><small>Standard releases</small><b>${realReleases.length}</b><span>${realReleases[0] ? realReleases[0].title.split(":")[0] : releases.length ? `${releases.length} first load(s), no diffs yet` : "none in the window"}</span></a>
      <a class="tile ${counts.affects + counts.reviewing ? "warn" : ""}" href="/triage"><small>Needs you</small><b>${counts.affects + counts.reviewing}</b><span>${inbox.length} not yet placed</span></a>
      <a class="tile ${ending.length ? "warn" : ""}" href="/platforms"><small>Support ending</small><b>${ending.length}</b><span>${ending[0] ? `${ending[0].release.label}: ${ending[0].clause}` : "none within 90 days"}</span></a>
    </div>
    <div class="glance" aria-label="At a glance">
      <section class="box"><h2><a href="/?kind=kev">Known exploited</a> <span class="count">by vendor, 30 days</span></h2>${donut(glance.vendors, { label: "Known exploited by vendor, 30 days" })}</section>
      <section class="box"><h2><a href="/">Wire</a> <span class="count">items a day, 14 days</span></h2>${lines(glance.days.series, { label: "Wire items a day, 14 days", ticks: glance.days.ticks })}</section>
      <section class="box"><h2><a href="/vulnerabilities?watch=1&changed=1">Watched CVEs</a> <span class="count">changed, ${windowWord}, by CVSS</span></h2>${bars(glance.severity, { label: `Watched CVEs changed in ${windowWord}, by CVSS severity` })}<p class="small"><a href="/vulnerabilities?watch=1&changed=1">In the table</a></p></section>
      <section class="box"><h2><a href="/vulnerabilities?sort=epss">Vulnerabilities</a> <span class="count">by EPSS band</span></h2>${donut(glance.epss, { label: "Vulnerabilities by EPSS band" })}</section>
      <section class="box"><h2><a href="/triage">Triage</a> <span class="count">by state</span></h2>${stacked(glance.triage, { label: "Triage by state" })}<p class="small"><a href="/triage">The board</a></p></section>
      <section class="box"><h2><a href="/sources">Sources</a> <span class="count">last fetch</span></h2>
        ${glance.sources.length
          ? html`<ul class="src-glance">${glance.sources.map((s) => html`<li><span><i class="dot t-${statusTones[s.status ?? ""] ?? "mute"}"></i><a href="/sources#src-${s.id}">${s.name}</a></span><span class="when">${s.at ? relativeTime(s.at, now) : "never"}${s.status && s.status !== "ok" ? html` · ${s.status}` : ""}</span></li>`)}</ul>`
          : html`<p class="small">No source has been fetched yet.</p>`}
      </section>
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

  return page({ title: "Today", active: "today", content, meta: html`${kev} KEV · ${watched} watched · ${realReleases.length} releases`, owner, open, strip: registerStrip(db, now), look });
}
