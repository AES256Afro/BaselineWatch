import type { DatabaseSync } from "node:sqlite";
import { latestDigest } from "../digest.ts";
import { html, newTabIf } from "../html.ts";
import { recentAlerts } from "../notify.ts";
import { relativeTime } from "../time.ts";
import { triageCounts, triageInbox } from "../triage.ts";
import { page } from "./layout.ts";
import { triageButtons } from "./triage.ts";

function parseJson<T>(text: string | null, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

/**
 * The Today page: what changed since you last looked, summary before detail, built for a phone
 * first. The window is a number of hours (?since=24, 72, 168), 24 by default.
 */
export function renderToday(options: { db: DatabaseSync; owner: boolean; open: boolean; now: Date; hours: number }): string {
  const { db, owner, open, now, hours } = options;
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
  const counts = triageCounts(db);
  const inbox = triageInbox(db, 8);
  const latest = db
    .prepare("SELECT i.title, i.url, i.published_at, s.name AS source_name FROM items i JOIN sources s ON s.id = i.source_id WHERE i.kind = 'article' ORDER BY COALESCE(i.published_at, i.fetched_at) DESC LIMIT 8")
    .all() as { title: string; url: string | null; published_at: string | null; source_name: string }[];
  const failing = db.prepare("SELECT id, name, last_error FROM sources WHERE enabled = 1 AND last_status = 'error' ORDER BY name").all() as { id: string; name: string; last_error: string | null }[];
  const alerts = recentAlerts(db, 5);
  const digest = latestDigest(db);
  const windowLink = (h: number) => html`<a class="${hours === h ? "on" : ""}" href="/today?since=${h}">${h === 24 ? "24 h" : h === 72 ? "3 days" : "7 days"}</a>`;

  const content = html`
    <div class="wire-top">
      <h1>Since ${sinceLabel}<small>What changed in the things you watch. Everything else is on the Wire.</small></h1>
      <div class="filters">${windowLink(24)}${windowLink(72)}${windowLink(168)}</div>
    </div>
    <div class="stats today">
      <a class="tile ${kev ? "bad" : ""}" href="/wire?kind=kev"><small>KEV additions</small><b>${kev}</b><span>${kevMine} match your stack</span></a>
      <a class="tile" href="/vulnerabilities?watch=1&changed=1"><small>Watched CVEs changed</small><b>${watched}</b><span>in the window</span></a>
      <a class="tile std" href="/"><small>Standard releases</small><b>${realReleases.length}</b><span>${realReleases[0] ? realReleases[0].title.split(":")[0] : releases.length ? `${releases.length} first load(s), no diffs yet` : "none in the window"}</span></a>
      <a class="tile" href="/triage"><small>Needs you</small><b>${counts.affects + counts.reviewing}</b><span>${inbox.length} not yet placed</span></a>
    </div>
    <div class="cols">
      <section class="main">
        <section class="box">
          <h2>Needs you <span class="count">sorted newest first</span></h2>
          ${inbox.length
            ? html`<ul class="need">${inbox.map((i) => {
                const s = parseJson<{ dueDate?: string; cvss?: number | null; epss?: number | null; kev?: boolean; watch?: string[] }>(i.signals_json, {});
                return html`<li class="${i.kind === "kev" || s.kev ? "kev" : i.kind === "release" ? "std" : ""}">
                  <div class="need-main"><b>${i.url ? html`<a href="${i.url}" ${newTabIf(i.url)}>${i.title}</a>` : i.title}</b>
                    <span class="small">${i.source_name} · ${relativeTime(i.published_at, now)}${s.dueDate ? ` · due ${s.dueDate}` : ""}${typeof s.cvss === "number" ? ` · CVSS ${s.cvss.toFixed(1)}` : ""}${typeof s.epss === "number" ? ` · EPSS ${(s.epss * 100).toFixed(0)}%` : ""}${s.watch?.length ? ` · ${s.watch.join(", ")}` : ""}</span></div>
                  ${owner ? triageButtons({ kind: "item", id: i.id }, null, `/today?since=${hours}`, { compact: true }) : ""}
                </li>`;
              })}</ul>`
            : html`<p class="small">Nothing waiting. New KEV entries, notable CVEs and standard releases appear here until placed.</p>`}
        </section>
        <section class="box">
          <h2>Standards <span class="count">${realReleases.length} release(s) with changes in the window</span></h2>
          ${realReleases.length
            ? html`<ul class="need">${realReleases.map((r) => html`<li class="std"><div class="need-main"><b>${r.url ? html`<a href="${r.url}" ${newTabIf(r.url)}>${r.title}</a>` : r.title}</b>${r.summary ? html`<span class="small">${r.summary}</span>` : ""}</div></li>`)}</ul>`
            : html`<p class="small">No standard moved${releases.length ? ` (${releases.length} first version(s) loaded, nothing to compare yet)` : ""}. The <a href="/atlas">Atlas</a> shows the rhythm and what is due next.</p>`}
        </section>
        <section class="box">
          <h2>Wire, latest <span class="count"><a href="/wire">all</a></span></h2>
          <ul class="latest">${latest.map((a) => html`<li><span class="src">${a.source_name}</span>${a.url ? html`<a href="${a.url}" ${newTabIf(a.url)}>${a.title}</a>` : a.title}<span class="when">${relativeTime(a.published_at, now)}</span></li>`)}</ul>
        </section>
      </section>
      <aside class="side">
        <section class="box">
          <h2>Sources</h2>
          ${failing.length ? html`<ul class="src-fail">${failing.map((f) => html`<li><a href="/sources"><b>${f.name}</b></a> <span class="small">${f.last_error ?? "error"}</span></li>`)}</ul>` : html`<p class="small">Every enabled source answered on its last fetch.</p>`}
        </section>
        <section class="box">
          <h2>Digest and alerts</h2>
          <p class="small">${digest ? html`Last digest <a href="/digest">${relativeTime(digest.generated_at, now)}</a>.` : html`<a href="/digest">No digest yet.</a>`}</p>
          ${alerts.length ? html`<ul class="alerts">${alerts.map((a) => html`<li class="${a.status}"><span class="when">${relativeTime(a.sent_at, now)} · ${a.kind} · ${a.status}</span>${a.url ? html`<a href="${a.url}" ${newTabIf(a.url)}>${a.title}</a>` : a.title}</li>`)}</ul>` : ""}
        </section>
      </aside>
    </div>`;

  return page({ title: "Today", active: "today", content, meta: html`${kev} KEV · ${watched} watched · ${realReleases.length} releases`, owner, open });
}
