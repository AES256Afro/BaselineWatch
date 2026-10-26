import type { DatabaseSync } from "node:sqlite";
import { fleetPlatformKeys, nextActions, platformBreakdown, type Action } from "../agenda.ts";
import { devicesTile } from "../devices.ts";
import { latestDigest } from "../digest.ts";
import { endingSupport, loadFleet } from "../fleet.ts";
import { candidateLimit, fixList, fixListCandidates, fixListHeadline, type FixList, type Remedy } from "../fixlist.ts";
import { html, newTabIf, type Html } from "../html.ts";
import { parseJson } from "../json.ts";
import type { LookState } from "../look.ts";
import { recentAlerts } from "../notify.ts";
import { pipelineHealth, pipelineSummary } from "../pipeline.ts";
import { listSaved } from "../saved.ts";
import { scanTile } from "../scanhistory.ts";
import { relativeTime } from "../time.ts";
import { trendingCves } from "../trending.ts";
import { triageCounts, triageInbox } from "../triage.ts";
import { page, registerStrip } from "./layout.ts";
import { triageButtons } from "./triage.ts";

/**
 * The Today page: the window's work, grouped by the remedy that ends it.
 *
 * It used to open on five counts and close on two charts. A count says how much happened and
 * nothing about what to do with it, and a line of news items a day answers a question nobody has
 * at seven in the morning. So: every figure on this page is printed with the comparison that
 * gives it meaning, in words, and the published fix sits beside the thing it fixes.
 *
 * The spine is src/fixlist.ts — the remedy is the row and the CVEs it clears are its contents,
 * because nobody patches a CVE, they install an update, and one cumulative is one evening's work.
 * Three groups in the order a person can act on them: install, mitigate, and the honest "nothing
 * published yet". Beside them, the things a remedy cannot express — a standard that moved, a date
 * the owner committed to, and whether this instance is itself still working.
 */

const hoursWord = (hours: number): string => (hours === 24 ? "24 hours" : hours === 72 ? "three days" : "seven days");

/** The CVEs a bucket holds, counted once each however many remedies name them. */
const cvesIn = (remedies: Remedy[]): Set<string> => new Set(remedies.flatMap((r) => r.cves.map((c) => c.cveId)));

function remedyCard(r: Remedy, owner: boolean, back: string): Html {
  const title = r.verb ? html`<span class="verb">${r.verb}</span> <code>${r.what}</code>` : html`<span class="said">${r.what}</span>`;
  // A row that stands for one CVE carries that CVE's own address. A row that stands for thirty
  // kernel commits does not: one of the thirty is not "where this is published", so the chips lead.
  const linked = r.url !== null && (r.cves.length === 1 || r.kind === "install" || r.kind === "mitigate");
  return html`<li class="remedy ${r.kind}">
    <div class="top">
      <div>
        <div class="what">${linked && r.url ? html`<a href="${r.url}" ${newTabIf(r.url)}>${title}</a>` : title}${r.where ? html` <span class="chip">${r.where}</span>` : ""}</div>
        <div class="small where">${r.detail}${r.dueDate ? html` · <b>due ${r.dueDate}</b>` : ""}</div>
      </div>
      ${owner && r.kind === "install"
        ? html`<form method="post" action="/today/done" class="inline">
            <input type="hidden" name="cves" value="${r.cves.map((c) => c.cveId).join(",")}">
            <input type="hidden" name="back" value="${back}">
            <button type="submit">Mark done</button>
          </form>`
        : ""}
    </div>
    <div class="clears">
      <span class="small">${r.kind === "none" ? "" : `Clears ${r.cves.length}:`}</span>
      ${r.cves.map((c) => html`<a class="cve${c.kev ? " kev" : c.watch ? " watch" : ""}" href="/vulnerabilities/${c.cveId}">${c.cveId}</a>`)}
      ${r.kevCount || r.watchCount
        ? html`<span class="small">· ${[r.kevCount ? `${r.kevCount} exploited` : null, r.watchCount ? `${r.watchCount} on your watchlist` : null].filter(Boolean).join(", ")}</span>`
        : ""}
    </div>
  </li>`;
}

/**
 * A busy week can hold more rows than anyone reads in a morning, and a page that scrolls for a
 * minute is the wall this one replaced. Each group draws the most urgent of its rows and says
 * plainly how many it is not drawing.
 */
const groupCap = 15;

function group(id: string, heading: string, blurb: string, remedies: Remedy[], owner: boolean, back: string, empty: string, rest: Html | string = ""): Html {
  const shown = remedies.slice(0, groupCap);
  const hidden = remedies.length - shown.length;
  return html`<section class="box wide fixgroup" id="${id}">
    <h2>${heading} <span class="count">${blurb}</span></h2>
    ${shown.length ? html`<ul class="remedies">${shown.map((r) => remedyCard(r, owner, back))}</ul>` : html`<p class="small">${empty}</p>`}
    ${hidden > 0 ? html`<p class="small">${hidden} more not drawn here: the ones with no date anyone owes, covering fewer CVEs. ${rest}</p>` : ""}
  </section>`;
}

export function renderToday(options: { db: DatabaseSync; owner: boolean; open: boolean; now: Date; hours: number; look: LookState }): string {
  const { db, owner, open, now, hours, look } = options;
  const since = new Date(now.getTime() - hours * 60 * 60 * 1000).toISOString();
  const back = `/today?since=${hours}`;
  const windowWord = hoursWord(hours);
  const fleet = loadFleet();

  // The work, keyed by the remedy that ends it.
  const candidates = fixListCandidates(db, since, [...fleetPlatformKeys(fleet)]);
  const list: FixList = fixList(db, candidates, since, candidates.length >= candidateLimit);
  const published = cvesIn(list.published);
  const mitigateOnly = cvesIn(list.mitigate);
  const nothing = cvesIn(list.none);

  // What the window's CVEs are about, as a sentence rather than a row of bars.
  const breakdown = platformBreakdown(db, since, fleet);
  const fleetRows = breakdown.rows.filter((r) => r.inFleet);

  // What a remedy cannot express: a date the owner committed to, and a standard that moved.
  const decisions: Action[] = nextActions(db, { since, now, fleet, limit: 10 }).filter((a) => a.kind === "overdue" || a.kind === "release");
  const releases = db
    .prepare("SELECT title, url, summary, signals_json FROM items WHERE kind = 'release' AND fetched_at >= ? ORDER BY published_at DESC LIMIT 12")
    .all(since) as { title: string; url: string | null; summary: string | null; signals_json: string | null }[];
  const realReleases = releases.filter((r) => {
    const s = parseJson<{ added?: number; removed?: number; modified?: number }>(r.signals_json, {});
    return (s.added ?? 0) + (s.removed ?? 0) + (s.modified ?? 0) > 0;
  });

  // Good news, which nothing on this page used to carry: what you finished inside the window.
  const cleared = (db.prepare("SELECT COUNT(*) AS n FROM triage WHERE state = 'done' AND updated_at >= ?").get(since) as { n: number }).n;
  const clearedRows = db
    .prepare(
      `SELECT t.updated_at AS at, i.title, i.external_id AS externalId, i.kind FROM triage t JOIN items i ON i.id = t.subject_id AND t.subject_kind = 'item'
        WHERE t.state = 'done' AND t.updated_at >= ? ORDER BY t.updated_at DESC LIMIT 4`,
    )
    .all(since) as { at: string; title: string; externalId: string; kind: string }[];

  const counts = triageCounts(db);
  const inbox = triageInbox(db, 6);
  const ending = endingSupport(fleet, now, 90);
  const failing = db.prepare("SELECT id, name, last_error FROM sources WHERE enabled = 1 AND last_status = 'error' ORDER BY name").all() as { id: string; name: string; last_error: string | null }[];
  const alerts = recentAlerts(db, 4);
  const talked = trendingCves(db, new Date(now.getTime() - 7 * 86_400_000).toISOString(), 8);
  const scan = scanTile(db);
  const saved = owner ? listSaved(db) : [];
  const devices = owner ? devicesTile(db) : null;
  const digest = latestDigest(db);
  const pipeline = pipelineHealth(db, now);
  const windowLink = (h: number) => html`<a class="${hours === h ? "on" : ""}" href="/today?since=${h}">${h === 24 ? "24 h" : h === 72 ? "3 days" : "7 days"}</a>`;

  const content = html`
    <div class="wire-top">
      <h1>${fixListHeadline(list)}<small>Grouped by the remedy rather than by the CVE, because one update is one job. Only what touches your fleet or your watchlist is counted; <a href="/vulnerabilities?changed=${hours === 24 ? 1 : hours}">the table</a> has the rest.</small></h1>
      <div class="filters">${windowLink(24)}${windowLink(72)}${windowLink(168)}</div>
    </div>

    <div class="stats today">
      <a class="tile${list.fixed ? " ok" : ""}" href="#install"><small>Fixed by an update</small><b>${list.fixed}</b><span>${list.install.length} update(s) to install</span></a>
      <a class="tile" href="#published"><small>No update named</small><b>${published.size}</b><span>fix published, version not named</span></a>
      <a class="tile${mitigateOnly.size ? " warn" : ""}" href="#mitigate"><small>Mitigation only</small><b>${mitigateOnly.size}</b><span>published action, no patch yet</span></a>
      <a class="tile" href="#nofix"><small>Nothing published</small><b>${nothing.size}</b><span>watching for a fix</span></a>
      <a class="tile" href="/triage?state=done"><small>Cleared</small><b>${cleared}</b><span>you finished in the last ${windowWord}</span></a>
    </div>
    ${fleetRows.length
      ? html`<p class="small plat-line">Across the platforms you run in the last ${windowWord}: ${fleetRows.map((r, i) => html`${i ? ", " : ""}<a href="/vulnerabilities?platform=${r.key}&amp;changed=${hours === 24 ? 1 : hours}">${r.label} ${r.total}</a>${r.kev ? html` (${r.kev} exploited)` : ""}`)}. ${breakdown.total} CVEs changed in all.</p>`
      : html`<p class="small plat-line">No CVE changed on a platform you run in the last ${windowWord}. ${breakdown.total} changed elsewhere, in <a href="/vulnerabilities?changed=${hours === 24 ? 1 : hours}">the table</a>.</p>`}

    <div class="cols">
      <section class="main">
        ${group(
          "install",
          "Install now",
          `${list.install.length} update(s) · ${list.fixed} CVE(s)`,
          list.install,
          owner,
          back,
          `Nothing in the last ${windowWord} has a patch, a fixed version or a KB waiting for you.`,
          html`<a href="/vulnerabilities?changed=${hours === 24 ? 1 : hours}">The table</a> has every CVE in the window.`,
        )}
        ${group(
          "published",
          "Published, but no update named",
          `${list.published.length} place(s) to read · ${published.size} CVE(s)`,
          list.published,
          owner,
          back,
          "Every fix in this window names the version it lands in.",
          html`<a href="/vulnerabilities?changed=${hours === 24 ? 1 : hours}">The table</a> has every CVE in the window.`,
        )}
        ${group(
          "mitigate",
          "Mitigation only",
          `${list.mitigate.length} published action(s) · ${mitigateOnly.size} CVE(s)`,
          list.mitigate,
          owner,
          back,
          "No publisher has asked for a workaround in this window.",
        )}
        ${group(
          "nofix",
          "Nothing published yet",
          `${nothing.size} CVE(s)`,
          list.none,
          owner,
          back,
          "Everything that touches you in this window has either a fix or a published action.",
        )}
        ${list.truncated ? html`<p class="small">More than ${list.considered} CVEs touched you in this window; this is the most urgent of them. <a href="/vulnerabilities?changed=${hours === 24 ? 1 : hours}">The table</a> has all of them.</p>` : ""}
      </section>

      <aside class="side">
        <section class="box">
          <h2><a href="/register">Standards moved</a> <span class="count">${realReleases.length} in the window</span></h2>
          ${realReleases.length
            ? html`<ul class="need">${realReleases.map((r) => html`<li class="std"><div class="need-main"><b>${r.url ? html`<a href="${r.url}" ${newTabIf(r.url)}>${r.title}</a>` : r.title}</b>${r.summary ? html`<span class="small">${r.summary}</span>` : ""}</div></li>`)}</ul>`
            : html`<p class="small">No standard moved${releases.length ? ` (${releases.length} first version(s) loaded, nothing to compare yet)` : ""}. The <a href="/atlas">Atlas</a> shows what is due next.</p>`}
        </section>

        <section class="box">
          <h2><a href="/triage">Needs you</a> <span class="count">${counts.affects + counts.reviewing} placed, ${inbox.length} not</span></h2>
          ${decisions.length
            ? html`<ul class="talked">${decisions.map((d) => html`<li><a href="${d.href}">${d.title}</a> <span class="small">${d.why}</span></li>`)}</ul>`
            : ""}
          ${inbox.length
            ? html`<ul class="need">${inbox.map((i) => html`<li class="${i.kind === "kev" ? "kev" : i.kind === "release" ? "std" : ""}">
                <div class="need-main"><b>${i.url ? html`<a href="${i.url}" ${newTabIf(i.url)}>${i.title}</a>` : i.title}</b>
                  <span class="small"><a href="/?source=${i.source_id}">${i.source_name}</a> · ${relativeTime(i.published_at, now)}</span></div>
                ${owner ? triageButtons({ kind: "item", id: i.id }, null, back, { compact: true }) : ""}
              </li>`)}</ul>`
            : decisions.length
              ? ""
              : html`<p class="small">Nothing waiting on a decision.</p>`}
          ${ending.length ? html`<p class="small"><b>Support ending:</b> ${ending.length} release(s) within 90 days — ${ending[0]!.release.label}: ${ending[0]!.clause}. <a href="/fleet">Your fleet</a>.</p>` : ""}
        </section>

        <section class="box">
          <h2><a href="/triage?state=done">Cleared</a> <span class="count">in the last ${windowWord}</span></h2>
          ${clearedRows.length
            ? html`<ul class="talked">${clearedRows.map((c) => html`<li><a href="${c.kind === "kev" || c.kind === "vulnerability" ? `/vulnerabilities/${c.externalId}` : "/triage"}">${c.title}</a> <span class="small">done ${relativeTime(c.at, now)}</span></li>`)}</ul>`
            : html`<p class="small">Nothing marked done in this window.</p>`}
        </section>

        ${saved.length ? html`<section class="box"><h2><a href="/saved">Saved searches</a></h2><ul class="talked">${saved.map((s) => html`<li><a href="${s.path}">${s.name}</a></li>`)}</ul></section>` : ""}

        <section class="box">
          <h2><a href="/vulnerabilities">Talked about</a> <span class="count">7 days, by sources</span></h2>
          ${talked.length
            ? html`<ul class="talked">${talked.map((c) => html`<li>${c.known ? html`<a href="/vulnerabilities/${c.cveId}">${c.cveId}</a>` : html`<span title="Not in this instance's table yet">${c.cveId}</span>`} <span class="small">${c.sources} sources · ${c.url ? html`<a href="${c.url}" ${newTabIf(c.url)}>${c.headline}</a>` : c.headline}</span></li>`)}</ul>`
            : html`<p class="small">No CVE named by two sources this week.</p>`}
        </section>

        <section class="box">
          <h2><a href="/sources">The instance</a></h2>
          <ul class="instance">
            <li><span>Sources answering</span><b class="${failing.length ? "bad" : ""}">${failing.length ? `${failing.length} failing` : "all"}</b></li>
            <li><span>Pipeline</span><b class="${pipeline.state === "ok" ? "" : pipeline.state}">${pipelineSummary(pipeline)}</b></li>
            <li><span><a href="${scan.href}">Network check</a></span><b class="${scan.state === "warn" ? "warn" : ""}">${scan.figure} · ${scan.text}</b></li>
            ${devices && devices.read ? html`<li><span><a href="/scan/devices">Devices</a></span><b>${devices.exposed} exposed of ${devices.read} read${devices.behind ? `, ${devices.behind} behind` : ""}</b></li>` : ""}
            <li><span><a href="/digest">Last digest</a></span><b>${digest ? relativeTime(digest.generated_at, now) : "none yet"}</b></li>
          </ul>
          ${failing.length ? html`<ul class="src-fail">${failing.map((f) => html`<li><a href="/sources#src-${f.id}"><b>${f.name}</b></a> <span class="small">${f.last_error ?? "error"}</span></li>`)}</ul>` : ""}
          ${alerts.length ? html`<ul class="alerts">${alerts.map((a) => html`<li class="${a.status}"><span class="when">${relativeTime(a.sent_at, now)} · ${a.kind} · ${a.status}</span>${a.url ? html`<a href="${a.url}" ${newTabIf(a.url)}>${a.title}</a>` : a.title}</li>`)}</ul>` : ""}
        </section>
      </aside>
    </div>`;

  return page({
    title: "Today",
    active: "today",
    content,
    meta: html`${list.install.length} update(s) · ${list.fixed} fixed · ${published.size} with no version named · ${nothing.size} with nothing published`,
    owner,
    open,
    strip: registerStrip(db, now),
    look,
    canonical: "/today",
    description: "The window's work, grouped by the update that ends it: what to install, where the fix is published without a version, what to mitigate, and what has nothing published yet.",
  });
}
