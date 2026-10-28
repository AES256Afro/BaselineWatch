import type { DatabaseSync } from "node:sqlite";
import { adapterFor, fetchable } from "../adapters/index.ts";
import type { Adapter, SourceRow } from "../adapters/types.ts";
import { html, newTab, newTabIf, type Html } from "../html.ts";
import { defaultRetention, formatBytes, storageReport } from "../housekeeping.ts";
import { knownRelease } from "../pipeline.ts";
import { productVersion } from "../version.ts";
import { shortStamp } from "../time.ts";
import type { LookState } from "../look.ts";
import { groupOf, standardGroups, type Group } from "./controls.ts";
import { curatedStores, daysSince } from "../curated.ts";
import { sourceLog, type FeedProbe, type NewSource } from "../newsource.ts";
import { repairsBySource, type Repair } from "../repairs.ts";
import { page } from "./layout.ts";

/** A known failure translated into what to do about it, drawn under the raw error. */
function hintFor(s: SourceRow, adapter: Adapter | null): Html {
  if (s.id === "nvd-cves" && s.last_status === "error" && /HTTP 404/.test(s.last_error ?? "")) {
    return html`<div class="note">NVD answers 404 when the request carries an invalid or expired API key. <a href="https://nvd.nist.gov/developers/request-an-api-key" ${newTab}>Request a free key</a> and set it as the NVD API key on the app's settings (BW_NVD_API_KEY), or clear the key — keyless pulls work at a slower rate. The cursor resumes where it stopped, so the gap backfills itself.</div>`;
  }
  if (s.last_status === "error" && /HTTP (403|429)/.test(s.last_error ?? "")) {
    return html`<div class="note">The publisher is refusing or rate-limiting requests right now; the scheduler keeps trying on the source's own schedule, so no action is needed unless it persists for days.</div>`;
  }
  if (s.format === "pdf-upload") {
    return html`<div class="note">Loaded by hand: get the PDF from <a href="https://workbench.cisecurity.org/" ${newTab}>CIS WorkBench</a> (free registration) under your licence, then upload it on <a href="/standards/${s.id}">the benchmark page</a>.</div>`;
  }
  if (!adapter && s.enabled) {
    return html`<div class="note">Planned: this source is registered but no adapter reads it yet, so it is skipped. It arrives in a later release; nothing to do here.</div>`;
  }
  return html``;
}

const groupLabel: Record<string, string> = {
  standards: "Standards and baselines",
  vulnerabilities: "Vulnerabilities",
  news: "News and advisories",
};

export interface SourcesPageOptions {
  db: DatabaseSync;
  owner: boolean;
  open: boolean;
  notice: { sourceId: string; status: string; detail: string } | null;
  look: LookState;
  /** The clock the ledger's ages are counted against; the wall clock when omitted. */
  now?: Date;
}

/** What answered for a source while its own address failed, and the repairs proposed for it. */
function repairNotes(s: SourceRow, repairs: Repair[], owner: boolean): Html {
  const fallback = s.answered_from
    ? html`<div class="note">Answered from its fallback <a href="${s.answered_from}" ${newTabIf(s.answered_from)}>${hostOf(s.answered_from)}</a>; its own address failed: ${s.primary_error ?? "error"}.${owner
        ? html` <form method="post" action="/sources/${s.id}/adopt-fallback" class="inline"><button type="submit">Make it the address</button></form>`
        : ""}</div>`
    : html``;
  if (!owner || repairs.length === 0) return fallback;
  return html`${fallback}<div class="note repair"><b>Proposed repair${repairs.length === 1 ? "" : "s"}</b>, found by this instance and probed:<ul>${repairs.map(
    (r) => html`<li><a href="${r.url}" ${newTabIf(r.url)}>${r.url}</a> — ${r.how}; ${r.items} entries${r.sample ? html`, the newest "${r.sample}"` : ""}. <form method="post" action="/sources/${s.id}/repairs/${r.id}/use" class="inline"><button type="submit">Use it</button></form></li>`,
  )}</ul></div>`;
}

const hostOf = (url: string): string => {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
};

/** The owner's form: an address and a few choices, probed before anything is saved. */
function addForm(input?: NewSource | null): Html {
  const v = input ?? null;
  const opt = (value: string, label: string, chosen: boolean) => html`<option value="${value}"${chosen ? html` selected` : ""}>${label}</option>`;
  return html`<form method="post" action="/sources/probe" class="stack">
      <label for="src-url">Feed address (RSS, RSS 1.0 or Atom)</label>
      <input type="url" id="src-url" name="url" required maxlength="500" placeholder="https://example.com/feed.xml" value="${v?.url ?? ""}">
      <label for="src-name">Name (optional: the feed's own title otherwise)</label>
      <input type="text" id="src-name" name="name" maxlength="100" value="${v?.name ?? ""}">
      <label for="src-group">Where its entries go</label>
      <select id="src-group" name="group">${opt("news", "News and advisories", v?.group !== "vulnerabilities")}${opt("vulnerabilities", "Vulnerabilities (a vendor's or a CERT's advisories)", v?.group === "vulnerabilities")}</select>
      <label for="src-topic">Beat</label>
      <select id="src-topic" name="topic">${opt("", "None", v?.topic !== "ai")}${opt("ai", "AI: every entry joins the AI beat", v?.topic === "ai")}</select>
      <label for="src-schedule">Checked</label>
      <select id="src-schedule" name="schedule">${opt("hourly", "Hourly", v?.schedule === "hourly")}${opt("daily", "Daily", !v || v.schedule === "daily")}${opt("weekly", "Weekly", v?.schedule === "weekly")}</select>
      <label for="src-licence">Licence or terms (optional)</label>
      <input type="text" id="src-licence" name="licence" maxlength="200" value="${v?.licence ?? ""}">
      <button type="submit" class="primary">Probe it</button>
    </form>`;
}

/** The ledger of what is kept by hand (M20.1), public: it is the honest answer to "where does this come from". */
function keptByHand(db: DatabaseSync, now: Date): Html {
  const status = new Map((db.prepare("SELECT id, name, last_status FROM sources").all() as { id: string; name: string; last_status: string | null }[]).map((r) => [r.id, r]));
  return html`<section id="by-hand">
      <h2><a href="#by-hand">Kept by hand</a> <span class="count">${curatedStores.length}</span></h2>
      <p class="note">What this site shows that no publisher sends it: data typed into the repository and shipped with each release. Each row says how it goes stale, what checks it, and which part of the plan's M20 is meant to replace it with something this instance fetches or the owner enters; the rest are kept by hand on purpose.</p>
      <div class="table-wrap"><table><caption class="visually-hidden">Data kept by hand</caption>
        <thead><tr><th scope="col">Where</th><th scope="col">Holds</th><th scope="col">Goes stale when</th><th scope="col">Checked by</th><th scope="col">Reviewed</th><th scope="col">Replaced by</th></tr></thead>
        <tbody>${curatedStores.map((c) => {
          const checker = c.checkedBy === null
            ? html`<span class="state wait">nothing</span>`
            : "source" in c.checkedBy
              ? html`<a href="#src-${c.checkedBy.source}">${status.get(c.checkedBy.source)?.name ?? c.checkedBy.source}</a>${status.get(c.checkedBy.source)?.last_status ? html` <span class="status ${status.get(c.checkedBy.source)!.last_status!}">${status.get(c.checkedBy.source)!.last_status!}</span>` : ""}`
              : html`<code>${c.checkedBy.script}</code>`;
          return html`<tr><td><code>${c.where}</code></td><td>${c.holds}</td><td>${c.staleWhen}</td><td>${checker}</td><td class="n reviewed">${c.reviewed}<div class="small">${daysSince(c.reviewed, now)} days ago</div></td><td>${c.retiredBy ?? html`<span class="small">kept on purpose</span>`}</td></tr>`;
        })}</tbody>
      </table></div>
    </section>`;
}

const actionWords: Record<string, string> = { added: "added", address: "moved", enabled: "turned on", disabled: "turned off" };

/** The owner's own changes, newest first: the record that the data stayed current without a commit. */
function changeLog(db: DatabaseSync): Html {
  const log = sourceLog(db);
  return html`<section id="changes">
      <h2><a href="#changes">Changes made here</a> <span class="count">${log.length}</span></h2>
      ${log.length === 0
        ? html`<p class="note">None yet: every source here came with a release. A source added, moved, or turned on or off on this page is recorded here.</p>`
        : html`<div class="table-wrap"><table><caption class="visually-hidden">Changes made to sources on this instance</caption>
            <thead><tr><th scope="col">When</th><th scope="col">Source</th><th scope="col">Change</th></tr></thead>
            <tbody>${log.map((e) => html`<tr><td>${shortStamp(e.at)}</td><td><a href="#src-${e.source_id}">${e.name ?? e.source_id}</a></td><td>${actionWords[e.action] ?? e.action}${e.before ? html` · was <code>${e.before}</code>` : ""}${e.after ? html` · now <code>${e.after}</code>` : ""}</td></tr>`)}</tbody>
          </table></div>`}
    </section>`;
}

/**
 * A source's note folded to its first sentence: the rest — how it is read, what it covers, why it is
 * here — is a click away rather than the reason every row is ten lines tall.
 */
function aboutNote(notes: string): Html {
  const m = /^(.+?[.;:])\s+(\S.*)$/s.exec(notes);
  if (!m || m[1]!.length > 160) return html`<div class="note">${notes}</div>`;
  return html`<details class="note about"><summary>${m[1]}</summary>${m[2]}</details>`;
}

/** The standards group cut under the ladder's headings, as Controls draws them; other groups in one piece. */
function ordered<T extends SourceRow>(group: string, list: T[]): { heading: Group | null; sources: T[] }[] {
  if (group !== "standards") return [{ heading: null, sources: list }];
  return standardGroups.map((g) => ({ heading: g, sources: list.filter((s) => groupOf(s.id) === g.id) })).filter((g) => g.sources.length > 0);
}

export function renderSources({ db, owner, open, notice, look, now = new Date() }: SourcesPageOptions): string {
  const repairs = owner ? repairsBySource(db) : new Map<string, Repair[]>();
  const rows = db
    .prepare(
      `SELECT s.*, (SELECT COUNT(*) FROM items i WHERE i.source_id = s.id) AS item_count
       FROM sources s
       ORDER BY CASE group_name WHEN 'standards' THEN 0 WHEN 'vulnerabilities' THEN 1 ELSE 2 END, name`,
    )
    .all() as unknown as (SourceRow & { item_count: number })[];

  const groups = new Map<string, (SourceRow & { item_count: number })[]>();
  for (const row of rows) {
    const list = groups.get(row.group_name) ?? [];
    list.push(row);
    groups.set(row.group_name, list);
  }

  const tables: Html[] = [];
  for (const [group, list] of groups) {
    tables.push(html`<section id="${group}">
      <h2><a href="/?group=${group}">${groupLabel[group] ?? group}</a> <span class="count"><a href="#${group}">${list.length}</a></span></h2>
      <div class="table-wrap"><table><caption class="visually-hidden">Sources read by this instance</caption>
        <thead><tr><th scope="col">Source</th><th scope="col">Format</th><th scope="col">Checked</th><th scope="col">Items</th><th scope="col">Last fetch</th><th scope="col">Licence</th>${owner ? html`<th scope="col"></th>` : ""}</tr></thead>
        ${ordered(group, list).map(({ heading, sources }) => html`<tbody>${heading ? html`<tr class="series"><th scope="rowgroup" colspan="${owner ? 7 : 6}"><b>${heading.label}</b> · ${heading.line}</th></tr>` : ""}${sources.map((s) => {
          const adapter = adapterFor(s);
          return html`<tr id="src-${s.id}" class="${s.enabled ? "" : "off"}">
            <td><a href="${s.url}" ${newTabIf(s.url)}>${s.name}</a>${s.origin === "owner" ? html` <span class="small">added here</span>` : ""}${s.notes ? aboutNote(s.notes) : ""}</td>
            <td>${s.format}</td>
            <td>${s.enabled ? s.schedule : "off"}${adapter ? "" : html`<div class="note">no adapter yet</div>`}</td>
            <td class="n"><a href="/?source=${s.id}">${s.item_count}</a></td>
            <td>${s.last_fetch_at
              ? html`${shortStamp(s.last_fetch_at)} <span class="status ${s.last_status ?? ""}">${s.last_status ?? ""}</span>${s.last_duration_ms !== null ? html` <span class="small">${s.last_duration_ms} ms</span>` : ""}`
              : html`<span class="state wait">never</span>`}${s.last_error ? html`<div class="note err">${s.last_error}</div>` : ""}${hintFor(s, adapter)}${repairNotes(s, repairs.get(s.id) ?? [], owner)}</td>
            <td>${s.licence ?? "—"}${s.restricted ? html`<div class="note">Restricted: the entries are shown to the signed-in owner only; visitors see versions and counts, and the API and MCP tools return neither names nor text.</div>` : ""}</td>
            ${owner
              ? html`<td><div class="acts">${fetchable(adapter) ? html`<form method="post" action="/sources/${s.id}/fetch" class="inline"><button type="submit">Fetch now</button></form>` : s.format === "pdf-upload" ? html`<a href="/standards/${s.id}">Upload</a>` : ""}${
                  s.format === "pdf-upload" ? "" : html`<form method="post" action="/sources/${s.id}/${s.enabled ? "disable" : "enable"}" class="inline"><button type="submit">${s.enabled ? "Turn off" : "Turn on"}</button></form>`
                }</div></td>`
              : ""}
          </tr>`;
        })}</tbody>`)}
      </table></div>
    </section>`);
  }

  // What the instance is holding, and what the weekly pass let go (M13). Public, like the counts:
  // the rules are the product's policy, and a disk figure says nothing a visitor should not see.
  const storage = storageReport(db);
  const last = storage.lastRun;
  // Nothing polls for this: it is what the owner's last check saw, if they have made one.
  const release = knownRelease(db);
  const storageSection = html`<section id="storage">
      <h2>What this instance keeps <span class="count">${formatBytes(storage.databaseBytes)}</span></h2>
      <p class="note">A standard's snapshot is the product: the exact bytes NIST, DISA or Microsoft served, kept for good, because they are the "before" in every diff. A news or vulnerability feed's bytes are a delivery: the items are normalised out of them on arrival, so each document's newest fetch is kept and the rest go after ${defaultRetention.feedSnapshotDays} days. Network scans are kept ${defaultRetention.networkScanDays} days and the alert log ${defaultRetention.alertDays}; a device's readings ${defaultRetention.deviceReadingDays}, except its newest, which stays. Microsoft's update rows, the exploit indexes, the certificates seen for your domains and the vendors' end dates are kept; the Tor exit list is swapped whole each day. Nothing deletes a timeline item, a CVE, a requirement, a change or an explanation.</p>
      <div class="table-wrap"><table><caption class="visually-hidden">What this instance keeps</caption>
        <tbody>
          <tr><th scope="row">Database</th><td class="n">${formatBytes(storage.databaseBytes)}</td></tr>
          <tr><th scope="row">Snapshots</th><td class="n">${storage.snapshots} (${formatBytes(storage.snapshotBytes)}), ${storage.keptSnapshots} kept as a standard's evidence</td></tr>
          <tr><th scope="row">Article images</th><td class="n">${storage.imageBlobs}</td></tr>
          <tr><th scope="row">Oldest snapshot held</th><td class="n">${storage.oldestSnapshotAt ? shortStamp(storage.oldestSnapshotAt) : "none yet"}</td></tr>
          <tr><th scope="row">Version</th><td class="n">${productVersion} running${release.version
            ? release.newer
              ? html` · <b>${release.version} is published</b> (checked ${shortStamp(release.checkedAt)})`
              : html` · the newest release, checked ${shortStamp(release.checkedAt)}`
            : release.checkedAt
              ? html` · the last check (${shortStamp(release.checkedAt)}) got no answer`
              : html` · <span class="state wait">never checked</span>`}${owner
            ? html` <form method="post" action="/sources/check-version" class="inline"><button type="submit">Check now</button></form>`
            : ""}</td></tr>
          <tr><th scope="row">Last housekeeping</th><td class="n">${last
            ? html`${shortStamp(last.ranAt)}: ${last.snapshotsDeleted} snapshot(s), ${last.blobsDeleted} blob(s) (${formatBytes(last.blobBytesFreed)}), ${last.networkScansDeleted} scan(s), ${last.deviceReadingsDeleted ?? 0} reading(s), ${last.alertsDeleted} alert(s)${last.vacuumed ? ", file rewritten" : ""}`
            : html`<span class="state wait">not yet; the pass runs weekly</span>`}</td></tr>
        </tbody>
      </table></div>
    </section>`;

  const content = html`
    <h1>Sources</h1>
    <p class="lede">Everything BaselineWatch reads, with how often and under what terms. Sources are fetched on their schedule; ${owner ? "Fetch now runs one immediately, and Turn off or Turn on takes a source out of or back into the schedule." : "the owner can fetch one immediately, or turn one off or on."}</p>
    ${notice ? html`<div class="notice ${notice.status}"><b>${notice.sourceId}</b>: ${notice.status}${notice.detail ? html` · ${notice.detail}` : ""}</div>` : ""}
    ${owner
      ? html`<details class="fold" id="add"><summary><b>Add a source</b> · a feed by its address, probed before anything is saved</summary>${addForm()}<p class="small">The address is fetched once, from public hosts only, and read by the same feed adapter that will read it on its schedule; nothing is saved until the first entries are shown and you add it. Headlines and links only, as for every feed.</p></details>`
      : ""}
    ${tables}
    ${owner ? changeLog(db) : ""}
    ${keptByHand(db, now)}
    ${storageSection}`;

  return page({ title: "Sources", active: "sources", content, meta: html`${rows.length} sources`, owner, open, look });
}

export interface SourceProbePageOptions {
  owner: boolean;
  open: boolean;
  look: LookState;
  /** The form as read; null when it could not be. */
  input: NewSource | null;
  /** Null when the probe was not made: the address is already a source. */
  probe: FeedProbe | null;
  duplicate: { id: string; name: string } | null;
}

/** What a feed would bring if added now, with the form to add it or to try again. */
export function renderSourceProbe({ owner, open, look, input, probe, duplicate }: SourceProbePageOptions): string {
  const hidden = (i: NewSource) => html`<input type="hidden" name="url" value="${i.url}"><input type="hidden" name="name" value="${i.name}"><input type="hidden" name="group" value="${i.group}"><input type="hidden" name="topic" value="${i.topic ?? ""}"><input type="hidden" name="schedule" value="${i.schedule}"><input type="hidden" name="licence" value="${i.licence ?? ""}">`;
  const body = duplicate
    ? html`<div class="notice error">This address is already read, as <a href="/sources#src-${duplicate.id}">${duplicate.name}</a>.</div>`
    : probe && probe.ok
      ? html`<div class="notice ok">It answers: ${probe.feed.format === "atom" ? "an Atom" : "an RSS"} feed${probe.feed.title ? html`, "${probe.feed.title}"` : ""}, with ${probe.feed.count} entries.</div>
          <h2>The newest entries</h2>
          <ul>${probe.feed.items.map((i) => html`<li>${i.url ? html`<a href="${i.url}" ${newTabIf(i.url)}>${i.title}</a>` : i.title}${i.publishedAt ? html` <span class="small">${shortStamp(i.publishedAt)}</span>` : ""}</li>`)}</ul>
          ${input
            ? html`<form method="post" action="/sources/add" class="stack">${hidden(input)}<p class="small">It will be named "${input.name || probe.feed.title || hostOf(input.url)}", go to ${input.group === "vulnerabilities" ? "Vulnerabilities" : "the News"}${input.topic === "ai" ? " on the AI beat" : ""} and be checked ${input.schedule}. It is fetched once on adding, so its entries arrive now.</p><button type="submit" class="primary">Add it</button></form>`
            : ""}`
      : html`<div class="notice error">Not added: ${probe?.error ?? "the form could not be read"}.</div>`;
  const content = html`
    <h1>Add a source</h1>
    <p class="lede">${input ? html`<code>${input.url}</code>` : "A feed by its address."}</p>
    ${body}
    <section class="box"><h2>${probe && probe.ok && !duplicate ? "Or change it" : "Try again"}</h2>${addForm(input)}</section>
    <p><a href="/sources">Back to the sources</a></p>`;
  return page({ title: "Add a source", active: "sources", content, owner, open, look });
}
