import type { DatabaseSync } from "node:sqlite";
import { adapterFor, fetchable } from "../adapters/index.ts";
import type { Adapter, SourceRow } from "../adapters/types.ts";
import { html, newTab, newTabIf, type Html } from "../html.ts";
import { defaultRetention, formatBytes, storageReport } from "../housekeeping.ts";
import { knownRelease } from "../pipeline.ts";
import { productVersion } from "../version.ts";
import { shortStamp } from "../time.ts";
import type { LookState } from "../look.ts";
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
}

export function renderSources({ db, owner, open, notice, look }: SourcesPageOptions): string {
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
      <div class="table-wrap"><table>
        <thead><tr><th>Source</th><th>Format</th><th>Checked</th><th>Items</th><th>Last fetch</th><th>Licence</th>${owner ? html`<th></th>` : ""}</tr></thead>
        <tbody>${list.map((s) => {
          const adapter = adapterFor(s);
          return html`<tr id="src-${s.id}" class="${s.enabled ? "" : "off"}">
            <td><a href="${s.url}" ${newTabIf(s.url)}>${s.name}</a>${s.notes ? html`<div class="note">${s.notes}</div>` : ""}</td>
            <td>${s.format}</td>
            <td>${s.enabled ? s.schedule : "off"}${adapter ? "" : html`<div class="note">no adapter yet</div>`}</td>
            <td class="n"><a href="/?source=${s.id}">${s.item_count}</a></td>
            <td>${s.last_fetch_at
              ? html`${shortStamp(s.last_fetch_at)} <span class="status ${s.last_status ?? ""}">${s.last_status ?? ""}</span>${s.last_duration_ms !== null ? html` <span class="small">${s.last_duration_ms} ms</span>` : ""}`
              : html`<span class="state wait">never</span>`}${s.last_error ? html`<div class="note err">${s.last_error}</div>` : ""}${hintFor(s, adapter)}</td>
            <td>${s.licence ?? "—"}${s.restricted ? html`<div class="note">Restricted: the entries are shown to the signed-in owner only; visitors see versions and counts, and the API and MCP tools return neither names nor text.</div>` : ""}</td>
            ${owner
              ? html`<td><div class="acts">${fetchable(adapter) ? html`<form method="post" action="/sources/${s.id}/fetch" class="inline"><button type="submit">Fetch now</button></form>` : s.format === "pdf-upload" ? html`<a href="/standards/${s.id}">Upload</a>` : ""}${
                  s.format === "pdf-upload" ? "" : html`<form method="post" action="/sources/${s.id}/${s.enabled ? "disable" : "enable"}" class="inline"><button type="submit">${s.enabled ? "Turn off" : "Turn on"}</button></form>`
                }</div></td>`
              : ""}
          </tr>`;
        })}</tbody>
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
      <p class="note">A standard's snapshot is the product: the exact bytes NIST, DISA or Microsoft served, kept for good, because they are the "before" in every diff. A news or vulnerability feed's bytes are a delivery: the items are normalised out of them on arrival, so each document's newest fetch is kept and the rest go after ${defaultRetention.feedSnapshotDays} days. Network scans are kept ${defaultRetention.networkScanDays} days and the alert log ${defaultRetention.alertDays}. Nothing deletes a timeline item, a CVE, a requirement, a change or an explanation.</p>
      <div class="table-wrap"><table>
        <tbody>
          <tr><th>Database</th><td class="n">${formatBytes(storage.databaseBytes)}</td></tr>
          <tr><th>Snapshots</th><td class="n">${storage.snapshots} (${formatBytes(storage.snapshotBytes)}), ${storage.keptSnapshots} kept as a standard's evidence</td></tr>
          <tr><th>Article images</th><td class="n">${storage.imageBlobs}</td></tr>
          <tr><th>Oldest snapshot held</th><td class="n">${storage.oldestSnapshotAt ? shortStamp(storage.oldestSnapshotAt) : "none yet"}</td></tr>
          <tr><th>Version</th><td class="n">${productVersion} running${release.version
            ? release.newer
              ? html` · <b>${release.version} is published</b> (checked ${shortStamp(release.checkedAt)})`
              : html` · the newest release, checked ${shortStamp(release.checkedAt)}`
            : release.checkedAt
              ? html` · the last check (${shortStamp(release.checkedAt)}) got no answer`
              : html` · <span class="state wait">never checked</span>`}${owner
            ? html` <form method="post" action="/sources/check-version" class="inline"><button type="submit">Check now</button></form>`
            : ""}</td></tr>
          <tr><th>Last housekeeping</th><td class="n">${last
            ? html`${shortStamp(last.ranAt)}: ${last.snapshotsDeleted} snapshot(s), ${last.blobsDeleted} blob(s) (${formatBytes(last.blobBytesFreed)}), ${last.networkScansDeleted} scan(s), ${last.alertsDeleted} alert(s)${last.vacuumed ? ", file rewritten" : ""}`
            : html`<span class="state wait">not yet; the pass runs weekly</span>`}</td></tr>
        </tbody>
      </table></div>
    </section>`;

  const content = html`
    <h1>Sources</h1>
    <p class="lede">Everything BaselineWatch reads, with how often and under what terms. Sources are fetched on their schedule; ${owner ? "Fetch now runs one immediately, and Turn off or Turn on takes a source out of or back into the schedule." : "the owner can fetch one immediately, or turn one off or on."}</p>
    ${notice ? html`<div class="notice ${notice.status}"><b>${notice.sourceId}</b>: ${notice.status}${notice.detail ? html` · ${notice.detail}` : ""}</div>` : ""}
    ${tables}
    ${storageSection}`;

  return page({ title: "Sources", active: "sources", content, meta: html`${rows.length} sources`, owner, open, look });
}
