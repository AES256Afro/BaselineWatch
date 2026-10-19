import type { DatabaseSync } from "node:sqlite";
import { adapterFor, fetchable } from "../adapters/index.ts";
import type { Adapter, SourceRow } from "../adapters/types.ts";
import { html, newTab, newTabIf, type Html } from "../html.ts";
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
    tables.push(html`<section>
      <h2>${groupLabel[group] ?? group} <span class="count">${list.length}</span></h2>
      <div class="table-wrap"><table>
        <thead><tr><th>Source</th><th>Format</th><th>Checked</th><th>Items</th><th>Last fetch</th><th>Licence</th>${owner ? html`<th></th>` : ""}</tr></thead>
        <tbody>${list.map((s) => {
          const adapter = adapterFor(s);
          return html`<tr class="${s.enabled ? "" : "off"}">
            <td><a href="${s.url}" ${newTabIf(s.url)}>${s.name}</a>${s.notes ? html`<div class="note">${s.notes}</div>` : ""}</td>
            <td>${s.format}</td>
            <td>${s.enabled ? s.schedule : "off"}${adapter ? "" : html`<div class="note">no adapter yet</div>`}</td>
            <td class="n">${s.item_count}</td>
            <td>${s.last_fetch_at
              ? html`${shortStamp(s.last_fetch_at)} <span class="status ${s.last_status ?? ""}">${s.last_status ?? ""}</span>${s.last_duration_ms !== null ? html` <span class="small">${s.last_duration_ms} ms</span>` : ""}`
              : html`<span class="state wait">never</span>`}${s.last_error ? html`<div class="note err">${s.last_error}</div>` : ""}${hintFor(s, adapter)}</td>
            <td>${s.licence ?? "—"}</td>
            ${owner ? html`<td>${fetchable(adapter) ? html`<form method="post" action="/sources/${s.id}/fetch" class="inline"><button type="submit">Fetch now</button></form>` : s.format === "pdf-upload" ? html`<a href="/standards/${s.id}">Upload</a>` : ""}</td>` : ""}
          </tr>`;
        })}</tbody>
      </table></div>
    </section>`);
  }

  const content = html`
    <h1>Sources</h1>
    <p class="lede">Everything BaselineWatch reads, with how often and under what terms. Sources are fetched on their schedule; ${owner ? "Fetch now runs one immediately." : "the owner can fetch one immediately."}</p>
    ${notice ? html`<div class="notice ${notice.status}"><b>${notice.sourceId}</b>: ${notice.status}${notice.detail ? html` · ${notice.detail}` : ""}</div>` : ""}
    ${tables}`;

  return page({ title: "Sources", active: "sources", content, meta: html`${rows.length} sources`, owner, open, look });
}
