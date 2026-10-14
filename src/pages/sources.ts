import type { DatabaseSync } from "node:sqlite";
import { html, type Html } from "../html.ts";
import { page } from "./layout.ts";

interface SourceRow {
  id: string;
  name: string;
  kind: string;
  group_name: string;
  url: string;
  format: string;
  schedule: string;
  enabled: number;
  licence: string | null;
  notes: string | null;
  last_fetch_at: string | null;
  last_status: string | null;
  last_error: string | null;
}

const groupLabel: Record<string, string> = {
  standards: "Standards and baselines",
  vulnerabilities: "Vulnerabilities",
  news: "News and advisories",
};

export function renderSources(ctx: { db: DatabaseSync }): string {
  const rows = ctx.db
    .prepare("SELECT * FROM sources ORDER BY CASE group_name WHEN 'standards' THEN 0 WHEN 'vulnerabilities' THEN 1 ELSE 2 END, name")
    .all() as unknown as SourceRow[];

  const groups = new Map<string, SourceRow[]>();
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
        <thead><tr><th>Source</th><th>Kind</th><th>Format</th><th>Checked</th><th>Last fetch</th><th>Licence</th></tr></thead>
        <tbody>${list.map(
          (s) => html`<tr class="${s.enabled ? "" : "off"}">
            <td><a href="${s.url}" rel="noopener">${s.name}</a>${s.notes ? html`<div class="note">${s.notes}</div>` : ""}</td>
            <td>${s.kind}</td>
            <td>${s.format}</td>
            <td>${s.enabled ? s.schedule : "off"}</td>
            <td>${s.last_fetch_at ? html`${s.last_fetch_at.slice(0, 16).replace("T", " ")} <span class="status ${s.last_status ?? ""}">${s.last_status ?? ""}</span>` : html`<span class="state wait">never</span>`}${s.last_error ? html`<div class="note err">${s.last_error}</div>` : ""}</td>
            <td>${s.licence ?? "—"}</td>
          </tr>`,
        )}</tbody>
      </table></div>
    </section>`);
  }

  const content = html`
    <h1>Sources</h1>
    <p class="lede">Everything BaselineWatch reads, with how often and under what terms. Nothing is fetched in this build; the table shows the register the adapters will work from. Enabling and disabling arrives with M1.</p>
    ${tables}`;

  return page({ title: "Sources", active: "sources", content, meta: html`${rows.length} sources` });
}
