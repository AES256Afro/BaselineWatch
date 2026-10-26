import type { DatabaseSync } from "node:sqlite";
import { html, newTabIf, type Html } from "../html.ts";
import { titleWithin, type Publication, type Series } from "../publications.ts";
import { changeSummaryFor, changeSummaryText, type DocumentRow } from "../register.ts";
import { relativeTime } from "../time.ts";

/**
 * One table for a source's publications, drawn the same on Controls, the all-standards catalog and
 * the standard's own page: a row per publication with its current version, the draft that will
 * replace it, what the current version changed, and the earlier versions folded under a count.
 * Publications that share a number sit under one series row, so SP 800-63B is found under SP 800-63
 * rather than by scrolling.
 */

/** Everything counts as new while its publication date is this fresh. */
export const newForDays = 60;

const day = (d: DocumentRow): string => (d.published_at ?? d.parsed_at).slice(0, 10);

function isNew(d: DocumentRow, now: Date): boolean {
  return d.published_at !== null && now.getTime() - Date.parse(d.published_at) <= newForDays * 86_400_000;
}

function versionCell(sourceId: string, d: DocumentRow, now: Date): Html {
  return html`<a href="/standards/${sourceId}/${d.id}"><b>${d.version_label ?? d.title ?? "version unknown"}</b></a>${isNew(d, now) ? html` <span class="chip ok">new</span>` : ""}
    <div class="note">${day(d)} · <a href="/standards/${sourceId}/${d.id}/browse">${d.requirement_count} entries</a></div>`;
}

function draftCell(p: Publication): Html {
  const loaded = p.draft ? html`<a href="/standards/${p.sourceId}/${p.draft.id}"><b>${p.draft.version_label}</b></a><div class="note">${day(p.draft)}</div>` : html``;
  // CSRC's announcement reads "SP 800-73-6, Interfaces for … Part 1 – …Initial Working Draft"; the cell keeps the number and the stage.
  const announced = p.openDrafts.map((o) => {
    const number = o.title.split(",")[0]!.trim();
    const stage = /((?:Initial|Final|Second|Third)?\s*(?:Public|Working) Draft)$/i.exec(o.title)?.[1]?.trim().toLowerCase() ?? "draft";
    return html`<div>${o.url ? html`<a href="${o.url}" ${newTabIf(o.url)}><b>${number}</b></a>` : html`<b>${number}</b>`}<div class="note">${stage}${o.published_at ? html` · ${o.published_at.slice(0, 10)}` : ""} · <span class="chip na">open for comment</span></div></div>`;
  });
  return p.draft || announced.length ? html`${loaded}${announced}` : html`<span class="small">none</span>`;
}

function changedCell(db: DatabaseSync, p: Publication): Html {
  const d = p.current ?? p.draft;
  if (!d) return html``;
  if (!d.previous_document_id) return html`<span class="small">first version loaded</span>`;
  return html`<a href="/standards/${p.sourceId}/${d.id}">${changeSummaryText(changeSummaryFor(db, d.id))}</a>`;
}

function earlierCell(p: Publication): Html {
  if (p.earlier.length === 0) return html`<span class="small">none</span>`;
  return html`<details class="earlier"><summary>${p.earlier.length} earlier</summary><ul class="plain">${p.earlier.map(
    (d) => html`<li><a href="/standards/${p.sourceId}/${d.id}">${d.version_label ?? d.title ?? "version unknown"}</a> <span class="when">${day(d)}</span></li>`,
  )}</ul></details>`;
}

/** The table for one source's series; a publication's heading goes to its every version on the standard's page. */
export function publicationsTable(db: DatabaseSync, series: Series[], now: Date): Html {
  const row = (s: Series, p: Publication, nested: boolean): Html => {
    const subtitle = titleWithin(s, p);
    return html`<tr${nested ? html` class="in-series"` : ""}>
    <td class="pub"><a href="/standards/${p.sourceId}#doc-${p.key.replace(/[^a-z0-9]+/gi, "-")}"><b>${p.label}</b></a>${subtitle ? html`<div class="note">${subtitle}</div>` : ""}</td>
    <td>${p.current ? versionCell(p.sourceId, p.current, now) : html`<span class="small">no final version yet</span>`}</td>
    <td>${draftCell(p)}</td>
    <td>${changedCell(db, p)}</td>
    <td>${earlierCell(p)}</td>
  </tr>`;
  };
  return html`<div class="table-wrap"><table class="pubs"><caption class="visually-hidden">Publications, their current version, draft and earlier versions</caption>
    <thead><tr><th scope="col">Publication</th><th scope="col">Current</th><th scope="col">Draft</th><th scope="col">What the latest changed</th><th scope="col">Earlier</th></tr></thead>
    ${series.map((s) =>
      s.publications.length > 1
        ? html`<tbody><tr class="series"><th scope="rowgroup" colspan="5">${s.number ? html`<b>${s.number}</b> · ` : ""}${s.title} <span class="count">${s.publications.length} publications</span></th></tr>${s.publications.map((p) => row(s, p, true))}</tbody>`
        : html`<tbody>${row(s, s.publications[0]!, false)}</tbody>`,
    )}
  </table></div>`;
}

/** The figures a folded group shows before it is opened. */
export function seriesSummary(series: Series[]): { publications: number; entries: number; drafts: number; newest: DocumentRow | null } {
  const pubs = series.flatMap((s) => s.publications);
  const currents = pubs.map((p) => p.current).filter((d): d is DocumentRow => d !== null);
  const newest = [...currents].sort((a, b) => (b.published_at ?? b.parsed_at).localeCompare(a.published_at ?? a.parsed_at))[0] ?? null;
  return {
    publications: pubs.length,
    entries: currents.reduce((sum, d) => sum + d.requirement_count, 0),
    drafts: pubs.filter((p) => p.draft || p.openDrafts.length).length,
    newest,
  };
}

/** One standard as a folded group: the figures on the fold, the publications inside. */
export function standardFold(db: DatabaseSync, source: { id: string; name: string; notes: string | null }, series: Series[], now: Date): Html {
  const { publications, entries, drafts, newest } = seriesSummary(series);
  const single = publications === 1 ? series[0]!.publications[0]! : null;
  const figures = single
    ? html`${single.current?.version_label ?? single.draft?.version_label ?? ""} · ${entries.toLocaleString("en-US")} entries`
    : html`${publications} publications · ${entries.toLocaleString("en-US")} entries`;
  return html`<details class="fold" id="src-${source.id}">
    <summary><b>${source.name}</b><span class="fold-meta">${figures}${drafts ? html` · <span class="chip na">${drafts} draft${drafts === 1 ? "" : "s"}</span>` : ""}${newest ? html` · updated ${relativeTime(newest.published_at ?? newest.parsed_at, now)}` : ""}</span></summary>
    ${source.notes ? html`<p class="std-note">${source.notes}</p>` : ""}
    ${publicationsTable(db, series, now)}
    <p class="small"><a href="/standards/${source.id}">Every version of ${source.name}, with what each changed →</a></p>
  </details>`;
}
