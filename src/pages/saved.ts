import type { DatabaseSync } from "node:sqlite";
import { html, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { isSaved, listSaved, savablePath } from "../saved.ts";
import { page } from "./layout.ts";

/**
 * Saved searches: the page that lists them, and the one-line form the list pages carry so the
 * owner can keep what they are looking at. Both are drawn for the owner alone; a visitor is told
 * what the page is for.
 */

/** The form a list page shows its owner: name this view and keep it. Nothing when the path carries no filter, or is already kept. */
export function saveSearchForm(db: DatabaseSync, path: string, owner: boolean): Html {
  if (!owner || !savablePath(path)) return html``;
  if (isSaved(db, path)) return html`<p class="small saved-note">This list is <a href="/saved">saved</a>.</p>`;
  return html`<form method="post" action="/saved" class="inline save-search">
    <input type="hidden" name="path" value="${path}">
    <label class="visually-hidden" for="save-name">Name this search</label>
    <input type="text" id="save-name" name="name" placeholder="Name this list" required maxlength="60">
    <button type="submit">Save</button>
  </form>`;
}

export function renderSaved(options: { db: DatabaseSync; owner: boolean; open: boolean; look: LookState; notice?: string | undefined }): string {
  const { db, owner, open, look, notice } = options;
  const saved = listSaved(db);
  const content = html`<div class="wire-top">
    <h1>Saved searches<small>The lists you come back to: a filtered table, a News filter, a search, a month's updates — named once, kept here and on Today.</small></h1>
  </div>
  ${notice ? html`<div class="notice">${notice}</div>` : ""}
  <section class="box wide">
    ${saved.length
      ? html`<ul class="refs saved-list">${saved.map((s) => html`<li><a href="${s.path}"><b>${s.name}</b></a> <span class="small"><code>${s.path}</code></span>${owner ? html` <form method="post" action="/saved/${s.id}/delete" class="inline"><button type="submit" class="link">Remove</button></form>` : ""}</li>`)}</ul>`
      : html`<p class="small">${owner ? "Nothing saved yet. Open the Vulnerabilities table, the News or a search with a filter on, and the Save box at the top keeps it here." : "The owner's saved lists appear here; sign in to keep your own."}</p>`}
  </section>`;
  return page({ title: "Saved searches", active: "saved", content, owner, open, look });
}
