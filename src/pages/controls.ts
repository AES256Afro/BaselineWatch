import type { DatabaseSync } from "node:sqlite";
import { html, newTab, type Html } from "../html.ts";
import { getSource } from "../ingest.ts";
import type { LookState } from "../look.ts";
import { getDocument, licenceOf, withheldFrom } from "../register.ts";
import { documentSources, type SourceLink } from "../sourcelinks.ts";
import { relativeTime } from "../time.ts";
import { latestRegisterChanges, page } from "./layout.ts";

/**
 * Controls: the third rung of the ladder the guide teaches (/guide#ladder). A standard is the
 * rulebook and a baseline picks its rules for a kind of system; a control is one rule — AC-2,
 * IA-2, a STIG rule, a CIS recommendation. This page is one rule at a time: search every
 * standard's current version at once, open any standard's controls, and see which of them have
 * moved lately, which is what the change register holds.
 *
 * A licence-restricted source is listed with its counts and never searched or quoted, the way
 * the Register treats it.
 */

export interface LatestVersion {
  sourceId: string;
  name: string;
  restricted: number;
  licence: string | null;
  documentId: number;
  documentKey: string;
  versionLabel: string | null;
  publishedAt: string | null;
  requirementCount: number;
}

/** The current version of every standard whose entries are controls, newest publication per document key. */
export function latestVersions(db: DatabaseSync): LatestVersion[] {
  return db
    .prepare(
      `SELECT s.id AS sourceId, s.name, s.restricted, s.licence, d.id AS documentId, d.document_key AS documentKey,
              d.version_label AS versionLabel, COALESCE(d.published_at, d.parsed_at) AS publishedAt, d.requirement_count AS requirementCount
         FROM documents d
         JOIN sources s ON s.id = d.source_id
        WHERE s.kind IN ('requirement-set', 'setting-set')
          AND d.id = (SELECT d2.id FROM documents d2
                       WHERE d2.source_id = d.source_id AND d2.document_key = d.document_key
                       ORDER BY COALESCE(d2.published_at, d2.parsed_at) DESC, d2.id DESC LIMIT 1)
        ORDER BY s.name, d.document_key`,
    )
    .all() as unknown as LatestVersion[];
}

export interface ControlHit {
  sourceId: string;
  name: string;
  documentId: number;
  versionLabel: string | null;
  ref: string;
  title: string | null;
  family: string | null;
  severity: string | null;
  statement: string | null;
}

/**
 * One search across the current version of every standard a visitor may read. LIKE rather than
 * FTS5: the requirement tables carry no full-text index, the corpus is tens of thousands of rows
 * rather than millions, and a label search ("ac-2", "SV-2542") is what people actually type.
 */
export function searchControls(db: DatabaseSync, versions: LatestVersion[], q: string, limit = 200): ControlHit[] {
  const ids = versions.map((v) => v.documentId);
  if (ids.length === 0 || q.trim() === "") return [];
  const like = `%${q.trim().toLowerCase()}%`;
  return db
    .prepare(
      `SELECT s.id AS sourceId, s.name, d.id AS documentId, d.version_label AS versionLabel,
              r.ref, r.title, r.family, r.severity, r.statement
         FROM requirements r
         JOIN documents d ON d.id = r.document_id
         JOIN sources s ON s.id = d.source_id
        WHERE r.document_id IN (${ids.map(() => "?").join(", ")})
          AND (lower(r.ref) LIKE ? OR lower(r.title) LIKE ? OR lower(r.statement) LIKE ?)
        ORDER BY (lower(r.ref) LIKE ?) DESC, (lower(r.title) LIKE ?) DESC, s.name, r.ref
        LIMIT ?`,
    )
    .all(...ids, like, like, like, like, like, limit) as unknown as ControlHit[];
}

/**
 * Where a version's own words live at the publisher, looked up once per document however many
 * rows of the page name it. A control's own page carries the address of that one rule; this is
 * the version it belongs to, so a table of controls is not a dead end either.
 */
function publisherFor(db: DatabaseSync): (sourceId: string, documentId: number) => SourceLink | null {
  const cache = new Map<number, SourceLink | null>();
  return (sourceId, documentId) => {
    const held = cache.get(documentId);
    if (held !== undefined) return held;
    const source = getSource(db, sourceId);
    const doc = getDocument(db, documentId);
    const link = source && doc ? (documentSources(source, doc)[0] ?? null) : null;
    cache.set(documentId, link);
    return link;
  };
}

export function renderControls(options: { db: DatabaseSync; q: string | undefined; now: Date; owner: boolean; open: boolean; look: LookState }): string {
  const { db, q, now, owner, open, look } = options;
  const all = latestVersions(db);
  const readable = all.filter((v) => !withheldFrom({ restricted: v.restricted }, owner));
  const withheld = all.filter((v) => withheldFrom({ restricted: v.restricted }, owner));
  const query = (q ?? "").trim();
  const hits = query ? searchControls(db, readable, query) : [];
  const moved = latestRegisterChanges(db, 6);
  const publisher = publisherFor(db);

  const results: Html = query
    ? html`<section class="box wide" id="results">
        <h2>${hits.length === 0 ? html`Nothing matches “${query}”` : html`${hits.length}${hits.length === 200 ? "+" : ""} control(s) matching “${query}”`}</h2>
        ${hits.length === 0
          ? html`<p class="small">Try a label (<code>AC-2</code>, <code>SV-254238</code>, <code>3.1.1</code>), a word from the title, or a phrase from the control's text. Only the current version of each standard is searched; older versions are on the standard's own page.</p>`
          : html`<div class="table-wrap"><table class="browse"><caption class="visually-hidden">Controls matching the search</caption>
              <thead><tr><th scope="col">Control</th><th scope="col">Standard</th><th scope="col">Title</th><th scope="col">Text</th></tr></thead>
              <tbody>${hits.map(
                (h) => html`<tr>
                  <td class="id"><a href="/standards/${h.sourceId}/${h.documentId}/${h.ref}"><b>${(h.ref ?? "").toUpperCase()}</b></a>${h.severity ? html`<div class="note">${h.severity}</div>` : ""}</td>
                  <td><a href="/standards/${h.sourceId}">${h.name}</a><div class="note">${h.versionLabel ?? ""}${(() => {
                    const l = publisher(h.sourceId, h.documentId);
                    return l ? html`${h.versionLabel ? " · " : ""}<a href="${l.href}" ${newTab}>at the publisher</a>` : "";
                  })()}</div></td>
                  <td>${h.title ?? ""}${h.family ? html`<div class="note">${h.family}</div>` : ""}</td>
                  <td class="desc"><span>${(h.statement ?? "").slice(0, 200)}</span></td>
                </tr>`,
              )}</tbody>
            </table></div>`}
      </section>`
    : html``;

  const content = html`
    <div class="wire-top">
      <h1>Controls<small>One rule at a time. A <a href="/guide#ladder">standard</a> is the rulebook, a <a href="/baselines">baseline</a> picks its rules for a kind of system, and a control is one of those rules — what must be true, not how to make it true on a particular machine.</small></h1>
    </div>
    <form method="get" action="/controls" class="search" role="search">
      <label class="visually-hidden" for="q">Search every standard's current version</label>
      <input type="search" id="q" name="q" value="${query}" placeholder="AC-2, multi-factor, SV-254238, password age…">
      <button type="submit">Search</button>
    </form>
    ${results}
    <div class="cols">
      <section class="main">
        <section class="box wide" id="standards">
          <h2>Open a standard's controls <span class="count">${readable.length} current version(s)</span></h2>
          <div class="table-wrap"><table><caption class="visually-hidden">Standards and their current versions</caption>
            <thead><tr><th scope="col">Standard</th><th scope="col">Version</th><th scope="col" class="n">Controls</th><th scope="col">Published</th><th scope="col">At the publisher</th></tr></thead>
            <tbody>${readable.map((v) => {
              const l = publisher(v.sourceId, v.documentId);
              return html`<tr>
                <td><a href="/standards/${v.sourceId}">${v.name}</a>${v.documentKey && readable.filter((o) => o.sourceId === v.sourceId).length > 1 ? html`<div class="note">${v.documentKey}</div>` : ""}</td>
                <td>${v.versionLabel ?? "—"}</td>
                <td class="n"><a href="/standards/${v.sourceId}/${v.documentId}/browse">${v.requirementCount}</a></td>
                <td>${v.publishedAt ? v.publishedAt.slice(0, 10) : "—"}</td>
                <td>${l ? html`<a href="${l.href}" ${newTab}>${l.short ?? l.label}</a>` : html`<a href="/learn">who publishes it</a>`}</td>
              </tr>`;
            })}</tbody>
          </table></div>
          <p class="small">Every control opens a page of its own, and each of those ends at the publisher: the rule in NIST's own reference tool or the publisher's file, the exact document this instance read, and the body that wrote it. Nothing here asks to be taken on trust.</p>
          ${withheld.length
            ? html`<p class="small">${withheld.length} source(s) carry a licence that forbids showing their entries to anyone but this instance's owner, so their controls are counted but never listed: ${withheld.map((v, i) => html`${i > 0 ? ", " : ""}<a href="/standards/${v.sourceId}">${v.name}</a> (${licenceOf({ licence: v.licence })})`)}.</p>`
            : ""}
        </section>
      </section>
      <aside class="side">
        <section class="box" id="changed">
          <h2><a href="/register">What changed</a></h2>
          <p class="small">A control is not a fixed thing: publishers revise the text, move a rule between severities, add and withdraw. The change register keeps every version and shows each control before and after, with the publisher's stated reason.</p>
          ${moved.length
            ? html`<ul class="latest">${moved.map(
                (r) => html`<li><a href="/standards/${r.sourceId}/${r.documentId}">${r.name}${r.versionLabel ? html` ${r.versionLabel}` : ""}</a><span class="when">${r.changeCount === 0 ? "first version" : `${r.changeCount} changed`} · ${relativeTime(r.at, now)}</span></li>`,
              )}</ul>`
            : html`<p class="small">No release has been read yet.</p>`}
        </section>
        <section class="box" id="technical">
          <h2><a href="/stigs">The technical end</a></h2>
          <p class="small">A control says what must be true; a <a href="/stigs">STIG rule</a> says how to check and fix it on one platform, and a <a href="/baselines">baseline export</a> turns that into the Jamf, Intune or shell setting that enforces it. Every STIG rule here links to the controls it implements through its CCIs, and every control page lists the rules that reach it.</p>
        </section>
      </aside>
    </div>`;

  return page({
    title: "Controls",
    active: "controls",
    content,
    meta: html`${readable.reduce((sum, v) => sum + v.requirementCount, 0)} controls`,
    owner,
    open,
    look,
  });
}
