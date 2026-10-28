import type { DatabaseSync } from "node:sqlite";
import { authorityForSource, rungs, type Rung } from "../authorities.ts";
import { html, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { openDrafts, seriesOf } from "../publications.ts";
import { licenceOf, withheldFrom, type DocumentRow } from "../register.ts";
import { relativeTime } from "../time.ts";
import { latestRegisterChanges, page } from "./layout.ts";
import { seriesSummary, standardFold } from "./publications.ts";

/**
 * Controls: the third rung of the ladder the guide teaches (/guide#ladder). A standard is the
 * rulebook and a baseline picks its rules for a kind of system; a control is one rule — AC-2,
 * IA-2, a STIG rule, a CIS recommendation. This page is one rule at a time: search every
 * standard's current version at once, open any standard's controls, and see which of them have
 * moved lately, which is what the change register holds.
 *
 * The standards are grouped by the rung of the ladder each sits on, and each standard is one
 * folded group: its publications, gathered into series, each with its current version, its draft
 * and its earlier versions, so nobody scrolls nineteen NIST PIV rows to find SP 800-63C.
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
  const exact = q.trim().toLowerCase();
  const like = `%${exact}%`;
  // "ac-2" typed whole puts AC-2 first, ahead of CTL-AC-20 and every AC-2(n) that merely contains it.
  return db
    .prepare(
      `SELECT s.id AS sourceId, s.name, d.id AS documentId, d.version_label AS versionLabel,
              r.ref, r.title, r.family, r.severity, r.statement
         FROM requirements r
         JOIN documents d ON d.id = r.document_id
         JOIN sources s ON s.id = d.source_id
        WHERE r.document_id IN (${ids.map(() => "?").join(", ")})
          AND (lower(r.ref) LIKE ? OR lower(r.title) LIKE ? OR lower(r.statement) LIKE ?)
        ORDER BY (lower(r.ref) = ? OR lower(COALESCE(r.label, '')) = ?) DESC, (lower(r.ref) LIKE ?) DESC, (lower(r.title) LIKE ?) DESC, s.name, r.ref
        LIMIT ?`,
    )
    .all(...ids, like, like, like, exact, exact, like, like, limit) as unknown as ControlHit[];
}

interface StandardSource {
  id: string;
  name: string;
  notes: string | null;
  restricted: number;
  licence: string | null;
}

/** The groups the page is cut into: the ladder's rungs first, then what sits beside it. */
export interface Group {
  id: string;
  label: string;
  line: string;
}

const rungGroup = (id: Rung): Group => {
  const r = rungs.find((x) => x.id === id)!;
  return { id, label: r.label, line: r.line };
};

export const standardGroups: Group[] = [
  { ...rungGroup("catalog"), label: "Control catalogues" },
  { ...rungGroup("baseline"), label: "Baselines" },
  { ...rungGroup("setting"), label: "Configuration settings" },
  { id: "nist-pubs", label: "Other NIST guidance", line: "publications NIST writes beside the catalogue — identity and PIV cards, firmware, keys and platform security — each with its own versions" },
  rungGroup("policy"),
  rungGroup("check"),
  { id: "other", label: "Other standards", line: "tracked here, not yet placed on the ladder" },
  { id: "blocklists", label: "Blocklists and canaries", line: "not rules but lists the Scan checks against: the domains and addresses a resolver or browser should refuse" },
];

export function groupOf(sourceId: string): string {
  if (/^(canary|adfection)-/.test(sourceId)) return "blocklists";
  const rung = authorityForSource(sourceId)?.rung;
  if (rung && standardGroups.some((g) => g.id === rung)) return rung;
  return sourceId.startsWith("nist-") ? "nist-pubs" : "other";
}

function standardSources(db: DatabaseSync): StandardSource[] {
  return db
    .prepare(
      `SELECT s.id, s.name, s.notes, s.restricted, s.licence FROM sources s
        WHERE s.kind IN ('requirement-set', 'setting-set') AND EXISTS (SELECT 1 FROM documents d WHERE d.source_id = s.id)
        ORDER BY s.name`,
    )
    .all() as unknown as StandardSource[];
}

export function renderControls(options: { db: DatabaseSync; q: string | undefined; now: Date; owner: boolean; open: boolean; look: LookState }): string {
  const { db, q, now, owner, open, look } = options;
  const all = latestVersions(db);
  const readable = all.filter((v) => !withheldFrom({ restricted: v.restricted }, owner));
  const query = (q ?? "").trim();
  const hits = query ? searchControls(db, readable, query) : [];
  const moved = latestRegisterChanges(db, 6);

  const sources = standardSources(db);
  const withheld = sources.filter((s) => withheldFrom(s, owner));
  const drafts = openDrafts(db);
  const documents = db.prepare("SELECT * FROM documents WHERE source_id = ?");
  const grouped = new Map<string, Html[]>();
  let entryCount = 0;
  for (const source of sources) {
    if (withheldFrom(source, owner)) continue;
    const series = seriesOf(source.id, documents.all(source.id) as unknown as DocumentRow[], drafts);
    entryCount += seriesSummary(series).entries;
    const g = groupOf(source.id);
    grouped.set(g, [...(grouped.get(g) ?? []), standardFold(db, source, series, now)]);
  }

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
                  <td><a href="/standards/${h.sourceId}">${h.name}</a>${h.versionLabel ? html`<div class="note">${h.versionLabel}</div>` : ""}</td>
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
      <section class="main" id="standards">
        <p class="lede">Every standard below is folded to one line. Open one to see its publications — each with the version in force, the draft that will replace it, what the latest version changed, and the versions before it.</p>
        ${standardGroups
          .filter((g) => grouped.has(g.id))
          .map(
            (g) => html`<section class="fold-group" id="group-${g.id}">
              <h2><a href="#group-${g.id}">${g.label}</a> <span class="count">${grouped.get(g.id)!.length}</span></h2>
              <p class="small">${g.line}.</p>
              ${grouped.get(g.id)}
            </section>`,
          )}
        ${withheld.length
          ? html`<p class="small">${withheld.length} source(s) carry a licence that forbids showing their entries to anyone but this instance's owner, so their controls are counted but never listed: ${withheld.map((v, i) => html`${i > 0 ? ", " : ""}<a href="/standards/${v.id}">${v.name}</a> (${licenceOf({ licence: v.licence })})`)}.</p>`
          : ""}
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
    meta: html`${entryCount.toLocaleString("en-US")} controls`,
    owner,
    open,
    look,
  });
}
