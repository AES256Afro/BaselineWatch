import type { DatabaseSync } from "node:sqlite";
import { baseNumber } from "../adapters/csrc-pubs.ts";
import { referenceKey } from "../adapters/nasa-policy.ts";
import { fleetPlatforms, loadFleet, releasesOf, type Fleet } from "../fleet.ts";
import { html, newTab, newTabIf, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { latestDocument, loadRequirements } from "../register.ts";
import { relativeTime } from "../time.ts";
import { page } from "./layout.ts";

/**
 * The all-standards catalog at /standards: per operating system the current, new and draft standards
 * tracked, the NIST publications with CSRC's drafts open for comment, and NASA's document set.
 */
interface Who {
  owner: boolean;
  open: boolean;
  look: LookState;
}

/** Everything on this page counts as new while its publication date is this fresh. */
const newForDays = 60;

interface LatestRow {
  id: number;
  source_id: string;
  document_key: string;
  version_label: string | null;
  title: string | null;
  published_at: string | null;
  parsed_at: string;
  source_url: string | null;
}

/** The newest loaded version of every publication the NIST sources track. */
function latestPerKey(db: DatabaseSync, sourceIds: string[]): LatestRow[] {
  const marks = sourceIds.map(() => "?").join(", ");
  return db
    .prepare(
      `SELECT d.id, d.source_id, d.document_key, d.version_label, d.title, d.published_at, d.parsed_at, d.source_url
       FROM documents d
       WHERE d.source_id IN (${marks})
         AND d.id = (SELECT MAX(x.id) FROM documents x WHERE x.source_id = d.source_id AND x.document_key = d.document_key)
       ORDER BY d.source_id, d.document_key`,
    )
    .all(...sourceIds) as unknown as LatestRow[];
}

function isDraft(versionLabel: string | null): boolean {
  return versionLabel !== null && /\(draft\)/i.test(versionLabel);
}

function statusChip(row: { version_label: string | null; published_at: string | null }, now: Date): Html {
  if (isDraft(row.version_label)) return html`<span class="chip na">draft</span>`;
  if (row.published_at && now.getTime() - Date.parse(row.published_at) <= newForDays * 86_400_000) return html`<span class="chip ok">new</span>`;
  return html`<span class="chip">current</span>`;
}

const nistSources = ["nist-sp-800-53", "nist-sp-800-53b", "nist-sp-800-171", "nist-piv", "nist-platform"];
const nistSourceNames: Record<string, string> = {
  "nist-sp-800-53": "SP 800-53",
  "nist-sp-800-53b": "SP 800-53B baselines",
  "nist-sp-800-171": "SP 800-171",
  "nist-piv": "PIV and digital identity",
  "nist-platform": "Platform security",
};

interface DraftItem {
  title: string;
  url: string | null;
  published_at: string | null;
}

/** A link to the bytes a document was read from: the zip, PDF, JSON or page the publisher serves. */
function sourceLink(url: string | null): Html {
  return url ? html`<a href="${url}" ${newTab}>source</a>` : html``;
}

/** The drafts CSRC has open for comment, as the csrc-drafts feed last delivered them. */
function openDrafts(db: DatabaseSync, limit = 100): DraftItem[] {
  return db
    .prepare("SELECT title, url, published_at FROM items WHERE source_id = 'csrc-drafts' ORDER BY COALESCE(published_at, fetched_at) DESC LIMIT ?")
    .all(limit) as unknown as DraftItem[];
}

/** The publication number a draft announcement names, for the join to a tracked publication. */
function draftNumber(title: string): string | null {
  const m = /\b(SP\s+\d{3,4}-\d+[A-Za-z]?|FIPS\s+\d+(?:-\d+)?|(?:NIST\s*)?IR\s+\d+[A-Za-z]?|CSWP\s+\d+)\b/i.exec(title);
  return m ? m[1]!.replace(/\s+/g, " ") : null;
}

function osSection(db: DatabaseSync, fleet: Fleet, now: Date): Html {
  const sections = fleetPlatforms.map((p) => {
    const rows: Html[] = [];
    for (const r of releasesOf(fleet, p.id)) {
      if (r.status === "ended") continue;
      const held: [string, string, string | undefined][] = [
        ["DISA STIG", "disa-stigs", r.documents.stig],
        ["NIST mSCP", "nist-mscp", r.documents.mscp],
        ["Microsoft baseline", "microsoft-sct", r.documents.sct],
      ];
      for (const [label, sourceId, key] of held) {
        if (!key) continue;
        const doc = key ? latestDocument(db, sourceId, key) : null;
        rows.push(html`<tr>
          <td><b>${r.label}</b></td>
          <td>${label}</td>
          <td>${doc ? html`<a href="/standards/${sourceId}/${doc.id}">${doc.version_label ?? doc.title ?? key}</a>` : html`<span class="small">not loaded yet</span>`}</td>
          <td class="small">${doc?.published_at ? relativeTime(doc.published_at, now) : "—"}</td>
          <td class="small">${sourceLink(doc?.source_url ?? null)}</td>
          <td>${doc ? statusChip(doc, now) : html`<span class="chip na">pending</span>`}</td>
        </tr>`);
      }
    }
    if (rows.length === 0) return html``;
    return html`<section class="std" id="os-${p.id}">
      <div class="std-head"><b><a href="#os-${p.id}">${p.label}</a></b><span class="small"><a href="/baselines/${p.id}">builder</a> · <a href="/baselines/${p.id}/tests">test plan</a></span></div>
      <div class="table-wrap"><table><caption class="visually-hidden">Standards tracked, by release</caption>
        <thead><tr><th scope="col">Release</th><th scope="col">Standard</th><th scope="col">Current version</th><th scope="col">Published</th><th scope="col">Source</th><th scope="col"></th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </section>`;
  });
  return html`${sections}`;
}

function nistSection(db: DatabaseSync, now: Date): Html {
  const latest = latestPerKey(db, nistSources);
  const tracked = new Map<string, LatestRow>();
  for (const row of latest) if (row.version_label) tracked.set(baseNumber(row.version_label), row);
  const drafts = openDrafts(db);
  return html`<section class="std" id="nist">
    <div class="std-head"><b><a href="#nist">NIST publications</a></b><span class="small">${latest.length} tracked · <a href="/register">Register</a></span></div>
    ${latest.length
      ? html`<div class="table-wrap"><table><caption class="visually-hidden">Publications tracked</caption>
          <thead><tr><th scope="col">Publication</th><th scope="col">Set</th><th scope="col">Current version</th><th scope="col">Published</th><th scope="col">Source</th><th scope="col"></th></tr></thead>
          <tbody>${latest.map(
            (d) => html`<tr>
              <td><a href="/standards/${d.source_id}/${d.id}">${d.title ?? d.document_key}</a></td>
              <td class="small">${nistSourceNames[d.source_id] ?? d.source_id}</td>
              <td>${d.version_label ?? "—"}</td>
              <td class="small">${d.published_at ? relativeTime(d.published_at, now) : "—"}</td>
              <td class="small">${sourceLink(d.source_url)}</td>
              <td>${statusChip(d, now)}</td>
            </tr>`,
          )}</tbody>
        </table></div>`
      : html`<p class="small">Nothing loaded yet; the NIST sources fill this table on their first fetch (<a href="/sources">Sources</a>).</p>`}
    <h3 id="drafts"><a href="#drafts">Drafts open for comment</a></h3>
    ${drafts.length
      ? html`<ul class="plain">${drafts.map((d) => {
          const number = d.title ? draftNumber(d.title) : null;
          const match = number ? tracked.get(baseNumber(number)) : undefined;
          return html`<li>${d.url ? html`<a href="${d.url}" ${newTabIf(d.url)}>${d.title}</a>` : d.title} <span class="when">${d.published_at ? relativeTime(d.published_at, now) : ""}</span>${match ? html` <a class="chip na" href="/standards/${match.source_id}/${match.id}">tracked here</a>` : ""}</li>`;
        })}</ul>`
      : html`<p class="small">None on hand: CSRC's drafts-open-for-comment feed has not been fetched yet (<a href="/sources">Sources</a>), or nothing is open.</p>`}
  </section>`;
}

/** Sections whose tables repeat what the page already shows, folded by default. */
const foldedFamilies = /fips|nist/i;

function nasaSection(db: DatabaseSync): Html {
  const doc = latestDocument(db, "nasa-cyber-ref", referenceKey);
  const intro = html`<p class="std-note">
    NASA's per-OS hardening standards (the Agency Security Configuration Standards, enumerated by NASA-SPEC-2600) are written by OCIO's
    Cybersecurity Standards and Engineering Team and published on <a href="https://cset.nasa.gov" ${newTab}>cset.nasa.gov</a>, behind a NASA
    sign-in. What is public is the quarterly <a href="https://www.nasa.gov/cybersecurity-policies/" ${newTab}>Cybersecurity Policy Reference</a>:
    the list of every key document — directives, handbooks, the NASA standards, memoranda, and the FIPS and NIST publications NASA cites —
    with dates, expiries and status notes. That list is tracked here like any standard, so each quarterly update is a diff.
  </p>`;
  if (!doc) {
    return html`<section class="std" id="nasa">
      <div class="std-head"><b><a href="#nasa">NASA (CSET / OCIO)</a></b><span class="small"><a href="/standards/nasa-cyber-ref">versions</a></span></div>
      ${intro}
      <p class="small">The reference has not been fetched yet: <a href="/sources">Sources</a> → NASA Cybersecurity Policy Reference → Fetch now.</p>
    </section>`;
  }
  interface Row {
    ref: string;
    label: string;
    title: string;
    statement: string | null;
    guidance: string | null;
    url: string | null;
  }
  const families = new Map<string, Row[]>();
  for (const r of loadRequirements(db, doc.id)) {
    const list = families.get(r.family ?? "Other") ?? [];
    list.push({ ref: r.ref, label: r.label, title: r.title, statement: r.statement, guidance: r.guidance, url: typeof r.extra.url === "string" ? r.extra.url : null });
    families.set(r.family ?? "Other", list);
  }
  // The id leads to the document itself, where NASA's reference links it (CSET and NTSS pages
  // need a NASA sign-in; the row says nothing extra, the destination does). The title stays on
  // this instance's page for the row, with its history once editions diff.
  const table = (rows: Row[]): Html =>
    html`<div class="table-wrap"><table><caption class="visually-hidden">Documents in this reference</caption>
      <thead><tr><th scope="col">Document</th><th scope="col">Title</th><th scope="col">Dates</th><th scope="col">Status note</th></tr></thead>
      <tbody>${rows.map(
        (r) => html`<tr>
          <td>${r.url ? html`<a href="${r.url}" ${newTab}>${r.label}</a>` : html`<a href="/standards/nasa-cyber-ref/${doc.id}/${encodeURIComponent(r.ref)}">${r.label}</a>`}</td>
          <td><a href="/standards/nasa-cyber-ref/${doc.id}/${encodeURIComponent(r.ref)}">${r.title}</a></td>
          <td class="small">${r.statement?.replace(/^Listed as .*?(?=\b(?:From|Dated|Expires|Expiry)\b)/, "").trim() ?? ""}</td>
          <td class="small">${r.guidance ? html`<span class="chip na">${r.guidance}</span>` : ""}</td>
        </tr>`,
      )}</tbody>
    </table></div>`;
  const sections = [...families.entries()].map(([family, rows]) =>
    foldedFamilies.test(family)
      ? html`<details><summary>${family} (${rows.length}) — NASA's citation list; the tracked versions are above</summary>${table(rows)}</details>`
      : html`<h3 id="nasa-${family.toLowerCase().replace(/[^a-z0-9]+/g, "-")}">${family} (${rows.length})</h3>${table(rows)}`,
  );
  return html`<section class="std" id="nasa">
    <div class="std-head"><b><a href="#nasa">NASA (CSET / OCIO)</a></b><span class="small">${doc.version_label ?? ""} · <a href="/standards/nasa-cyber-ref">versions and changes</a></span></div>
    ${intro}
    ${sections}
  </section>`;
}

export function renderCatalog(options: { db: DatabaseSync; now?: Date; fleet?: Fleet } & Who): string {
  const { db, owner, open, look } = options;
  const now = options.now ?? new Date();
  const fleet = options.fleet ?? loadFleet();
  const content = html`
    <div class="cols">
      <section class="main">
        <h1>All standards</h1>
        <p class="lede">
          Every standard this instance follows, in one place: per operating system the hardening standards and their current versions,
          the NIST publications with the drafts open for comment, and NASA's cybersecurity document set as OCIO publishes it. A
          <span class="chip ok">new</span> version is one published in the last ${newForDays} days; a <span class="chip na">draft</span>
          is not yet the standard.
        </p>
        <h2 id="by-os"><a href="#by-os">By operating system</a></h2>
        ${osSection(db, fleet, now)}
        ${nistSection(db, now)}
        ${nasaSection(db)}
      </section>
      <aside class="side">
        <section class="box">
          <h2>Where each lives</h2>
          <p class="small">
            NIST publications: <a href="https://csrc.nist.gov/publications" ${newTab}>CSRC</a>, with
            <a href="https://csrc.nist.gov/publications/drafts-open-for-comment" ${newTab}>drafts open for comment</a>.
            NASA directives: <a href="https://nodis3.gsfc.nasa.gov/" ${newTab}>NODIS</a>.
            NASA specifications and standards: <a href="https://standards.nasa.gov/" ${newTab}>NTSS</a> (NASA account required).
            ASCS technical standards and IT handbooks: <a href="https://cset.nasa.gov" ${newTab}>CSET</a> (NASA access only).
            DISA STIGs: <a href="https://www.cyber.mil/stigs/downloads/" ${newTab}>cyber.mil</a>.
          </p>
        </section>
        <section class="box">
          <h2><a href="/register">In the Register</a></h2>
          <p class="small">Each row here is backed by the Register: every loaded version, each release's changed rows with before and after, and the publisher's stated reason. The <a href="/atlas">Atlas</a> draws the release timeline.</p>
        </section>
      </aside>
    </div>`;
  return page({ title: "All standards", active: "catalog", content, owner, open, look });
}
