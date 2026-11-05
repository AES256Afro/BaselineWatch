import type { DatabaseSync } from "node:sqlite";
import { referenceKey } from "../adapters/nasa-policy.ts";
import { fleetPlatforms, loadFleet, releasesOf, type Fleet } from "../fleet.ts";
import { html, newTab, newTabIf, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { getSource } from "../ingest.ts";
import { isDraft, openDrafts, seriesOf, type OpenDraft } from "../publications.ts";
import { latestDocument, listDocuments, loadRequirements } from "../register.ts";
import { relativeTime } from "../time.ts";
import { page } from "./layout.ts";
import { newForDays, standardFold } from "./publications.ts";

/**
 * The all-standards catalog at /standards: per operating system the current, new and draft standards
 * tracked, the NIST publications with CSRC's drafts open for comment, and NASA's document set.
 */
interface Who {
  owner: boolean;
  open: boolean;
  look: LookState;
}

function statusChip(row: { version_label: string | null; published_at: string | null }, now: Date): Html {
  if (isDraft(row.version_label)) return html`<span class="chip na">draft</span>`;
  if (row.published_at && now.getTime() - Date.parse(row.published_at) <= newForDays * 86_400_000) return html`<span class="chip ok">new</span>`;
  return html`<span class="chip">current</span>`;
}

const nistSources = ["nist-sp-800-53", "nist-sp-800-53b", "nist-sp-800-171", "nist-piv", "nist-platform"];

/** A link to the bytes a document was read from: the zip, PDF, JSON or page the publisher serves. */
function sourceLink(url: string | null): Html {
  return url ? html`<a href="${url}" ${newTab}>source</a>` : html``;
}

function osSection(db: DatabaseSync, fleet: Fleet, now: Date): Html {
  const sections = fleetPlatforms.map((p) => {
    const rows: Html[] = [];
    let fresh = 0;
    let pending = 0;
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
        if (!doc) pending++;
        else if (!isDraft(doc.version_label) && doc.published_at && now.getTime() - Date.parse(doc.published_at) <= newForDays * 86_400_000) fresh++;
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
    const releases = releasesOf(fleet, p.id).filter((r) => r.status !== "ended").length;
    return html`<details class="fold" id="os-${p.id}">
      <summary><b>${p.label}</b><span class="fold-meta">${releases} release${releases === 1 ? "" : "s"} · ${rows.length} standard${rows.length === 1 ? "" : "s"}${fresh ? html` · <span class="chip ok">${fresh} new</span>` : ""}${pending ? html` · ${pending} not loaded yet` : ""}</span><span class="small"><a href="/baselines/${p.id}">builder</a> · <a href="/baselines/${p.id}/tests">test plan</a></span></summary>
      <div class="table-wrap"><table><caption class="visually-hidden">Standards tracked, by release</caption>
        <thead><tr><th scope="col">Release</th><th scope="col">Standard</th><th scope="col">Current version</th><th scope="col">Published</th><th scope="col">Source</th><th scope="col"></th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </details>`;
  });
  return html`${sections}`;
}

function nistSection(db: DatabaseSync, now: Date): Html {
  const drafts = openDrafts(db);
  const folds: Html[] = [];
  const matched = new Set<OpenDraft>();
  for (const id of nistSources) {
    const source = getSource(db, id);
    const documents = listDocuments(db, id);
    if (!source || documents.length === 0) continue;
    const series = seriesOf(id, documents, drafts);
    for (const p of series.flatMap((x) => x.publications)) for (const o of p.openDrafts) matched.add(o);
    folds.push(standardFold(db, { id, name: source.name, notes: null }, series, now));
  }
  const elsewhere = drafts.filter((d) => !matched.has(d));
  return html`<section class="std" id="nist">
    <div class="std-head"><b><a href="#nist">NIST publications</a></b><span class="small">${folds.length} standards · <a href="/learn#body-sp-800-53">where it comes from</a> · <a href="/register">Register</a></span></div>
    <p class="std-note">One line per standard; open one for its publications, each with the version in force, the draft that will replace it and the versions before. A draft of a tracked publication sits on its row.</p>
    ${folds.length ? folds : html`<p class="small">Nothing loaded yet; the NIST sources fill this on their first fetch (<a href="/sources">Sources</a>).</p>`}
    <h3 id="drafts"><a href="#drafts">Other drafts open for comment</a></h3>
    ${elsewhere.length
      ? html`<details class="fold"><summary><b>${elsewhere.length} draft${elsewhere.length === 1 ? "" : "s"} of publications not tracked here</b><span class="fold-meta">newest ${elsewhere[0]!.published_at ? relativeTime(elsewhere[0]!.published_at, now) : ""}</span></summary><ul class="plain">${elsewhere.map(
          (d) => html`<li>${d.url ? html`<a href="${d.url}" ${newTabIf(d.url)}>${d.title}</a>` : d.title} <span class="when">${d.published_at ? relativeTime(d.published_at, now) : ""}</span></li>`,
        )}</ul></details>`
      : html`<p class="small">None on hand: CSRC's drafts-open-for-comment feed has not been fetched yet (<a href="/sources">Sources</a>), or nothing else is open.</p>`}
  </section>`;
}

/** Families whose tables repeat what the page already shows, said so on the fold. */
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
  // Each family is one folded line: the reference runs to hundreds of documents, and a reader
  // looking for one NPR should not scroll past the handbooks to reach it.
  const sections = [...families.entries()].map(
    ([family, rows]) => html`<details class="fold" id="nasa-${family.toLowerCase().replace(/[^a-z0-9]+/g, "-")}">
      <summary><b>${family}</b><span class="fold-meta">${rows.length} document${rows.length === 1 ? "" : "s"}${foldedFamilies.test(family) ? " · NASA's citation list; the tracked versions are above" : ""}</span></summary>
      ${table(rows)}
    </details>`,
  );
  return html`<section class="std" id="nasa">
    <div class="std-head"><b><a href="#nasa">NASA (CSET / OCIO)</a></b><span class="small">${doc.version_label ?? ""} · <a href="/learn#body-nasa-ascs">where it comes from</a> · <a href="/standards/nasa-cyber-ref">versions and changes</a></span></div>
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
          is not yet the standard. For where each of these comes from — the law, the policy and the
          catalogue above it, and the other bodies that answer the same step —
          <a href="/learn">Learn</a> draws the whole chain.
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
          <p class="small"><a href="/learn">Learn</a> lists every publisher on the chain — NIST, CISA,
          DISA, CNSS, NASA, CIS, Microsoft, the NSA, the ACSC and the NCSC — each with the address its
          own words live at, what it takes to read them, and what it derives from.</p>
        </section>
        <section class="box">
          <h2><a href="/register">In the Register</a></h2>
          <p class="small">Each row here is backed by the Register: every loaded version, each release's changed rows with before and after, and the publisher's stated reason. The <a href="/atlas">Atlas</a> draws the release timeline.</p>
        </section>
      </aside>
    </div>`;
  return page({ title: "All standards", active: "catalog", content, owner, open, look });
}
