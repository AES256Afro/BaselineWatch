import type { DatabaseSync } from "node:sqlite";
import type { SourceRow } from "../adapters/types.ts";
import { summarizeChanges, type RequirementChange } from "../differ.ts";
import { html, newTab, newTabIf, type Html } from "../html.ts";
import { getSource } from "../ingest.ts";
import type { NormalizedRequirement } from "../oscal.ts";
import { lines, redline } from "../redline.ts";
import {

/**
 * The Register's pages: a standard and its versions, a release's changes, every requirement of a
 * version to browse and search, and one control before and after with the publisher's reason.
 */
  baselinesFor,
  changeSummaryFor,
  changeSummaryText,
  explanationsFor,
  getDocument,
  licenceOf,
  listDocuments,
  loadRequirements,
  notedChangeCount,
  notesFor,
  releaseChanges,
  withheldFrom,
  withheldLabel,
  type DocumentRow,
} from "../register.ts";
import { relativeTime, shortStamp } from "../time.ts";
import { cciMap, controlPageBase, stigRulesForControl } from "../stigs.ts";
import { getTriage } from "../triage.ts";
import type { LookState } from "../look.ts";
import { authorityBox } from "./learn.ts";
import { page } from "./layout.ts";
import { mappingLine } from "./stigs.ts";
import { triageForm } from "./triage.ts";

interface Who {
  owner: boolean;
  open: boolean;
  look: LookState;
}

// A key is a heading, so it is given the publisher's words: "catalog-rev4" is the superseded
// revision held beside the current one, not a slug anybody should have to read.
const keyLabel = (key: string): string =>
  key === "catalog"
    ? "Catalog"
    : key === "catalog-rev4"
      ? "Catalog, Revision 4 (withdrawn)"
      : key.startsWith("profile:")
        ? `${key.slice(8).charAt(0).toUpperCase()}${key.slice(9)} baseline`
        : key;

/**
 * What a visitor sees in place of a licence-restricted source's entries: the rule, the licence
 * that imposes it, and where the owner signs in. Versions, counts and change counts stay on the
 * page around it; names and text do not.
 */
function withheldBox(source: SourceRow, open: boolean): Html {
  return html`<div class="empty withheld" id="withheld">
    <b>Entries shown to the owner only.</b>
    <p>${source.name} is tracked under terms that do not allow its entries to be shown to third parties: ${licenceOf(source)}. Its versions, how many entries each holds and how many came, went or changed are public; the names and text are drawn for the signed-in owner alone, and the API and MCP tools return neither.${open ? "" : html` <a href="/login">Owner sign-in</a>.`}</p>
  </div>`;
}

export function renderStandard(options: { db: DatabaseSync; sourceId: string; now: Date; notice?: string | undefined } & Who): string | null {
  const { db, sourceId, now, owner, open, notice, look } = options;
  const source = getSource(db, sourceId);
  if (!source) return null;
  // Non-standard sources (KEV, advisories) also keep versioned documents; their release pages
  // link back here, so the page answers for any source that has at least one version.
  if (source.group_name !== "standards" && listDocuments(db, sourceId).length === 0) return null;
  const upload =
    source.format === "pdf-upload"
      ? owner
        ? html`<section class="box upload">
            <h2>Upload a benchmark PDF</h2>
            <p class="small">The PDF stays in this instance's data directory under your own CIS licence. Upload the same benchmark again when CIS publishes a new version and the Register shows what changed, recommendation by recommendation.</p>
            <p class="small">Where to get one: sign in to <a href="https://workbench.cisecurity.org/" ${newTab}>CIS WorkBench</a> (free registration) → Benchmarks → your platform → Download PDF; or use your organisation's SecureSuite copy.</p>
            <form method="post" action="/uploads/cis" enctype="multipart/form-data" class="stack">
              <label for="cis-pdf">Benchmark PDF</label>
              <input type="file" id="cis-pdf" name="pdf" accept="application/pdf,.pdf" required>
              <label for="cis-version">Version (optional, read from the PDF when blank)</label>
              <input type="text" id="cis-version" name="version" maxlength="40" placeholder="v1.1.0">
              <label for="cis-published">Published (optional)</label>
              <input type="date" id="cis-published" name="published">
              <button type="submit" class="primary">Upload and diff</button>
            </form>
          </section>`
        : html`<section class="box"><h2>Benchmarks by upload</h2><p class="small">CIS Benchmarks are licensed for internal use, so the owner uploads each PDF by hand; the Register then diffs it against the previous upload of the same benchmark.</p></section>`
      : html``;
  const documents = listDocuments(db, sourceId);
  const byKey = new Map<string, DocumentRow[]>();
  for (const d of documents) byKey.set(d.document_key, [...(byKey.get(d.document_key) ?? []), d]);

  // The key's heading reads the newest version; the count is a permalink to its table of versions.
  const anchor = (key: string) => `doc-${key.replace(/[^a-z0-9]+/gi, "-")}`;
  const sections = [...byKey.entries()].map(
    ([key, docs]) => html`<section class="box" id="${anchor(key)}">
      <h2><a href="/standards/${sourceId}/${docs[0]!.id}/browse">${keyLabel(key)}</a> <span class="count"><a href="#${anchor(key)}">${docs.length} version${docs.length === 1 ? "" : "s"}</a></span></h2>
      <div class="table-wrap"><table><caption class="visually-hidden">Versions of this standard</caption>
        <thead><tr><th scope="col">Version</th><th scope="col">Published</th><th scope="col">Requirements</th><th scope="col">Against the previous version</th><th scope="col">Loaded</th></tr></thead>
        <tbody>${docs.map((d) => {
          const summary = d.previous_document_id ? changeSummaryText(changeSummaryFor(db, d.id)) : "first version loaded";
          return html`<tr>
            <td><a href="/standards/${sourceId}/${d.id}"><b>${d.version_label ?? "version unknown"}</b></a></td>
            <td>${d.published_at ? d.published_at.slice(0, 10) : "—"}</td>
            <td class="n"><a href="/standards/${sourceId}/${d.id}/browse">${d.requirement_count}</a></td>
            <td>${d.previous_document_id ? html`<a href="/standards/${sourceId}/${d.id}">${summary}</a>` : html`<a href="/standards/${sourceId}/${d.id}/browse">${summary}</a>`}</td>
            <td class="small">${relativeTime(d.parsed_at, now)}</td>
          </tr>`;
        })}</tbody>
      </table></div>
    </section>`,
  );

  const content = html`
    <h1>${source.name}</h1>
    <p class="lede">${source.notes ?? ""} <a href="${source.url}" ${newTabIf(source.url)}>Source</a>${source.licence ? html` · ${source.licence}` : ""}.</p>
    ${notice ? html`<div class="notice ok">${notice}</div>` : ""}
    ${authorityBox(sourceId)}
    ${upload}
    ${withheldFrom(source, owner) ? withheldBox(source, open) : ""}
    ${documents.length === 0
      ? html`<div class="empty"><b>No version loaded yet.</b><p>${source.format === "pdf-upload" ? "Nothing uploaded so far." : owner ? html`Fetch it from the <a href="/sources">Sources</a> page, or run <code>npm run backfill -- ${sourceId}</code> to load the published history first.` : "The owner can fetch it from the Sources page."}</p></div>`
      : sections}`;

  return page({ title: source.name, active: "register", content, meta: html`${documents.length} versions`, owner, open, look });
}

function fieldLabel(field: string | null): string {
  switch (field) {
    case "statement":
      return "Control text";
    case "guidance":
      return "Discussion";
    case "params":
      return "Parameters";
    case "related":
      return "Related controls";
    case "extra":
      return "Assessment and other text";
    case "title":
      return "Title";
    case "status":
      return "Status";
    default:
      return field ?? "";
  }
}

/** Every requirement of one version, for reading the standard itself rather than its changes. */
export function renderBrowse(options: { db: DatabaseSync; sourceId: string; documentId: number; q: string | undefined; family: string | undefined } & Who): string | null {
  const { db, sourceId, documentId, q, family, owner, open, look } = options;
  const source = getSource(db, sourceId);
  const doc = getDocument(db, documentId);
  if (!source || !doc || doc.source_id !== sourceId) return null;
  if (withheldFrom(source, owner)) {
    // The version is public knowledge; what it lists is not, so nothing of it is read, searched or drawn,
    // and the look switch leads back to the bare page rather than echoing a search for a name.
    const content = html`
      <div class="rel">
        <h1>${source.name} <span class="arrow">${doc.version_label ?? "version unknown"}</span></h1>
        <div class="when">${doc.requirement_count} entries · published ${doc.published_at ? doc.published_at.slice(0, 10) : "date unknown"}<br><a href="/standards/${sourceId}/${documentId}">Changes in this version</a></div>
      </div>
      ${withheldBox(source, open)}`;
    return page({ title: `${source.name} ${doc.version_label ?? ""}`.trim(), active: "register", content, meta: html`${doc.requirement_count} entries`, owner, open, look: { ...look, back: `/standards/${sourceId}/${documentId}/browse` } });
  }
  const all = loadRequirements(db, documentId);
  const families = [...new Set(all.map((r) => r.family).filter((f): f is string => f !== null))].sort();
  const needle = q?.toLowerCase();
  const rows = all.filter((r) => (!family || r.family === family) && (!needle || r.label.toLowerCase().includes(needle) || r.title.toLowerCase().includes(needle) || (r.statement ?? "").toLowerCase().includes(needle)));
  const changed = new Set(releaseChanges(db, documentId).map((c) => c.ref));
  const link = (f?: string) => `/standards/${sourceId}/${documentId}/browse${f ? `?family=${encodeURIComponent(f)}` : ""}${q ? `${f ? "&" : "?"}q=${encodeURIComponent(q)}` : ""}`;

  const content = html`
    <div class="rel">
      <h1>${source.name} <span class="arrow">${doc.version_label ?? "version unknown"}</span></h1>
      <div class="when"><a href="/standards/${sourceId}/${documentId}/browse">${doc.requirement_count} requirements</a> · published ${doc.published_at ? doc.published_at.slice(0, 10) : "date unknown"}<br><a href="/standards/${sourceId}/${documentId}">Changes in this version</a></div>
    </div>
    <div class="wire-top">
      <form method="get" action="/standards/${sourceId}/${documentId}/browse" class="search" role="search">
        ${family ? html`<input type="hidden" name="family" value="${family}">` : ""}
        <label class="visually-hidden" for="q">Search this version</label>
        <input type="search" id="q" name="q" value="${q ?? ""}" placeholder="Label, title or words in the control text">
        <button type="submit">Search</button>
      </form>
    </div>
    ${families.length > 1
      ? html`<div class="filters"><a class="${!family ? "on" : ""}" href="${link()}">All</a>${families.map((f) => html`<a class="${family === f ? "on" : ""}" href="${link(f)}">${f}</a>`)}</div>`
      : ""}
    <div class="table-wrap"><table class="browse"><caption class="visually-hidden">Controls in this version</caption>
      <thead><tr><th scope="col">Ref</th><th scope="col">Title</th><th scope="col">Text</th><th scope="col"></th></tr></thead>
      <tbody>${rows.slice(0, 400).map(
        (r) => html`<tr class="${r.status === "withdrawn" ? "off" : ""}${changed.has(r.ref) ? " changed" : ""}">
          <td class="id"><a href="/standards/${sourceId}/${documentId}/${r.ref}"><b>${r.label}</b></a>${r.parentRef ? html`<div class="note">in ${r.parentRef.toUpperCase()}</div>` : ""}</td>
          <td>${r.title}${r.status === "withdrawn" ? html` <span class="chip del">withdrawn</span>` : ""}</td>
          <td class="desc"><span>${(r.statement ?? r.guidance ?? "").slice(0, 240)}</span></td>
          <td>${changed.has(r.ref) ? html`<span class="chip mod">changed here</span>` : ""}</td>
        </tr>`,
      )}</tbody>
    </table></div>
    <p class="small">${rows.length > 400 ? `Showing 400 of ${rows.length}; narrow with the search or a family.` : `${rows.length} of ${all.length}.`}</p>`;

  return page({ title: `${source.name} ${doc.version_label ?? ""}`.trim(), active: "register", content, meta: html`${all.length} requirements`, owner, open, look });
}

/** One release and its changes, narrowed to one family when `family` is given: the Atlas map leads here cell by cell. */
export function renderRelease(options: { db: DatabaseSync; sourceId: string; documentId: number; now: Date; family?: string | undefined } & Who): string | null {
  const { db, sourceId, documentId, owner, open, look } = options;
  const source = getSource(db, sourceId);
  const doc = getDocument(db, documentId);
  if (!source || !doc || doc.source_id !== sourceId) return null;
  const previous = doc.previous_document_id ? getDocument(db, doc.previous_document_id) : null;
  const withheld = withheldFrom(source, owner);
  // A withheld release has no families to narrow to and nothing to say about one named in the address.
  const family = withheld ? undefined : options.family;
  const changes = releaseChanges(db, documentId);
  const summary = summarizeChanges(changes.map((c) => ({ ref: c.ref, kind: c.kind, field: c.field as RequirementChange["field"], before: c.before_text, after: c.after_text })));
  // A generated summary of a restricted release would quote its entries (none is made; an old one is not shown either).
  const explanations = explanationsFor(db, documentId).filter((e) => !withheld || e.kind !== "generated");
  const labels = new Map<string, { label: string; title: string; family: string | null }>();
  if (!withheld) {
    for (const r of loadRequirements(db, documentId)) labels.set(r.ref, { label: r.label, title: r.title, family: r.family });
    if (previous) for (const r of loadRequirements(db, previous.id)) if (!labels.has(r.ref)) labels.set(r.ref, { label: r.label, title: r.title, family: r.family });
  }
  // The pills name the first few refs of each kind and lead to the table below; for a withheld release they count them and lead to the box that stands in for the tables.
  const named = (refs: string[]): Html => (withheld ? html`` : html`: ${refs.map((r) => labels.get(r)?.label ?? r).slice(0, 10).join(", ")}${refs.length > 10 ? "…" : ""}`);
  const tables = withheld ? { substantive: "#withheld", editorial: "#withheld" } : { substantive: "#substantive", editorial: "#editorial" };

  const byRef = new Map<string, typeof changes>();
  for (const c of changes) byRef.set(c.ref, [...(byRef.get(c.ref) ?? []), c]);
  const order = [...byRef.keys()].sort();
  const row = (ref: string): Html => {
    const list = byRef.get(ref) ?? [];
    const kind = list.some((c) => c.kind === "added") ? "added" : list.some((c) => c.kind === "removed") ? "removed" : "modified";
    const fields = kind === "modified" ? [...new Set(list.map((c) => fieldLabel(c.field)))].join(", ") : kind;
    const meta = labels.get(ref);
    return html`<tr class="${kind}">
      <td><a href="/standards/${sourceId}/${documentId}/${ref}"><b>${meta?.label ?? ref.toUpperCase()}</b></a></td>
      <td>${meta?.title ?? ""}</td>
      <td><span class="chip ${kind === "added" ? "ins" : kind === "removed" ? "del" : ""}">${fields}</span></td>
    </tr>`;
  };
  // The families the changes fall in make the strip; the family asked for narrows both tables.
  const familyCounts = new Map<string, number>();
  for (const ref of order) {
    const f = labels.get(ref)?.family;
    if (f) familyCounts.set(f, (familyCounts.get(f) ?? 0) + 1);
  }
  const inFamily = (ref: string) => !family || labels.get(ref)?.family === family;
  const substantive = order.filter((r) => inFamily(r) && (summary.added.includes(r) || summary.removed.includes(r) || summary.substantive.includes(r)));
  const editorial = order.filter((r) => inFamily(r) && summary.editorial.includes(r));
  const familyLink = (f?: string) => `/standards/${sourceId}/${documentId}${f ? `?family=${encodeURIComponent(f)}` : ""}`;
  const familyStrip =
    familyCounts.size > 1 || family
      ? html`<div class="filters"><a class="${!family ? "on" : ""}" href="${familyLink()}">All · ${byRef.size}</a>${[...familyCounts.keys()].sort().map((f) => html`<a class="${family === f ? "on" : ""}" href="${familyLink(f)}">${f} · ${familyCounts.get(f)}</a>`)}</div>`
      : html``;
  const inWords = family ? ` in ${family}` : "";

  const content = html`
    <div class="rel">
      <h1>${source.name} <span class="arrow">${previous ? html`${previous.version_label ?? "previous"} → ` : ""}${doc.version_label ?? "version unknown"}</span></h1>
      <div class="when">Published ${doc.published_at ? doc.published_at.slice(0, 10) : "date unknown"}<br>Snapshot taken ${shortStamp(doc.parsed_at)} · <a href="${doc.source_url ?? source.url}" ${newTabIf(doc.source_url ?? source.url)}>${keyLabel(doc.document_key)} source</a></div>
    </div>
    <div class="pills">
      ${summary.added.length ? html`<a class="pill ins" href="${tables.substantive}">+ ${summary.added.length} added${named(summary.added)}</a>` : ""}
      ${summary.removed.length ? html`<a class="pill del" href="${tables.substantive}">− ${summary.removed.length} removed${named(summary.removed)}</a>` : ""}
      ${summary.substantive.length ? html`<a class="pill mod" href="${tables.substantive}">~ ${summary.substantive.length} revised${named(summary.substantive)}</a>` : ""}
      ${summary.editorial.length ? html`<a class="pill" href="${tables.editorial}">${summary.editorial.length} with discussion, related-control or assessment updates</a>` : ""}
      ${!previous ? html`<a class="pill none" href="/standards/${sourceId}/${documentId}/browse">First version loaded: ${doc.requirement_count} requirements, nothing to compare yet</a>` : ""}
      ${previous && changes.length === 0 ? html`<a class="pill none" href="/standards/${sourceId}/${previous.id}">No control-level changes against ${previous.version_label ?? "the previous version"}</a>` : ""}
      ${changes.length ? (() => { const noted = notedChangeCount(db, documentId); return noted ? html`<a class="pill" href="${tables.substantive}">${noted} of ${byRef.size} changed requirements carry the publisher's note</a>` : ""; })() : ""}
    </div>
    ${explanations.map((e) =>
      e.kind === "publisher"
        ? html`<div class="why"><small>Why this release, in the publisher's words</small><p>${e.text}</p>${e.source_url ? html`<cite><a href="${e.source_url}" ${newTabIf(e.source_url)}>${e.source_url}</a></cite>` : ""}</div>`
        : e.kind === "generated"
          ? html`<div class="why gen"><small>Summary <span class="badge">Generated</span></small><p>${e.text}</p></div>`
          : html`<div class="why none"><small>Why this release</small><p>${e.text}</p></div>`,
    )}
    ${withheld
      ? withheldBox(source, open)
      : html`${familyStrip}
        ${family && !substantive.length && !editorial.length
          ? html`<p class="small">No control in ${family} changed in this release. <a href="/standards/${sourceId}/${documentId}/browse?family=${encodeURIComponent(family)}">Read the family's controls in this version</a>.</p>`
          : ""}
        ${substantive.length
          ? html`<section class="box" id="substantive"><h2><a href="#substantive">Controls added, removed or revised${inWords}</a> <span class="count"><a href="#substantive">${substantive.length}</a></span></h2>
              <div class="table-wrap"><table><caption class="visually-hidden">Controls added, removed or revised</caption><thead><tr><th scope="col">Control</th><th scope="col">Title</th><th scope="col">Change</th></tr></thead><tbody>${substantive.map(row)}</tbody></table></div></section>`
          : ""}
        ${editorial.length
          ? html`<section class="box" id="editorial"><h2><a href="#editorial">Discussion, related-control and assessment updates${inWords}</a> <span class="count"><a href="#editorial">${editorial.length}</a></span></h2>
              <div class="table-wrap"><table><caption class="visually-hidden">Discussion, related-control and assessment updates</caption><thead><tr><th scope="col">Control</th><th scope="col">Title</th><th scope="col">What moved</th></tr></thead><tbody>${editorial.map(row)}</tbody></table></div></section>`
          : ""}`}
    <p class="small">${withheld ? "" : html`<a href="/standards/${sourceId}/${documentId}/browse">Read every requirement in this version</a> · `}<a href="/standards/${sourceId}">All versions of ${source.name}</a></p>`;

  // The look switch on a withheld release leads back to the bare page, not to a family someone typed into the address.
  return page({
    title: `${source.name} ${doc.version_label ?? ""}${family ? ` · ${family}` : ""}`.trim(),
    active: "register",
    content,
    meta: html`${changes.length} changes`,
    owner,
    open,
    look: withheld ? { ...look, back: `/standards/${sourceId}/${documentId}` } : look,
  });
}

function paramsText(r: NormalizedRequirement): string | null {
  if (!r.params.length) return null;
  return r.params.map((p) => `${p.id}: ${p.label ?? ""}${p.choices ? ` [${p.choices.join("; ")}]` : ""}`).join("\n");
}

export function renderControl(options: { db: DatabaseSync; sourceId: string; documentId: number; ref: string; now: Date } & Who): string | null {
  const { db, sourceId, documentId, ref, owner, open, look } = options;
  const source = getSource(db, sourceId);
  const doc = getDocument(db, documentId);
  if (!source || !doc || doc.source_id !== sourceId) return null;
  if (withheldFrom(source, owner)) {
    // The same page for every ref, looked up or not, so the answer says nothing about whether a name is on the
    // list; the look switch leads back to the release, since the page's own address is the name.
    const content = html`
      <div class="rel">
        <h1><code class="ref">${withheldLabel}</code> Entry shown to the owner only</h1>
        <div class="when">${source.name} ${doc.version_label ?? ""}<br><a href="/standards/${sourceId}/${documentId}">All changes in this version</a></div>
      </div>
      ${withheldBox(source, open)}`;
    return page({ title: `${withheldLabel} · ${source.name}`, active: "register", content, owner, open, look: { ...look, back: `/standards/${sourceId}/${documentId}` } });
  }
  const previous = doc.previous_document_id ? getDocument(db, doc.previous_document_id) : null;
  const after = loadRequirements(db, documentId).find((r) => r.ref === ref) ?? null;
  const before = previous ? (loadRequirements(db, previous.id).find((r) => r.ref === ref) ?? null) : null;
  if (!after && !before) return null;
  const shown = after ?? before!;
  const baselines = baselinesFor(db, ref);
  const changedFields = new Set(releaseChanges(db, documentId).filter((c) => c.ref === ref).map((c) => c.field ?? c.kind));
  const kind = !before ? (previous ? "added" : "first") : !after ? "removed" : changedFields.size ? "modified" : "unchanged";
  const notes = notesFor(db, documentId, ref);
  // The CCI join, both ways: a STIG rule names the controls it implements; a control lists the followed rules that implement it.
  const map = sourceId === "disa-stigs" || sourceId === "nist-sp-800-53" ? cciMap(db) : null;
  const mapping = map && sourceId === "disa-stigs" ? html`<p class="rule-controls">${mappingLine(shown, map, controlPageBase(db))}</p>` : html``;
  const implementers = map && sourceId === "nist-sp-800-53" && map.documentId !== null ? stigRulesForControl(db, ref, map) : [];
  const implementedBy =
    map && sourceId === "nist-sp-800-53" && map.documentId !== null
      ? html`<section class="box">
          <h2><a href="/stigs">STIG rules that implement this control</a> <span class="count"><a href="/stigs">${implementers.reduce((n, h) => n + h.rules.length, 0)}</a></span></h2>
          ${implementers.length
            ? implementers.map(
                (hit) => html`<h3 class="small"><a href="/stigs/${hit.stig.platform}?stig=${encodeURIComponent(hit.stig.key)}">${hit.stig.product}</a> ${hit.stig.latest.version_label ?? ""}</h3>
                  <ul class="change-list">${hit.rules.map((r) => html`<li><a href="/standards/disa-stigs/${hit.stig.latest.id}/${r.ref}"><b>${r.label}</b></a> <span class="chip sev ${r.family === "CAT I" ? "critical" : r.family === "CAT II" ? "high" : "medium"}">${r.family ?? ""}</span> ${r.title}</li>`)}</ul>`,
              )
            : html`<p class="small">No followed STIG rule cites a CCI indexed to this control (CCI list ${map.version ?? ""}).</p>`}
        </section>`
      : html``;

  const field = (name: string, label: string, b: string | null, a: string | null): Html => {
    const changed = changedFields.has(name) || (b ?? "") !== (a ?? "");
    if (!b && !a) return html``;
    if (!changed || kind === "first") {
      return html`<section class="field"><h3>${label}</h3><p class="prose">${lines(a ?? b)}</p></section>`;
    }
    return html`<section class="field changed">
      <h3>${label} <span class="chip mod">changed</span></h3>
      <div class="diff">
        <div><h5>Before · ${previous?.version_label ?? "previous"}</h5><p class="prose">${lines(b)}</p></div>
        <div><h5>After · ${doc.version_label ?? "this version"}</h5><p class="prose">${redline(b, a)}</p></div>
      </div>
    </section>`;
  };

  const content = html`
    <div class="rel">
      <h1><code class="ref">${shown.label}</code> ${shown.title}${before && after && before.title !== after.title ? html` <span class="small">(was: ${before.title})</span>` : ""}</h1>
      <div class="when">${source.name} ${doc.version_label ?? ""}${previous ? html` against ${previous.version_label ?? "previous"}` : ""}<br><a href="/standards/${sourceId}/${documentId}">All changes in this version</a></div>
    </div>
    <div class="pills">
      <a class="pill ${kind === "added" ? "ins" : kind === "removed" ? "del" : kind === "modified" ? "mod" : "none"}" href="/standards/${sourceId}/${documentId}">${kind === "first" ? "first version loaded" : kind}</a>
      ${shown.family ? html`<a class="pill" href="/standards/${sourceId}/${documentId}?family=${encodeURIComponent(shown.family)}">${shown.family}</a>` : ""}
      ${shown.status === "withdrawn" ? html`<span class="pill del">withdrawn</span>` : ""}
      ${baselines.map((b) => html`<a class="pill" href="/standards/nist-sp-800-53b">${b.charAt(0).toUpperCase()}${b.slice(1)} baseline</a>`)}
      ${shown.parentRef ? html`<a class="pill" href="/standards/${sourceId}/${documentId}/${shown.parentRef}">part of ${shown.parentRef.toUpperCase()}</a>` : ""}
    </div>
    ${mapping}
    ${notes.map((n) => html`<div class="why"><small>Why it changed, in the publisher's words</small><p>${n.text}</p>${n.source_url ? html`<cite><a href="${n.source_url}" ${newTabIf(n.source_url)}>${n.source_url}</a></cite>` : ""}</div>`)}
    ${(() => {
      const t = getTriage(db, "control", documentId, ref);
      if (owner) return html`<details class="box triage-box" ${t ? "open" : ""}><summary>Triage${t ? html`: ${t.state}${t.due_at ? html`, due ${t.due_at}` : ""}` : ""}</summary>${triageForm({ kind: "control", id: documentId, key: ref }, t, `/standards/${sourceId}/${documentId}/${ref}`)}</details>`;
      return t ? html`<div class="box triage-box"><b>Triage:</b> ${t.state}${t.due_at ? html`, due ${t.due_at}` : ""}${t.note ? html`<p class="small">${t.note}</p>` : ""}</div>` : "";
    })()}
    ${field("title", "Title", before?.title ?? null, after?.title ?? null)}
    ${field("statement", "Control", before?.statement ?? null, after?.statement ?? null)}
    ${field("guidance", "Discussion", before?.guidance ?? null, after?.guidance ?? null)}
    ${field("params", "Parameters", before ? paramsText(before) : null, after ? paramsText(after) : null)}
    ${field("related", "Related controls", before?.related.length ? [...before.related].sort().join(", ") : null, after?.related.length ? [...after.related].sort().join(", ") : null)}
    ${field("extra", "Fix", typeof before?.extra.fix === "string" ? before.extra.fix : null, typeof after?.extra.fix === "string" ? after.extra.fix : null)}
    ${field("extra", "Assessment objective", typeof before?.extra.assessmentObjective === "string" ? before.extra.assessmentObjective : null, typeof after?.extra.assessmentObjective === "string" ? after.extra.assessmentObjective : null)}
    ${typeof shown.extra.url === "string" && /^https?:\/\//i.test(shown.extra.url) ? html`<section class="field"><h3>Published at</h3><p class="prose"><a href="${shown.extra.url}" ${newTabIf(shown.extra.url)}>${shown.extra.url}</a></p></section>` : ""}
    ${implementedBy}`;

  const shortTitle = shown.title.length > 70 ? `${shown.title.slice(0, 69).trimEnd()}…` : shown.title;
  return page({ title: `${shown.label} ${shortTitle}`, active: "register", content, owner, open, look });
}

export type { SourceRow };
