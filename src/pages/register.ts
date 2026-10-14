import type { DatabaseSync } from "node:sqlite";
import type { SourceRow } from "../adapters/types.ts";
import { summarizeChanges, type RequirementChange } from "../differ.ts";
import { html, type Html } from "../html.ts";
import { getSource } from "../ingest.ts";
import type { NormalizedRequirement } from "../oscal.ts";
import { lines, redline } from "../redline.ts";
import { baselinesFor, changeSummaryFor, changeSummaryText, explanationsFor, getDocument, listDocuments, loadRequirements, releaseChanges, type DocumentRow } from "../register.ts";
import { relativeTime, shortStamp } from "../time.ts";
import { page } from "./layout.ts";

interface Who {
  owner: boolean;
  open: boolean;
}

const keyLabel = (key: string): string => (key === "catalog" ? "Catalog" : key.startsWith("profile:") ? `${key.slice(8).charAt(0).toUpperCase()}${key.slice(9)} baseline` : key);

export function renderStandard(options: { db: DatabaseSync; sourceId: string; now: Date } & Who): string | null {
  const { db, sourceId, now, owner, open } = options;
  const source = getSource(db, sourceId);
  if (!source || source.group_name !== "standards") return null;
  const documents = listDocuments(db, sourceId);
  const byKey = new Map<string, DocumentRow[]>();
  for (const d of documents) byKey.set(d.document_key, [...(byKey.get(d.document_key) ?? []), d]);

  const sections = [...byKey.entries()].map(
    ([key, docs]) => html`<section class="box">
      <h2>${keyLabel(key)} <span class="count">${docs.length} version${docs.length === 1 ? "" : "s"}</span></h2>
      <div class="table-wrap"><table>
        <thead><tr><th>Version</th><th>Published</th><th>Requirements</th><th>Against the previous version</th><th>Loaded</th></tr></thead>
        <tbody>${docs.map((d) => {
          const summary = d.previous_document_id ? changeSummaryText(changeSummaryFor(db, d.id)) : "first version loaded";
          return html`<tr>
            <td><a href="/standards/${sourceId}/${d.id}"><b>${d.version_label ?? "version unknown"}</b></a></td>
            <td>${d.published_at ? d.published_at.slice(0, 10) : "—"}</td>
            <td class="n">${d.requirement_count}</td>
            <td>${summary}</td>
            <td class="small">${relativeTime(d.parsed_at, now)}</td>
          </tr>`;
        })}</tbody>
      </table></div>
    </section>`,
  );

  const content = html`
    <h1>${source.name}</h1>
    <p class="lede">${source.notes ?? ""} <a href="${source.url}" rel="noopener">Source</a>${source.licence ? html` · ${source.licence}` : ""}.</p>
    ${documents.length === 0
      ? html`<div class="empty"><b>No version loaded yet.</b><p>${owner ? html`Fetch it from the <a href="/sources">Sources</a> page, or run <code>npm run backfill -- ${sourceId}</code> to load the published history first.` : "The owner can fetch it from the Sources page."}</p></div>`
      : sections}`;

  return page({ title: source.name, active: "register", content, meta: html`${documents.length} versions`, owner, open });
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

export function renderRelease(options: { db: DatabaseSync; sourceId: string; documentId: number; now: Date } & Who): string | null {
  const { db, sourceId, documentId, owner, open } = options;
  const source = getSource(db, sourceId);
  const doc = getDocument(db, documentId);
  if (!source || !doc || doc.source_id !== sourceId) return null;
  const previous = doc.previous_document_id ? getDocument(db, doc.previous_document_id) : null;
  const changes = releaseChanges(db, documentId);
  const summary = summarizeChanges(changes.map((c) => ({ ref: c.ref, kind: c.kind, field: c.field as RequirementChange["field"], before: c.before_text, after: c.after_text })));
  const explanations = explanationsFor(db, documentId);
  const labels = new Map<string, { label: string; title: string }>();
  for (const r of loadRequirements(db, documentId)) labels.set(r.ref, { label: r.label, title: r.title });
  if (previous) for (const r of loadRequirements(db, previous.id)) if (!labels.has(r.ref)) labels.set(r.ref, { label: r.label, title: r.title });

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
  const substantive = order.filter((r) => summary.added.includes(r) || summary.removed.includes(r) || summary.substantive.includes(r));
  const editorial = order.filter((r) => summary.editorial.includes(r));

  const content = html`
    <div class="rel">
      <h1>${source.name} <span class="arrow">${previous ? html`${previous.version_label ?? "previous"} → ` : ""}${doc.version_label ?? "version unknown"}</span></h1>
      <div class="when">Published ${doc.published_at ? doc.published_at.slice(0, 10) : "date unknown"}<br>Snapshot taken ${shortStamp(doc.parsed_at)} · <a href="${doc.source_url ?? source.url}" rel="noopener">${keyLabel(doc.document_key)} source</a></div>
    </div>
    <div class="pills">
      ${summary.added.length ? html`<span class="pill ins">+ ${summary.added.length} added: ${summary.added.map((r) => labels.get(r)?.label ?? r).slice(0, 10).join(", ")}${summary.added.length > 10 ? "…" : ""}</span>` : ""}
      ${summary.removed.length ? html`<span class="pill del">− ${summary.removed.length} removed: ${summary.removed.map((r) => labels.get(r)?.label ?? r).slice(0, 10).join(", ")}${summary.removed.length > 10 ? "…" : ""}</span>` : ""}
      ${summary.substantive.length ? html`<span class="pill mod">~ ${summary.substantive.length} revised: ${summary.substantive.map((r) => labels.get(r)?.label ?? r).slice(0, 10).join(", ")}${summary.substantive.length > 10 ? "…" : ""}</span>` : ""}
      ${summary.editorial.length ? html`<span class="pill">${summary.editorial.length} with discussion, related-control or assessment updates</span>` : ""}
      ${!previous ? html`<span class="pill none">First version loaded: ${doc.requirement_count} requirements, nothing to compare yet</span>` : ""}
      ${previous && changes.length === 0 ? html`<span class="pill none">No control-level changes against ${previous.version_label ?? "the previous version"}</span>` : ""}
    </div>
    ${explanations.map((e) =>
      e.kind === "publisher"
        ? html`<div class="why"><small>Why this release, in the publisher's words</small><p>${e.text}</p>${e.source_url ? html`<cite><a href="${e.source_url}" rel="noopener">${e.source_url}</a></cite>` : ""}</div>`
        : e.kind === "generated"
          ? html`<div class="why gen"><small>Summary <span class="badge">Generated</span></small><p>${e.text}</p></div>`
          : html`<div class="why none"><small>Why this release</small><p>${e.text}</p></div>`,
    )}
    ${substantive.length
      ? html`<section class="box"><h2>Controls added, removed or revised <span class="count">${substantive.length}</span></h2>
          <div class="table-wrap"><table><thead><tr><th>Control</th><th>Title</th><th>Change</th></tr></thead><tbody>${substantive.map(row)}</tbody></table></div></section>`
      : ""}
    ${editorial.length
      ? html`<section class="box"><h2>Discussion, related-control and assessment updates <span class="count">${editorial.length}</span></h2>
          <div class="table-wrap"><table><thead><tr><th>Control</th><th>Title</th><th>What moved</th></tr></thead><tbody>${editorial.map(row)}</tbody></table></div></section>`
      : ""}
    <p class="small"><a href="/standards/${sourceId}">All versions of ${source.name}</a></p>`;

  return page({ title: `${source.name} ${doc.version_label ?? ""}`.trim(), active: "register", content, meta: html`${changes.length} changes`, owner, open });
}

function paramsText(r: NormalizedRequirement): string | null {
  if (!r.params.length) return null;
  return r.params.map((p) => `${p.id}: ${p.label ?? ""}${p.choices ? ` [${p.choices.join("; ")}]` : ""}`).join("\n");
}

export function renderControl(options: { db: DatabaseSync; sourceId: string; documentId: number; ref: string; now: Date } & Who): string | null {
  const { db, sourceId, documentId, ref, owner, open } = options;
  const source = getSource(db, sourceId);
  const doc = getDocument(db, documentId);
  if (!source || !doc || doc.source_id !== sourceId) return null;
  const previous = doc.previous_document_id ? getDocument(db, doc.previous_document_id) : null;
  const after = loadRequirements(db, documentId).find((r) => r.ref === ref) ?? null;
  const before = previous ? (loadRequirements(db, previous.id).find((r) => r.ref === ref) ?? null) : null;
  if (!after && !before) return null;
  const shown = after ?? before!;
  const baselines = baselinesFor(db, ref);
  const changedFields = new Set(releaseChanges(db, documentId).filter((c) => c.ref === ref).map((c) => c.field ?? c.kind));
  const kind = !before ? (previous ? "added" : "first") : !after ? "removed" : changedFields.size ? "modified" : "unchanged";

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
      <span class="pill ${kind === "added" ? "ins" : kind === "removed" ? "del" : kind === "modified" ? "mod" : "none"}">${kind === "first" ? "first version loaded" : kind}</span>
      ${shown.family ? html`<span class="pill">${shown.family}</span>` : ""}
      ${shown.status === "withdrawn" ? html`<span class="pill del">withdrawn</span>` : ""}
      ${baselines.map((b) => html`<span class="pill">${b.charAt(0).toUpperCase()}${b.slice(1)} baseline</span>`)}
      ${shown.parentRef ? html`<a class="pill" href="/standards/${sourceId}/${documentId}/${shown.parentRef}">part of ${shown.parentRef.toUpperCase()}</a>` : ""}
    </div>
    ${field("title", "Title", before?.title ?? null, after?.title ?? null)}
    ${field("statement", "Control", before?.statement ?? null, after?.statement ?? null)}
    ${field("guidance", "Discussion", before?.guidance ?? null, after?.guidance ?? null)}
    ${field("params", "Parameters", before ? paramsText(before) : null, after ? paramsText(after) : null)}
    ${field("related", "Related controls", before?.related.length ? [...before.related].sort().join(", ") : null, after?.related.length ? [...after.related].sort().join(", ") : null)}
    ${field("extra", "Fix", typeof before?.extra.fix === "string" ? before.extra.fix : null, typeof after?.extra.fix === "string" ? after.extra.fix : null)}
    ${field("extra", "Assessment objective", typeof before?.extra.assessmentObjective === "string" ? before.extra.assessmentObjective : null, typeof after?.extra.assessmentObjective === "string" ? after.extra.assessmentObjective : null)}`;

  const shortTitle = shown.title.length > 70 ? `${shown.title.slice(0, 69).trimEnd()}…` : shown.title;
  return page({ title: `${shown.label} ${shortTitle}`, active: "register", content, owner, open });
}

export type { SourceRow };
