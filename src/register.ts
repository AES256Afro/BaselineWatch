import type { DatabaseSync } from "node:sqlite";
import type { DocumentTarget, ParsedDocument, SourceRow } from "./adapters/types.ts";
import { diffRequirements, summarizeChanges, type ChangeSummary, type RequirementChange } from "./differ.ts";
import type { NormalizedRequirement } from "./oscal.ts";

export interface DocumentRow {
  id: number;
  source_id: string;
  document_key: string;
  snapshot_id: number;
  version_label: string | null;
  title: string | null;
  published_at: string | null;
  parsed_at: string;
  source_url: string | null;
  requirement_count: number;
  previous_document_id: number | null;
}

export interface ChangeRow {
  id: number;
  source_id: string;
  document_key: string;
  from_document_id: number | null;
  to_document_id: number;
  ref: string;
  kind: "added" | "removed" | "modified";
  field: string | null;
  before_text: string | null;
  after_text: string | null;
  computed_at: string;
}

export interface ExplanationRow {
  id: number;
  change_id: number | null;
  to_document_id: number | null;
  kind: "publisher" | "generated" | "none";
  text: string;
  source_url: string | null;
  created_at: string;
}

function parseJson<T>(text: string | null, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

export function getDocument(db: DatabaseSync, id: number): DocumentRow | null {
  return (db.prepare("SELECT * FROM documents WHERE id = ?").get(id) as unknown as DocumentRow | undefined) ?? null;
}

export function latestDocument(db: DatabaseSync, sourceId: string, key: string): DocumentRow | null {
  return (
    (db.prepare("SELECT * FROM documents WHERE source_id = ? AND document_key = ? ORDER BY published_at DESC, id DESC LIMIT 1").get(sourceId, key) as unknown as DocumentRow | undefined) ??
    null
  );
}

export function listDocuments(db: DatabaseSync, sourceId: string): DocumentRow[] {
  return db.prepare("SELECT * FROM documents WHERE source_id = ? ORDER BY document_key, published_at DESC, id DESC").all(sourceId) as unknown as DocumentRow[];
}

/** Every requirement of a stored document, in the shape the differ and the pages use. */
export function loadRequirements(db: DatabaseSync, documentId: number): NormalizedRequirement[] {
  const rows = db.prepare("SELECT * FROM requirements WHERE document_id = ? ORDER BY sort_key, ref").all(documentId) as unknown as {
    ref: string;
    parent_ref: string | null;
    family: string | null;
    label: string | null;
    title: string | null;
    statement: string | null;
    guidance: string | null;
    params_json: string | null;
    related_json: string | null;
    sort_key: string | null;
    status: string;
    extra_json: string | null;
  }[];
  return rows.map((r) => ({
    ref: r.ref,
    parentRef: r.parent_ref,
    family: r.family,
    label: r.label ?? r.ref.toUpperCase(),
    title: r.title ?? "",
    statement: r.statement,
    guidance: r.guidance,
    params: parseJson(r.params_json, []),
    related: parseJson(r.related_json, []),
    sortKey: r.sort_key ?? r.ref,
    status: r.status === "withdrawn" ? "withdrawn" : "active",
    extra: parseJson(r.extra_json, {}),
  }));
}

export function requirementIn(db: DatabaseSync, documentId: number, ref: string): NormalizedRequirement | null {
  return loadRequirements(db, documentId).find((r) => r.ref === ref) ?? null;
}

export interface StoredDocument {
  documentId: number;
  previousId: number | null;
  changes: RequirementChange[];
  summary: ChangeSummary;
}

export function changeSummaryText(summary: ChangeSummary): string {
  const parts: string[] = [];
  if (summary.added.length) parts.push(`${summary.added.length} added`);
  if (summary.removed.length) parts.push(`${summary.removed.length} removed`);
  if (summary.substantive.length) parts.push(`${summary.substantive.length} revised`);
  if (summary.editorial.length) parts.push(`${summary.editorial.length} with discussion or related-control updates`);
  return parts.length ? parts.join(", ") : "no control-level changes";
}

/**
 * Stores a parsed document and its requirements, diffs it against the previous version of the
 * same document, records the changes and the explanation, and posts a release item to the Wire.
 */
export function storeDocument(
  db: DatabaseSync,
  options: { source: SourceRow; target: DocumentTarget; parsed: ParsedDocument; snapshotId: number; fetchedAt: string },
): StoredDocument {
  const { source, target, parsed, snapshotId, fetchedAt } = options;
  const publishedAt = target.publishedAt ?? parsed.publishedAt ?? fetchedAt;
  const versionLabel = target.versionLabel ?? parsed.versionLabel;
  const previous = latestDocument(db, source.id, target.key);

  db.exec("BEGIN");
  try {
    const inserted = db
      .prepare(
        `INSERT INTO documents (source_id, document_key, snapshot_id, version_label, title, published_at, parsed_at, source_url, requirement_count, previous_document_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(source.id, target.key, snapshotId, versionLabel, parsed.title, publishedAt, fetchedAt, target.url, parsed.requirements.length, previous?.id ?? null);
    const documentId = Number(inserted.lastInsertRowid);

    const insertRequirement = db.prepare(
      `INSERT INTO requirements (document_id, ref, parent_ref, family, label, title, statement, guidance, params_json, related_json, sort_key, status, extra_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const r of parsed.requirements) {
      insertRequirement.run(
        documentId,
        r.ref,
        r.parentRef,
        r.family,
        r.label,
        r.title,
        r.statement,
        r.guidance,
        JSON.stringify(r.params),
        JSON.stringify(r.related),
        r.sortKey,
        r.status,
        JSON.stringify(r.extra),
      );
    }

    let changes: RequirementChange[] = [];
    if (previous) {
      changes = diffRequirements(loadRequirements(db, previous.id), parsed.requirements);
      const insertChange = db.prepare(
        `INSERT INTO changes (source_id, document_key, from_document_id, to_document_id, ref, kind, field, before_text, after_text, computed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );
      for (const c of changes) insertChange.run(source.id, target.key, previous.id, documentId, c.ref, c.kind, c.field, c.before, c.after, fetchedAt);
    }
    const summary = summarizeChanges(changes);

    if (target.rationale) {
      db.prepare("INSERT INTO explanations (change_id, to_document_id, kind, text, source_url, created_at) VALUES (NULL, ?, 'publisher', ?, ?, ?)").run(
        documentId,
        target.rationale.text,
        target.rationale.url,
        fetchedAt,
      );
    } else if (previous && changes.length) {
      db.prepare("INSERT INTO explanations (change_id, to_document_id, kind, text, source_url, created_at) VALUES (NULL, ?, 'none', ?, NULL, ?)").run(
        documentId,
        "No stated reason was captured with this release. Check the publisher's release notes.",
        fetchedAt,
      );
    }

    const label = versionLabel ? `${versionLabel}` : publishedAt.slice(0, 10);
    const title = previous
      ? `${source.name} ${label}: ${changeSummaryText(summary)}`
      : `${source.name} ${label}: loaded as the first version (${parsed.requirements.length} requirements)`;
    // A republication of the same version with no control-level change is kept as a document
    // (the bytes moved) but is not news.
    const republished = previous !== null && changes.length === 0 && (previous.version_label ?? null) === (versionLabel ?? null);
    if (!republished) db.prepare(
      `INSERT INTO items (source_id, kind, external_id, title, url, canonical_url, summary, published_at, fetched_at, signals_json)
       VALUES (?, 'release', ?, ?, ?, NULL, ?, ?, ?, ?)`,
    ).run(
      source.id,
      `${target.key}#${documentId}`,
      title,
      `/standards/${source.id}/${documentId}`,
      previous
        ? [summary.added.length ? `Added: ${summary.added.slice(0, 8).join(", ")}${summary.added.length > 8 ? "…" : ""}` : null, summary.substantive.length ? `Revised: ${summary.substantive.slice(0, 8).join(", ")}${summary.substantive.length > 8 ? "…" : ""}` : null, summary.removed.length ? `Removed: ${summary.removed.slice(0, 8).join(", ")}` : null]
            .filter(Boolean)
            .join(". ") || "Editorial changes only."
        : parsed.title,
      publishedAt,
      fetchedAt,
      JSON.stringify({ release: true, documentKey: target.key, added: summary.added.length, removed: summary.removed.length, modified: summary.modified.length }),
    );

    db.exec("COMMIT");
    return { documentId, previousId: previous?.id ?? null, changes, summary };
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

export function releaseChanges(db: DatabaseSync, documentId: number): ChangeRow[] {
  return db.prepare("SELECT * FROM changes WHERE to_document_id = ? ORDER BY ref, field").all(documentId) as unknown as ChangeRow[];
}

export function explanationsFor(db: DatabaseSync, documentId: number): ExplanationRow[] {
  return db.prepare("SELECT * FROM explanations WHERE to_document_id = ? ORDER BY kind, id").all(documentId) as unknown as ExplanationRow[];
}

/** Which baselines (latest profile of each) include a control. */
export function baselinesFor(db: DatabaseSync, ref: string): string[] {
  const rows = db
    .prepare(
      `SELECT d.document_key FROM documents d
       WHERE d.source_id = 'nist-sp-800-53b'
         AND d.id = (SELECT id FROM documents x WHERE x.source_id = d.source_id AND x.document_key = d.document_key ORDER BY published_at DESC, id DESC LIMIT 1)
         AND EXISTS (SELECT 1 FROM requirements r WHERE r.document_id = d.id AND r.ref = ?)
       ORDER BY CASE d.document_key WHEN 'profile:low' THEN 0 WHEN 'profile:moderate' THEN 1 WHEN 'profile:high' THEN 2 ELSE 3 END`,
    )
    .all(ref) as { document_key: string }[];
  return rows.map((r) => r.document_key.replace("profile:", ""));
}

export interface StandardSummary {
  source: SourceRow;
  documents: DocumentRow[];
  latest: DocumentRow | null;
  latestSummary: ChangeSummary | null;
}

export function changeSummaryFor(db: DatabaseSync, documentId: number): ChangeSummary {
  const rows = releaseChanges(db, documentId);
  return summarizeChanges(rows.map((r) => ({ ref: r.ref, kind: r.kind, field: r.field as RequirementChange["field"], before: r.before_text, after: r.after_text })));
}
