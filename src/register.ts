import type { DatabaseSync } from "node:sqlite";
import type { DocumentTarget, ParsedDocument, SourceRow } from "./adapters/types.ts";
import { diffRequirements, summarizeChanges, type ChangeSummary, type RequirementChange } from "./differ.ts";
import type { NormalizedRequirement } from "./oscal.ts";
import { parseJson } from "./json.ts";

/**
 * The Register's data layer: documents and their requirements, storing a parsed version and linking
 * it to the one before, the changes and explanations of a release, and what is withheld from whom
 * when a source's licence restricts its entries.
 */
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

/**
 * A licence-restricted source (`sources.restricted`): its entries are shown to the signed-in
 * owner only, a visitor sees versions and counts, and the API and MCP tools return neither
 * names nor text to anyone. These three say so in one voice wherever the rule applies.
 */
export const withheldLabel = "withheld (licence)";

/** Whether the entries of a source are kept from whoever is asking. */
export function withheldFrom(source: Pick<SourceRow, "restricted">, owner: boolean): boolean {
  return source.restricted === 1 && !owner;
}

/** The licence as the Sources page states it, for the sentence that says why. */
export function licenceOf(source: Pick<SourceRow, "licence">): string {
  return source.licence ?? "the publisher's terms do not allow its entries to be shown to third parties";
}

/** The Wire summary of a restricted source's release: what moved is counted in the title, never named here. */
export const withheldReleaseSummary = "Entries withheld under the publisher's licence; the owner sees them on the Register.";

export function getDocument(db: DatabaseSync, id: number): DocumentRow | null {
  return (db.prepare("SELECT * FROM documents WHERE id = ?").get(id) as unknown as DocumentRow | undefined) ?? null;
}

export function latestDocument(db: DatabaseSync, sourceId: string, key: string): DocumentRow | null {
  return (
    (db.prepare("SELECT * FROM documents WHERE source_id = ? AND document_key = ? ORDER BY published_at DESC, id DESC LIMIT 1").get(sourceId, key) as unknown as DocumentRow | undefined) ??
    null
  );
}

/**
 * The document a new version follows: the newest one published on or before it, so a historic
 * release loaded after the current one slots into its place in time instead of hanging off the
 * end. A version with no date is taken to follow the newest of all.
 */
function previousFor(db: DatabaseSync, sourceId: string, key: string, publishedAt: string | null): DocumentRow | null {
  if (!publishedAt) return latestDocument(db, sourceId, key);
  return (
    (db
      .prepare("SELECT * FROM documents WHERE source_id = ? AND document_key = ? AND (published_at <= ? OR published_at IS NULL) ORDER BY published_at DESC, id DESC LIMIT 1")
      .get(sourceId, key, publishedAt) as unknown as DocumentRow | undefined) ?? null
  );
}

/** The document published next after a date: the one to re-diff when a version arrives out of order. */
function successorOf(db: DatabaseSync, sourceId: string, key: string, publishedAt: string, excludeId: number): DocumentRow | null {
  return (
    (db
      .prepare("SELECT * FROM documents WHERE source_id = ? AND document_key = ? AND published_at > ? AND id <> ? ORDER BY published_at ASC, id ASC LIMIT 1")
      .get(sourceId, key, publishedAt, excludeId) as unknown as DocumentRow | undefined) ?? null
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
  const previous = previousFor(db, source.id, target.key, publishedAt);

  db.exec("BEGIN IMMEDIATE");
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

    // The document's own change log knows more than the listing that pointed at it.
    const rationale = parsed.rationale ?? target.rationale ?? null;
    if (rationale) {
      db.prepare("INSERT INTO explanations (change_id, to_document_id, kind, text, source_url, created_at) VALUES (NULL, ?, 'publisher', ?, ?, ?)").run(
        documentId,
        rationale.text,
        rationale.url,
        fetchedAt,
      );
    }
    // Per-requirement notes from the publisher's change log, attached to the changes they explain.
    if (previous && changes.length && parsed.notes?.length) {
      const byLabel = new Map<string, string>();
      for (const r of parsed.requirements) byLabel.set(r.label.toUpperCase(), r.ref);
      for (const r of loadRequirements(db, previous.id)) if (!byLabel.has(r.label.toUpperCase())) byLabel.set(r.label.toUpperCase(), r.ref);
      const changeIds = db.prepare("SELECT id FROM changes WHERE to_document_id = ? AND ref = ?");
      const insertNote = db.prepare("INSERT INTO explanations (change_id, to_document_id, kind, text, source_url, created_at) VALUES (?, NULL, 'publisher', ?, ?, ?)");
      for (const note of parsed.notes) {
        const ref = note.ref ?? (note.label ? byLabel.get(note.label.toUpperCase()) : undefined);
        if (!ref) continue;
        for (const row of changeIds.all(documentId, ref) as { id: number }[]) insertNote.run(row.id, note.text, rationale?.url ?? null, fetchedAt);
      }
    }
    if (!rationale && previous && changes.length) {
      db.prepare("INSERT INTO explanations (change_id, to_document_id, kind, text, source_url, created_at) VALUES (NULL, ?, 'none', ?, NULL, ?)").run(
        documentId,
        "No stated reason was captured with this release. Check the publisher's release notes.",
        fetchedAt,
      );
    }

    writeReleaseItem(
      db,
      source,
      { id: documentId, key: target.key, versionLabel: versionLabel ?? null, publishedAt, title: parsed.title, requirementCount: parsed.requirements.length },
      previous,
      changes,
      summary,
      fetchedAt,
    );

    // A version that arrived out of order (a backfill run after the current release was already
    // loaded) has a successor in time: that one is re-diffed against the newcomer, so the chain
    // reads in publication order whatever order the documents came in.
    const successor = successorOf(db, source.id, target.key, publishedAt, documentId);
    if (successor) relinkDocument(db, source, successor, getDocument(db, documentId), fetchedAt);

    db.exec("COMMIT");
    return { documentId, previousId: previous?.id ?? null, changes, summary };
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

/**
 * Gives a stored document the publisher's reason when a later pass knows it: a history entry that
 * turned out to be bytes already loaded. The "no stated reason" marker goes with it.
 *
 * A reason the adapter names for that release replaces one already stored, because the two are not
 * equally good. A note read off a publication page is whatever that page said on the day it was
 * fetched, and the page moves on: the catalog loaded in 2024 as SP 800-53 5.1.1+u4 was carrying
 * CSRC's Planning Note about Release 5.2.0, nineteen months its junior. A reason pinned to the
 * release in the adapter stays about that release. A generated summary is never touched.
 *
 * Returns whether anything was written.
 */
export function adoptRationale(db: DatabaseSync, documentId: number, rationale: { text: string; url: string | null } | null | undefined, at: string): boolean {
  if (!rationale) return false;
  const stored = db
    .prepare("SELECT id, text FROM explanations WHERE to_document_id = ? AND change_id IS NULL AND kind = 'publisher' ORDER BY id")
    .all(documentId) as unknown as { id: number; text: string }[];
  if (stored.some((row) => row.text === rationale.text)) return false;
  for (const row of stored) db.prepare("DELETE FROM explanations WHERE id = ?").run(row.id);
  db.prepare("DELETE FROM explanations WHERE to_document_id = ? AND change_id IS NULL AND kind = 'none'").run(documentId);
  db.prepare("INSERT INTO explanations (change_id, to_document_id, kind, text, source_url, created_at) VALUES (NULL, ?, 'publisher', ?, ?, ?)").run(documentId, rationale.text, rationale.url, at);
  return true;
}

export function releaseChanges(db: DatabaseSync, documentId: number): ChangeRow[] {
  return db.prepare("SELECT * FROM changes WHERE to_document_id = ? ORDER BY ref, field").all(documentId) as unknown as ChangeRow[];
}

export function explanationsFor(db: DatabaseSync, documentId: number): ExplanationRow[] {
  return db.prepare("SELECT * FROM explanations WHERE to_document_id = ? ORDER BY kind, id").all(documentId) as unknown as ExplanationRow[];
}

/** The publisher's notes attached to a requirement's changes in one release, deduplicated. */
export function notesFor(db: DatabaseSync, documentId: number, ref: string): ExplanationRow[] {
  const rows = db
    .prepare(
      `SELECT e.* FROM explanations e JOIN changes c ON c.id = e.change_id
       WHERE c.to_document_id = ? AND c.ref = ? ORDER BY e.id`,
    )
    .all(documentId, ref) as unknown as ExplanationRow[];
  const seen = new Set<string>();
  return rows.filter((r) => (seen.has(r.text) ? false : (seen.add(r.text), true)));
}

/** How many of a release's changes carry a publisher's note. */
export function notedChangeCount(db: DatabaseSync, documentId: number): number {
  return (db.prepare("SELECT COUNT(DISTINCT c.ref) AS n FROM explanations e JOIN changes c ON c.id = e.change_id WHERE c.to_document_id = ?").get(documentId) as { n: number }).n;
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

interface ReleaseDoc {
  id: number;
  key: string;
  versionLabel: string | null;
  publishedAt: string;
  title: string | null;
  requirementCount: number;
}

/**
 * The Wire entry for a release, written the first time and rewritten when the release is re-diffed.
 * A republication of the same version with no control-level change is kept as a document (the
 * bytes moved) but is not news, so it gets no entry and loses one it had.
 */
function writeReleaseItem(db: DatabaseSync, source: SourceRow, doc: ReleaseDoc, previous: DocumentRow | null, changes: RequirementChange[], summary: ChangeSummary, at: string): void {
  const externalId = `${doc.key}#${doc.id}`;
  const republished = previous !== null && changes.length === 0 && (previous.version_label ?? null) === (doc.versionLabel ?? null);
  if (republished) {
    db.prepare("DELETE FROM items WHERE source_id = ? AND external_id = ?").run(source.id, externalId);
    return;
  }
  const label = doc.versionLabel ?? doc.publishedAt.slice(0, 10);
  const title = previous
    ? `${source.name} ${label}: ${changeSummaryText(summary)}`
    : `${source.name} ${label}: loaded as the first version (${doc.requirementCount} requirements)`;
  // A restricted source's entries never reach the Wire, which every visitor reads: the title counts them.
  const text = previous
    ? source.restricted === 1
      ? withheldReleaseSummary
      : [
          summary.added.length ? `Added: ${summary.added.slice(0, 8).join(", ")}${summary.added.length > 8 ? "…" : ""}` : null,
          summary.substantive.length ? `Revised: ${summary.substantive.slice(0, 8).join(", ")}${summary.substantive.length > 8 ? "…" : ""}` : null,
          summary.removed.length ? `Removed: ${summary.removed.slice(0, 8).join(", ")}` : null,
        ]
          .filter(Boolean)
          .join(". ") || "Editorial changes only."
    : doc.title;
  db.prepare(
    `INSERT INTO items (source_id, kind, external_id, title, url, canonical_url, summary, published_at, fetched_at, signals_json)
     VALUES (?, 'release', ?, ?, ?, NULL, ?, ?, ?, ?)
     ON CONFLICT (source_id, external_id) DO UPDATE SET title = excluded.title, summary = excluded.summary, published_at = excluded.published_at, signals_json = excluded.signals_json`,
  ).run(
    source.id,
    externalId,
    title,
    `/standards/${source.id}/${doc.id}`,
    text,
    doc.publishedAt,
    at,
    JSON.stringify({ release: true, documentKey: doc.key, added: summary.added.length, removed: summary.removed.length, modified: summary.modified.length }),
  );
}

/**
 * Gives a stored document a different predecessor: its changes are recomputed against the new one,
 * the publisher's per-requirement notes are matched back by ref, the "no stated reason" marker and
 * any generated summary follow the new diff, and the Wire entry is rewritten. Runs inside the
 * caller's transaction.
 */
function relinkDocument(db: DatabaseSync, source: SourceRow, doc: DocumentRow, previous: DocumentRow | null, at: string): ChangeSummary {
  const notes = db
    .prepare("SELECT c.ref, e.kind, e.text, e.source_url FROM explanations e JOIN changes c ON c.id = e.change_id WHERE c.to_document_id = ? ORDER BY e.id")
    .all(doc.id) as { ref: string; kind: string; text: string; source_url: string | null }[];
  db.prepare("DELETE FROM explanations WHERE change_id IN (SELECT id FROM changes WHERE to_document_id = ?)").run(doc.id);
  db.prepare("DELETE FROM changes WHERE to_document_id = ?").run(doc.id);
  db.prepare("DELETE FROM explanations WHERE to_document_id = ? AND change_id IS NULL AND kind IN ('none', 'generated')").run(doc.id);

  const changes = previous ? diffRequirements(loadRequirements(db, previous.id), loadRequirements(db, doc.id)) : [];
  const insertChange = db.prepare(
    `INSERT INTO changes (source_id, document_key, from_document_id, to_document_id, ref, kind, field, before_text, after_text, computed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  for (const c of changes) insertChange.run(source.id, doc.document_key, previous?.id ?? null, doc.id, c.ref, c.kind, c.field, c.before, c.after, at);

  const changeIds = db.prepare("SELECT id FROM changes WHERE to_document_id = ? AND ref = ?");
  const insertNote = db.prepare("INSERT INTO explanations (change_id, to_document_id, kind, text, source_url, created_at) VALUES (?, NULL, ?, ?, ?, ?)");
  const seen = new Set<string>();
  for (const note of notes) {
    const once = `${note.ref}\n${note.text}`;
    if (seen.has(once)) continue;
    seen.add(once);
    for (const row of changeIds.all(doc.id, note.ref) as { id: number }[]) insertNote.run(row.id, note.kind, note.text, note.source_url, at);
  }

  db.prepare("UPDATE documents SET previous_document_id = ? WHERE id = ?").run(previous?.id ?? null, doc.id);
  const explained = (db.prepare("SELECT COUNT(*) AS n FROM explanations WHERE to_document_id = ? AND change_id IS NULL").get(doc.id) as { n: number }).n > 0;
  if (previous && changes.length && !explained) {
    db.prepare("INSERT INTO explanations (change_id, to_document_id, kind, text, source_url, created_at) VALUES (NULL, ?, 'none', ?, NULL, ?)").run(
      doc.id,
      "No stated reason was captured with this release. Check the publisher's release notes.",
      at,
    );
  }
  const summary = summarizeChanges(changes);
  writeReleaseItem(
    db,
    source,
    { id: doc.id, key: doc.document_key, versionLabel: doc.version_label, publishedAt: doc.published_at ?? doc.parsed_at, title: doc.title, requirementCount: doc.requirement_count },
    previous,
    changes,
    summary,
    at,
  );
  return summary;
}

/**
 * Puts every document of a source back in publication order and re-diffs the ones whose
 * predecessor was wrong. Repairs a history that was backfilled after the current release had
 * already been fetched; a chain already in order is left alone, so it is safe to run again.
 */
export function relinkSource(db: DatabaseSync, source: SourceRow, at: string): { keys: number; relinked: number } {
  const keys = db.prepare("SELECT DISTINCT document_key FROM documents WHERE source_id = ? ORDER BY document_key").all(source.id) as { document_key: string }[];
  let relinked = 0;
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const { document_key } of keys) {
      const docs = db
        .prepare("SELECT * FROM documents WHERE source_id = ? AND document_key = ? ORDER BY published_at ASC, id ASC")
        .all(source.id, document_key) as unknown as DocumentRow[];
      docs.forEach((doc, i) => {
        const expected = i > 0 ? (docs[i - 1] ?? null) : null;
        if ((doc.previous_document_id ?? null) === (expected?.id ?? null)) return;
        relinkDocument(db, source, doc, expected, at);
        relinked += 1;
      });
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
  return { keys: keys.length, relinked };
}
