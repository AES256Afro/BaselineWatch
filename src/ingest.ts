import type { DatabaseSync } from "node:sqlite";
import { adapterFor, fetchable } from "./adapters/index.ts";
import { canonicalUrl, type Adapter, type AlertDraft, type DocumentTarget, type ParsedDocument, type ParsedItem, type PullSettings, type SourceRow } from "./adapters/types.ts";
import { putBlob, sha256Hex } from "./blobs.ts";
import { httpGet, type HttpGet } from "./http.ts";
import { summarizeRelease, type LlmSettings } from "./llm.ts";
import { notify, type Transport } from "./notify.ts";
import { adoptRationale, changeSummaryText, getDocument, storeDocument, type StoredDocument } from "./register.ts";

export interface DocumentOutcome {
  key: string;
  status: "ok" | "unchanged" | "error";
  documentId: number | null;
  versionLabel: string | null;
  summary: string | null;
  error: string | null;
  /** Set when a new version with changes arrived after an earlier one. */
  alert?: AlertDraft;
}

/**
 * Fetches one versioned document of a standards source, snapshots it, and stores and diffs it
 * when its bytes are new. Exported so the backfill command can load history in order.
 */
async function addGeneratedSummary(
  db: DatabaseSync,
  http: HttpGet,
  llm: LlmSettings,
  source: SourceRow,
  stored: StoredDocument,
  parsed: ParsedDocument,
  at: string,
): Promise<void> {
  const previous = stored.previousId ? getDocument(db, stored.previousId) : null;
  const labels = new Map(parsed.requirements.map((r) => [r.ref, { label: r.label, title: r.title }]));
  const text = await summarizeRelease(llm, http, {
    standard: source.name,
    version: parsed.versionLabel ?? "this version",
    previousVersion: previous?.version_label ?? null,
    rationale: parsed.rationale?.text ?? null,
    changes: stored.changes.map((c) => ({ label: labels.get(c.ref)?.label ?? c.ref.toUpperCase(), title: labels.get(c.ref)?.title ?? "", kind: c.kind, field: c.field, before: c.before, after: c.after })),
  });
  if (text) {
    db.prepare("INSERT INTO explanations (change_id, to_document_id, kind, text, source_url, created_at) VALUES (NULL, ?, 'generated', ?, NULL, ?)").run(stored.documentId, text, at);
  }
}

export async function ingestDocumentTarget(
  db: DatabaseSync,
  dataDir: string,
  source: SourceRow,
  adapter: Adapter,
  target: DocumentTarget,
  deps: { http: HttpGet; now: () => Date; settings?: PullSettings },
): Promise<DocumentOutcome> {
  const base = { key: target.key, documentId: null as number | null, versionLabel: null as string | null, summary: null as string | null, error: null as string | null };
  try {
    // A listing that names the file and its publication date is enough to know nothing moved.
    if (target.publishedAt) {
      const seen = db
        .prepare("SELECT id, version_label FROM documents WHERE source_id = ? AND document_key = ? AND source_url = ? AND published_at = ? ORDER BY id DESC LIMIT 1")
        .get(source.id, target.key, target.url, target.publishedAt) as { id: number; version_label: string | null } | undefined;
      if (seen) {
        adoptRationale(db, seen.id, target.rationale, deps.now().toISOString());
        return { ...base, status: "unchanged", documentId: seen.id, versionLabel: seen.version_label };
      }
    }
    const response = await deps.http(target.url, { ...(adapter.headers ? { headers: adapter.headers } : {}), timeoutMs: 180_000, maxBytes: 100 * 1024 * 1024 });
    const fetchedAt = deps.now().toISOString();
    const sha256 = sha256Hex(response.bytes);
    const existing = db.prepare("SELECT id FROM snapshots WHERE source_id = ? AND document_key = ? AND sha256 = ?").get(source.id, target.key, sha256) as { id: number } | undefined;
    if (existing) {
      const doc = db.prepare("SELECT id, version_label FROM documents WHERE snapshot_id = ?").get(existing.id) as { id: number; version_label: string | null } | undefined;
      // The same bytes under a history entry that knows why the release happened: keep the reason.
      if (doc) adoptRationale(db, doc.id, target.rationale, deps.now().toISOString());
      return { ...base, status: "unchanged", documentId: doc?.id ?? null, versionLabel: doc?.version_label ?? null };
    }
    if (!adapter.parseDocument) throw new Error(`adapter ${adapter.id} cannot parse documents`);
    const parsed = await adapter.parseDocument(response.bytes, target, { db, source, http: deps.http });
    return storeParsedDocument(db, dataDir, source, target, parsed, response.bytes, sha256, { fetchedAt, contentType: response.contentType, etag: response.etag, lastModified: response.lastModified, http: deps.http, ...(deps.settings ? { settings: deps.settings } : {}) });
  } catch (error) {
    return { ...base, status: "error", error: error instanceof Error ? error.message : String(error) };
  }
}

/** The part of a document's ingestion after the bytes are in hand and parsed: snapshot, store, diff, summarise. */
async function storeParsedDocument(
  db: DatabaseSync,
  dataDir: string,
  source: SourceRow,
  target: DocumentTarget,
  parsed: ParsedDocument,
  bytes: Uint8Array,
  sha256: string,
  options: { fetchedAt: string; contentType: string | null; etag: string | null; lastModified: string | null; http: HttpGet; settings?: PullSettings },
): Promise<DocumentOutcome> {
  const blob = putBlob(dataDir, bytes);
  const snapshot = db
    .prepare(
      `INSERT INTO snapshots (source_id, document_key, sha256, bytes, media_type, blob_path, fetched_at, etag, last_modified)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(source.id, target.key, sha256, blob.bytes, options.contentType, blob.relativePath, options.fetchedAt, options.etag, options.lastModified);
  const stored = storeDocument(db, { source, target, parsed, snapshotId: Number(snapshot.lastInsertRowid), fetchedAt: options.fetchedAt });
  if (options.settings?.llmUrl && stored.previousId && stored.changes.length > 0) {
    await addGeneratedSummary(db, options.http, { url: options.settings.llmUrl, model: options.settings.llmModel ?? "llama3.2:3b" }, source, stored, parsed, options.fetchedAt);
  }
  const versionLabel = target.versionLabel ?? parsed.versionLabel;
  const summary = stored.previousId ? changeSummaryText(stored.summary) : `first version, ${parsed.requirements.length} requirements`;
  return {
    key: target.key,
    status: "ok",
    documentId: stored.documentId,
    versionLabel,
    summary,
    error: null,
    ...(stored.previousId && stored.changes.length
      ? { alert: { kind: "release" as const, title: `${source.name} ${versionLabel ?? ""}: ${summary}`.trim(), body: parsed.rationale?.text.slice(0, 600) ?? summary, url: `/standards/${source.id}/${stored.documentId}` } }
      : {}),
  };
}

/**
 * A document the owner brought by hand (a CIS Benchmark PDF): parsed first so the key can come
 * from the document's own title, then stored and diffed like any fetched release.
 */
export async function storeUploadedDocument(
  db: DatabaseSync,
  dataDir: string,
  source: SourceRow,
  adapter: Adapter,
  bytes: Uint8Array,
  options: { filename: string; keyFor: (title: string | null) => string; versionLabel: string | null; publishedAt: string | null; now: () => Date },
): Promise<DocumentOutcome> {
  const base = { key: "", documentId: null as number | null, versionLabel: null as string | null, summary: null as string | null, error: null as string | null };
  try {
    if (!adapter.parseDocument) throw new Error(`adapter ${adapter.id} cannot parse documents`);
    const probe: DocumentTarget = { key: "upload", url: `upload:${options.filename}`, versionLabel: options.versionLabel, publishedAt: options.publishedAt };
    const parsed = await adapter.parseDocument(bytes, probe, { db, source, http: httpGet });
    const key = options.keyFor(parsed.title);
    const target: DocumentTarget = { ...probe, key };
    const sha256 = sha256Hex(bytes);
    const existing = db.prepare("SELECT id FROM snapshots WHERE source_id = ? AND document_key = ? AND sha256 = ?").get(source.id, key, sha256) as { id: number } | undefined;
    if (existing) {
      const doc = db.prepare("SELECT id, version_label FROM documents WHERE snapshot_id = ?").get(existing.id) as { id: number; version_label: string | null } | undefined;
      return { ...base, key, status: "unchanged", documentId: doc?.id ?? null, versionLabel: doc?.version_label ?? null };
    }
    const fetchedAt = options.now().toISOString();
    const outcome = await storeParsedDocument(db, dataDir, source, target, parsed, bytes, sha256, { fetchedAt, contentType: "application/pdf", etag: null, lastModified: null, http: httpGet });
    db.prepare("UPDATE sources SET last_fetch_at = ?, last_status = 'ok', last_error = NULL, fetch_count = fetch_count + 1 WHERE id = ?").run(fetchedAt, source.id);
    return outcome;
  } catch (error) {
    return { ...base, status: "error", error: error instanceof Error ? error.message : String(error) };
  }
}

export type IngestStatus = "ok" | "unchanged" | "error" | "skipped";

export interface IngestResult {
  sourceId: string;
  status: IngestStatus;
  /** Items the adapter produced from this fetch. */
  items: number;
  inserted: number;
  updated: number;
  snapshotId: number | null;
  error: string | null;
  detail: string | null;
  durationMs: number;
}

export interface IngestDeps {
  http?: HttpGet;
  now?: () => Date;
  settings?: PullSettings;
  log?: (line: string) => void;
  /** Where alerts go; null or absent means they are only logged as unconfigured. */
  transport?: Transport | null;
  /** The address people use, to make alert links absolute. */
  baseUrl?: string;
}

/** Sends a run's alerts, at most five singly and the rest as one line, and records each. */
async function sendAlerts(db: DatabaseSync, deps: IngestDeps, drafts: AlertDraft[]): Promise<void> {
  if (!drafts.length) return;
  const http = deps.http ?? httpGet;
  const now = deps.now ?? (() => new Date());
  const absolute = (url: string | null | undefined) => (url && url.startsWith("/") && deps.baseUrl ? `${deps.baseUrl}${url}` : (url ?? null));
  const transport = deps.transport ?? null;
  const single = drafts.slice(0, 5);
  for (const d of single) await notify(db, transport, { ...d, url: absolute(d.url) }, http, now);
  if (drafts.length > single.length) {
    const rest = drafts.slice(single.length);
    await notify(
      db,
      transport,
      { kind: rest[0]!.kind, title: `${rest.length} more ${rest[0]!.kind === "kev" ? "KEV additions" : rest[0]!.kind === "watch" ? "watched CVEs" : "releases"}`, body: rest.map((r) => r.title).join("\n").slice(0, 3000), url: absolute(rest[0]!.kind === "release" ? "/" : "/wire") },
      http,
      now,
    );
  }
}

export const defaultPullSettings: PullSettings = { nvdApiKey: null, nvdBackfillDays: 7 };

export function getSource(db: DatabaseSync, id: string): SourceRow | null {
  return (db.prepare("SELECT * FROM sources WHERE id = ?").get(id) as unknown as SourceRow | undefined) ?? null;
}

export function listSources(db: DatabaseSync, options: { enabledOnly?: boolean } = {}): SourceRow[] {
  const sql = options.enabledOnly ? "SELECT * FROM sources WHERE enabled = 1 ORDER BY id" : "SELECT * FROM sources ORDER BY id";
  return db.prepare(sql).all() as unknown as SourceRow[];
}

function recordOutcome(
  db: DatabaseSync,
  source: SourceRow,
  outcome: { status: IngestStatus; error?: string | null; etag?: string | null; lastModified?: string | null; fetchedAt: string; durationMs: number },
): void {
  db.prepare(
    `UPDATE sources SET last_fetch_at = ?, last_status = ?, last_error = ?, etag = COALESCE(?, etag), last_modified = COALESCE(?, last_modified),
       last_duration_ms = ?, fetch_count = fetch_count + 1 WHERE id = ?`,
  ).run(outcome.fetchedAt, outcome.status, outcome.error ? outcome.error.slice(0, 500) : null, outcome.etag ?? null, outcome.lastModified ?? null, outcome.durationMs, source.id);
}

/** Inserts new items and updates changed ones; read and starred flags are never touched. */
export function upsertItems(db: DatabaseSync, sourceId: string, items: ParsedItem[], fetchedAt: string): { inserted: number; updated: number } {
  const exists = db.prepare("SELECT title, url, summary, published_at, signals_json FROM items WHERE source_id = ? AND external_id = ?");
  const insert = db.prepare(
    `INSERT INTO items (source_id, kind, external_id, title, url, canonical_url, summary, published_at, fetched_at, signals_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const update = db.prepare(
    `UPDATE items SET title = ?, url = ?, canonical_url = ?, summary = ?, published_at = COALESCE(?, published_at), signals_json = ?
     WHERE source_id = ? AND external_id = ?`,
  );
  let inserted = 0;
  let updated = 0;
  db.exec("BEGIN");
  try {
    for (const item of items) {
      const signals = item.signals ? JSON.stringify(item.signals) : null;
      const current = exists.get(sourceId, item.externalId) as
        | { title: string; url: string | null; summary: string | null; published_at: string | null; signals_json: string | null }
        | undefined;
      if (!current) {
        insert.run(sourceId, item.kind, item.externalId, item.title, item.url, canonicalUrl(item.url), item.summary, item.publishedAt, fetchedAt, signals);
        inserted += 1;
      } else if (current.title !== item.title || current.url !== item.url || current.summary !== item.summary || current.signals_json !== signals) {
        update.run(item.title, item.url, canonicalUrl(item.url), item.summary, item.publishedAt, signals, sourceId, item.externalId);
        updated += 1;
      }
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
  return { inserted, updated };
}

/**
 * Fetches one source once. A parsing adapter gets a conditional GET, a content-addressed
 * snapshot, a parse and an upsert; a pulling adapter runs its own requests. Either way the
 * source's status row records the outcome, and a source's own failure never throws.
 */
export async function ingestSource(db: DatabaseSync, dataDir: string, source: SourceRow, deps: IngestDeps = {}): Promise<IngestResult> {
  const http = deps.http ?? httpGet;
  const now = deps.now ?? (() => new Date());
  const log = deps.log ?? (() => {});
  const started = Date.now();
  const base = { sourceId: source.id, items: 0, inserted: 0, updated: 0, snapshotId: null as number | null, error: null as string | null, detail: null as string | null };
  const done = (partial: Partial<IngestResult> & { status: IngestStatus }): IngestResult => ({ ...base, ...partial, durationMs: Date.now() - started });

  const adapter = adapterFor(source);
  if (!adapter) {
    return done({ status: "skipped", error: "no adapter for this source yet" });
  }
  if (!fetchable(adapter)) {
    return done({ status: "skipped", error: "this source is loaded by upload, not fetched" });
  }

  try {
    if (adapter.pull) {
      const outcome = await adapter.pull({ db, dataDir, source, http, now, settings: deps.settings ?? defaultPullSettings, log });
      const result = done({ status: "ok", items: outcome.items, inserted: outcome.inserted, updated: outcome.updated, detail: outcome.detail ?? null });
      recordOutcome(db, source, { status: "ok", fetchedAt: now().toISOString(), durationMs: result.durationMs });
      if (outcome.alerts?.length) await sendAlerts(db, deps, outcome.alerts);
      return result;
    }
    if (adapter.documents) {
      const outcomes: DocumentOutcome[] = [];
      for (const target of await adapter.documents(source, { db, http, now })) {
        outcomes.push(await ingestDocumentTarget(db, dataDir, source, adapter, target, { http, now, ...(deps.settings ? { settings: deps.settings } : {}) }));
      }
      const errors = outcomes.filter((o) => o.status === "error");
      const fresh = outcomes.filter((o) => o.status === "ok");
      const status: IngestStatus = errors.length === outcomes.length ? "error" : fresh.length ? "ok" : "unchanged";
      const detail = outcomes.map((o) => `${o.key}${o.versionLabel ? ` ${o.versionLabel}` : ""}: ${o.status === "ok" ? o.summary : o.status === "error" ? o.error : "unchanged"}`).join("; ");
      const result = done({ status, items: outcomes.length, inserted: fresh.length, detail, error: errors.length ? errors.map((e) => `${e.key}: ${e.error}`).join("; ") : null });
      recordOutcome(db, source, { status, error: result.error, fetchedAt: now().toISOString(), durationMs: result.durationMs });
      await sendAlerts(db, deps, outcomes.flatMap((o) => (o.alert ? [o.alert] : [])));
      return result;
    }
    if (!adapter.parse) throw new Error(`adapter ${adapter.id} can neither parse nor pull`);

    const response = await http(source.url, {
      etag: source.etag,
      lastModified: source.last_modified,
      ...(adapter.headers ? { headers: adapter.headers } : {}),
    });
    const fetchedAt = now().toISOString();
    if (response.notModified) {
      const result = done({ status: "unchanged" });
      recordOutcome(db, source, { status: "unchanged", fetchedAt, durationMs: result.durationMs });
      return result;
    }

    const sha256 = sha256Hex(response.bytes);
    const parsed = adapter.parse(response.bytes, source, now());
    const existing = db
      .prepare("SELECT id FROM snapshots WHERE source_id = ? AND document_key = ? AND sha256 = ?")
      .get(source.id, parsed.documentKey, sha256) as { id: number } | undefined;

    let snapshotId: number;
    let status: IngestStatus = "ok";
    if (existing) {
      snapshotId = existing.id;
      status = "unchanged";
    } else {
      const blob = putBlob(dataDir, response.bytes);
      const inserted = db
        .prepare(
          `INSERT INTO snapshots (source_id, document_key, sha256, bytes, media_type, blob_path, fetched_at, etag, last_modified)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(source.id, parsed.documentKey, sha256, blob.bytes, response.contentType, blob.relativePath, fetchedAt, response.etag, response.lastModified);
      snapshotId = Number(inserted.lastInsertRowid);
      if (parsed.versionLabel) {
        db.prepare(
          `INSERT INTO documents (source_id, document_key, snapshot_id, version_label, title, published_at, parsed_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        ).run(source.id, parsed.documentKey, snapshotId, parsed.versionLabel, source.name, fetchedAt, fetchedAt);
      }
    }

    const before = status === "unchanged" ? new Set<string>() : new Set((db.prepare("SELECT external_id FROM items WHERE source_id = ?").all(source.id) as { external_id: string }[]).map((r) => r.external_id));
    const counts = status === "unchanged" ? { inserted: 0, updated: 0 } : upsertItems(db, source.id, parsed.items, fetchedAt);
    if (status !== "unchanged") adapter.after?.(db, parsed.items, now());
    const result = done({ status, items: parsed.items.length, snapshotId, ...counts });
    recordOutcome(db, source, { status, etag: response.etag, lastModified: response.lastModified, fetchedAt, durationMs: result.durationMs });
    // New KEV entries are news, except on a source's very first fetch, which loads the whole catalog.
    if (status === "ok" && source.fetch_count > 0 && counts.inserted > 0) {
      const fresh = parsed.items.filter((i) => i.kind === "kev" && !before.has(i.externalId));
      await sendAlerts(
        db,
        deps,
        fresh.map((i) => {
          const s = (i.signals ?? {}) as { dueDate?: string; ransomware?: boolean };
          return { kind: "kev" as const, title: `KEV: ${i.title}`, body: `${s.ransomware ? "Known ransomware use. " : ""}${s.dueDate ? `Due ${s.dueDate}. ` : ""}${i.summary ?? ""}`.slice(0, 600), url: i.url };
        }),
      );
    }
    return result;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const result = done({ status: "error", error: message });
    recordOutcome(db, source, { status: "error", error: message, fetchedAt: now().toISOString(), durationMs: result.durationMs });
    return result;
  }
}
