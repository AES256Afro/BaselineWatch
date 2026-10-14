import type { DatabaseSync } from "node:sqlite";
import { adapterFor } from "./adapters/index.ts";
import { canonicalUrl, type ParsedItem, type PullSettings, type SourceRow } from "./adapters/types.ts";
import { putBlob, sha256Hex } from "./blobs.ts";
import { httpGet, type HttpGet } from "./http.ts";

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

  try {
    if (adapter.pull) {
      const outcome = await adapter.pull({ db, dataDir, source, http, now, settings: deps.settings ?? defaultPullSettings, log });
      const result = done({ status: "ok", items: outcome.items, inserted: outcome.inserted, updated: outcome.updated, detail: outcome.detail ?? null });
      recordOutcome(db, source, { status: "ok", fetchedAt: now().toISOString(), durationMs: result.durationMs });
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

    const counts = status === "unchanged" ? { inserted: 0, updated: 0 } : upsertItems(db, source.id, parsed.items, fetchedAt);
    if (status !== "unchanged") adapter.after?.(db, parsed.items, now());
    const result = done({ status, items: parsed.items.length, snapshotId, ...counts });
    recordOutcome(db, source, { status, etag: response.etag, lastModified: response.lastModified, fetchedAt, durationMs: result.durationMs });
    return result;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const result = done({ status: "error", error: message });
    recordOutcome(db, source, { status: "error", error: message, fetchedAt: now().toISOString(), durationMs: result.durationMs });
    return result;
  }
}
