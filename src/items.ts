import type { DatabaseSync } from "node:sqlite";
import { canonicalUrl, type ParsedItem } from "./adapters/types.ts";

/** Inserts new timeline items and updates changed ones; read and starred flags are never touched. */
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
