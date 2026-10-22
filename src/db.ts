import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

/**
 * The database: open with the pragmas every connection needs, apply the migrations in src/migrations
 * in name order once each, and the two figures /health reports — a table's row count and the file's size.
 */
const migrationsDir = path.join(import.meta.dirname, "migrations");

/** Opens (or creates) the database with the pragmas every connection needs. */
export function openDatabase(file: string): DatabaseSync {
  const db = new DatabaseSync(file);
  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA foreign_keys = ON");
  db.exec("PRAGMA busy_timeout = 5000");
  return db;
}

export interface MigrationResult {
  /** Migration ids applied by this call, in order. Empty when the schema was already current. */
  applied: string[];
  /** Every migration on disk. */
  known: string[];
}

const migrationName = /^\d{4}_[a-z0-9_]+\.sql$/;

/**
 * Applies every migration file in `dir` that is not yet recorded in schema_migrations,
 * each inside its own transaction. Files are plain SQL named NNNN_name.sql and run in
 * name order. A failed migration rolls back and stops the run.
 */
export function migrate(db: DatabaseSync, dir: string = migrationsDir): MigrationResult {
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL)");
  const known = readdirSync(dir).filter((f) => migrationName.test(f)).sort();
  const done = new Set(
    (db.prepare("SELECT id FROM schema_migrations").all() as { id: string }[]).map((r) => r.id),
  );
  const applied: string[] = [];
  for (const file of known) {
    const id = file.replace(/\.sql$/, "");
    if (done.has(id)) continue;
    const sql = readFileSync(path.join(dir, file), "utf8");
    // The write lock is taken up front, and the check repeated under it: two processes starting on
    // the same file (the server and a cron fetch) then apply a new migration once, not twice.
    db.exec("BEGIN IMMEDIATE");
    try {
      if (db.prepare("SELECT 1 FROM schema_migrations WHERE id = ?").get(id)) {
        db.exec("COMMIT");
        continue;
      }
      db.exec(sql);
      db.prepare("INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?)").run(id, new Date().toISOString());
      db.exec("COMMIT");
    } catch (error) {
      db.exec("ROLLBACK");
      throw new Error(`migration ${id} failed: ${(error as Error).message}`, { cause: error });
    }
    applied.push(id);
  }
  return { applied, known: known.map((f) => f.replace(/\.sql$/, "")) };
}

const countable = new Set(["sources", "snapshots", "documents", "requirements", "changes", "items", "triage", "watchlist", "vulns", "vuln_changes", "schema_migrations", "exploits", "msrc_vulns", "ct_certs", "device_readings"]);

/** Row count of one of the known tables. The name is checked against an allowlist, never interpolated from input. */
export function countRows(db: DatabaseSync, table: string, where = ""): number {
  if (!countable.has(table)) throw new Error(`not a countable table: ${table}`);
  const row = db.prepare(`SELECT COUNT(*) AS n FROM ${table} ${where}`).get() as { n: number };
  return row.n;
}

/** Size of the database file as SQLite sees it, in bytes. */
export function databaseBytes(db: DatabaseSync): number {
  const row = db.prepare("SELECT page_count * page_size AS bytes FROM pragma_page_count(), pragma_page_size()").get() as { bytes: number };
  return row.bytes;
}
