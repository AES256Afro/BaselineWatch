import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { countRows, databaseBytes, migrate, openDatabase } from "../src/db.ts";

const temporary: string[] = [];
afterEach(() => {
  for (const dir of temporary.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function scratch(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "bw-db-"));
  temporary.push(dir);
  return dir;
}

describe("migrate", () => {
  it("applies every migration once and is idempotent", () => {
    const db = openDatabase(path.join(scratch(), "t.db"));
    const first = migrate(db);
    expect(first.known.length).toBeGreaterThanOrEqual(2);
    expect(first.applied).toEqual(first.known);
    expect(first.applied[0]).toBe("0001_init");

    const second = migrate(db);
    expect(second.applied).toEqual([]);
    expect(countRows(db, "schema_migrations")).toBe(first.known.length);
    db.close();
  });

  it("creates the pipeline tables and seeds the source register", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all() as { name: string }[]).map((r) => r.name);
    for (const expected of ["sources", "snapshots", "documents", "requirements", "baseline_settings", "changes", "explanations", "items", "triage", "watchlist", "app_settings"]) {
      expect(tables).toContain(expected);
    }
    expect(countRows(db, "sources")).toBeGreaterThanOrEqual(25);
    expect(countRows(db, "sources", "WHERE group_name = 'standards'")).toBeGreaterThanOrEqual(7);
    const kev = db.prepare("SELECT url, schedule FROM sources WHERE id = ?").get("cisa-kev") as { url: string; schedule: string };
    expect(kev.url).toMatch(/known_exploited_vulnerabilities\.json$/);
    expect(kev.schedule).toBe("hourly");
    // Reddit refuses the JSON listing to non-browser clients (403); every subreddit must point
    // at the Atom feed, the lesson of migrations 0004 and 0020.
    const reddits = db.prepare("SELECT id, url, format FROM sources WHERE id LIKE 'reddit-%'").all() as { id: string; url: string; format: string }[];
    expect(reddits.length).toBeGreaterThanOrEqual(6);
    for (const r of reddits) {
      expect(r.url, r.id).toMatch(/\/new\.rss\?limit=\d+$/);
      expect(r.format, r.id).toBe("atom");
    }
    db.close();
  });

  it("enforces foreign keys and check constraints", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    expect(() =>
      db.prepare("INSERT INTO snapshots (source_id, document_key, sha256, bytes, blob_path, fetched_at) VALUES ('no-such-source', 'k', 'x', 1, 'p', 'now')").run(),
    ).toThrow(/FOREIGN KEY/);
    expect(() => db.prepare("INSERT INTO triage (subject_kind, subject_id, state, created_at, updated_at) VALUES ('item', 1, 'bogus', 'now', 'now')").run()).toThrow(/CHECK/);
    db.close();
  });

  it("rejects a count on an unknown table and reports a size", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    expect(() => countRows(db, "sqlite_master")).toThrow(/not a countable table/);
    expect(databaseBytes(db)).toBeGreaterThan(0);
    db.close();
  });
});
