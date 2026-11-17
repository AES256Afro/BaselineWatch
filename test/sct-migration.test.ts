import { readFileSync } from "node:fs";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import { parsePolicyRules, policyScope } from "../src/adapters/sct.ts";
import type { NormalizedRequirement } from "../src/oscal.ts";
import { buildProfile } from "../src/baselines.ts";
import { getDecision, loadDecisions, saveDecision } from "../src/decisions.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource } from "../src/ingest.ts";
import { loadRequirements, storeDocument } from "../src/register.ts";
import { fixture } from "./helpers.ts";
import { toolkitGpoNames } from "./sct-gpo-names.ts";

/**
 * Migration 0061 re-keys what an instance stored before policyScope dropped the release from a GPO
 * name: the requirements, change rows, triage and the builder's `sct:` decisions. The stored rows
 * are made the way the earlier parser made them, the migration is run, and the result has to be
 * what a fresh parse gives.
 */

const migration = readFileSync(path.join(import.meta.dirname, "../src/migrations/0061_sct_refs_without_release.sql"), "utf8");
const policyRules = new TextDecoder().decode(fixture("sct.PolicyRules"));
const at = "2026-11-01T00:00:00.000Z";

/** The fixture's GPO renamed to a Windows 11 release. */
const rulesFor = (release: string, rewrite: (xml: string) => string = (x) => x) => rewrite(policyRules.replaceAll("Windows Server 2025 v2602", `Windows 11 ${release}`));

/** What the parser before 0061 stored: the release left in the scope. */
function legacy(requirements: NormalizedRequirement[], release: string): NormalizedRequirement[] {
  return requirements.map((r) => {
    const family = (r.family ?? "").replace(/^Windows 11 - /, `Windows 11 ${release} - `);
    const ref = `${family.toLowerCase()}${r.ref.slice((r.family ?? "").length)}`;
    return { ...r, ref, sortKey: ref, family, extra: { ...r.extra, policy: family } };
  });
}

function store(db: DatabaseSync, key: string, version: string, publishedAt: string, requirements: NormalizedRequirement[]): number {
  const snapshot = db
    .prepare("INSERT INTO snapshots (source_id, document_key, sha256, bytes, media_type, blob_path, fetched_at) VALUES ('microsoft-sct', ?, ?, 0, 'application/zip', 'blobs/x', ?)")
    .run(key, `${key}@${version}`, at);
  const stored = storeDocument(db, {
    source: getSource(db, "microsoft-sct")!,
    target: { key, url: `https://example.test/${version}.zip`, versionLabel: version, publishedAt },
    parsed: { title: key, versionLabel: version, publishedAt, requirements },
    snapshotId: Number(snapshot.lastInsertRowid),
    fetchedAt: at,
  });
  return stored.documentId;
}

const refs = (db: DatabaseSync, id: number) => loadRequirements(db, id).map((r) => r.ref).sort();

describe("migration 0061: Microsoft baseline refs without the release", () => {
  it("re-keys requirements, change rows, triage and decisions so they follow the setting", () => {
    const db = openDatabase(":memory:");
    migrate(db);

    // Two Windows 11 baselines as the earlier parser stored them, and a second release of 25H2 with one value changed.
    const v25 = store(db, "baseline:windows-11-v25h2", "2026-02", "2026-02-23T00:00:00.000Z", legacy(parsePolicyRules(rulesFor("25H2")), "25H2"));
    const v25b = store(db, "baseline:windows-11-v25h2", "2026-06", "2026-06-01T00:00:00.000Z", legacy(parsePolicyRules(rulesFor("25H2", (x) => x.replace("<RegData>255</RegData>", "<RegData>91</RegData>"))), "25H2"));
    const v26 = store(db, "baseline:windows-11-v26h2", "v2", "2026-10-08T00:00:00.000Z", legacy(parsePolicyRules(rulesFor("26H2")), "26H2"));
    expect(refs(db, v25b).filter((r) => refs(db, v26).includes(r))).toHaveLength(2); // only the Internet Explorer settings match
    const audit = loadRequirements(db, v25b).find((r) => r.extra.kind === "audit")!;
    expect(audit.ref).toMatch(/^windows 11 25h2 - member server\|audit\|/);
    const changed = (db.prepare("SELECT DISTINCT ref FROM changes WHERE to_document_id = ?").all(v25b) as { ref: string }[]).map((c) => c.ref);
    expect(changed).toHaveLength(1);
    expect(changed[0]).toMatch(/^windows 11 25h2 - member server\|computer\|/);

    // One document where two GPOs' names differ only by release: the first stored keeps the ref.
    const twin = store(db, "baseline:windows-10-version-1809-and-windows-server-2019", "2019", "2019-01-01T00:00:00.000Z", []);
    const insert = db.prepare("INSERT INTO requirements (document_id, ref, family, label, title, statement, sort_key, extra_json) VALUES (?, ?, ?, 'x', 'x', ?, ?, ?)");
    for (const [scope, value] of [["Windows 10 1809 - Computer", "1"], ["Windows 10 1903 - Computer", "2"]] as const) {
      const ref = `${scope.toLowerCase()}|computer|software\\x\\y`;
      insert.run(twin, ref, scope, value, ref, JSON.stringify({ kind: "registry", policy: scope }));
    }

    // Triage on a setting, and the owner's decisions: one on a setting in 25H2 only, and two on the
    // audit setting in 25H2 and 26H2 that now name the same item.
    db.prepare("INSERT INTO triage (subject_kind, subject_id, subject_key, state, created_at, updated_at) VALUES ('control', ?, ?, 'reviewing', ?, ?)").run(v25b, audit.ref, at, at);
    const registry = loadRequirements(db, v25b).find((r) => r.extra.kind === "registry" && r.ref.startsWith("windows 11 25h2"))!;
    saveDecision(db, "windows", `sct:${registry.ref}`, { decision: "exclude", reason: "Kiosks only" }, new Date("2026-10-01T00:00:00Z"));
    saveDecision(db, "windows", `sct:${audit.ref}`, { decision: "exclude", reason: "Older" }, new Date("2026-10-02T00:00:00Z"));
    saveDecision(db, "windows", `sct:${audit.ref.replace("25h2", "26h2")}`, { decision: "modify", value: "Success", reason: "Newer" }, new Date("2026-10-03T00:00:00Z"));

    db.exec("BEGIN IMMEDIATE");
    db.exec(migration);
    db.exec("COMMIT");

    // Every stored row is what a fresh parse gives now.
    for (const [id, release] of [[v25, "25H2"], [v26, "26H2"]] as const) {
      const fresh = parsePolicyRules(rulesFor(release));
      const stored = loadRequirements(db, id);
      expect(stored.map((r) => [r.ref, r.sortKey, r.family, r.extra.policy]).sort()).toEqual(fresh.map((r) => [r.ref, r.sortKey, r.family, r.extra.policy]).sort());
    }
    expect(refs(db, v25b)).toEqual(refs(db, v26));
    const newAudit = audit.ref.replace("windows 11 25h2 - ", "windows 11 - ");
    expect((db.prepare("SELECT DISTINCT ref FROM changes WHERE to_document_id = ?").all(v25b) as { ref: string }[]).map((c) => c.ref)).toEqual([changed[0]!.replace("windows 11 25h2 - ", "windows 11 - ")]);
    expect(db.prepare("SELECT subject_key FROM triage WHERE subject_id = ?").get(v25b)).toEqual({ subject_key: newAudit });

    // The colliding pair: one moves, the other keeps its ref; nothing is lost.
    expect(refs(db, twin)).toEqual(["windows 10 - computer|computer|software\\x\\y", "windows 10 1903 - computer|computer|software\\x\\y"]);

    // Decisions: the 25H2-only one moves; of the two on the audit setting the newer moves and the older keeps its id.
    const decisions = loadDecisions(db, "windows");
    expect(decisions.get(`sct:${registry.ref.replace("windows 11 25h2 - ", "windows 11 - ")}`)?.reason).toBe("Kiosks only");
    expect(decisions.get(`sct:${newAudit}`)).toMatchObject({ decision: "modify", value: "Success", reason: "Newer" });
    expect(getDecision(db, "windows", `sct:${audit.ref}`)?.reason).toBe("Older");
    expect(decisions.size).toBe(3);

    // The builder: the decision shows on both releases, and 25H2 against 26H2 differs by nothing.
    for (const sct of [`baseline:windows-11-v25h2@${v25b}`, `baseline:windows-11-v26h2@${v26}`]) {
      const profile = buildProfile(db, { platform: "windows", sct });
      const item = profile.items.find((i) => i.id === `sct:${newAudit}`);
      expect(item?.decision?.decision).toBe("modify");
      const excluded = profile.items.find((i) => i.id === `sct:${registry.ref.replace("windows 11 25h2 - ", "windows 11 - ")}`);
      expect(excluded?.included).toBe(false);
    }
    const next = buildProfile(db, { platform: "windows", sct: `baseline:windows-11-v25h2@${v25b}` }).next.find((c) => c.component === "sct")!;
    expect(next.next.key).toBe("baseline:windows-11-v26h2");
    expect([next.added.length, next.removed.length, next.changed.length]).toEqual([0, 0, 1]); // the value 26H2 still has at 255

    // A second run changes nothing.
    const before = JSON.stringify([db.prepare("SELECT * FROM requirements ORDER BY id").all(), db.prepare("SELECT * FROM baseline_decisions ORDER BY item_id").all(), db.prepare("SELECT * FROM changes ORDER BY id").all()]);
    db.exec("BEGIN IMMEDIATE");
    db.exec(migration);
    db.exec("COMMIT");
    expect(JSON.stringify([db.prepare("SELECT * FROM requirements ORDER BY id").all(), db.prepare("SELECT * FROM baseline_decisions ORDER BY item_id").all(), db.prepare("SELECT * FROM changes ORDER BY id").all()])).toBe(before);
    db.close();
  });

  it("maps every GPO name the toolkit ships, as the earlier parser stored it, to what policyScope gives now", () => {
    // The migration's name mapping on its own: the statements that fill sct_scope_map from sct_scope_names.
    const start = migration.indexOf("CREATE TEMP TABLE sct_scope_map");
    const end = migration.indexOf("-- The requirements whose ref changes");
    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    /** What the parser before 0061 stored: "MSFT" and a "v2602" token dropped, the release left in. */
    const earlier = (name: string) => name.replace(/^MSFT\s+/i, "").replace(/\s+v\d{2,}[A-Za-z0-9]*\b/i, "").replace(/\s+/g, " ").trim();
    const names = [...toolkitGpoNames.map(([name]) => name), "MSFT Windows 11 25H2 - Version 2 Settings 1809"];
    const db = openDatabase(":memory:");
    db.exec("CREATE TEMP TABLE sct_scope_names (old TEXT PRIMARY KEY)");
    const add = db.prepare("INSERT OR IGNORE INTO sct_scope_names (old) VALUES (?)");
    // The family is stored as published, the scope inside a ref in lower case: both are read.
    for (const name of names) {
      add.run(earlier(name));
      add.run(earlier(name).toLowerCase());
    }
    db.exec(migration.slice(start, end));
    const mapped = new Map((db.prepare("SELECT old, new FROM sct_scope_map").all() as { old: string; new: string }[]).map((r) => [r.old, r.new]));
    for (const name of names) {
      const stored = earlier(name);
      expect(mapped.get(stored) ?? stored, name).toBe(policyScope(name));
      expect(mapped.get(stored.toLowerCase()) ?? stored.toLowerCase(), `${name} (lower case)`).toBe(policyScope(name).toLowerCase());
    }
    db.close();
  });
});
