import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { curatedStores, notCurated, storePath } from "../src/curated.ts";
import { migrate, openDatabase } from "../src/db.ts";

const root = path.join(import.meta.dirname, "..");

function tsFiles(dir: string): string[] {
  return readdirSync(path.join(root, dir)).flatMap((name) => {
    const rel = `${dir}/${name}`;
    if (statSync(path.join(root, rel)).isDirectory()) return name === "migrations" ? [] : tsFiles(rel);
    return name.endsWith(".ts") ? [rel] : [];
  });
}

/**
 * Top-level array constants of eight or more lines that quote something: the shape a hand-kept
 * list takes. An adapter object or a lookup table written as an object is not caught, on purpose:
 * this is a tripwire for the common case, not a parser.
 */
function longLists(): string[] {
  const found: string[] = [];
  for (const file of tsFiles("src")) {
    const lines = readFileSync(path.join(root, file), "utf8").split("\n");
    for (let i = 0; i < lines.length; i += 1) {
      const m = /^(?:export )?const (\w+)\b[^=]*=\s*(?:\[|new (?:Set|Map)\(\[)\s*$/.exec(lines[i]!);
      if (!m) continue;
      let quoted = 0;
      let j = i + 1;
      for (; j < lines.length && !/^\]/.test(lines[j]!); j += 1) if (/["`]/.test(lines[j]!)) quoted += 1;
      if (quoted >= 8) found.push(`${file}#${m[1]}`);
      i = j;
    }
  }
  return found;
}

describe("the hand-kept ledger (M20.1)", () => {
  it("names only paths and constants that exist", () => {
    for (const store of curatedStores) {
      const { path: p, name } = storePath(store.where);
      expect(existsSync(path.join(root, p)), store.where).toBe(true);
      if (name) expect(readFileSync(path.join(root, p), "utf8"), store.where).toMatch(new RegExp(`\\bconst ${name}\\b`));
      expect(store.reviewed).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      if (store.retiredBy) expect(store.retiredBy).toMatch(/^M20\.\d$/);
    }
  });

  it("has a row for every file kept under data/", () => {
    const covered = curatedStores.map((s) => storePath(s.where).path);
    for (const name of readdirSync(path.join(root, "data"))) {
      if (!/\.ya?ml$/.test(name) && name !== "test-plans") continue;
      expect(covered, `data/${name} has no row in src/curated.ts`).toContain(`data/${name}`);
    }
  });

  it("knows every long hard-coded list in src/, as a row or as something that does not go stale", () => {
    const known = new Set([...curatedStores.map((s) => s.where), ...Object.keys(notCurated)]);
    const unknown = longLists().filter((l) => !known.has(l));
    expect(unknown, "add each to curatedStores, or to notCurated with the reason it is not data").toEqual([]);
  });

  it("checks against sources this instance actually has", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const ids = new Set((db.prepare("SELECT id FROM sources").all() as { id: string }[]).map((r) => r.id));
    db.close();
    for (const store of curatedStores) if (store.checkedBy && "source" in store.checkedBy) expect(ids.has(store.checkedBy.source), store.where).toBe(true);
  });
});
