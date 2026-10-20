#!/usr/bin/env node
/**
 * Rewrites public/scan/SHA256SUMS from the scripts beside it, in the format `sha256sum -c` and
 * `shasum -a 256 -c` read. Run it after editing a script; test/scan-scripts.test.ts fails the
 * check when a recorded sum no longer matches the file, so a stale sum cannot ship.
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const dir = path.join(import.meta.dirname, "..", "public", "scan");
const files = readdirSync(dir)
  .filter((name) => /\.(ps1|sh)$/.test(name))
  .sort();
const lines = files.map((name) => `${createHash("sha256").update(readFileSync(path.join(dir, name))).digest("hex")}  ${name}`);
writeFileSync(path.join(dir, "SHA256SUMS"), lines.join("\n") + "\n");
for (const line of lines) console.log(line);
