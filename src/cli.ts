// Command line entry:
//   node src/cli.ts fetch <source-id|all|due>     the same ingestion the scheduler runs, then exit
//   node src/cli.ts backfill <source-id>          load a standard's published history, oldest first, then its current documents
import { mkdirSync } from "node:fs";
import path from "node:path";
import { adapterFor } from "./adapters/index.ts";
import { loadConfig } from "./config.ts";
import { migrate, openDatabase } from "./db.ts";
import { httpGet } from "./http.ts";
import { getSource, ingestDocumentTarget, ingestSource, listSources } from "./ingest.ts";
import { dueSources, formatResult } from "./scheduler.ts";

const [command, target] = process.argv.slice(2);

if ((command !== "fetch" && command !== "backfill") || !target) {
  console.error("usage: node src/cli.ts fetch <source-id|all|due>\n       node src/cli.ts backfill <source-id>");
  process.exit(2);
}

const config = loadConfig();
mkdirSync(config.dataDir, { recursive: true });
const db = openDatabase(path.join(config.dataDir, "baselinewatch.db"));
migrate(db);

let failures = 0;
const deps = { settings: { nvdApiKey: config.nvdApiKey, nvdBackfillDays: config.nvdBackfillDays }, log: (line: string) => console.log(line) };

if (command === "backfill") {
  const source = getSource(db, target);
  const adapter = source ? adapterFor(source) : null;
  if (!source || !adapter?.history) {
    console.error(source ? `${target} has no published history to load` : `no such source: ${target}`);
    process.exit(1);
  }
  const targets = [...adapter.history(source), ...(adapter.documents ? await adapter.documents(source, { db, http: httpGet, now: () => new Date() }) : [])];
  for (const t of targets) {
    const outcome = await ingestDocumentTarget(db, config.dataDir, source, adapter, t, { http: httpGet, now: () => new Date() });
    console.log(`[backfill] ${source.id} ${t.key.padEnd(18)} ${(outcome.versionLabel ?? "").padEnd(8)} ${outcome.status.padEnd(9)} ${outcome.summary ?? outcome.error ?? ""}`);
    if (outcome.status === "error") failures += 1;
  }
} else {
  const sources =
    target === "all" ? listSources(db, { enabledOnly: true }) : target === "due" ? dueSources(db, new Date()) : [getSource(db, target)].filter((s) => s !== null);
  if (sources.length === 0) {
    console.error(target === "due" ? "nothing is due" : `no such source: ${target}`);
    process.exit(target === "due" ? 0 : 1);
  }
  for (const source of sources) {
    const result = await ingestSource(db, config.dataDir, source, deps);
    console.log(formatResult(result));
    if (result.status === "error") failures += 1;
  }
}

db.close();
// Let the process end on its own once the HTTP client's sockets have closed. Calling
// process.exit() here trips a libuv assertion on Windows while keep-alive sockets are still closing.
process.exitCode = failures > 0 ? 1 : 0;
