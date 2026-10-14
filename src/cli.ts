// Command line entry: `node src/cli.ts fetch <source-id|all|due>`.
// Runs the same ingestion the scheduler runs, then exits; useful on a server and in a shell.
import { mkdirSync } from "node:fs";
import path from "node:path";
import { loadConfig } from "./config.ts";
import { migrate, openDatabase } from "./db.ts";
import { getSource, ingestSource, listSources } from "./ingest.ts";
import { dueSources, formatResult } from "./scheduler.ts";

const [command, target] = process.argv.slice(2);

if (command !== "fetch" || !target) {
  console.error("usage: node src/cli.ts fetch <source-id|all|due>");
  process.exit(2);
}

const config = loadConfig();
mkdirSync(config.dataDir, { recursive: true });
const db = openDatabase(path.join(config.dataDir, "baselinewatch.db"));
migrate(db);

const sources =
  target === "all" ? listSources(db, { enabledOnly: true }) : target === "due" ? dueSources(db, new Date()) : [getSource(db, target)].filter((s) => s !== null);

if (sources.length === 0) {
  console.error(target === "due" ? "nothing is due" : `no such source: ${target}`);
  process.exit(target === "due" ? 0 : 1);
}

let failures = 0;
for (const source of sources) {
  const result = await ingestSource(db, config.dataDir, source);
  console.log(formatResult(result));
  if (result.status === "error") failures += 1;
}
db.close();
// Let the process end on its own once the HTTP client's sockets have closed. Calling
// process.exit() here trips a libuv assertion on Windows while keep-alive sockets are still closing.
process.exitCode = failures > 0 ? 1 : 0;
