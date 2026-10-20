// Command line entry:
//   node src/cli.ts fetch <source-id|all|due>     the same ingestion the scheduler runs, then exit
//   node src/cli.ts backfill <source-id>          load a standard's published history, oldest first, then its current documents
//   node src/cli.ts relink <source-id|all>        put a standard's versions back in publication order and re-diff the ones that were linked wrong
//   node src/cli.ts images <count|all>            fetch og:image for existing news articles that have none, newest first (new articles get theirs at ingest)
//   node src/cli.ts netscan <run|due>             the network scan (M12.3): run now, or only when due and turned on, then exit
import { mkdirSync } from "node:fs";
import path from "node:path";
import { adapterFor } from "./adapters/index.ts";
import { loadConfig } from "./config.ts";
import { migrate, openDatabase } from "./db.ts";
import { httpGet } from "./http.ts";
import { getSource, ingestDocumentTarget, ingestSource, listSources } from "./ingest.ts";
import { backfillImages } from "./images.ts";
import { maybeRunNetworkScan, netScanEnabled, runNetworkScan } from "./netscan.ts";
import { parseNotifyUrl } from "./notify.ts";
import { relinkSource } from "./register.ts";
import { dueSources, formatResult } from "./scheduler.ts";

const [command, target] = process.argv.slice(2);

if ((command !== "fetch" && command !== "backfill" && command !== "relink" && command !== "images" && command !== "netscan") || !target) {
  console.error(
    "usage: node src/cli.ts fetch <source-id|all|due>\n       node src/cli.ts backfill <source-id>\n       node src/cli.ts relink <source-id|all>\n       node src/cli.ts images <count|all>\n       node src/cli.ts netscan <run|due>",
  );
  process.exit(2);
}

const config = loadConfig();
mkdirSync(config.dataDir, { recursive: true });
const db = openDatabase(path.join(config.dataDir, "baselinewatch.db"));
migrate(db);

let failures = 0;
const deps = { settings: { nvdApiKey: config.nvdApiKey, nvdBackfillDays: config.nvdBackfillDays, newsImages: config.newsImages }, log: (line: string) => console.log(line) };

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
} else if (command === "images") {
  if (!config.newsImages) {
    console.error("article images are off on this instance (BW_NEWS_IMAGES)");
    process.exit(1);
  }
  const limit = target === "all" ? 10_000 : Number(target);
  if (!Number.isInteger(limit) || limit <= 0) {
    console.error(`images takes a count or "all", got "${target}"`);
    process.exit(2);
  }
  const out = await backfillImages(db, config.dataDir, { http: httpGet, log: (line: string) => console.log(line) }, { limit });
  console.log(`[images] examined ${out.examined} article(s) without an image, stored ${out.stored}`);
} else if (command === "netscan") {
  if (target !== "run" && target !== "due") {
    console.error(`netscan takes "run" or "due", got "${target}"`);
    process.exit(2);
  }
  if (!netScanEnabled(db)) {
    console.error("the network scan is off; the owner turns it on at /scan/network (it sends packets on your network)");
    process.exit(target === "due" ? 0 : 1);
  }
  const options = { transport: parseNotifyUrl(config.notifyUrl), baseUrl: config.baseUrl, log: (line: string) => console.log(line) };
  if (target === "run") await runNetworkScan(db, options);
  else if (!(await maybeRunNetworkScan(db, { ...options, timeZone: config.timeZone }))) console.log("[netscan] not due: one already ran today");
} else if (command === "relink") {
  const sources = target === "all" ? listSources(db) : [getSource(db, target)].filter((s) => s !== null);
  if (sources.length === 0) {
    console.error(`no such source: ${target}`);
    process.exit(1);
  }
  for (const source of sources) {
    const out = relinkSource(db, source, new Date().toISOString());
    if (out.keys) console.log(`[relink] ${source.id.padEnd(18)} ${out.keys} document key(s), ${out.relinked} relinked`);
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
