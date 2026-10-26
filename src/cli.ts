// Command line entry:
//   node src/cli.ts fetch <source-id|all|due>     the same ingestion the scheduler runs, then exit
//   node src/cli.ts backfill <source-id>          load a standard's published history, oldest first, then its current documents; a stream (nvd-cves) forgets its cursor and pulls its window again
//   node src/cli.ts relink <source-id|all>        put a standard's versions back in publication order and re-diff the ones that were linked wrong
//   node src/cli.ts images <count|all>            fetch og:image for existing news articles that have none, newest first (new articles get theirs at ingest)
//   node src/cli.ts netscan <run|due>             the network scan (M12.3): run now, or only when due and turned on, then exit
//   node src/cli.ts rehearsal <today|date> [note] record that the backup was restored and checked (docs/DEPLOY.md)
import { mkdirSync } from "node:fs";
import path from "node:path";
import { adapterFor } from "./adapters/index.ts";
import { loadConfig } from "./config.ts";
import { migrate, openDatabase } from "./db.ts";
import { httpGet } from "./http.ts";
import { getSource, ingestDocumentTarget, ingestSource, listSources } from "./ingest.ts";
import { backfillImages } from "./images.ts";
import { maybeRunNetworkScan, netScanEnabled, runNetworkScan } from "./netscan.ts";
import { lastRehearsal, recordRehearsal } from "./housekeeping.ts";
import { parseNotifyUrl } from "./notify.ts";
import { relinkSource } from "./register.ts";
import { dueSources, formatResult } from "./scheduler.ts";

const [command, target] = process.argv.slice(2);

if ((command !== "fetch" && command !== "backfill" && command !== "relink" && command !== "images" && command !== "netscan" && command !== "rehearsal") || !target) {
  console.error(
    "usage: node src/cli.ts fetch <source-id|all|due>\n       node src/cli.ts backfill <source-id>\n       node src/cli.ts relink <source-id|all>\n       node src/cli.ts images <count|all>\n       node src/cli.ts netscan <run|due>\n       node src/cli.ts rehearsal <today|YYYY-MM-DD> [note]",
  );
  process.exit(2);
}

const config = loadConfig();
mkdirSync(config.dataDir, { recursive: true });
const db = openDatabase(path.join(config.dataDir, "baselinewatch.db"));
migrate(db);

let failures = 0;
const deps = { settings: { nvdApiKey: config.nvdApiKey, nvdBackfillDays: config.nvdBackfillDays, newsImages: config.newsImages }, log: (line: string) => console.log(line) };

if (command === "rehearsal") {
  // The restore itself happens on the box; this records that it was done, so the digest stops asking.
  const when = target === "today" ? new Date() : new Date(target);
  if (Number.isNaN(when.getTime())) {
    console.error(`rehearsal takes "today" or a date, got "${target}"`);
    process.exit(2);
  }
  const note = process.argv.slice(4).join(" ") || null;
  const previous = lastRehearsal(db);
  const recorded = recordRehearsal(db, when.toISOString(), note);
  console.log(`[rehearsal] recorded ${recorded.at.slice(0, 10)}${recorded.note ? `: ${recorded.note}` : ""}${previous ? ` (previous: ${previous.at.slice(0, 10)})` : " (the first one)"}`);
} else if (command === "backfill") {
  const source = getSource(db, target);
  const adapter = source ? adapterFor(source) : null;
  if (!source || !adapter || (!adapter.history && !adapter.rewind)) {
    console.error(source ? `${target} has no published history to load` : `no such source: ${target}`);
    process.exit(1);
  }
  if (adapter.rewind) {
    // A stream has no history to load: forget where the last pull left off and pull the window
    // again, so every record in it is normalised afresh (how vuln_cpe_matches is filled for CVEs
    // that predate migration 0045). A first pull raises no alerts, and neither does this.
    adapter.rewind(db);
    const result = await ingestSource(db, config.dataDir, source, deps);
    console.log(formatResult(result));
    if (result.status === "error") failures += 1;
  } else {
    const targets = [...(adapter.history ? adapter.history(source) : []), ...(adapter.documents ? await adapter.documents(source, { db, http: httpGet, now: () => new Date() }) : [])];
    for (const t of targets) {
      const outcome = await ingestDocumentTarget(db, config.dataDir, source, adapter, t, { http: httpGet, now: () => new Date() });
      console.log(`[backfill] ${source.id} ${t.key.padEnd(18)} ${(outcome.versionLabel ?? "").padEnd(8)} ${outcome.status.padEnd(9)} ${outcome.summary ?? outcome.error ?? ""}`);
      if (outcome.status === "error") failures += 1;
    }
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
