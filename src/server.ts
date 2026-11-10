import { httpGet } from "./http.ts";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { createApp } from "./app.ts";
import { loadConfig } from "./config.ts";
import { migrate, openDatabase } from "./db.ts";
import { maybeRunHousekeeping } from "./housekeeping.ts";
import { listSources, pullSettings } from "./ingest.ts";
import { maybeRunExposureScan } from "./exposure.ts";
import { maybeRunNetworkScan } from "./netscan.ts";
import { parseNotifyUrl } from "./notify.ts";
import { relinkSource } from "./register.ts";
import { recomputePlatforms } from "./vulns.ts";
import { startScheduler, type Scheduler } from "./scheduler.ts";
import { productName, productVersion } from "./version.ts";
import { counted } from "./html.ts";

/**
 * Start: read the config, open and migrate the database, put every standard's versions in
 * publication order, fill what a migration left empty, listen, and run the scheduler unless told not to.
 */
const config = loadConfig();
mkdirSync(config.dataDir, { recursive: true });

const db = openDatabase(path.join(config.dataDir, "baselinewatch.db"));
const migration = migrate(db);
if (migration.applied.length > 0) {
  console.log(`[db] applied ${counted(migration.applied.length, "migration")}: ${migration.applied.join(", ")}`);
}
// Every standard's versions in publication order before anything is served: a chain linked
// wrong by an older version is re-diffed once here, and a chain already in order costs a query.
for (const source of listSources(db)) {
  const out = relinkSource(db, source, new Date().toISOString());
  if (out.relinked > 0) console.log(`[register] ${source.id}: ${counted(out.relinked, "version")} relinked into publication order`);
}
// Migration 0032 added the platform a CVE affects; rows that predate it are filled once here.
const platformed = recomputePlatforms(db);
if (platformed > 0) console.log(`[vulns] read the platform of ${counted(platformed, "CVE")}`);
if (!config.adminPassword) {
  console.log("[auth] no BW_ADMIN_PASSWORD set: single-user mode, anyone who reaches the page can mark items and fetch sources");
}

const app = createApp({ config, db, migrations: migration.known, startedAt: Date.now() });
// Express 5 hands a listen error to this callback rather than throwing it; unread, a port that
// is taken was reported as "listening" and the process then exited 0 with nothing served.
const server = app.listen(config.port, config.host, (error?: Error) => {
  if (error) {
    console.error(`[server] could not listen on ${config.host}:${config.port}: ${error.message}`);
    process.exit(1);
  }
  console.log(`${productName} ${productVersion} listening on http://${config.host}:${config.port} (data: ${path.resolve(config.dataDir)})`);
});

// The last line of defence: a fault that escapes every handler is logged with its stack before
// the process goes, so the container's restart is not the only trace it leaves. A rejection
// nobody awaited is logged and the process stays up; the scheduler retries on its next tick.
process.on("uncaughtException", (error) => {
  console.error("[server] uncaught exception, exiting:", error);
  process.exit(1);
});
process.on("unhandledRejection", (reason) => {
  console.error("[server] unhandled rejection:", reason);
});

let scheduler: Scheduler | null = null;
if (config.scheduler) {
  scheduler = startScheduler({
    db,
    dataDir: config.dataDir,
    settings: pullSettings(config),
    transport: parseNotifyUrl(config.notifyUrl),
    baseUrl: config.baseUrl,
    digest: { period: config.digest, hour: config.digestHour, timeZone: config.timeZone },
    // The LAN scan (M12.3) runs itself daily once the owner has turned it on at /scan/network.
    network: async () => {
      const daily = { timeZone: config.timeZone, baseUrl: config.baseUrl, transport: parseNotifyUrl(config.notifyUrl), log: (line: string) => console.log(line) };
      const network = await maybeRunNetworkScan(db, daily);
      const exposure = await maybeRunExposureScan(db, { ...daily, http: httpGet });
      return network || exposure;
    },
    // The weekly pass (M13): what is past its keep window goes, the store loses the blobs nothing
    // points at any more, and the file is rewritten when it has gone loose.
    housekeeping: () => maybeRunHousekeeping(db, config.dataDir, { log: (line) => console.log(line) }),
  });
  if (config.notifyUrl && !parseNotifyUrl(config.notifyUrl)) {
    console.log("[notify] BW_NOTIFY_URL is not an ntfy://, gotify:// or http(s):// address; alerts will be logged as unconfigured");
  }
  setTimeout(() => {
    void scheduler?.runOnce().catch((error: unknown) => console.log(`[scheduler] first run failed: ${error instanceof Error ? error.message : String(error)}`));
  }, 10_000).unref();
} else {
  console.log("[scheduler] off (BW_SCHEDULER=false); run `npm run fetch -- due` from cron instead");
}

function shutdown(signal: string): void {
  console.log(`[server] ${signal}, closing`);
  scheduler?.stop();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
