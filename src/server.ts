import { mkdirSync } from "node:fs";
import path from "node:path";
import { createApp, pullSettings } from "./app.ts";
import { loadConfig } from "./config.ts";
import { migrate, openDatabase } from "./db.ts";
import { parseNotifyUrl } from "./notify.ts";
import { startScheduler, type Scheduler } from "./scheduler.ts";
import { productName, productVersion } from "./version.ts";

const config = loadConfig();
mkdirSync(config.dataDir, { recursive: true });

const db = openDatabase(path.join(config.dataDir, "baselinewatch.db"));
const migration = migrate(db);
if (migration.applied.length > 0) {
  console.log(`[db] applied ${migration.applied.length} migration(s): ${migration.applied.join(", ")}`);
}
if (!config.adminPassword) {
  console.log("[auth] no BW_ADMIN_PASSWORD set: single-user mode, anyone who reaches the page can mark items and fetch sources");
}

const app = createApp({ config, db, migrations: migration.known, startedAt: Date.now() });
const server = app.listen(config.port, config.host, () => {
  console.log(`${productName} ${productVersion} listening on http://${config.host}:${config.port} (data: ${path.resolve(config.dataDir)})`);
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
  });
  if (config.notifyUrl && !parseNotifyUrl(config.notifyUrl)) {
    console.log("[notify] BW_NOTIFY_URL is not an ntfy://, gotify:// or http(s):// address; alerts will be logged as unconfigured");
  }
  setTimeout(() => {
    void scheduler?.runOnce();
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
