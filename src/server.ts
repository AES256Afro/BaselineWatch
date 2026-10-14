import { mkdirSync } from "node:fs";
import path from "node:path";
import { createApp } from "./app.ts";
import { loadConfig } from "./config.ts";
import { migrate, openDatabase } from "./db.ts";
import { productName, productVersion } from "./version.ts";

const config = loadConfig();
mkdirSync(config.dataDir, { recursive: true });

const db = openDatabase(path.join(config.dataDir, "baselinewatch.db"));
const migration = migrate(db);
if (migration.applied.length > 0) {
  console.log(`[db] applied ${migration.applied.length} migration(s): ${migration.applied.join(", ")}`);
}

const app = createApp({ config, db, migrations: migration.known, startedAt: Date.now() });
const server = app.listen(config.port, config.host, () => {
  console.log(`${productName} ${productVersion} listening on http://${config.host}:${config.port} (data: ${path.resolve(config.dataDir)})`);
});

function shutdown(signal: string): void {
  console.log(`[server] ${signal}, closing`);
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
