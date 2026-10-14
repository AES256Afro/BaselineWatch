// Validates boxpilot/baselinewatch.yaml with BoxPilot's own catalog validator, so the manifest
// that goes into the BoxPilot catalog is checked by the code that will load it.
//
// Needs a BoxPilot checkout: BOXPILOT_DIR, or ../BoxPilot next to this repository. Without one
// the check is skipped with a notice (CI has no BoxPilot checkout); pass --strict to fail instead.
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parse } from "yaml";

const strict = process.argv.includes("--strict");
const manifestPath = path.resolve("boxpilot/baselinewatch.yaml");
const boxpilotDir = path.resolve(process.env.BOXPILOT_DIR ?? path.join("..", "BoxPilot"));
const schemaPath = path.join(boxpilotDir, "server", "catalog", "schema.mjs");

const available = await stat(schemaPath).then(() => true, () => false);
if (!available) {
  const message = `manifest check skipped: no BoxPilot checkout at ${boxpilotDir} (set BOXPILOT_DIR)`;
  if (strict) {
    console.error(message);
    process.exit(1);
  }
  console.log(message);
  process.exit(0);
}

const { validateManifest } = await import(pathToFileURL(schemaPath).href);
const raw = parse(await readFile(manifestPath, "utf8"));
const { manifest, errors } = validateManifest(raw);
if (errors.length > 0) {
  console.error(`manifest has ${errors.length} problem(s):`);
  for (const error of errors) console.error(`  - ${error}`);
  process.exit(1);
}
console.log(`manifest ok: ${manifest.id} ${manifest.image.version} (${manifest.image.reference}), validated by ${path.relative(process.cwd(), schemaPath)}`);
