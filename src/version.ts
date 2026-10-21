import { readFileSync } from "node:fs";
import path from "node:path";

/**
 * The product's name, version and repository. package.json is the only source of the version.
 */
const pkg = JSON.parse(
  readFileSync(path.join(import.meta.dirname, "..", "package.json"), "utf8"),
) as { name: string; version: string };

/** The one source of the version is package.json. */
export const productVersion: string = pkg.version;
export const productName = "BaselineWatch";
export const repositoryUrl = "https://github.com/AES256Afro/BaselineWatch";
