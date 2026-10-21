// The release, as one command, so a version can never again be tagged without being written down
// (0.36.0, 0.36.1 and 0.37.0 were, and the changelog stopped describing what runs).
//
//   node scripts/release.ts 0.38.0          bump package.json, the lock and the catalog manifest,
//                                            and open the CHANGELOG entry from the commits since
//                                            the last tag, for you to write up as prose
//   node scripts/release.ts --check         the invariant, run by `npm run check` and by CI:
//                                            package.json = lock = manifest = the newest entry,
//                                            and that entry has been written, not left as a draft
//   node scripts/release.ts --check --tag v0.38.0    the same, plus: the tag names that version
//   node scripts/release.ts --verify https://cybercard.net
//                                            after the deploy: /health runs the version we released
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

/** The newest `## x.y.z — date` entry of a changelog. */
export interface ChangelogEntry {
  version: string;
  date: string;
  body: string;
}

/** Every place this repository writes its version. */
export interface Versions {
  package: string | null;
  lock: string | null;
  lockRoot: string | null;
  manifestVersion: string | null;
  manifestReference: string | null;
  entry: ChangelogEntry | null;
}

/** Why a request failed, in the words a person needs: the system's code, else the message. */
function reason(error: unknown): string {
  const cause = (error as { cause?: { code?: string } }).cause;
  return cause?.code ?? (error instanceof Error ? error.message : String(error));
}

export const repoRoot = path.resolve(path.join(import.meta.dirname, ".."));

/** The marker the draft leaves behind; the check fails while it is still there. */
export const draftMarker = "TODO: rewrite the lines above as prose";

const semver = /^\d+\.\d+\.\d+$/;

/** -1, 0 or 1, comparing two x.y.z strings the way a release goes. */
export function compareVersions(a: string, b: string): number {
  const left = a.split(".").map(Number);
  const right = b.split(".").map(Number);
  for (let i = 0; i < 3; i += 1) {
    if (left[i] !== right[i]) return (left[i] ?? 0) < (right[i] ?? 0) ? -1 : 1;
  }
  return 0;
}

/** The newest entry of a changelog: its version, its date and its body. */
export function newestEntry(changelog: string): ChangelogEntry | null {
  const match = /^## (\d+\.\d+\.\d+) — (\d{4}-\d{2}-\d{2})\s*$/m.exec(changelog);
  if (!match) return null;
  const rest = changelog.slice(match.index + match[0].length);
  const next = /^## \d+\.\d+\.\d+ /m.exec(rest);
  return { version: match[1] ?? "", date: match[2] ?? "", body: (next ? rest.slice(0, next.index) : rest).trim() };
}

/** Every place a version is written, read from the working tree. */
export function readVersions(root: string = repoRoot): Versions {
  const pkg = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")) as { version?: string };
  const lock = JSON.parse(readFileSync(path.join(root, "package-lock.json"), "utf8")) as { version?: string; packages?: Record<string, { version?: string }> };
  const manifest = readFileSync(path.join(root, "boxpilot/baselinewatch.yaml"), "utf8");
  const changelog = readFileSync(path.join(root, "CHANGELOG.md"), "utf8");
  return {
    package: pkg.version ?? null,
    lock: lock.version ?? null,
    lockRoot: lock.packages?.[""]?.version ?? null,
    manifestVersion: /^\s+version:\s*"([^"]+)"\s*$/m.exec(manifest)?.[1] ?? null,
    manifestReference: /reference:\s*\S+:(\S+)\s*$/m.exec(manifest)?.[1] ?? null,
    entry: newestEntry(changelog),
  };
}

/**
 * What disagrees. Empty means the tree is releasable: one version everywhere, and the newest
 * changelog entry is that version, written rather than left as the draft the bump wrote.
 */
export function consistencyProblems(versions: Versions, options: { tag?: string } = {}): string[] {
  const problems: string[] = [];
  const v = versions.package;
  if (!v || !semver.test(v)) problems.push(`package.json version is not x.y.z: ${v}`);
  if (versions.lock !== v) problems.push(`package-lock.json version is ${versions.lock}, package.json is ${v}`);
  if (versions.lockRoot !== v) problems.push(`package-lock.json packages[""].version is ${versions.lockRoot}, package.json is ${v}`);
  if (versions.manifestVersion !== v) problems.push(`the catalog manifest's image.version is ${versions.manifestVersion}, package.json is ${v}`);
  if (versions.manifestReference !== v) problems.push(`the catalog manifest's image.reference is tagged ${versions.manifestReference}, package.json is ${v}`);
  if (!versions.entry) problems.push("CHANGELOG.md has no `## x.y.z — YYYY-MM-DD` entry");
  else if (versions.entry.version !== v) problems.push(`the newest CHANGELOG entry is ${versions.entry.version}, package.json is ${v}: write the entry before the tag`);
  else if (versions.entry.body.includes(draftMarker)) problems.push(`the ${v} CHANGELOG entry is still the draft: write it up and remove the "${draftMarker}" line`);
  else if (versions.entry.body.length < 40) problems.push(`the ${v} CHANGELOG entry says almost nothing (${versions.entry.body.length} characters)`);
  if (options.tag) {
    const tagged = options.tag.replace(/^v/, "");
    if (tagged !== v) problems.push(`the tag is ${options.tag} but this tree is ${v}: tag the release commit, not another`);
  }
  return problems;
}

function git(args: string[], root: string = repoRoot): string {
  return execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();
}

/** The subjects since the last tag, newest last: the raw material for the entry. */
export function subjectsSinceLastTag(root: string = repoRoot): string[] {
  let range = "";
  try {
    range = `${git(["describe", "--tags", "--abbrev=0"], root)}..HEAD`;
  } catch {
    range = "";
  }
  const out = git(["log", "--no-merges", "--reverse", "--format=%s", ...(range ? [range] : [])], root);
  return out ? out.split("\n").filter((line) => !/^Release \d|release \d/.test(line)) : [];
}

/** The entry the bump opens: the heading, a line per commit, and the marker that keeps it from shipping as is. */
export function draftEntry(version: string, date: string, subjects: string[]): string {
  const lines = subjects.length ? subjects.map((s) => `- ${s}`) : ["- "];
  return `## ${version} — ${date}\n\n${lines.join("\n")}\n- ${draftMarker} — what changed, and what it means for someone reading the page.\n`;
}

/** Writes the version into every place that carries it, and opens the changelog entry. */
export function applyBump(version: string, { root = repoRoot, date, subjects = [] }: { root?: string; date: string; subjects?: string[] }): { previous: string | undefined; version: string; wroteEntry: boolean } {
  const pkgPath = path.join(root, "package.json");
  const lockPath = path.join(root, "package-lock.json");
  const manifestPath = path.join(root, "boxpilot/baselinewatch.yaml");
  const changelogPath = path.join(root, "CHANGELOG.md");

  const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: string };
  const previous = pkg.version;
  pkg.version = version;
  writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);

  const lock = JSON.parse(readFileSync(lockPath, "utf8")) as { version?: string; packages?: Record<string, { version?: string }> };
  lock.version = version;
  const root0 = lock.packages?.[""];
  if (root0) root0.version = version;
  writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);

  // Targeted replacement, not a YAML round trip: the manifest's comments are part of the file.
  const manifest = readFileSync(manifestPath, "utf8")
    .replace(/(reference:\s*\S+:)\S+/m, `$1${version}`)
    .replace(/^(\s+version:\s*")[^"]+(")$/m, `$1${version}$2`);
  writeFileSync(manifestPath, manifest);

  const changelog = readFileSync(changelogPath, "utf8");
  const existing = newestEntry(changelog);
  let wroteEntry = false;
  if (existing?.version !== version) {
    const at = changelog.search(/^## \d+\.\d+\.\d+ /m);
    const entry = draftEntry(version, date, subjects);
    writeFileSync(changelogPath, at === -1 ? `${changelog.trimEnd()}\n\n${entry}` : `${changelog.slice(0, at)}${entry}\n${changelog.slice(at)}`);
    wroteEntry = true;
  }
  return { previous, version, wroteEntry };
}

/** After the deploy: what the instance says it is running. */
export async function runningVersion(baseUrl: string): Promise<string | null> {
  let response;
  try {
    response = await fetch(new URL("/health", baseUrl), { headers: { accept: "application/json" } });
  } catch (error) {
    throw new Error(`could not reach ${baseUrl}: ${reason(error)}`, { cause: error });
  }
  if (!response.ok) throw new Error(`HTTP ${response.status} from ${baseUrl}/health`);
  const body = (await response.json()) as { version?: string };
  return body.version ?? null;
}

async function main(argv: string[]): Promise<number> {
  const check = argv.includes("--check");
  const verify = argv[argv.indexOf("--verify") + 1];
  const tag = argv.includes("--tag") ? argv[argv.indexOf("--tag") + 1] : null;

  if (check) {
    const versions = readVersions();
    const problems = consistencyProblems(versions, tag ? { tag } : {});
    if (problems.length) {
      console.error(`release check: ${problems.length} problem(s)`);
      for (const problem of problems) console.error(`  - ${problem}`);
      return 1;
    }
    console.log(`release check ok: ${versions.package} in package.json, the lock, the catalog manifest and CHANGELOG.md${tag ? `, and the tag ${tag}` : ""}`);
    return 0;
  }

  if (argv.includes("--verify")) {
    if (!verify) {
      console.error("--verify needs the instance's address, e.g. --verify https://cybercard.net");
      return 2;
    }
    const expected = readVersions().package;
    let running;
    try {
      running = await runningVersion(verify);
    } catch (error) {
      console.error(error instanceof Error ? error.message : String(error));
      return 1;
    }
    if (running !== expected) {
      console.error(`${verify} is running ${running ?? "an unknown version"}, this tree is ${expected}`);
      return 1;
    }
    console.log(`${verify} is running ${running}, as released`);
    return 0;
  }

  const version = argv.find((a) => semver.test(a));
  if (!version) {
    console.error("usage: node scripts/release.ts <x.y.z> [--date YYYY-MM-DD] | --check [--tag vX.Y.Z] | --verify <url>");
    return 2;
  }
  const current = readVersions().package;
  if (!current) {
    console.error("package.json carries no version");
    return 1;
  }
  if (compareVersions(version, current) <= 0) {
    console.error(`${version} is not ahead of ${current}`);
    return 1;
  }
  if (!argv.includes("--allow-dirty") && git(["status", "--porcelain"]) !== "") {
    console.error("the working tree has uncommitted changes: commit the work first, then release it");
    return 1;
  }
  const date = (argv.includes("--date") ? argv[argv.indexOf("--date") + 1] : null) ?? new Date().toISOString().slice(0, 10);
  const subjects = subjectsSinceLastTag();
  const result = applyBump(version, { date, subjects });
  console.log(`${result.previous} → ${version} in package.json, package-lock.json and the catalog manifest`);
  if (result.wroteEntry) {
    console.log(`CHANGELOG.md opened with ${subjects.length} commit subject(s) since the last tag.`);
    console.log("Write them up as prose and remove the TODO line; `npm run check` fails while it is there.");
  } else {
    console.log(`CHANGELOG.md already carries ${version}; left as it is.`);
  }
  console.log(`Then: git commit -am "Release ${version}: ..." && git tag v${version} && git push origin main --tags`);
  return 0;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await main(process.argv.slice(2));
}
