// Two instances side by side, for the restore rehearsal (docs/DEPLOY.md): the counts the live
// instance reports against the counts the restored copy reports, and a verdict.
//
//   node scripts/health-diff.ts https://cybercard.net http://127.0.0.1:8795
//   node scripts/health-diff.ts live.json http://127.0.0.1:8795 --tolerance 0.2
//
// A restored copy is a backup, so it is behind: every count may be lower by up to the tolerance
// (10% by default). It may never be ahead, and it must carry the same migrations — a restore that
// answers with fewer migrations is a restore of the wrong volume.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

/** As much of /health as the comparison reads. */
export interface HealthAnswer {
  name?: string;
  version?: string;
  database?: Record<string, number>;
}

export interface CountRow {
  field: string;
  live: number;
  restored: number;
  delta: number;
}

/** The counted fields of /health, in the order a person reads them. */
export const counted = ["migrations", "sources", "snapshots", "changes", "items", "vulns"];

export async function readHealth(where: string): Promise<HealthAnswer> {
  if (/^https?:\/\//.test(where)) {
    let response: Response;
    try {
      response = await fetch(new URL("/health", where), { headers: { accept: "application/json" } });
    } catch (error) {
      const cause = (error as { cause?: { code?: string } }).cause;
      throw new Error(`could not reach ${where}: ${cause?.code ?? (error instanceof Error ? error.message : String(error))}`, { cause: error });
    }
    if (!response.ok) throw new Error(`HTTP ${response.status} from ${where}/health`);
    return (await response.json()) as HealthAnswer;
  }
  return JSON.parse(readFileSync(where, "utf8")) as HealthAnswer;
}

/**
 * What differs, and whether the restore passed. `live` is the instance of record, `restored` the
 * copy brought up from the backup.
 */
export function compareHealth(live: HealthAnswer, restored: HealthAnswer, { tolerance = 0.1 }: { tolerance?: number } = {}): { rows: CountRow[]; problems: string[]; ok: boolean } {
  const rows: CountRow[] = [];
  const problems: string[] = [];
  for (const field of counted) {
    const a = live.database?.[field] ?? 0;
    const b = restored.database?.[field] ?? 0;
    const delta = b - a;
    rows.push({ field, live: a, restored: b, delta });
    if (field === "migrations") {
      if (a !== b) problems.push(`migrations differ (${a} live, ${b} restored): the restored volume is not this app's`);
      continue;
    }
    if (delta > 0) problems.push(`${field}: the restored copy has more than the live instance (${b} against ${a})`);
    // An empty table is its own finding: it reads as "behind" but means the restore lost something.
    else if (a > 0 && b === 0) problems.push(`${field}: the restored copy holds none`);
    else if (a > 0 && b < a * (1 - tolerance)) problems.push(`${field}: the restored copy holds ${b} against ${a}, more than ${Math.round(tolerance * 100)}% behind`);
  }
  if (live.name !== restored.name) problems.push(`these are not the same product: ${live.name} against ${restored.name}`);
  return { rows, problems, ok: problems.length === 0 };
}

export function formatTable(rows: CountRow[]): string {
  const width = Math.max(...rows.map((r) => r.field.length));
  return rows
    .map((r) => `  ${r.field.padEnd(width)}  ${String(r.live).padStart(9)}  ${String(r.restored).padStart(9)}  ${r.delta === 0 ? "same" : r.delta > 0 ? `+${r.delta}` : String(r.delta)}`)
    .join("\n");
}

async function main(argv: string[]): Promise<number> {
  const positional = argv.filter((a) => !a.startsWith("--"));
  const [live, restored] = positional;
  if (!live || !restored) {
    console.error("usage: node scripts/health-diff.ts <live url or file> <restored url or file> [--tolerance 0.1]");
    return 2;
  }
  const tolerance = argv.includes("--tolerance") ? Number(argv[argv.indexOf("--tolerance") + 1]) : 0.1;
  let a: HealthAnswer;
  let b: HealthAnswer;
  try {
    [a, b] = await Promise.all([readHealth(live), readHealth(restored)]);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
  const result = compareHealth(a, b, { tolerance });
  console.log(`  ${"".padEnd(10)}  ${"live".padStart(9)}  ${"restored".padStart(9)}`);
  console.log(formatTable(result.rows));
  console.log(`  version   ${String(a.version).padStart(9)}  ${String(b.version).padStart(9)}`);
  if (!result.ok) {
    console.error(`\nthe rehearsal did not pass: ${result.problems.length} problem(s)`);
    for (const problem of result.problems) console.error(`  - ${problem}`);
    return 1;
  }
  console.log("\nthe restored copy holds what the live instance holds, allowing for the backup's age.");
  console.log("Record it: npm run rehearsal -- today \"restored from <archive> on <host>\"");
  return 0;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await main(process.argv.slice(2));
}
