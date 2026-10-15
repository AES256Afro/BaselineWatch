/**
 * CVSS v3.0 and v3.1 base scores from a vector string, for sources that publish the vector but not
 * the number (OSV and the GitHub Advisory Database). Follows the specification's equations and its
 * Roundup; CVSS 4.0 and 2.0 vectors are left unscored.
 */

const av: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const ac: Record<string, number> = { L: 0.77, H: 0.44 };
const ui: Record<string, number> = { N: 0.85, R: 0.62 };
const cia: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
const prUnchanged: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const prChanged: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

/** CVSS v3.1's Roundup: to one decimal, upwards, without floating-point surprises. */
function roundup(value: number): number {
  const scaled = Math.round(value * 100_000);
  return scaled % 10_000 === 0 ? scaled / 100_000 : (Math.floor(scaled / 10_000) + 1) / 10;
}

export function cvssSeverity(score: number): "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
  if (score <= 0) return "NONE";
  if (score < 4) return "LOW";
  if (score < 7) return "MEDIUM";
  if (score < 9) return "HIGH";
  return "CRITICAL";
}

export interface CvssScore {
  version: string;
  score: number;
  severity: "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  vector: string;
}

/** The base score of a CVSS:3.0 or CVSS:3.1 vector, or null when the vector is not one or is incomplete. */
export function scoreCvss3(vector: string | null | undefined): CvssScore | null {
  if (!vector) return null;
  const trimmed = vector.trim();
  const match = /^CVSS:(3\.[01])\/(.+)$/.exec(trimmed);
  if (!match) return null;
  const version = match[1]!;
  const metrics: Record<string, string> = {};
  for (const part of match[2]!.split("/")) {
    const [key, value] = part.split(":");
    if (key && value) metrics[key] = value;
  }
  const scope = metrics.S;
  const weights = {
    av: av[metrics.AV ?? ""],
    ac: ac[metrics.AC ?? ""],
    pr: (scope === "C" ? prChanged : prUnchanged)[metrics.PR ?? ""],
    ui: ui[metrics.UI ?? ""],
    c: cia[metrics.C ?? ""],
    i: cia[metrics.I ?? ""],
    a: cia[metrics.A ?? ""],
  };
  if (Object.values(weights).some((w) => w === undefined) || (scope !== "U" && scope !== "C")) return null;
  const iss = 1 - (1 - weights.c!) * (1 - weights.i!) * (1 - weights.a!);
  const impact = scope === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  const exploitability = 8.22 * weights.av! * weights.ac! * weights.pr! * weights.ui!;
  let score: number;
  if (impact <= 0) score = 0;
  else if (scope === "U") score = roundup(Math.min(impact + exploitability, 10));
  else score = roundup(Math.min(1.08 * (impact + exploitability), 10));
  return { version, score, severity: cvssSeverity(score), vector: trimmed };
}
