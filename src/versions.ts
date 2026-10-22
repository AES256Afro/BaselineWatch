/**
 * Dotted version numbers compared the way people read them: 10.0.26100.9711 against
 * 10.0.26100.9445, 156.0.8078.47 against 156.0.8078.46, 26.7.1 against 26.7. Numbers compare
 * as numbers, a missing part counts as zero, and anything after a letter is ignored, which is
 * enough for OS builds and browser versions. Distribution package versions are not compared
 * here: OSV compares those, by the distribution's own rules, when asked.
 */

export function versionParts(value: string): number[] {
  return (value.trim().match(/^\d+(\.\d+)*/)?.[0] ?? "").split(".").filter((p) => p !== "").map((p) => Number(p));
}

/** Negative when a is older than b, positive when newer, zero when the same as far as both go. */
export function compareDotted(a: string, b: string): number {
  const x = versionParts(a);
  const y = versionParts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i += 1) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** The newest of several versions, or null. */
export function newestVersion(values: string[]): string | null {
  return values.reduce<string | null>((best, v) => (best === null || compareDotted(v, best) > 0 ? v : best), null);
}
