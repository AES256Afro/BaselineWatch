/**
 * Dotted version numbers compared the way people read them: 10.0.26100.9711 against
 * 10.0.26100.9445, 156.0.8078.47 against 156.0.8078.46, 26.7.1 against 26.7. Numbers compare
 * as numbers, a missing part counts as zero, and anything after a letter is ignored, which is
 * enough for OS builds and browser versions. Debian and Ubuntu package versions are compared by
 * their own rules (compareDebian below); OSV names the fixed version, this module compares it
 * with the installed one.
 */

function versionParts(value: string): number[] {
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

/**
 * Debian's version comparison (deb-version(7)): epoch, then upstream, then revision, each part
 * compared as alternating runs of non-digits (letters before other characters, `~` before
 * everything, the end before anything but `~`) and numbers. Ubuntu's packages use it too.
 */
export function compareDebian(a: string, b: string): number {
  const split = (v: string): [number, string, string] => {
    const colon = v.indexOf(":");
    const epoch = colon > 0 && /^\d+$/.test(v.slice(0, colon)) ? Number(v.slice(0, colon)) : 0;
    const rest = colon > 0 ? v.slice(colon + 1) : v;
    const dash = rest.lastIndexOf("-");
    return dash >= 0 ? [epoch, rest.slice(0, dash), rest.slice(dash + 1)] : [epoch, rest, ""];
  };
  const [ea, ua, ra] = split(a.trim());
  const [eb, ub, rb] = split(b.trim());
  if (ea !== eb) return ea - eb;
  return verrevcmp(ua, ub) || verrevcmp(ra, rb);
}

const isDigit = (c: string): boolean => c >= "0" && c <= "9";
const order = (c: string): number => (c === "" || isDigit(c) ? 0 : /[A-Za-z]/.test(c) ? c.charCodeAt(0) : c === "~" ? -1 : c.charCodeAt(0) + 256);

function verrevcmp(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    let firstDiff = 0;
    while ((i < a.length && !isDigit(a[i]!)) || (j < b.length && !isDigit(b[j]!))) {
      const ac = order(a[i] ?? "");
      const bc = order(b[j] ?? "");
      if (ac !== bc) return ac - bc;
      i += 1;
      j += 1;
    }
    while (a[i] === "0") i += 1;
    while (b[j] === "0") j += 1;
    while (i < a.length && j < b.length && isDigit(a[i]!) && isDigit(b[j]!)) {
      if (!firstDiff) firstDiff = a.charCodeAt(i) - b.charCodeAt(j);
      i += 1;
      j += 1;
    }
    if (i < a.length && isDigit(a[i]!)) return 1;
    if (j < b.length && isDigit(b[j]!)) return -1;
    if (firstDiff) return firstDiff;
  }
  return 0;
}
