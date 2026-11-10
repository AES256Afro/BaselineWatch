/**
 * Words for numbers, in one place for every module: a count with its noun agreeing, and a byte
 * size the way a person reads it. Not in html.ts, so a module that renders no page need not
 * import the page template to say "3 sources".
 */

/** `counted(1, "release")` is "1 release"; `counted(3, "release")` is "3 releases". */
export function counted(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;
}

/** The verb that agrees with a count: `agree(1, "is", "are")` is "is". */
export function agree(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

/** "138 MB", "4.2 GB": the number a person reads, never a byte count on a page. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let n = bytes / 1024;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return `${n < 10 ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}

/** An EPSS probability as a percentage with the places it needs: "61%", "4.2%", "0.41%", "0.004%". */
export function epssPercent(p: number): string {
  const pct = p * 100;
  // Chosen by the value as it will be shown, so 9.99 reads "10%", not "10.0%".
  if (Number(pct.toFixed(1)) >= 10) return `${pct.toFixed(0)}%`;
  if (Number(pct.toFixed(2)) >= 1) return `${pct.toFixed(1)}%`;
  if (Number(pct.toFixed(3)) >= 0.1) return `${pct.toFixed(2)}%`;
  return `${pct.toFixed(3)}%`;
}
