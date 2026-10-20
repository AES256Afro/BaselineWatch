/**
 * One CSV cell: quoted when it holds a quote, a comma or a line break, and never a formula. A
 * spreadsheet runs a cell that starts with =, +, @ or - (and treats a leading tab or return the
 * same way), and a feed title or a note can start with any of those, so such a cell is prefixed
 * with an apostrophe. A plain negative number keeps its sign.
 */
export function csvCell(value: unknown): string {
  let s = value === null || value === undefined ? "" : String(value);
  s = s.replace(/^[\t\r]+/, "");
  if (/^[=+@]/.test(s) || /^-(?![\d.]|$)/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** A row of cells, joined. */
export function csvLine(cells: unknown[]): string {
  return cells.map(csvCell).join(",");
}
