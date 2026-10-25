/**
 * One CSV cell: quoted when it holds a quote, a comma or a line break, and never a formula.
 *
 * A spreadsheet runs a cell that starts with =, +, @ or -, and it skips leading whitespace and
 * control characters on the way to deciding, so the decision is made on the value with that run
 * removed while the cell keeps every byte it was given: a feed title of "\u0000=1+1" or " =1+1"
 * read as a formula before, because only a leading tab or return was taken off. A cell that would
 * be read as a formula is prefixed with an apostrophe. A plain negative number keeps its sign.
 */
export function csvCell(value: unknown): string {
  const s = value === null || value === undefined ? "" : String(value);
  // eslint-disable-next-line no-control-regex
  const bare = s.replace(/^[\s\u0000-\u001f\u007f-\u009f]+/, "");
  // A leading minus is kept only on a plain number: "-2+3+cmd|' /C calc'!A0" is a formula too.
  const formula = /^[=+@]/.test(bare) || (bare.startsWith("-") && !/^-(\d+(\.\d*)?|\.\d+)?$/.test(bare));
  const cell = formula ? `'${s}` : s;
  return /[",\n\r]/.test(cell) ? `"${cell.replace(/"/g, '""')}"` : cell;
}

/** A row of cells, joined. */
export function csvLine(cells: unknown[]): string {
  return cells.map(csvCell).join(",");
}
