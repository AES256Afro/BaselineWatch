/**
 * A reader's text as a LIKE pattern that matches it anywhere: \, % and _ are the reader's
 * characters, not wildcards. Every LIKE that takes one says ESCAPE '\'.
 */
export function likePattern(text: string): string {
  return `%${likeEscape(text)}%`;
}

/** The text with LIKE's wildcards and its escape character escaped, for a pattern built around it. */
export function likeEscape(text: string): string {
  return text.replace(/[\\%_]/g, (c) => `\\${c}`);
}
