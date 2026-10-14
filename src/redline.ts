import { html, type Html } from "./html.ts";

export type Op = { kind: "same" | "del" | "ins"; text: string };

/** Words, runs of whitespace, and single punctuation marks, so "software." and "software" share a word. */
function tokens(text: string): string[] {
  return text.match(/\s+|[\p{L}\p{N}_'’-]+|[^\s\p{L}\p{N}_'’-]/gu) ?? [];
}

/**
 * Word-level diff of two texts, Myers-free but adequate: a longest-common-subsequence over
 * tokens, with whitespace kept as tokens so the result re-flows exactly. Texts here are a
 * control's statement or discussion, hundreds of words at most.
 */
export function wordDiff(before: string, after: string): Op[] {
  const a = tokens(before);
  const b = tokens(after);
  const n = a.length;
  const m = b.length;
  if (n * m > 4_000_000) {
    return [
      { kind: "del", text: before },
      { kind: "ins", text: after },
    ];
  }
  // lcs[i][j] = length of LCS of a[i..] and b[j..]
  const lcs: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i -= 1) {
    const row = lcs[i]!;
    const next = lcs[i + 1]!;
    for (let j = m - 1; j >= 0; j -= 1) {
      row[j] = a[i] === b[j] ? next[j + 1]! + 1 : Math.max(next[j]!, row[j + 1]!);
    }
  }
  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  const push = (kind: Op["kind"], text: string) => {
    const last = ops[ops.length - 1];
    if (last && last.kind === kind) last.text += text;
    else ops.push({ kind, text });
  };
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      push("same", a[i]!);
      i += 1;
      j += 1;
    } else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) {
      push("del", a[i]!);
      i += 1;
    } else {
      push("ins", b[j]!);
      j += 1;
    }
  }
  while (i < n) push("del", a[i++]!);
  while (j < m) push("ins", b[j++]!);
  return ops;
}

/** The diff as HTML with <del> and <ins>, line breaks preserved. */
export function redline(before: string | null, after: string | null): Html {
  if (before === null && after === null) return html``;
  const ops = wordDiff(before ?? "", after ?? "");
  const parts = ops.map((op) => {
    const text = op.text.split("\n").map((line, index) => (index === 0 ? html`${line}` : html`<br>${line}`));
    if (op.kind === "same") return html`${text}`;
    return op.kind === "del" ? html`<del>${text}</del>` : html`<ins>${text}</ins>`;
  });
  return html`${parts}`;
}

/** Plain text with line breaks as <br>, for the untouched side of a two-column view. */
export function lines(text: string | null): Html {
  if (!text) return html``;
  return html`${text.split("\n").map((line, index) => (index === 0 ? html`${line}` : html`<br>${line}`))}`;
}
