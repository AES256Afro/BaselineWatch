import type { NormalizedRequirement } from "./oscal.ts";

export type ChangeField = "title" | "statement" | "guidance" | "params" | "related" | "status" | "extra";

export interface RequirementChange {
  ref: string;
  kind: "added" | "removed" | "modified";
  field: ChangeField | null;
  before: string | null;
  after: string | null;
}

/** Whitespace is never a change. */
function normalizeText(text: string | null | undefined): string | null {
  if (text === null || text === undefined) return null;
  const t = text.replace(/\s+/g, " ").trim();
  return t === "" ? null : t;
}

function paramsText(params: NormalizedRequirement["params"]): string | null {
  if (!params.length) return null;
  return params.map((p) => `${p.id}: ${p.label ?? ""}${p.choices ? ` [${p.choices.join("; ")}]` : ""}`).join("\n");
}

function relatedText(related: string[]): string | null {
  return related.length ? [...related].sort().join(", ") : null;
}

function extraText(extra: Record<string, unknown>): string | null {
  const keys = Object.keys(extra).sort();
  if (!keys.length) return null;
  return keys.map((k) => `${k}: ${typeof extra[k] === "string" ? normalizeText(extra[k] as string) : JSON.stringify(extra[k])}`).join("\n");
}

/**
 * Field-level differences between two versions of a requirement set, matched by ref. The
 * output is what the `changes` table stores; the UI draws word-level redlines from before/after.
 */
export function diffRequirements(before: NormalizedRequirement[], after: NormalizedRequirement[]): RequirementChange[] {
  const previous = new Map(before.map((r) => [r.ref, r]));
  const next = new Map(after.map((r) => [r.ref, r]));
  const changes: RequirementChange[] = [];

  for (const [ref, b] of previous) {
    if (!next.has(ref)) changes.push({ ref, kind: "removed", field: null, before: `${b.label} ${b.title}`, after: null });
  }
  for (const [ref, a] of next) {
    const b = previous.get(ref);
    if (!b) {
      changes.push({ ref, kind: "added", field: null, before: null, after: `${a.label} ${a.title}` });
      continue;
    }
    const fields: [ChangeField, string | null, string | null][] = [
      ["title", normalizeText(b.title), normalizeText(a.title)],
      ["statement", normalizeText(b.statement), normalizeText(a.statement)],
      ["guidance", normalizeText(b.guidance), normalizeText(a.guidance)],
      ["params", paramsText(b.params), paramsText(a.params)],
      ["related", relatedText(b.related), relatedText(a.related)],
      ["status", b.status === a.status ? null : b.status, b.status === a.status ? null : a.status],
      ["extra", extraText(b.extra), extraText(a.extra)],
    ];
    for (const [field, x, y] of fields) {
      if (x !== y) changes.push({ ref, kind: "modified", field, before: x, after: y });
    }
  }
  return changes;
}

export interface ChangeSummary {
  added: string[];
  removed: string[];
  modified: string[];
  /** Refs whose statement, title or parameters changed (the substantive ones). */
  substantive: string[];
  /** Refs where only guidance, related controls or assessment text moved. */
  editorial: string[];
}

export function summarizeChanges(changes: RequirementChange[]): ChangeSummary {
  const added = new Set<string>();
  const removed = new Set<string>();
  const modified = new Set<string>();
  const substantive = new Set<string>();
  for (const c of changes) {
    if (c.kind === "added") added.add(c.ref);
    else if (c.kind === "removed") removed.add(c.ref);
    else {
      modified.add(c.ref);
      if (c.field === "statement" || c.field === "title" || c.field === "params" || c.field === "status") substantive.add(c.ref);
    }
  }
  return {
    added: [...added],
    removed: [...removed],
    modified: [...modified],
    substantive: [...substantive],
    editorial: [...modified].filter((r) => !substantive.has(r)),
  };
}
