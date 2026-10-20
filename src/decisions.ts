import type { DatabaseSync } from "node:sqlite";
import type { BuilderPlatform, Profile, ProfileItem } from "./baselines.ts";

/**
 * The owner's decisions on a platform's baseline: for each item, beside what the publisher
 * recommends, whether the organisation applies it as published, applies it with its own value,
 * or does not apply it, with the reason and who owns it. No row means the recommendation stands.
 * The builder starts from these (an excluded item starts unticked), the test plan leaves the
 * excluded items out, and every export carries them.
 */

export type DecisionKind = "apply" | "modify" | "exclude";

export const decisionKinds: { id: DecisionKind; label: string; blurb: string }[] = [
  { id: "apply", label: "Apply as published", blurb: "The publisher's recommendation, unchanged." },
  { id: "modify", label: "Apply, modified", blurb: "Applied with the organisation's own value (a longer screen-lock time, a different banner)." },
  { id: "exclude", label: "Not applying", blurb: "Left out of the baseline, its exports and its test plan; the reason is the risk acceptance." },
];

export function isDecisionKind(value: unknown): value is DecisionKind {
  return value === "apply" || value === "modify" || value === "exclude";
}

export function decisionLabel(kind: DecisionKind): string {
  return decisionKinds.find((d) => d.id === kind)?.label ?? kind;
}

export interface Decision {
  itemId: string;
  decision: DecisionKind;
  value: string | null;
  reason: string | null;
  owner: string | null;
  decidedAt: string;
}

interface Row {
  item_id: string;
  decision: DecisionKind;
  value: string | null;
  reason: string | null;
  owner: string | null;
  decided_at: string;
}

const toDecision = (r: Row): Decision => ({ itemId: r.item_id, decision: r.decision, value: r.value, reason: r.reason, owner: r.owner, decidedAt: r.decided_at });

/** Every stored decision for a platform, by item id. */
export function loadDecisions(db: DatabaseSync, platform: BuilderPlatform): Map<string, Decision> {
  const rows = db.prepare("SELECT item_id, decision, value, reason, owner, decided_at FROM baseline_decisions WHERE platform = ?").all(platform) as unknown as Row[];
  return new Map(rows.map((r) => [r.item_id, toDecision(r)]));
}

export function getDecision(db: DatabaseSync, platform: BuilderPlatform, itemId: string): Decision | null {
  const row = db.prepare("SELECT item_id, decision, value, reason, owner, decided_at FROM baseline_decisions WHERE platform = ? AND item_id = ?").get(platform, itemId) as unknown as Row | undefined;
  return row ? toDecision(row) : null;
}

const clip = (v: string | null | undefined, n: number): string | null => {
  const t = (v ?? "").trim();
  return t ? t.slice(0, n) : null;
};

/**
 * Stores a decision. "Apply as published" with no reason or owner is the default, so it removes
 * the row rather than storing a copy of the recommendation.
 */
export function saveDecision(
  db: DatabaseSync,
  platform: BuilderPlatform,
  itemId: string,
  input: { decision: DecisionKind; value?: string | null; reason?: string | null; owner?: string | null },
  now: Date,
): Decision | null {
  const value = input.decision === "modify" ? clip(input.value, 500) : null;
  const reason = clip(input.reason, 2000);
  const owner = clip(input.owner, 120);
  if (input.decision === "apply" && !reason && !owner) {
    db.prepare("DELETE FROM baseline_decisions WHERE platform = ? AND item_id = ?").run(platform, itemId);
    return null;
  }
  const decidedAt = now.toISOString();
  db.prepare(
    `INSERT INTO baseline_decisions (platform, item_id, decision, value, reason, owner, decided_at) VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (platform, item_id) DO UPDATE SET decision = excluded.decision, value = excluded.value, reason = excluded.reason, owner = excluded.owner, decided_at = excluded.decided_at`,
  ).run(platform, itemId, input.decision, value, reason, owner, decidedAt);
  return { itemId, decision: input.decision, value, reason, owner, decidedAt };
}

/** "DISA STIG APPL-26-000001 (CAT II): title": what the publisher recommends, in a line. */
export function recommends(i: ProfileItem): string {
  const who = i.kind === "stig" ? "DISA STIG" : i.kind === "mscp" ? "NIST mSCP" : i.kind === "sct" ? "Microsoft baseline" : "SP 800-53 High";
  return `${who} ${i.label}${i.severity ? ` (${i.severity})` : ""}: ${i.title}${i.sctValue ? ` = ${i.sctValue}` : ""}`;
}

/** One line on what the owner decided. */
export function ourDecision(i: ProfileItem): string {
  const d = i.decision;
  if (!d) return "Apply as published";
  return `${decisionLabel(d.decision)}${d.decision === "modify" && d.value ? `: ${d.value}` : ""}`;
}

/** Every item of the profile with its recommendation and the decision on it, as CSV for a ticket system or a spreadsheet. */
export function decisionsCsv(profile: Profile, baseUrl: string): string {
  const cell = (v: unknown) => {
    const s = v === null || v === undefined ? "" : String(v);
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const rows = ["item,kind,severity,title,publisher recommends,decision,our value,reason,owner,decided,reference"];
  for (const i of profile.items) {
    const d = i.decision;
    rows.push([i.label, i.kind, i.severity ?? "", i.title, recommends(i), decisionLabel(d?.decision ?? "apply"), d?.value ?? "", d?.reason ?? "", d?.owner ?? "", d?.decidedAt.slice(0, 10) ?? "", i.url.startsWith("/") ? `${baseUrl}${i.url}` : i.url].map(cell).join(","));
  }
  return `${rows.join("\r\n")}\r\n`;
}
