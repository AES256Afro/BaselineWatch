import type { DatabaseSync } from "node:sqlite";
import { csvLine } from "./csv.ts";
import { withheldLabel } from "./register.ts";
import { parseJson } from "./json.ts";

export type TriageKind = "item" | "vuln" | "control";
export type TriageState = "new" | "reviewing" | "affects" | "done" | "dismissed";
export const triageStates: TriageState[] = ["new", "reviewing", "affects", "done", "dismissed"];
export const stateLabel: Record<TriageState, string> = { new: "New", reviewing: "Reviewing", affects: "Affects us", done: "Done", dismissed: "Not ours" };

export interface TriageRow {
  id: number;
  subject_kind: TriageKind;
  subject_id: number;
  subject_key: string;
  state: TriageState;
  note: string | null;
  due_at: string | null;
  created_at: string;
  updated_at: string;
}

export function isTriageState(value: unknown): value is TriageState {
  return typeof value === "string" && (triageStates as string[]).includes(value);
}

export function getTriage(db: DatabaseSync, kind: TriageKind, id: number, key = ""): TriageRow | null {
  return (db.prepare("SELECT * FROM triage WHERE subject_kind = ? AND subject_id = ? AND subject_key = ?").get(kind, id, key) as unknown as TriageRow | undefined) ?? null;
}

/** Sets the state (and optionally the note and due date) on a subject, creating the row if needed. */
export function setTriage(
  db: DatabaseSync,
  subject: { kind: TriageKind; id: number; key?: string },
  change: { state?: TriageState | undefined; note?: string | null | undefined; dueAt?: string | null | undefined },
  at: string,
): TriageRow {
  const key = subject.key ?? "";
  const existing = getTriage(db, subject.kind, subject.id, key);
  if (!existing) {
    db.prepare("INSERT INTO triage (subject_kind, subject_id, subject_key, state, note, due_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(
      subject.kind,
      subject.id,
      key,
      change.state ?? "new",
      change.note ?? null,
      change.dueAt ?? null,
      at,
      at,
    );
  } else {
    db.prepare("UPDATE triage SET state = ?, note = ?, due_at = ?, updated_at = ? WHERE id = ?").run(
      change.state ?? existing.state,
      change.note === undefined ? existing.note : change.note,
      change.dueAt === undefined ? existing.due_at : change.dueAt,
      at,
      existing.id,
    );
  }
  return getTriage(db, subject.kind, subject.id, key)!;
}

export function clearTriage(db: DatabaseSync, subject: { kind: TriageKind; id: number; key?: string }): boolean {
  return Number(db.prepare("DELETE FROM triage WHERE subject_kind = ? AND subject_id = ? AND subject_key = ?").run(subject.kind, subject.id, subject.key ?? "").changes) > 0;
}

/** A triaged subject with enough of its own data to draw a card. */
export interface TriageCard extends TriageRow {
  title: string;
  url: string;
  detail: string | null;
  signals: Record<string, unknown>;
  /** A requirement of a licence-restricted source, drawn for someone other than the owner: its key is its name, so the card carries neither. */
  withheld?: boolean;
}

/**
 * Every triaged subject, newest first, joined to its item, CVE or requirement. A requirement of a
 * licence-restricted source is named only when the owner is asking (`owner`); the API never is.
 */
export function listTriage(db: DatabaseSync, options: { state?: TriageState | undefined; limit?: number; owner?: boolean } = {}): TriageCard[] {
  const params: (string | number)[] = [];
  let where = "";
  if (options.state) {
    where = "WHERE t.state = ?";
    params.push(options.state);
  }
  const rows = db
    .prepare(
      `SELECT t.*,
              i.title AS item_title, i.url AS item_url, i.summary AS item_summary, i.signals_json AS item_signals, i.kind AS item_kind,
              v.cve_id AS vuln_cve, v.description AS vuln_description, v.cvss_score AS vuln_cvss, v.epss AS vuln_epss, v.kev AS vuln_kev, v.vendors_json AS vuln_vendors,
              d.source_id AS doc_source, d.version_label AS doc_version, s.name AS doc_standard, s.restricted AS doc_restricted,
              r.label AS req_label, r.title AS req_title
       FROM triage t
       LEFT JOIN items i ON t.subject_kind = 'item' AND i.id = t.subject_id
       LEFT JOIN vulns v ON t.subject_kind = 'vuln' AND v.id = t.subject_id
       LEFT JOIN documents d ON t.subject_kind = 'control' AND d.id = t.subject_id
       LEFT JOIN sources s ON s.id = d.source_id
       LEFT JOIN requirements r ON t.subject_kind = 'control' AND r.document_id = t.subject_id AND r.ref = t.subject_key
       ${where}
       ORDER BY CASE t.state WHEN 'affects' THEN 0 WHEN 'reviewing' THEN 1 WHEN 'new' THEN 2 WHEN 'done' THEN 3 ELSE 4 END, t.updated_at DESC
       LIMIT ?`,
    )
    .all(...params, Math.min(options.limit ?? 200, 500)) as unknown as (TriageRow & Record<string, unknown>)[];

  return rows.map((r) => {
    if (r.subject_kind === "item") {
      const signals = parseJson<Record<string, unknown>>(r.item_signals as string | null, {});
      return { ...r, title: (r.item_title as string) ?? "(item removed)", url: (r.item_url as string) ?? "/", detail: (r.item_summary as string | null) ?? null, signals: { ...signals, itemKind: r.item_kind } };
    }
    if (r.subject_kind === "vuln") {
      const vendors = parseJson<string[]>(r.vuln_vendors as string | null, []);
      return {
        ...r,
        title: `${r.vuln_cve ?? "CVE"}${vendors.length ? ` · ${vendors.slice(0, 2).join(", ")}` : ""}`,
        url: `/vulnerabilities/${r.vuln_cve}`,
        detail: (r.vuln_description as string | null) ?? null,
        signals: { cvss: r.vuln_cvss, epss: r.vuln_epss, kev: r.vuln_kev === 1 },
      };
    }
    const withheld = r.doc_restricted === 1 && !options.owner;
    return {
      ...r,
      subject_key: withheld ? "" : r.subject_key,
      title: `${withheld ? withheldLabel : `${r.req_label ?? r.subject_key.toUpperCase()} ${r.req_title ?? ""}`} (${r.doc_standard ?? r.doc_source ?? "standard"} ${r.doc_version ?? ""})`.trim(),
      url: withheld ? `/standards/${r.doc_source}/${r.subject_id}` : `/standards/${r.doc_source}/${r.subject_id}/${r.subject_key}`,
      detail: null,
      signals: { release: true },
      ...(withheld ? { withheld: true } : {}),
    };
  });
}

export function triageCounts(db: DatabaseSync): Record<TriageState, number> {
  const counts: Record<TriageState, number> = { new: 0, reviewing: 0, affects: 0, done: 0, dismissed: 0 };
  for (const r of db.prepare("SELECT state, COUNT(*) AS n FROM triage GROUP BY state").all() as { state: TriageState; n: number }[]) counts[r.state] = r.n;
  return counts;
}

/** Notable, unread, untriaged timeline items: the inbox the board starts from. */
export function triageInbox(db: DatabaseSync, limit = 30): { id: number; title: string; url: string | null; kind: string; published_at: string | null; signals_json: string | null; source_id: string; source_name: string }[] {
  return db
    .prepare(
      `SELECT i.id, i.title, i.url, i.kind, i.published_at, i.signals_json, s.id AS source_id, s.name AS source_name
       FROM items i JOIN sources s ON s.id = i.source_id
       WHERE i.kind IN ('kev', 'vulnerability', 'release') AND i.read = 0
         AND NOT EXISTS (SELECT 1 FROM triage t WHERE t.subject_kind = 'item' AND t.subject_id = i.id)
       ORDER BY COALESCE(i.published_at, i.fetched_at) DESC, i.id DESC LIMIT ?`,
    )
    .all(limit) as never;
}

/** The owner's download, so every card is named. */
export function triageCsv(db: DatabaseSync): string {
  const cards = listTriage(db, { limit: 500, owner: true });
  const lines = ["state,kind,title,url,note,due,updated"];
  for (const c of cards) lines.push(csvLine([c.state, c.subject_kind, c.title, c.url, c.note ?? "", c.due_at ?? "", c.updated_at]));
  return `${lines.join("\n")}\n`;
}
