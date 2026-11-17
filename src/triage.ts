import type { DatabaseSync } from "node:sqlite";
import { csvLine } from "./csv.ts";
import { withheldLabel } from "./register.ts";
import { parseJson } from "./json.ts";
import { cveIdPattern } from "./vulns.ts";

/**
 * Triage: the owner's state on any item, CVE or control-in-a-release — new, reviewing, affects us,
 * done, not ours — with a note and a due date, the board's counts and inbox, and the CSV of it all.
 */
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
 * The board's cards: every triaged subject joined to its item, CVE or requirement, by state and
 * then newest first. Two different things may be withheld, and conflating them on one `owner`
 * flag is what let the second one out until the audit of 25 October:
 *
 * - `notes`: the owner's own note on a card — their working text, up to two thousand characters of
 *   what they think about a CVE or a control. `/triage` and `/api/v1/triage` are gated for
 *   *reading*, not for the owner, so on a read-open instance it was public. It follows who is
 *   asking: the owner's own agent reads their notes through the API, a visitor does not.
 * - `restrictedLabels`: a restricted standard's requirement label and text. This is a licence
 *   term, not a privacy one, so it is false for the API and the feeds **even for the owner** —
 *   the API is how content would get redistributed — and true only where a page draws it.
 *
 * The state, the subject and the due date stay public either way: those are what the board teaches.
 */
export function listTriage(db: DatabaseSync, options: { state?: TriageState | undefined; limit?: number | null; notes?: boolean; restrictedLabels?: boolean } = {}): TriageCard[] {
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
       ${options.limit === null ? "" : "LIMIT ?"}`,
    )
    // limit: null is every row, for the owner's CSV; a page or the API is capped at five hundred.
    .all(...params, ...(options.limit === null ? [] : [Math.min(options.limit ?? 200, 500)])) as unknown as (TriageRow & Record<string, unknown>)[];

  // The owner's own note, kept or dropped once rather than at each of the places that draw it.
  const note = (r: { note: string | null }): string | null => (options.notes ? r.note : null);
  return rows.map((r) => {
    if (r.subject_kind === "item") {
      const signals = parseJson<Record<string, unknown>>(r.item_signals as string | null, {});
      return { ...r, note: note(r), title: (r.item_title as string) ?? "(item removed)", url: (r.item_url as string) ?? "/", detail: (r.item_summary as string | null) ?? null, signals: { ...signals, itemKind: r.item_kind } };
    }
    if (r.subject_kind === "vuln") {
      const vendors = parseJson<string[]>(r.vuln_vendors as string | null, []);
      return {
        ...r,
        note: note(r),
        title: `${r.vuln_cve ?? "CVE"}${vendors.length ? ` · ${vendors.slice(0, 2).join(", ")}` : ""}`,
        url: `/vulnerabilities/${r.vuln_cve}`,
        detail: (r.vuln_description as string | null) ?? null,
        signals: { cvss: r.vuln_cvss, epss: r.vuln_epss, kev: r.vuln_kev === 1 },
      };
    }
    const withheld = r.doc_restricted === 1 && !options.restrictedLabels;
    return {
      ...r,
      note: note(r),
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

/** How far back the inbox reaches: older than this, only a CVE on the watchlist waits for a decision. */
export const inboxDays = 30;

/** The instant the inbox's window starts: midnight UTC of the day thirty days back, so the date the backlog button names is the whole boundary. */
export function inboxCutoff(now: Date): string {
  return `${new Date(now.getTime() - inboxDays * 86_400_000).toISOString().slice(0, 10)}T00:00:00.000Z`;
}

/** Unread timeline items of the kinds the board places, with no triage row yet. */
const waitingSql = `i.kind IN ('kev', 'vulnerability', 'release') AND i.read = 0
  AND NOT EXISTS (SELECT 1 FROM triage t WHERE t.subject_kind = 'item' AND t.subject_id = i.id)`;
/** An item that names a CVE the watchlist marks. */
const watchedSql = "(i.kind IN ('kev', 'vulnerability') AND i.external_id IN (SELECT cve_id FROM vulns WHERE watch_hit = 1))";
/**
 * The inbox: what is waiting and either arrived in the window or is on the watchlist. Without the
 * window it held every KEV entry since 2021 (2,751 on the public instance, 2026-11-16), which is a
 * backlog, not an inbox; the backlog is cleared with one action below.
 *
 * The watchlist arm is the owner's alone: an older card shown to a visitor would be there only
 * because its CVE is watched, which is the watchlist read out one card at a time.
 */
const inboxSqlFor = (owner: boolean): string =>
  owner ? `${waitingSql} AND (COALESCE(i.published_at, i.fetched_at) >= ? OR ${watchedSql})` : `${waitingSql} AND COALESCE(i.published_at, i.fetched_at) >= ?`;

/** Who the inbox is drawn for: the owner sees the watchlist arm, anyone else the window alone. */
interface InboxOptions {
  owner?: boolean;
  offset?: number;
}

export interface InboxItem {
  id: number;
  title: string;
  url: string | null;
  kind: string;
  published_at: string | null;
  signals_json: string | null;
  source_id: string;
  source_name: string;
  /** The CVE a KEV or vulnerability item is about, for its page on this site. */
  cve_id: string | null;
  /** The CVE's description, or the item's summary, to its first sentence. */
  lead: string | null;
}

/** Words that say a sentence is about a flaw rather than about the project. */
const flawWords = /vulnerab|affect|allows?\b|could|attacker|overflow|injection|bypass|flaw|issue|exploit|cross-site|denial of service|execut|disclos|traversal|improper|missing|unauthori[sz]ed|vulnerable/i;

/** A description's first sentence, cut at a word if it runs long: what a card has room for. */
export function firstSentence(text: string | null, max = 220): string | null {
  const flat = (text ?? "").replace(/\s+/g, " ").trim();
  if (!flat) return null;
  // A full stop that ends a sentence: followed by a space and a capital, or the end. "v1.2" and "e.g. a" do not end one.
  const endOf = (from: string): number => {
    const end = /[.!?](?=\s+[A-Z(“"]|$)/.exec(from);
    return end ? end.index + 1 : from.length;
  };
  let sentence = flat.slice(0, endOf(flat));
  // A description that opens with the project's own blurb ("Wasmtime is a runtime for WebAssembly.")
  // leads with the next sentence when the first names no flaw and the next one does.
  const rest = flat.slice(sentence.length).trim();
  if (rest && !flawWords.test(sentence)) {
    const next = rest.slice(0, endOf(rest));
    if (flawWords.test(next)) sentence = next;
  }
  if (sentence.length <= max) return sentence;
  const cut = sentence.slice(0, max - 1);
  return `${cut.slice(0, Math.max(cut.lastIndexOf(" "), max / 2))}…`;
}

/** Notable, unread, untriaged timeline items from the last thirty days or on the watchlist: the inbox the board starts from. */
export function triageInbox(db: DatabaseSync, now: Date, limit = 30, options: InboxOptions = {}): InboxItem[] {
  const rows = db
    .prepare(
      `SELECT i.id, i.title, i.url, i.kind, i.published_at, i.signals_json, i.summary, s.id AS source_id, s.name AS source_name,
              CASE WHEN i.kind IN ('kev', 'vulnerability') THEN COALESCE(v.cve_id, i.external_id) END AS cve_id, v.description AS description
       FROM items i JOIN sources s ON s.id = i.source_id
       LEFT JOIN vulns v ON i.kind IN ('kev', 'vulnerability') AND v.cve_id = i.external_id
       WHERE ${inboxSqlFor(options.owner === true)}
       ORDER BY COALESCE(i.published_at, i.fetched_at) DESC, i.id DESC LIMIT ? OFFSET ?`,
    )
    .all(inboxCutoff(now), limit, Math.max(0, Math.floor(options.offset ?? 0))) as unknown as (Omit<InboxItem, "lead"> & { summary: string | null; description: string | null })[];
  // A CVE this instance has no row for still has a page here: it says where to read it.
  return rows.map(({ summary, description, ...r }) => ({ ...r, cve_id: r.cve_id && cveIdPattern.test(r.cve_id) ? r.cve_id : null, lead: firstSentence(description ?? summary) }));
}

/** How many items the inbox holds in all, however many a page draws. */
export function triageInboxCount(db: DatabaseSync, now: Date, options: InboxOptions = {}): number {
  return (db.prepare(`SELECT COUNT(*) AS n FROM items i WHERE ${inboxSqlFor(options.owner === true)}`).get(inboxCutoff(now)) as { n: number }).n;
}

/**
 * The backlog: KEV entries and notable CVEs that wait from before the window and name no watched
 * CVE. A standard release is not in it: a release is read, not dismissed in bulk, and the button
 * swept them in with the CVEs until the audit of 16 November.
 */
const backlogSql = `${waitingSql} AND i.kind IN ('kev', 'vulnerability') AND COALESCE(i.published_at, i.fetched_at) < ? AND NOT ${watchedSql}`;

/** What waits from before the window and is not on the watchlist: the backlog the inbox no longer shows. */
export function triageBacklogCount(db: DatabaseSync, now: Date, before = inboxCutoff(now)): number {
  return (db.prepare(`SELECT COUNT(*) AS n FROM items i WHERE ${backlogSql}`).get(before) as { n: number }).n;
}

/** The app_settings key that holds the last bulk dismissal's stamp, so it can be undone. */
const backlogStampKey = "triage.backlog.last";
/** How long the last bulk dismissal can be undone. */
export const backlogUndoHours = 24;

/**
 * Marks the backlog "not ours" in one go: every waiting KEV or CVE item from before `before` that
 * names no watched CVE. A watched CVE is the owner's by definition and stays in the inbox. Every
 * row it writes carries `at` as both its created and updated stamp, and `at` is kept, so
 * `undoBacklog` can take back exactly those rows the owner has not touched since. Returns how many.
 */
export function dismissBacklog(db: DatabaseSync, before: string, at: string): number {
  const n = Number(
    db
      .prepare(
        `INSERT INTO triage (subject_kind, subject_id, subject_key, state, note, due_at, created_at, updated_at)
         SELECT 'item', i.id, '', 'dismissed', NULL, NULL, ?, ? FROM items i WHERE ${backlogSql}`,
      )
      .run(at, at, before).changes,
  );
  if (n > 0) {
    db.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").run(
      backlogStampKey,
      JSON.stringify({ at, count: n }),
      at,
    );
  }
  return n;
}

/** The last bulk dismissal, while it can still be undone: when it ran and how many it marked. */
export function lastBacklogDismissal(db: DatabaseSync, now: Date): { at: string; count: number } | null {
  const row = db.prepare("SELECT value FROM app_settings WHERE key = ?").get(backlogStampKey) as { value: string } | undefined;
  const last = parseJson<{ at?: unknown; count?: unknown } | null>(row?.value ?? null, null);
  if (!last || typeof last.at !== "string" || typeof last.count !== "number") return null;
  const age = now.getTime() - Date.parse(last.at);
  if (!Number.isFinite(age) || age > backlogUndoHours * 3_600_000) return null;
  return { at: last.at, count: last.count };
}

/**
 * Takes the last bulk dismissal back: its rows, still dismissed and untouched since, are removed,
 * so those items wait in the backlog again. A row the owner has moved or noted since is theirs and
 * stays. Returns how many came back; zero once the undo window has passed.
 */
export function undoBacklog(db: DatabaseSync, now: Date): number {
  const last = lastBacklogDismissal(db, now);
  if (!last) return 0;
  const n = Number(
    db
      .prepare("DELETE FROM triage WHERE subject_kind = 'item' AND state = 'dismissed' AND note IS NULL AND due_at IS NULL AND created_at = ? AND updated_at = ?")
      .run(last.at, last.at).changes,
  );
  db.prepare("DELETE FROM app_settings WHERE key = ?").run(backlogStampKey);
  return n;
}

/** The owner's download, so every card is named. */
export function triageCsv(db: DatabaseSync): string {
  const cards = listTriage(db, { limit: null, notes: true, restrictedLabels: true });
  const lines = ["state,kind,title,url,note,due,updated"];
  for (const c of cards) lines.push(csvLine([c.state, c.subject_kind, c.title, c.url, c.note ?? "", c.due_at ?? "", c.updated_at]));
  return `${lines.join("\n")}\n`;
}
