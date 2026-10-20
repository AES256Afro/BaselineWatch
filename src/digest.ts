import type { DatabaseSync } from "node:sqlite";
import { stateLabel, triageCounts, type TriageState } from "./triage.ts";

/**
 * The digest: what moved since the last one, as plain text a notifier can carry and the
 * /digest page can show. Daily at a local hour, or weekly on Monday.
 */
export interface DigestRow {
  id: number;
  period: string;
  covers_from: string;
  covers_to: string;
  generated_at: string;
  text: string;
}

function parseJson<T>(text: string | null, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

export function buildDigest(db: DatabaseSync, options: { from: string; to: string; baseUrl: string; period: "daily" | "weekly" }): string {
  const { from, to, baseUrl } = options;
  const lines: string[] = [];
  const day = (iso: string) => iso.slice(0, 10);
  lines.push(`BaselineWatch ${options.period} digest, ${day(from)} to ${day(to)}`);
  lines.push("");

  const kev = db
    .prepare("SELECT title, url, signals_json FROM items WHERE kind = 'kev' AND fetched_at > ? AND fetched_at <= ? ORDER BY published_at DESC LIMIT 15")
    .all(from, to) as { title: string; url: string | null; signals_json: string | null }[];
  lines.push(`Known exploited (CISA KEV): ${kev.length ? `${kev.length} added` : "nothing new"}`);
  for (const k of kev) {
    const s = parseJson<{ dueDate?: string }>(k.signals_json, {});
    lines.push(`- ${k.title}${s.dueDate ? ` (due ${s.dueDate})` : ""}`);
  }
  lines.push("");

  const releases = db
    .prepare("SELECT title, url, summary FROM items WHERE kind = 'release' AND fetched_at > ? AND fetched_at <= ? ORDER BY published_at DESC LIMIT 10")
    .all(from, to) as { title: string; url: string | null; summary: string | null }[];
  lines.push(`Standards: ${releases.length ? `${releases.length} release(s)` : "no releases"}`);
  for (const r of releases) lines.push(`- ${r.title}${r.url ? ` ${baseUrl}${r.url}` : ""}`);
  lines.push("");

  const watched = db
    .prepare(
      `SELECT v.cve_id, v.cvss_score, v.epss, v.kev, v.watch_labels_json, GROUP_CONCAT(DISTINCT c.field) AS fields
       FROM vuln_changes c JOIN vulns v ON v.cve_id = c.cve_id
       WHERE c.observed_at > ? AND c.observed_at <= ? AND v.watch_hit = 1
       GROUP BY v.cve_id ORDER BY v.epss DESC NULLS LAST, v.cvss_score DESC NULLS LAST LIMIT 20`,
    )
    .all(from, to) as { cve_id: string; cvss_score: number | null; epss: number | null; kev: number; watch_labels_json: string | null; fields: string }[];
  lines.push(`Your stack: ${watched.length ? `${watched.length} CVE(s) new or changed` : "no CVE changes"}`);
  for (const w of watched) {
    const labels = parseJson<string[]>(w.watch_labels_json, []).join(", ");
    lines.push(`- ${w.cve_id} (${labels})${w.cvss_score !== null ? ` CVSS ${w.cvss_score.toFixed(1)}` : ""}${w.epss !== null ? ` EPSS ${(w.epss * 100).toFixed(0)}%` : ""}${w.kev ? " KEV" : ""}: ${w.fields} ${baseUrl}/vulnerabilities/${w.cve_id}`);
  }
  lines.push("");

  const notable = (db.prepare("SELECT COUNT(*) AS n FROM items WHERE kind = 'vulnerability' AND fetched_at > ? AND fetched_at <= ?").get(from, to) as { n: number }).n;
  const news = (db.prepare("SELECT COUNT(*) AS n FROM items WHERE kind = 'article' AND fetched_at > ? AND fetched_at <= ?").get(from, to) as { n: number }).n;
  const starred = db
    .prepare("SELECT title, url FROM items WHERE starred = 1 AND fetched_at > ? AND fetched_at <= ? ORDER BY published_at DESC LIMIT 10")
    .all(from, to) as { title: string; url: string | null }[];
  lines.push(`News: ${news} new stories, ${notable} notable CVEs${starred.length ? `, ${starred.length} starred` : ""}`);
  for (const s of starred) lines.push(`- ${s.title}${s.url ? ` ${s.url}` : ""}`);
  lines.push("");

  // The network scan (M12.3): a day-over-day change is news; an unchanged run says nothing here.
  const scans = db.prepare("SELECT changes_json FROM net_scans WHERE finished_at > ? AND finished_at <= ? AND changes_json IS NOT NULL ORDER BY id").all(from, to) as { changes_json: string }[];
  const netLines: string[] = [];
  let netChanges = 0;
  for (const scan of scans) {
    const changes = parseJson<{ resolverChanged?: { from: string | null; to: string | null } | null; newlyResolving?: { category: string; name: string }[]; newlySinkholed?: { category: string; name: string }[] }>(scan.changes_json, {});
    if (changes.resolverChanged) {
      netLines.push(`- the resolver changed: ${changes.resolverChanged.from ?? "none"} → ${changes.resolverChanged.to ?? "none"}`);
      netChanges += 1;
    }
    for (const c of (changes.newlyResolving ?? []).slice(0, 10)) netLines.push(`- ${c.name} (${c.category}) now resolves; it was sinkholed`);
    for (const c of (changes.newlySinkholed ?? []).slice(0, 10)) netLines.push(`- ${c.name} (${c.category}) is now sinkholed`);
    netChanges += (changes.newlyResolving?.length ?? 0) + (changes.newlySinkholed?.length ?? 0);
  }
  if (netChanges > 0) {
    lines.push(`This network: ${netChanges} change(s) ${baseUrl}/scan/network`);
    lines.push(...netLines);
    if (netChanges > netLines.length) lines.push(`- …and ${netChanges - netLines.length} more`);
    lines.push("");
  }

  const counts = triageCounts(db);
  const open = (["affects", "reviewing", "new"] as TriageState[]).map((s) => `${counts[s]} ${stateLabel[s].toLowerCase()}`).join(", ");
  const due = db.prepare("SELECT COUNT(*) AS n FROM triage WHERE due_at IS NOT NULL AND due_at <= ? AND state NOT IN ('done', 'dismissed')").get(day(to)) as { n: number };
  lines.push(`Triage: ${open}${due.n ? `; ${due.n} past due` : ""} ${baseUrl}/triage`);
  const failing = db.prepare("SELECT name FROM sources WHERE enabled = 1 AND last_status = 'error' ORDER BY name").all() as { name: string }[];
  if (failing.length) lines.push(`Sources failing: ${failing.map((f) => f.name).join(", ")} ${baseUrl}/sources`);
  // The lesson of the three-day NVD stall: staleness is a headline, not something to go look for.
  const newestVuln = (db.prepare("SELECT MAX(last_modified_at) AS m FROM vulns").get() as { m: string | null }).m;
  if (newestVuln) {
    const ageDays = (Date.parse(to) - Date.parse(newestVuln)) / 86_400_000;
    if (ageDays >= 1.5) lines.push(`Pipeline: the newest CVE change is ${Math.floor(ageDays)} day(s) old — the CVE pull may be stuck ${baseUrl}/sources`);
  }
  return lines.join("\n").trim();
}

export function latestDigest(db: DatabaseSync): DigestRow | null {
  return (db.prepare("SELECT * FROM digests ORDER BY id DESC LIMIT 1").get() as unknown as DigestRow | undefined) ?? null;
}

export function listDigests(db: DatabaseSync, limit = 30): DigestRow[] {
  return db.prepare("SELECT * FROM digests ORDER BY id DESC LIMIT ?").all(limit) as unknown as DigestRow[];
}

/** Writes a digest covering since the last one (or the period's length) up to `now`. */
export function writeDigest(db: DatabaseSync, options: { now: Date; baseUrl: string; period: "daily" | "weekly" }): DigestRow {
  const previous = latestDigest(db);
  const span = options.period === "weekly" ? 7 : 1;
  const to = options.now.toISOString();
  const from = previous?.covers_to ?? new Date(options.now.getTime() - span * 24 * 60 * 60 * 1000).toISOString();
  const text = buildDigest(db, { from, to, baseUrl: options.baseUrl, period: options.period });
  const id = Number(db.prepare("INSERT INTO digests (period, covers_from, covers_to, generated_at, text) VALUES (?, ?, ?, ?, ?)").run(options.period, from, to, to, text).lastInsertRowid);
  return db.prepare("SELECT * FROM digests WHERE id = ?").get(id) as unknown as DigestRow;
}

/** The local hour and weekday in a time zone, without a date library. */
export function localClock(now: Date, timeZone: string): { hour: number; weekday: number; dateKey: string } {
  let parts: Intl.DateTimeFormatPart[];
  try {
    parts = new Intl.DateTimeFormat("en-US", { timeZone, hour: "numeric", hour12: false, weekday: "short", year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(now);
  } catch {
    parts = new Intl.DateTimeFormat("en-US", { timeZone: "UTC", hour: "numeric", hour12: false, weekday: "short", year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(now);
  }
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? "";
  const weekdays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  return { hour: Number(get("hour")) % 24, weekday: weekdays.indexOf(get("weekday")), dateKey: `${get("year")}-${get("month")}-${get("day")}` };
}

/** Whether a digest should run now: the local hour has arrived, it is the right day, and none was written for that local date. */
export function digestDue(db: DatabaseSync, options: { now: Date; timeZone: string; period: "daily" | "weekly" | "off"; hour: number }): boolean {
  if (options.period === "off") return false;
  const clock = localClock(options.now, options.timeZone);
  if (clock.hour < options.hour) return false;
  if (options.period === "weekly" && clock.weekday !== 1) return false;
  const last = latestDigest(db);
  if (!last) return true;
  return localClock(new Date(last.generated_at), options.timeZone).dateKey !== clock.dateKey;
}
