import type { DatabaseSync } from "node:sqlite";
import { rehearsalLine, storageLine, storageReport } from "./housekeeping.ts";
import { latestReadings } from "./devices.ts";
import { latestExposure } from "./exposure.ts";
import { failingSources } from "./pipeline.ts";
import { stateLabel, triageCounts, type TriageState } from "./triage.ts";
import { parseJson } from "./json.ts";

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
  /** The same digest without the owner's own network, devices, domains and stack; NULL on a row written before 0044. */
  public_text: string | null;
}

/**
 * The digest in two texts.
 *
 * `text` is the owner's: what this instance tracks *and* what it found about their own network,
 * devices, domains and stack. `publicText` is the first half alone. They are built in one pass
 * over the same rows, because two passes would drift.
 *
 * The split exists because `/digest` and `/api/v1/digest` are gated for *reading*, not for the
 * owner, so on a read-open instance (cybercard.net is one) anyone could fetch the digest — and it
 * names the devices with something open on them, the certificates logged for the owner's domains,
 * their watchlist's products and the LAN's sinkhole changes. `/scan/network`, `/scan/history` and
 * `/scan/devices` each hide exactly those facts from a visitor; the digest handed all three over
 * in one block. The audit of 25 October found it.
 */
export interface DigestTexts {
  text: string;
  publicText: string;
}

export function buildDigest(db: DatabaseSync, options: { from: string; to: string; baseUrl: string; period: "daily" | "weekly" }): DigestTexts {
  const { from, to, baseUrl } = options;
  const lines: string[] = [];
  const publicLines: string[] = [];
  /** What this instance tracks: anyone who may read the site may read these. */
  const both = (line: string): void => {
    lines.push(line);
    publicLines.push(line);
  };
  /** What this instance learned about the owner's own network, devices, domains and stack. */
  const mine = (line: string): void => {
    lines.push(line);
  };
  const day = (iso: string) => iso.slice(0, 10);
  both(`BaselineWatch ${options.period} digest, ${day(from)} to ${day(to)}`);
  both("");

  const kev = db
    .prepare("SELECT title, url, signals_json FROM items WHERE kind = 'kev' AND fetched_at > ? AND fetched_at <= ? ORDER BY published_at DESC LIMIT 15")
    .all(from, to) as { title: string; url: string | null; signals_json: string | null }[];
  both(`Known exploited (CISA KEV): ${kev.length ? `${kev.length} added` : "nothing new"}`);
  for (const k of kev) {
    const s = parseJson<{ dueDate?: string }>(k.signals_json, {});
    both(`- ${k.title}${s.dueDate ? ` (due ${s.dueDate})` : ""}`);
  }
  both("");

  const releases = db
    .prepare("SELECT title, url, summary FROM items WHERE kind = 'release' AND fetched_at > ? AND fetched_at <= ? ORDER BY published_at DESC LIMIT 10")
    .all(from, to) as { title: string; url: string | null; summary: string | null }[];
  both(`Standards: ${releases.length ? `${releases.length} release(s)` : "no releases"}`);
  for (const r of releases) both(`- ${r.title}${r.url ? ` ${baseUrl}${r.url}` : ""}`);
  both("");

  const watched = db
    .prepare(
      `SELECT v.cve_id, v.cvss_score, v.epss, v.kev, v.watch_labels_json, GROUP_CONCAT(DISTINCT c.field) AS fields
       FROM vuln_changes c JOIN vulns v ON v.cve_id = c.cve_id
       WHERE c.observed_at > ? AND c.observed_at <= ? AND v.watch_hit = 1
       GROUP BY v.cve_id ORDER BY v.epss DESC NULLS LAST, v.cvss_score DESC NULLS LAST LIMIT 20`,
    )
    .all(from, to) as { cve_id: string; cvss_score: number | null; epss: number | null; kev: number; watch_labels_json: string | null; fields: string }[];
  mine(`Your stack: ${watched.length ? `${watched.length} CVE(s) new or changed` : "no CVE changes"}`);
  for (const w of watched) {
    const labels = parseJson<string[]>(w.watch_labels_json, []).join(", ");
    mine(`- ${w.cve_id} (${labels})${w.cvss_score !== null ? ` CVSS ${w.cvss_score.toFixed(1)}` : ""}${w.epss !== null ? ` EPSS ${(w.epss * 100).toFixed(0)}%` : ""}${w.kev ? " KEV" : ""}: ${w.fields} ${baseUrl}/vulnerabilities/${w.cve_id}`);
  }
  mine("");

  const notable = (db.prepare("SELECT COUNT(*) AS n FROM items WHERE kind = 'vulnerability' AND fetched_at > ? AND fetched_at <= ?").get(from, to) as { n: number }).n;
  const news = (db.prepare("SELECT COUNT(*) AS n FROM items WHERE kind = 'article' AND fetched_at > ? AND fetched_at <= ?").get(from, to) as { n: number }).n;
  const starred = db
    .prepare("SELECT title, url FROM items WHERE starred = 1 AND fetched_at > ? AND fetched_at <= ? ORDER BY published_at DESC LIMIT 10")
    .all(from, to) as { title: string; url: string | null }[];
  both(`News: ${news} new stories, ${notable} notable CVEs`);
  if (starred.length) mine(`Starred: ${starred.length}`);
  for (const s of starred) mine(`- ${s.title}${s.url ? ` ${s.url}` : ""}`);
  both("");

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
    mine(`This network: ${netChanges} change(s) ${baseUrl}/scan/network`);
    for (const line of netLines) mine(line);
    if (netChanges > netLines.length) mine(`- …and ${netChanges - netLines.length} more`);
    mine("");
  }

  // The owner's devices (S7): the ones whose last reading left something open, by name.
  const devices = latestReadings(db).filter((r) => r.worst === "bad" || r.worst === "warn");
  if (devices.length) {
    mine(`Devices: ${devices.length} with something open ${baseUrl}/scan/devices`);
    for (const d of devices.slice(0, 10)) {
      const open = d.findings.filter((f) => f.state === "bad" || f.state === "warn");
      mine(`- ${d.device} (${d.worst === "bad" ? "exposed" : "behind"}): ${open.map((f) => f.title).join(", ")}; read ${day(d.read_at)}`);
    }
    mine("");
  }

  // Router and exposure (S4): the last run's findings, when any is open; an all-clear says nothing here.
  const exposure = latestExposure(db);
  const exposed = exposure?.findings.filter((f) => f.state === "bad" || f.state === "warn") ?? [];
  if (exposed.length) {
    mine(`Exposure: ${exposed.length} finding(s) on the last run ${baseUrl}/scan/network#exposure`);
    for (const f of exposed) mine(`- ${f.title}: ${f.text}`);
    mine("");
  }

  // Certificates the transparency logs showed for the owner's domains in the window (S3): each one is worth a look.
  const certs = db.prepare("SELECT domain, names, issuer, not_before FROM ct_certs WHERE seen_at > ? AND seen_at <= ? ORDER BY not_before DESC LIMIT 20").all(from, to) as { domain: string; names: string; issuer: string | null; not_before: string | null }[];
  if (certs.length) {
    mine(`Certificates logged: ${certs.length} for your domains ${baseUrl}/scan/domain`);
    for (const c of certs.slice(0, 10)) mine(`- ${c.names.split("\n").join(", ")}${c.issuer ? ` by ${c.issuer}` : ""}${c.not_before ? `, from ${c.not_before.slice(0, 10)}` : ""}`);
    mine("");
  }

  const counts = triageCounts(db);
  const open = (["affects", "reviewing", "new"] as TriageState[]).map((s) => `${counts[s]} ${stateLabel[s].toLowerCase()}`).join(", ");
  const due = db.prepare("SELECT COUNT(*) AS n FROM triage WHERE due_at IS NOT NULL AND due_at <= ? AND state NOT IN ('done', 'dismissed')").get(day(to)) as { n: number };
  both(`Triage: ${open}${due.n ? `; ${due.n} past due` : ""} ${baseUrl}/triage`);
  // How long, not just which: an hour is a passing 403, a day is something to act on (M13.2).
  const failing = failingSources(db, new Date(to));
  if (failing.length) {
    both(`Sources failing: ${failing.map((f) => (f.hours === null ? f.name : `${f.name} (${f.hours} h)`)).join(", ")} ${baseUrl}/sources`);
  }
  both(storageLine(storageReport(db), baseUrl));
  const rehearsal = rehearsalLine(db, new Date(to), baseUrl);
  if (rehearsal) both(rehearsal);
  // The lesson of the three-day NVD stall: staleness is a headline, not something to go look for.
  const newestVuln = (db.prepare("SELECT MAX(last_modified_at) AS m FROM vulns").get() as { m: string | null }).m;
  if (newestVuln) {
    const ageDays = (Date.parse(to) - Date.parse(newestVuln)) / 86_400_000;
    if (ageDays >= 1.5) both(`Pipeline: the newest CVE change is ${Math.floor(ageDays)} day(s) old — the CVE pull may be stuck ${baseUrl}/sources`);
  }
  const tidy = (out: string[]): string => out.join("\n").replace(/\n{3,}/g, "\n\n").trim();
  return { text: tidy(lines), publicText: tidy(publicLines) };
}

/**
 * The text of a digest as this caller may read it. The owner gets all of it; everyone else gets
 * the half without the owner's own network, devices, domains and stack. A row written before
 * migration 0044 has no public half, and a guess at which of its lines were safe would be worse
 * than saying so, so a visitor is told it is the owner's.
 */
export function digestTextFor(d: DigestRow, owner: boolean): string {
  if (owner) return d.text;
  return d.public_text ?? "This digest was written before BaselineWatch separated the owner's own network from the part anyone may read, so it is the owner's alone. The next one will have a public half.";
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
  const { text, publicText } = buildDigest(db, { from, to, baseUrl: options.baseUrl, period: options.period });
  const id = Number(
    db
      .prepare("INSERT INTO digests (period, covers_from, covers_to, generated_at, text, public_text) VALUES (?, ?, ?, ?, ?, ?)")
      .run(options.period, from, to, to, text, publicText).lastInsertRowid,
  );
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

/**
 * Whether a digest should run now: the local hour has arrived and none has been written for the
 * period yet.
 *
 * A weekly digest prefers Monday but is not held to it. Requiring `weekday === 1` meant a process
 * down for all of one Monday wrote no digest that week and waited for the next — a week of
 * silence from a feature whose whole job is not to be silent. So: on a Monday it runs if none was
 * written today; on any other day it runs only once seven days have passed, which is Monday
 * again in the ordinary case and the day the instance came back in the case this fixes.
 */
export function digestDue(db: DatabaseSync, options: { now: Date; timeZone: string; period: "daily" | "weekly" | "off"; hour: number }): boolean {
  if (options.period === "off") return false;
  const clock = localClock(options.now, options.timeZone);
  if (clock.hour < options.hour) return false;
  const last = latestDigest(db);
  if (!last) return options.period === "daily" || clock.weekday === 1;
  const wroteToday = localClock(new Date(last.generated_at), options.timeZone).dateKey === clock.dateKey;
  if (wroteToday) return false;
  if (options.period === "daily") return true;
  if (clock.weekday === 1) return true;
  // Not a Monday: only if a whole week has gone by, so the catch-up happens once and not daily.
  return options.now.getTime() - Date.parse(last.generated_at) >= 7 * 86_400_000;
}
