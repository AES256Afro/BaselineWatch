import type { DatabaseSync } from "node:sqlite";
import { latestExposure, type ExposureRun } from "./exposure.ts";
import { parseChanges, type NetScanChanges, type NetScanRow } from "./netscan.ts";
import { counted } from "./words.ts";

/**
 * The scans over time (Scan 2.0, S6): every network run with what it found and what changed
 * since the one before, read from the rows the daily runs already keep, and the exposure runs
 * the owner's check kept. Nothing new is stored; this is the stored runs laid out as a history,
 * and the one figure Today shows for the area.
 */

export interface NetScanSummary extends NetScanRow {
  total: number;
  resolved: number;
  sinkholed: number;
  timeout: number;
  changes: NetScanChanges | null;
}

/** The network runs, newest first, each with its canary tallies in one query rather than one per run. */
export function listNetScans(db: DatabaseSync, limit = 30): NetScanSummary[] {
  const scans = db.prepare("SELECT * FROM net_scans ORDER BY id DESC LIMIT ?").all(limit) as unknown as NetScanRow[];
  if (scans.length === 0) return [];
  const tallies = db
    .prepare(`SELECT scan_id, outcome, COUNT(*) AS n FROM net_canaries WHERE scan_id IN (${scans.map(() => "?").join(", ")}) GROUP BY scan_id, outcome`)
    .all(...scans.map((s) => s.id)) as { scan_id: number; outcome: string; n: number }[];
  // The same counting as a single run's page, so the history and the run never disagree on a total.
  return scans.map((s) => ({ ...s, ...tallyRun(tallies.filter((t) => t.scan_id === s.id)), changes: parseChanges(s.changes_json) }));
}

/** A run's canaries counted by outcome. */
export interface RunTally {
  total: number;
  resolved: number;
  sinkholed: number;
  timeout: number;
}

/**
 * What one network run says about the resolver, read from its tallies alone: nothing asked;
 * some canary resolved; the resolver answered none (every one timed out or failed); it answered
 * some, all with a block, and not the rest; or every canary came back sinkholed. Enforcement is
 * only the last — silence is never read as a block. The page's line under the tiles and Today's
 * tile both read it.
 */
export type RunVerdict = "none" | "resolving" | "silent" | "partial" | "enforced";

export function runVerdict(tally: RunTally): RunVerdict {
  if (tally.total === 0) return "none";
  if (tally.resolved > 0) return "resolving";
  if (tally.sinkholed === 0) return "silent";
  if (tally.sinkholed < tally.total) return "partial";
  return "enforced";
}

/** A run's tallies from its canary rows, by outcome; a row may carry `n`, the count of a grouped query, and otherwise counts one. */
export function tallyRun(rows: readonly { outcome: string; n?: number }[]): RunTally {
  const of = (outcome: string): number => rows.reduce((sum, r) => sum + (r.outcome === outcome ? (r.n ?? 1) : 0), 0);
  const resolved = of("resolved");
  const sinkholed = of("sinkholed");
  const timeout = of("timeout");
  return { total: resolved + sinkholed + timeout, resolved, sinkholed, timeout };
}

export interface ScanTile {
  /** "ok" when the last network run saw every canary sinkholed; "warn" when some resolved or went unanswered; "na" when none has run. */
  state: "ok" | "warn" | "na";
  figure: string;
  text: string;
  href: string;
}

/** The one figure Today shows for the Scan area: the last network run's canaries, or that none has run. */
export function scanTile(db: DatabaseSync): ScanTile {
  const last = listNetScans(db, 1)[0];
  const verdict = last ? runVerdict(last) : "none";
  if (!last || verdict === "none") return { state: "na", figure: "—", text: "network check not run", href: "/scan/network" };
  const changed = (last.changes?.newlyResolving.length ?? 0) + (last.changes?.newlySinkholed.length ?? 0);
  const also = changed ? `, ${changed} changed` : "";
  // Ok only when every canary was answered with a block: a resolver that timed out on all of
  // them sinkholed nothing, and one that timed out on some has not shown the rest blocked.
  return {
    state: verdict === "enforced" ? "ok" : "warn",
    figure: `${last.sinkholed}/${last.total}`,
    text:
      verdict === "resolving"
        ? `${counted(last.resolved, "canary", "canaries")} resolved${also}`
        : verdict === "silent"
          ? `the resolver did not answer${also}`
          : verdict === "enforced"
            ? `every canary sinkholed${also}`
            : `${counted(last.timeout, "canary", "canaries")} unanswered${also}`,
    href: "/scan/history",
  };
}

/** The owner's exposure runs: the last and the one before, as the check keeps them. */
export function exposureHistory(db: DatabaseSync): { last: ExposureRun | null; previous: ExposureRun | null } {
  const previous = (db.prepare("SELECT value FROM app_settings WHERE key = 'exposure.previous'").get() as { value: string } | undefined)?.value;
  let before: ExposureRun | null = null;
  try {
    before = previous ? (JSON.parse(previous) as ExposureRun) : null;
  } catch {
    before = null;
  }
  return { last: latestExposure(db), previous: before };
}
