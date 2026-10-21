import type { DatabaseSync } from "node:sqlite";
import { latestExposure, type ExposureRun } from "./exposure.ts";
import { parseChanges, type NetScanChanges, type NetScanRow } from "./netscan.ts";

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
  return scans.map((s) => {
    const of = (outcome: string): number => tallies.find((t) => t.scan_id === s.id && t.outcome === outcome)?.n ?? 0;
    const resolved = of("resolved");
    const sinkholed = of("sinkholed");
    const timeout = of("timeout");
    return { ...s, total: resolved + sinkholed + timeout, resolved, sinkholed, timeout, changes: parseChanges(s.changes_json) };
  });
}

export interface ScanTile {
  /** "ok" when the last network run saw every canary sinkholed; "warn" when some resolved; "na" when none has run. */
  state: "ok" | "warn" | "na";
  figure: string;
  text: string;
  href: string;
}

/** The one figure Today shows for the Scan area: the last network run's canaries, or that none has run. */
export function scanTile(db: DatabaseSync): ScanTile {
  const last = listNetScans(db, 1)[0];
  if (!last || last.total === 0) return { state: "na", figure: "—", text: "network check not run", href: "/scan/network" };
  const changed = (last.changes?.newlyResolving.length ?? 0) + (last.changes?.newlySinkholed.length ?? 0);
  return {
    state: last.resolved === 0 ? "ok" : "warn",
    figure: `${last.sinkholed}/${last.total}`,
    text: last.resolved === 0 ? `every canary sinkholed${changed ? `, ${changed} changed` : ""}` : `${last.resolved} canar${last.resolved === 1 ? "y" : "ies"} resolved${changed ? `, ${changed} changed` : ""}`,
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
