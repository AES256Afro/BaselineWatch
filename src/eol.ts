import type { DatabaseSync } from "node:sqlite";
import type { FleetPlatform } from "./fleet.ts";

/**
 * endoflife.date as it bears on the fleet (N5): one row per product cycle, and the mapping from a
 * fleet release (data/platforms.yaml's ids) to the cycles that are it — Windows has two per
 * version, Home/Pro and Enterprise, with different ends. The adapter in src/adapters/endoflife.ts
 * fills the table; the Fleet page and the Wire read it.
 */

export interface EolCycle {
  product: string;
  cycle: string;
  label: string | null;
  release_date: string | null;
  eol: string;
  support: string | null;
  latest: string | null;
  latest_release_date: string | null;
  lts: number;
  link: string | null;
  seen_at: string;
}

/** The products read, in the order the fleet lists its platforms. */
export const eolProducts = ["windows", "macos", "ios", "ipados", "android", "rhel", "ubuntu"] as const;

export const productLabel: Record<string, string> = { windows: "Windows", macos: "macOS", ios: "iOS", ipados: "iPadOS", android: "Android", rhel: "RHEL", ubuntu: "Ubuntu" };

/** The endoflife.date cycles a fleet release is, with the word for each when a version has several. */
export function eolCyclesFor(platform: FleetPlatform, releaseId: string): { product: string; cycle: string; edition: string | null }[] {
  const id = releaseId.trim();
  if (platform === "windows") {
    const win10 = /^10-(\d{2}H\d)$/i.exec(id);
    const win11 = /^(\d{2}H\d)$/i.exec(id);
    const base = win10 ? `10-${win10[1]!.toLowerCase()}` : win11 ? `11-${win11[1]!.toLowerCase()}` : null;
    return base ? [{ product: "windows", cycle: `${base}-w`, edition: "Home and Pro" }, { product: "windows", cycle: `${base}-e`, edition: "Enterprise and Education" }] : [];
  }
  if (platform === "macos" || platform === "ios" || platform === "ipados" || platform === "android") return /^\d+(\.\d+)?$/.test(id) ? [{ product: platform, cycle: id, edition: null }] : [];
  if (platform === "linux") {
    const rhel = /^rhel-(\d+)$/i.exec(id);
    if (rhel) return [{ product: "rhel", cycle: rhel[1]!, edition: null }];
    const ubuntu = /^ubuntu-(\d{2}\.\d{2})$/i.exec(id);
    if (ubuntu) return [{ product: "ubuntu", cycle: ubuntu[1]!, edition: null }];
  }
  return [];
}

/** What endoflife.date holds for a fleet release: each cycle that is it, with its edition word. */
export function eolFor(db: DatabaseSync, platform: FleetPlatform, releaseId: string): (EolCycle & { edition: string | null })[] {
  const select = db.prepare("SELECT * FROM eol_cycles WHERE product = ? AND cycle = ?");
  return eolCyclesFor(platform, releaseId).flatMap((c) => {
    const row = select.get(c.product, c.cycle) as unknown as EolCycle | undefined;
    return row ? [{ ...row, edition: c.edition }] : [];
  });
}

/** A cycle's end as a person reads it: the date, "not yet", or "already". */
export function eolWord(value: string | null): string {
  if (value === null) return "—";
  if (value === "false") return "not yet";
  if (value === "true") return "already";
  return value;
}

/** Stores a product's cycles whole, replacing what was there for it. */
export function replaceEolCycles(db: DatabaseSync, product: string, rows: Omit<EolCycle, "seen_at">[], seenAt: string): void {
  const insert = db.prepare("INSERT INTO eol_cycles (product, cycle, label, release_date, eol, support, latest, latest_release_date, lts, link, seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
  db.exec("BEGIN IMMEDIATE");
  try {
    db.prepare("DELETE FROM eol_cycles WHERE product = ?").run(product);
    for (const r of rows) insert.run(r.product, r.cycle, r.label, r.release_date, r.eol, r.support, r.latest, r.latest_release_date, r.lts, r.link, seenAt);
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}
