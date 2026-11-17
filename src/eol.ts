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

/**
 * endoflife.date's cycle suffix for a Windows EditionID, with the word for it. Microsoft's own
 * grouping: Home and Pro (Core*, Professional*, which includes Pro Education and Pro for
 * Workstations) on the -w cycle; Enterprise and Education (and Enterprise multi-session, whose
 * EditionID is ServerRdsh, and IoT Enterprise) on -e; the long-term servicing channels on their
 * own. A Server edition is its own product; null for an edition this does not know.
 */
export function windowsEdition(edition: string | null | undefined): { suffix: "w" | "e" | "e-lts" | "iot-lts"; word: string } | "server" | null {
  const e = (edition ?? "").trim().toLowerCase();
  if (!e) return null;
  if (/^iotenterprises/.test(e)) return { suffix: "iot-lts", word: "IoT Enterprise LTSC" };
  if (/^enterprises/.test(e)) return { suffix: "e-lts", word: "Enterprise LTSC" };
  if (e === "serverrdsh" || /^(enterprise|education|iotenterprise)/.test(e)) return { suffix: "e", word: "Enterprise and Education" };
  if (/^server/.test(e)) return "server";
  if (/^(core|professional)/.test(e)) return { suffix: "w", word: "Home and Pro" };
  return null;
}

/** A Windows edition as windowsEdition reads it, other than a Server edition. */
export type WindowsEdition = Exclude<ReturnType<typeof windowsEdition>, "server" | null>;

/**
 * The endoflife.date cycles a fleet release is, with the word for each when a version has several.
 * Given a Windows edition, only that edition's cycle — and, for Home/Pro and Enterprise/Education,
 * the bare cycle Windows 10 22H2 uses for every edition — in that order.
 */
export function eolCyclesFor(platform: FleetPlatform, releaseId: string, edition?: WindowsEdition): { product: string; cycle: string; edition: string | null }[] {
  const id = releaseId.trim();
  if (platform === "windows") {
    const win10 = /^10-(\d{2}H\d|\d{4})$/i.exec(id);
    const win11 = /^(\d{2}H\d)$/i.exec(id);
    const base = win10 ? `10-${win10[1]!.toLowerCase()}` : win11 ? `11-${win11[1]!.toLowerCase()}` : null;
    if (!base) return [];
    if (edition) {
      const own = { product: "windows", cycle: `${base}-${edition.suffix}`, edition: edition.word };
      return edition.suffix === "w" || edition.suffix === "e" ? [own, { product: "windows", cycle: base, edition: edition.word }] : [own];
    }
    // endoflife.date splits a Windows 11 release by edition (-w, -e); Windows 10 22H2 is one cycle,
    // "10-22h2", so a Windows 10 release is asked for both forms and keeps whichever exists.
    const split = [{ product: "windows", cycle: `${base}-w`, edition: "Home and Pro" }, { product: "windows", cycle: `${base}-e`, edition: "Enterprise and Education" }];
    return win10 ? [...split, { product: "windows", cycle: base, edition: null }] : split;
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
export function eolFor(db: DatabaseSync, platform: FleetPlatform, releaseId: string, edition?: WindowsEdition): (EolCycle & { edition: string | null })[] {
  const select = db.prepare("SELECT * FROM eol_cycles WHERE product = ? AND cycle = ?");
  return eolCyclesFor(platform, releaseId, edition).flatMap((c) => {
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
