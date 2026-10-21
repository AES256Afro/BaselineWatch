import type { DatabaseSync } from "node:sqlite";
import { parseJson } from "./json.ts";

/**
 * Microsoft's Security Update Guide as it bears on one CVE (N5): the KB that fixes it on each
 * product, Microsoft's own severity, and whether Microsoft says it is exploited or was publicly
 * disclosed. One row per CVE, from the monthly CVRF document that carries it; the adapter in
 * src/adapters/msrc.ts fills the table, the Fix panel and the CVE chips read it.
 */

export interface MsrcFix {
  /** The KB article number, when the fix is one; a Chromium or Azure Linux row has none. */
  kb: string | null;
  /** The support article for a KB, else the link Microsoft gave (a catalog search, release notes). */
  url: string | null;
  /** What Microsoft called it when it is not a KB: "Release Notes", a package version. */
  label: string | null;
  /** Product names with the "for x64-based Systems" suffixes folded away. */
  products: string[];
  fixedBuild: string | null;
  restart: boolean | null;
}

export interface MsrcVulnDraft {
  cveId: string;
  releaseId: string;
  title: string;
  family: string | null;
  vendor: string | null;
  severity: string | null;
  exploited: boolean;
  disclosed: boolean;
  exploitability: string | null;
  cvssScore: number | null;
  cvssVector: string | null;
  description: string | null;
  fixes: MsrcFix[];
  releasedAt: string | null;
  revisedAt: string | null;
}

export interface MsrcVulnRow {
  cve_id: string;
  release_id: string;
  title: string;
  family: string | null;
  vendor: string | null;
  severity: string | null;
  exploited: number;
  disclosed: number;
  exploitability: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  description: string | null;
  fixes_json: string;
  released_at: string | null;
  revised_at: string | null;
  seen_at: string;
}

export const releaseNoteUrl = (releaseId: string): string => `https://msrc.microsoft.com/update-guide/releaseNote/${releaseId}`;
export const kbUrl = (kb: string): string => `https://support.microsoft.com/help/${kb}`;

/** Stores a release's rows; a CVE re-released in a later month takes the later month's words. */
export function upsertMsrcVulns(db: DatabaseSync, drafts: MsrcVulnDraft[], seenAt: string): { inserted: number; updated: number } {
  const count = (): number => (db.prepare("SELECT COUNT(*) AS n FROM msrc_vulns").get() as { n: number }).n;
  const before = count();
  const upsert = db.prepare(
    `INSERT INTO msrc_vulns (cve_id, release_id, title, family, vendor, severity, exploited, disclosed, exploitability, cvss_score, cvss_vector, description, fixes_json, released_at, revised_at, seen_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (cve_id) DO UPDATE SET release_id = excluded.release_id, title = excluded.title, family = excluded.family, vendor = excluded.vendor,
       severity = excluded.severity, exploited = excluded.exploited, disclosed = excluded.disclosed, exploitability = excluded.exploitability,
       cvss_score = excluded.cvss_score, cvss_vector = excluded.cvss_vector, description = excluded.description, fixes_json = excluded.fixes_json,
       released_at = excluded.released_at, revised_at = excluded.revised_at, seen_at = excluded.seen_at`,
  );
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const d of drafts) {
      upsert.run(d.cveId, d.releaseId, d.title, d.family, d.vendor, d.severity, d.exploited ? 1 : 0, d.disclosed ? 1 : 0, d.exploitability, d.cvssScore, d.cvssVector, d.description, JSON.stringify(d.fixes), d.releasedAt, d.revisedAt, seenAt);
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
  const inserted = count() - before;
  return { inserted, updated: Math.max(0, drafts.length - inserted) };
}

export type MsrcVuln = MsrcVulnRow & { fixes: MsrcFix[] };

/** What the guide says about one CVE, or null when Microsoft has not published it. */
export function msrcFor(db: DatabaseSync, cveId: string): MsrcVuln | null {
  const row = db.prepare("SELECT * FROM msrc_vulns WHERE cve_id = ?").get(cveId.toUpperCase()) as unknown as MsrcVulnRow | undefined;
  return row ? { ...row, fixes: parseJson<MsrcFix[]>(row.fixes_json, []) } : null;
}

/** For a page of CVE rows: which ones Microsoft marks exploited or publicly disclosed, in one query. */
export function msrcFlags(db: DatabaseSync, cveIds: string[]): Map<string, { exploited: boolean; disclosed: boolean }> {
  const out = new Map<string, { exploited: boolean; disclosed: boolean }>();
  if (cveIds.length === 0) return out;
  const rows = db
    .prepare(`SELECT cve_id, exploited, disclosed FROM msrc_vulns WHERE (exploited = 1 OR disclosed = 1) AND cve_id IN (${cveIds.map(() => "?").join(", ")})`)
    .all(...cveIds.map((c) => c.toUpperCase())) as { cve_id: string; exploited: number; disclosed: number }[];
  for (const r of rows) out.set(r.cve_id, { exploited: r.exploited === 1, disclosed: r.disclosed === 1 });
  return out;
}
