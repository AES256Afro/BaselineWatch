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

/** The Chromium CVEs republished for Edge and the Azure Linux ones: Microsoft's documents carry them, Microsoft's count does not. */
const republishedSql = "((family = 'Microsoft Edge (Chromium-based)' AND COALESCE(vendor, '') <> 'Microsoft') OR family = 'Mariner')";

export function isRepublished(row: Pick<MsrcVulnRow, "family" | "vendor">): boolean {
  return (row.family === "Microsoft Edge (Chromium-based)" && row.vendor !== "Microsoft") || row.family === "Mariner";
}

export interface MsrcReleaseSummary {
  release_id: string;
  released_at: string | null;
  revised_at: string | null;
  total: number;
  microsoft: number;
  critical: number;
  exploited: number;
  disclosed: number;
}

/** The monthly releases this instance holds, newest first, each counted the way Microsoft's own release note counts. */
export function msrcReleases(db: DatabaseSync, limit = 12): MsrcReleaseSummary[] {
  return db
    .prepare(
      `SELECT release_id, MIN(released_at) AS released_at, MAX(revised_at) AS revised_at, COUNT(*) AS total,
         SUM(CASE WHEN NOT ${republishedSql} THEN 1 ELSE 0 END) AS microsoft,
         SUM(CASE WHEN severity = 'Critical' AND NOT ${republishedSql} THEN 1 ELSE 0 END) AS critical,
         SUM(CASE WHEN exploited = 1 AND NOT ${republishedSql} THEN 1 ELSE 0 END) AS exploited,
         SUM(CASE WHEN disclosed = 1 AND NOT ${republishedSql} THEN 1 ELSE 0 END) AS disclosed
       FROM msrc_vulns GROUP BY release_id ORDER BY released_at DESC LIMIT ?`,
    )
    .all(limit) as unknown as MsrcReleaseSummary[];
}

const severityOrder = "CASE severity WHEN 'Critical' THEN 4 WHEN 'Important' THEN 3 WHEN 'Moderate' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END";

/** One release's rows: exploited first, then disclosed, then by Microsoft's severity and CVSS. */
export function msrcRows(db: DatabaseSync, releaseId: string): MsrcVuln[] {
  const rows = db.prepare(`SELECT * FROM msrc_vulns WHERE release_id = ? ORDER BY exploited DESC, disclosed DESC, ${severityOrder} DESC, cvss_score DESC, cve_id`).all(releaseId) as unknown as MsrcVulnRow[];
  return rows.map((row) => ({ ...row, fixes: parseJson<MsrcFix[]>(row.fixes_json, []) }));
}

/** "2026-Oct" as a person says it: October 2026. */
export function releaseName(releaseId: string): string {
  const names: Record<string, string> = { Jan: "January", Feb: "February", Mar: "March", Apr: "April", May: "May", Jun: "June", Jul: "July", Aug: "August", Sep: "September", Oct: "October", Nov: "November", Dec: "December" };
  const match = /^(\d{4})-([A-Z][a-z]{2})$/.exec(releaseId);
  return match ? `${names[match[2]!] ?? match[2]} ${match[1]}` : releaseId;
}
