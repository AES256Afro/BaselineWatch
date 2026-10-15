import type { DatabaseSync } from "node:sqlite";

/**
 * The Atlas: where and when the baselines moved. A release timeline per standard and a
 * change-intensity map by control family, computed from the Register's documents and changes.
 */
export interface TimelineRelease {
  documentId: number;
  key: string;
  version: string | null;
  publishedAt: string;
  changes: number;
  first: boolean;
}

export interface TimelineRow {
  sourceId: string;
  name: string;
  releases: TimelineRelease[];
}

export function releaseTimeline(db: DatabaseSync, from: string, to: string): TimelineRow[] {
  const rows = db
    .prepare(
      `SELECT d.id, d.source_id, s.name, d.document_key, d.version_label, d.published_at, d.previous_document_id,
              (SELECT COUNT(DISTINCT c.ref) FROM changes c WHERE c.to_document_id = d.id) AS changes
       FROM documents d JOIN sources s ON s.id = d.source_id
       WHERE s.group_name = 'standards' AND d.published_at >= ? AND d.published_at <= ?
       ORDER BY s.name, d.published_at, d.id`,
    )
    .all(from, to) as { id: number; source_id: string; name: string; document_key: string; version_label: string | null; published_at: string; previous_document_id: number | null; changes: number }[];
  const bySource = new Map<string, TimelineRow>();
  for (const r of rows) {
    const row = bySource.get(r.source_id) ?? { sourceId: r.source_id, name: r.name, releases: [] };
    row.releases.push({ documentId: r.id, key: r.document_key, version: r.version_label, publishedAt: r.published_at, changes: r.changes, first: r.previous_document_id === null });
    bySource.set(r.source_id, row);
  }
  return [...bySource.values()];
}

export interface HeatmapRow {
  documentId: number;
  version: string | null;
  publishedAt: string | null;
  counts: Record<string, number>;
  total: number;
  first: boolean;
}

export interface Heatmap {
  families: string[];
  rows: HeatmapRow[];
  max: number;
}

/** Changed controls per family per release of a requirement-set document (the 800-53 catalog by default). */
export function familyHeatmap(db: DatabaseSync, sourceId = "nist-sp-800-53", key = "catalog"): Heatmap {
  const docs = db
    .prepare("SELECT id, version_label, published_at, previous_document_id FROM documents WHERE source_id = ? AND document_key = ? ORDER BY published_at, id")
    .all(sourceId, key) as { id: number; version_label: string | null; published_at: string | null; previous_document_id: number | null }[];
  const familySet = new Set<string>();
  const rows: HeatmapRow[] = [];
  for (const d of docs) {
    for (const f of db.prepare("SELECT DISTINCT family FROM requirements WHERE document_id = ? AND family IS NOT NULL").all(d.id) as { family: string }[]) familySet.add(f.family);
    const counts: Record<string, number> = {};
    let total = 0;
    const changed = db
      .prepare(
        `SELECT COALESCE(r.family, p.family) AS family, COUNT(DISTINCT c.ref) AS n
         FROM changes c
         LEFT JOIN requirements r ON r.document_id = c.to_document_id AND r.ref = c.ref
         LEFT JOIN requirements p ON p.document_id = c.from_document_id AND p.ref = c.ref
         WHERE c.to_document_id = ? GROUP BY COALESCE(r.family, p.family)`,
      )
      .all(d.id) as { family: string | null; n: number }[];
    for (const c of changed) {
      if (!c.family) continue;
      counts[c.family] = c.n;
      total += c.n;
    }
    rows.push({ documentId: d.id, version: d.version_label, publishedAt: d.published_at, counts, total, first: d.previous_document_id === null });
  }
  const families = [...familySet].sort();
  const max = rows.reduce((m, r) => Math.max(m, ...Object.values(r.counts)), 0);
  return { families, rows, max };
}

export interface Velocity {
  releases: number;
  changedRequirements: number;
  kevAdditions: number;
  notableCves: number;
  affectsUs: number;
}

export function velocity(db: DatabaseSync, sinceIso: string): Velocity {
  const n = (sql: string, ...params: string[]) => (db.prepare(sql).get(...params) as { n: number }).n;
  return {
    releases: n("SELECT COUNT(*) AS n FROM documents d JOIN sources s ON s.id = d.source_id WHERE s.group_name = 'standards' AND d.previous_document_id IS NOT NULL AND d.published_at >= ?", sinceIso),
    changedRequirements: n("SELECT COUNT(DISTINCT c.to_document_id || ':' || c.ref) AS n FROM changes c JOIN documents d ON d.id = c.to_document_id WHERE d.published_at >= ?", sinceIso),
    kevAdditions: n("SELECT COUNT(*) AS n FROM items WHERE kind = 'kev' AND published_at >= ?", sinceIso),
    notableCves: n("SELECT COUNT(*) AS n FROM items WHERE kind = 'vulnerability' AND published_at >= ?", sinceIso),
    affectsUs: n("SELECT COUNT(*) AS n FROM triage WHERE state = 'affects'"),
  };
}

export interface Expectation {
  what: string;
  when: string;
  basis: string;
}

/** What is due next, from each publisher's cadence and the latest release seen. */
export function expectedNext(db: DatabaseSync, now: Date): Expectation[] {
  const out: Expectation[] = [];
  const latestStig = (db.prepare("SELECT MAX(published_at) AS at FROM documents WHERE source_id = 'disa-stigs'").get() as { at: string | null }).at;
  if (latestStig) {
    const last = new Date(latestStig);
    const quarterMonth = Math.floor(last.getUTCMonth() / 3) * 3 + 3; // the next quarter's first month
    const next = new Date(Date.UTC(last.getUTCFullYear(), quarterMonth, 1));
    const month = next.toLocaleString("en-US", { month: "long", timeZone: "UTC" });
    out.push({ what: "DISA quarterly STIG release", when: `${month} ${next.getUTCFullYear()}`, basis: `quarterly; last seen ${latestStig.slice(0, 10)}` });
  } else {
    out.push({ what: "DISA quarterly STIG release", when: "late January, April, July, October", basis: "DISA's maintenance cadence" });
  }
  const latestSct = (db.prepare("SELECT MAX(published_at) AS at FROM documents WHERE source_id = 'microsoft-sct'").get() as { at: string | null }).at;
  out.push({ what: "Microsoft Security Baseline refresh", when: "with the next Windows feature update or Office channel release", basis: latestSct ? `last toolkit publication ${latestSct.slice(0, 10)}` : "no toolkit publication seen yet" });
  const latestNist = (db.prepare("SELECT MAX(published_at) AS at FROM documents WHERE source_id = 'nist-sp-800-53' AND document_key = 'catalog'").get() as { at: string | null }).at;
  out.push({ what: "NIST SP 800-53 patch release", when: "no fixed cadence", basis: latestNist ? `last catalog change ${latestNist.slice(0, 10)}; drafts appear on the CSRC comment feed first` : "watch the CSRC drafts feed" });
  const epss = (db.prepare("SELECT value FROM app_settings WHERE key = 'epss.date'").get() as { value: string } | undefined)?.value;
  out.push({ what: "EPSS scores", when: "daily", basis: epss ? `last joined ${epss}` : "not joined yet" });
  out.push({ what: "CISA KEV additions", when: "most weekdays", basis: `${velocity(db, new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString()).kevAdditions} in the last 30 days` });
  return out;
}
