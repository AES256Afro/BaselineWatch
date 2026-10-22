import type { DatabaseSync } from "node:sqlite";

/**
 * NVD's CPE match criteria with their version ranges: one row per cpeMatch entry of a CVE's
 * configurations, in vuln_cpe_matches (migration 0043). vulns.cpes_json keeps the vulnerable
 * criteria strings as before; this table adds the bounds NVD attaches to a criterion, so a later
 * change can ask whether version X of vendor:product falls inside any of them. Nothing matches an
 * installed application against them yet; rangesFor() is the one reader.
 */

/** One cpeMatch entry of an NVD API 2.0 configuration node, as NVD writes it. */
export interface NvdCpeMatch {
  vulnerable?: boolean;
  criteria?: string;
  matchCriteriaId?: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

/** An NVD configuration: nodes of entries, OR within a node, AND across a configuration's nodes when it says so. */
export interface NvdConfiguration {
  operator?: string;
  negate?: boolean;
  nodes?: { operator?: string; negate?: boolean; cpeMatch?: NvdCpeMatch[] }[];
}

/** A criterion with its range, the way vuln_cpe_matches keeps it. */
export interface CpeMatch {
  /** The criterion as NVD wrote it, escapes and all. */
  criteria: string;
  /** a (application), o (operating system) or h (hardware). */
  part: string;
  vendor: string;
  product: string;
  /** The criterion's own version field: "*" when a range says it, "-" for none, else one version. */
  version: string;
  versionStart: string | null;
  /** Whether the start is inside the range; null when there is no start. */
  startInclusive: boolean | null;
  versionEnd: string | null;
  endInclusive: boolean | null;
  /** False for the platform a match is conditioned on, the "running on" side of an AND configuration. */
  vulnerable: boolean;
}

interface CpeMatchRow {
  cve_id: string;
  criteria: string;
  part: string;
  vendor: string;
  product: string;
  version: string;
  version_start: string | null;
  start_inclusive: number | null;
  version_end: string | null;
  end_inclusive: number | null;
  vulnerable: number;
}

/**
 * The fields of a CPE 2.3 formatted string: cpe, 2.3, part, vendor, product, version, update,
 * edition, language, sw_edition, target_sw, target_hw, other. A colon inside a value is escaped
 * with a backslash, so this is not a plain split on ":".
 */
export function splitCpe(criteria: string): string[] {
  const fields: string[] = [];
  let current = "";
  for (let i = 0; i < criteria.length; i += 1) {
    const ch = criteria[i]!;
    if (ch === "\\" && i + 1 < criteria.length) {
      current += ch + criteria[i + 1];
      i += 1;
    } else if (ch === ":") {
      fields.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}

/** One entry as a row, or null when its criterion is not a CPE 2.3 string with a part, vendor, product and version. */
export function cpeMatchOf(entry: NvdCpeMatch): CpeMatch | null {
  if (!entry.criteria) return null;
  const fields = splitCpe(entry.criteria);
  if (fields[0] !== "cpe" || fields[1] !== "2.3" || fields.length < 6) return null;
  const [, , part, vendor, product, version] = fields;
  if (!part || !vendor || !product || !version) return null;
  const versionStart = entry.versionStartIncluding ?? entry.versionStartExcluding ?? null;
  const versionEnd = entry.versionEndIncluding ?? entry.versionEndExcluding ?? null;
  return {
    criteria: entry.criteria,
    part,
    vendor: vendor.toLowerCase(),
    product: product.toLowerCase(),
    version,
    versionStart,
    startInclusive: versionStart === null ? null : entry.versionStartIncluding !== undefined,
    versionEnd,
    endInclusive: versionEnd === null ? null : entry.versionEndIncluding !== undefined,
    vulnerable: entry.vulnerable === true,
  };
}

/**
 * Every cpeMatch entry of a record's configurations, in order, each once: NVD repeats a criterion
 * across configurations (once alone, once as the vulnerable side of an AND), and a row says the
 * same thing wherever it sat. The same criterion with other bounds is another row.
 */
export function cpeMatchesOf(configurations: NvdConfiguration[]): CpeMatch[] {
  const out: CpeMatch[] = [];
  const seen = new Set<string>();
  for (const configuration of configurations) {
    for (const node of configuration.nodes ?? []) {
      for (const entry of node.cpeMatch ?? []) {
        const match = cpeMatchOf(entry);
        if (!match) continue;
        const key = [match.criteria, match.versionStart, match.startInclusive, match.versionEnd, match.endInclusive, match.vulnerable].join("\u0000");
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(match);
      }
    }
  }
  return out;
}

/** Replaces a CVE's rows whole with what its record says now. The caller holds the transaction. */
export function replaceCpeMatches(db: DatabaseSync, cveId: string, matches: CpeMatch[]): void {
  db.prepare("DELETE FROM vuln_cpe_matches WHERE cve_id = ?").run(cveId);
  if (matches.length === 0) return;
  const insert = db.prepare(
    `INSERT INTO vuln_cpe_matches (cve_id, criteria, part, vendor, product, version, version_start, start_inclusive, version_end, end_inclusive, vulnerable)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const flag = (value: boolean | null): number | null => (value === null ? null : value ? 1 : 0);
  for (const m of matches) {
    insert.run(cveId, m.criteria, m.part, m.vendor, m.product, m.version, m.versionStart, flag(m.startInclusive), m.versionEnd, flag(m.endInclusive), m.vulnerable ? 1 : 0);
  }
}

/**
 * Every row that names a vendor and product, across every CVE, by CVE id then in the order NVD
 * wrote them: the question "is version X of vendor:product inside any range of any CVE" starts
 * here. Names are matched as NVD writes them, lowercase; the caller's case does not matter.
 */
export function rangesFor(db: DatabaseSync, vendor: string, product: string): (CpeMatch & { cveId: string })[] {
  const rows = db
    .prepare("SELECT * FROM vuln_cpe_matches WHERE vendor = ? AND product = ? ORDER BY cve_id, id")
    .all(vendor.trim().toLowerCase(), product.trim().toLowerCase()) as unknown as CpeMatchRow[];
  return rows.map((r) => ({
    cveId: r.cve_id,
    criteria: r.criteria,
    part: r.part,
    vendor: r.vendor,
    product: r.product,
    version: r.version,
    versionStart: r.version_start,
    startInclusive: r.start_inclusive === null ? null : r.start_inclusive === 1,
    versionEnd: r.version_end,
    endInclusive: r.end_inclusive === null ? null : r.end_inclusive === 1,
    vulnerable: r.vulnerable === 1,
  }));
}
