import type { DatabaseSync } from "node:sqlite";
import { fixContext, fixTags, matchingEntries, type MitigationEntry } from "./fix.ts";
import { parseJson } from "./json.ts";
import { kbUrl, type MsrcFix } from "./msrc.ts";
import { movedInWindowSql, notableInWindowSql, scopeSql, type AffectedPackage, type VulnRow } from "./vulns.ts";
import type { PlatformChoice } from "./platforms.ts";

/**
 * Today's work, keyed by the remedy rather than by the CVE.
 *
 * `src/fix.ts` answers "what has been published for this CVE" one CVE at a time, which is the
 * right shape for a CVE page and the wrong one for a morning. Nobody patches a CVE; they install
 * an update, and one October cumulative is nine rows in the table and one evening's work. This
 * inverts the map: the remedy is the row, the CVEs it clears are its contents, and a CVE with no
 * published remedy is still a row, because "nothing yet" is an answer and not an omission.
 *
 * Four buckets, in the order a person can act on them: `install` (a named artefact — a KB, a
 * fixed version, a vendor's own release — that you can apply today), `published` (a fix exists but
 * no installable version is named: the vendor's advisory to read, or a commit upstream),
 * `mitigate` (the publisher has said what to do but shipped no fix), and `none`.
 *
 * That second bucket is the one that keeps the page honest. Most NVD references tagged `Patch` are
 * git commits and bug-tracker entries: they prove a fix exists, they are not an update you install,
 * and counting them as fixes turned a quiet week into "122 updates" on real data. They are grouped
 * by the host that holds them, which is the only grouping that means anything for a commit.
 *
 * Everything here is already in the database. Nothing is scored, ranked by a model, or guessed:
 * a remedy appears because a publisher published it, and it carries that publisher's own address.
 */

export type RemedyKind = "install" | "advisory" | "upstream" | "mitigate" | "none";

export interface RemedyCve {
  cveId: string;
  kev: boolean;
  watch: boolean;
  cvss: number | null;
  epss: number | null;
  /** The earliest KEV due date on this CVE, when CISA set one. */
  dueDate: string | null;
}

export interface Remedy {
  /** Stable within a render; what two CVEs must share to be the same job. */
  key: string;
  kind: RemedyKind;
  /** "Install", "Upgrade", "Update to" — null where the remedy is the publisher's own sentence. */
  verb: string | null;
  /** The thing to do: a KB number, a fixed version, an advisory title, CISA's required action. */
  what: string;
  /** Where it applies: the products Microsoft names, an ecosystem, a platform. */
  where: string | null;
  /** The line under it: which document said so. */
  detail: string;
  /** The publisher's own address for this remedy, where one is published. */
  url: string | null;
  cves: RemedyCve[];
  kevCount: number;
  watchCount: number;
  /** The earliest KEV due date across its CVEs, so the list can lead with a date someone owes. */
  dueDate: string | null;
}

export interface FixList {
  install: Remedy[];
  /** A fix exists but names no installable version: the vendor's advisory, then upstream commits. */
  published: Remedy[];
  mitigate: Remedy[];
  none: Remedy[];
  /** CVEs read for this list. */
  considered: number;
  /** Of those, how many have an update that can actually be installed. */
  fixed: number;
  /** How many candidates the window held in all; `considered` is the prefix that was read. */
  total: number;
}

/** The default cap: enough for a busy Patch Tuesday, bounded enough that the page stays a page. */
export const candidateLimit = 150;

/**
 * The CVEs worth a remedy row: ones that moved in the window and are notable by the same line the
 * Wire uses (src/vulns.ts).
 *
 * Both halves of that sentence were wrong when this shipped, and the page said so in its own
 * numbers: 803 candidates in a day, of which exactly two had been published by NVD inside the
 * window, and 117 of the 150 it drew were Linux kernel entries whose only reference is a git
 * commit — which is why the "install" group read zero while the database held three thousand
 * CVEs with Microsoft KBs against them.
 *
 * So the window is now published-or-really-changed rather than anything `vuln_changes` touched,
 * and a CVE earns its row by being exploited, watched, likely to be exploited or newly critical —
 * not by naming a platform the fleet happens to run. The kernel publishes hundreds of those a
 * week and they are answered by taking your distribution's updates, not by reading 113 rows.
 * They are all still in the table, which is where every CVE belongs.
 */
/** A CVE the owner marked done or not theirs has left the work, by Today's own button or the CVE page's. */
const settledSql = "NOT EXISTS (SELECT 1 FROM triage t WHERE t.subject_kind = 'vuln' AND t.subject_id = v.id AND t.subject_key = '' AND t.state IN ('done', 'dismissed'))";

/** Today narrowed to one platform, or to the most dangerous, as the picker on the page says. */
export interface FixScope {
  platform?: PlatformChoice | undefined;
  danger?: boolean | undefined;
}

export function fixListCandidates(db: DatabaseSync, since: string, limit = candidateLimit, scope: FixScope = {}): VulnRow[] {
  const narrowed = scopeSql(scope);
  return db
    .prepare(
      `SELECT v.* FROM vulns v
        WHERE ${movedInWindowSql} AND ${notableInWindowSql} AND ${settledSql}${narrowed.sql}
        ORDER BY v.kev DESC, v.watch_hit DESC, v.epss IS NULL, v.epss DESC, v.cvss_score DESC
        LIMIT ?`,
    )
    .all(since, since, since, ...narrowed.params, limit) as unknown as VulnRow[];
}

/** How many there were in all, so a truncated list can say what it is a prefix of. */
export function fixListTotal(db: DatabaseSync, since: string, scope: FixScope = {}): number {
  const narrowed = scopeSql(scope);
  return (db.prepare(`SELECT COUNT(*) AS n FROM vulns v WHERE ${movedInWindowSql} AND ${notableInWindowSql} AND ${settledSql}${narrowed.sql}`).get(since, since, since, ...narrowed.params) as { n: number }).n;
}

/** Microsoft's published fixes for a set of CVEs, in one query rather than one per CVE. */
function msrcFixes(db: DatabaseSync, cveIds: string[]): Map<string, MsrcFix[]> {
  const out = new Map<string, MsrcFix[]>();
  if (cveIds.length === 0) return out;
  const rows = db
    .prepare(`SELECT cve_id, fixes_json FROM msrc_vulns WHERE cve_id IN (${cveIds.map(() => "?").join(", ")})`)
    .all(...cveIds.map((c) => c.toUpperCase())) as { cve_id: string; fixes_json: string }[];
  for (const r of rows) {
    const fixes = parseJson<MsrcFix[]>(r.fixes_json, []).filter((f) => f.kb || f.label);
    if (fixes.length) out.set(r.cve_id.toUpperCase(), [...(out.get(r.cve_id.toUpperCase()) ?? []), ...fixes]);
  }
  return out;
}

/** CISA's required action per CVE, in one query. */
function kevActions(db: DatabaseSync, cveIds: string[]): Map<string, { action: string; dueDate: string | null }> {
  const out = new Map<string, { action: string; dueDate: string | null }>();
  if (cveIds.length === 0) return out;
  const rows = db
    .prepare(`SELECT external_id, summary, signals_json FROM items WHERE source_id = 'cisa-kev' AND external_id IN (${cveIds.map(() => "?").join(", ")})`)
    .all(...cveIds.map((c) => c.toUpperCase())) as { external_id: string; summary: string | null; signals_json: string | null }[];
  for (const r of rows) {
    const s = parseJson<{ requiredAction?: string; dueDate?: string }>(r.signals_json, {});
    const action = s.requiredAction ?? /Required action:\s*(.+)$/s.exec(r.summary ?? "")?.[1]?.trim() ?? null;
    if (action) out.set(r.external_id.toUpperCase(), { action, dueDate: s.dueDate ?? null });
  }
  return out;
}

/** The vendor advisories on the Wire that name any of these CVEs, in one scan rather than one per CVE. */
function advisoriesByCve(db: DatabaseSync, cveIds: string[], since: string): Map<string, { id: number; source: string; title: string; url: string | null }[]> {
  const out = new Map<string, { id: number; source: string; title: string; url: string | null }[]>();
  if (cveIds.length === 0) return out;
  const wanted = new Set(cveIds.map((c) => c.toUpperCase()));
  const rows = db
    .prepare(
      `SELECT i.id, s.name AS source, i.title, i.url, i.signals_json FROM items i JOIN sources s ON s.id = i.source_id
        WHERE s.group_name = 'vulnerabilities' AND i.kind = 'article' AND COALESCE(i.published_at, i.fetched_at) >= ?
        ORDER BY i.published_at DESC LIMIT 600`,
    )
    .all(since) as { id: number; source: string; title: string; url: string | null; signals_json: string | null }[];
  for (const r of rows) {
    for (const cve of parseJson<{ cves?: string[] }>(r.signals_json, {}).cves ?? []) {
      const key = String(cve).toUpperCase();
      if (!wanted.has(key)) continue;
      out.set(key, [...(out.get(key) ?? []), { id: r.id, source: r.source, title: r.title, url: r.url }]);
    }
  }
  return out;
}

/** The mitigation entries whose STIG rules actually resolve, worked out once for the whole page. */
function resolvedMitigations(db: DatabaseSync): { entry: MitigationEntry; label: string }[] {
  // The same rules the CVE page's Fix panel reads, from the same cache.
  const { entries, stigs } = fixContext(db);
  if (entries.length === 0) return [];
  const out: { entry: MitigationEntry; label: string }[] = [];
  for (const entry of entries) {
    const phrase = entry.ruleTitleContains.toLowerCase();
    for (const { stig, rules } of stigs) {
      const rule = rules.find((r) => r.title.toLowerCase().includes(phrase));
      if (rule) {
        out.push({ entry, label: `${stig.product}: ${rule.label}` });
        break;
      }
    }
  }
  return out;
}

const hostOf = (url: string): string => {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
};

/** Shortens a product list the way a person would read it aloud. */
const productLine = (products: string[]): string | null =>
  products.length === 0 ? null : products.length <= 2 ? products.join(" and ") : `${products.slice(0, 2).join(", ")} and ${products.length - 2} more`;

/**
 * The window's work, grouped by remedy. One pass over the candidate CVEs; every lookup it needs
 * was fetched in a handful of queries above, so this costs the same for one CVE and for a hundred.
 */
export function fixList(db: DatabaseSync, rows: VulnRow[], since: string, total = rows.length): FixList {
  const cveIds = rows.map((r) => r.cve_id);
  const msrc = msrcFixes(db, cveIds);
  const kev = kevActions(db, cveIds);
  const advisories = advisoriesByCve(db, cveIds, since);
  const mitigations = resolvedMitigations(db);
  const byKey = new Map<string, Remedy>();
  const fixedCves = new Set<string>();

  const add = (r: Omit<Remedy, "cves" | "kevCount" | "watchCount" | "dueDate">, cve: RemedyCve): void => {
    const existing = byKey.get(r.key);
    if (existing) {
      if (!existing.cves.some((c) => c.cveId === cve.cveId)) existing.cves.push(cve);
    } else {
      byKey.set(r.key, { ...r, cves: [cve], kevCount: 0, watchCount: 0, dueDate: null });
    }
    if (r.kind === "install") fixedCves.add(cve.cveId);
  };

  for (const row of rows) {
    const id = row.cve_id.toUpperCase();
    const cve: RemedyCve = {
      cveId: row.cve_id,
      kev: row.kev === 1,
      watch: row.watch_hit === 1,
      cvss: row.cvss_score,
      epss: row.epss,
      dueDate: row.kev_due_date,
    };
    let placed = false;

    // 1. Microsoft's own answer, which names the KB and the products it is for.
    for (const f of msrc.get(id) ?? []) {
      const what = f.kb ? `KB${f.kb}` : (f.label ?? "update");
      add(
        {
          key: `kb:${what}`,
          kind: "install",
          verb: "Install",
          what,
          where: productLine(f.products),
          detail: `Microsoft Security Update Guide${f.fixedBuild ? ` · fixed build ${f.fixedBuild}` : ""}${f.restart ? " · needs a restart" : ""}`,
          url: f.url ?? (f.kb ? kbUrl(f.kb) : null),
        },
        cve,
      );
      placed = true;
    }

    // 2. A package advisory that names the version the flaw is fixed in.
    for (const p of parseJson<AffectedPackage[]>(row.packages_json, []).filter((p) => p.fixed.length)) {
      const fixed = p.fixed[0]!;
      add(
        {
          key: `pkg:${p.ecosystem}:${p.name}:${fixed}`,
          kind: "install",
          verb: "Upgrade",
          what: `${p.name} ${fixed}`,
          where: p.ecosystem,
          detail: `Package advisory ${p.advisory}`,
          url: null,
        },
        cve,
      );
      placed = true;
    }

    // 3. A vendor advisory on the Wire: the Chrome release, the USN, the PSIRT bulletin.
    if (!placed) {
      for (const a of (advisories.get(id) ?? []).slice(0, 2)) {
        add(
          { key: `adv:${a.id}`, kind: "install", verb: "Apply", what: a.title, where: null, detail: a.source, url: a.url },
          cve,
        );
        placed = true;
      }
    }

    // 4. NVD's own references. A CNA tag of "Vendor Advisory" is the vendor's own bulletin, which
    //    is a job a person can do — read it, learn the version. A bare "Patch" tag is usually a
    //    commit or a bug entry: real evidence, no update. Both group by host, because one
    //    Atlassian bulletin covering eight CVEs is one read, and thirty kernel commits are one
    //    line, not thirty rows. Neither counts towards "fixed".
    if (!placed) {
      const refs = parseJson<{ url: string; tags: string[] }[]>(row.references_json, []).filter((r) => r.tags.some((t) => fixTags.test(t)));
      const vendor = refs.find((r) => r.tags.some((t) => /^vendor advisory$/i.test(t)));
      if (vendor) {
        const host = hostOf(vendor.url);
        add({ key: `adv-host:${host}`, kind: "advisory", verb: "Read", what: `${host} advisory`, where: null, detail: "The vendor's own bulletin, tagged Vendor Advisory on NVD. It names the fixed version.", url: vendor.url }, cve);
        placed = true;
      } else if (refs[0]) {
        const host = hostOf(refs[0].url);
        add({ key: `up-host:${host}`, kind: "upstream", verb: null, what: `Patched upstream at ${host}`, where: null, detail: "Tagged Patch on NVD. A fix exists in the source; no installable version is named here.", url: refs[0].url }, cve);
        placed = true;
      }
    }

    if (placed) continue;

    // 5. No patch, but the publisher has said what to do. CISA's words, not ours.
    const action = kev.get(id);
    if (action) {
      add(
        { key: `kev:${action.action}`, kind: "mitigate", verb: null, what: action.action, where: null, detail: "CISA KEV required action", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
        cve,
      );
      placed = true;
    }
    for (const m of matchingEntries(mitigations.map((x) => x.entry), { cveId: row.cve_id, description: row.description, kevName: null })) {
      const resolved = mitigations.find((x) => x.entry.id === m.id);
      if (!resolved) continue;
      add(
        { key: `stig:${m.id}`, kind: "mitigate", verb: null, what: m.note, where: null, detail: resolved.label, url: m.source?.url ?? null },
        cve,
      );
      placed = true;
    }

    // 6. Nothing published. One row for all of them, because the answer is the same answer.
    if (!placed) {
      add(
        {
          key: "none",
          kind: "none",
          verb: null,
          what: "No patch, advisory or mitigation published",
          where: null,
          detail: "Nothing on NVD tagged Patch, Vendor Advisory or Mitigation, no vendor advisory in the News, no KEV action, no fixed package version. BaselineWatch does not guess at one.",
          url: null,
        },
        cve,
      );
    }
  }

  const remedies = [...byKey.values()];
  for (const r of remedies) {
    r.kevCount = r.cves.filter((c) => c.kev).length;
    r.watchCount = r.cves.filter((c) => c.watch).length;
    r.dueDate = r.cves.map((c) => c.dueDate).filter((d): d is string => Boolean(d)).sort()[0] ?? null;
    r.cves.sort((a, b) => Number(b.kev) - Number(a.kev) || Number(b.watch) - Number(a.watch) || a.cveId.localeCompare(b.cveId));
  }
  // Most urgent first: a date someone owes, then exploitation, then the size of the job.
  const order = (a: Remedy, b: Remedy): number =>
    (a.dueDate ?? "9999").localeCompare(b.dueDate ?? "9999") || b.kevCount - a.kevCount || b.watchCount - a.watchCount || b.cves.length - a.cves.length || a.what.localeCompare(b.what);

  return {
    install: remedies.filter((r) => r.kind === "install").sort(order),
    // The vendor's own bulletin first: it is a job, where a commit is a fact.
    published: remedies.filter((r) => r.kind === "advisory" || r.kind === "upstream").sort((a, b) => (a.kind === b.kind ? order(a, b) : a.kind === "advisory" ? -1 : 1)),
    mitigate: remedies.filter((r) => r.kind === "mitigate").sort(order),
    none: remedies.filter((r) => r.kind === "none"),
    considered: rows.length,
    fixed: fixedCves.size,
    total,
  };
}

/**
 * The sentence the page opens on, from the same figures. It leads with the CVEs rather than the
 * updates because the two do not move together: Microsoft ships a KB per Windows build, so one
 * CVE can carry eleven of them, and "11 updates close 2 CVEs" reads like a defect. How many
 * updates there are is the install group's own count, where it belongs.
 */
export function fixListHeadline(list: FixList): string {
  if (list.considered === 0) return "Nothing that touches you changed in this window";
  const of = `this window's ${list.considered} CVE${list.considered === 1 ? "" : "s"}`;
  if (list.fixed === 0) return `No update to install yet for any of ${of}`;
  return `${list.fixed} of ${of} ${list.fixed === 1 ? "has" : "have"} an update you can install`;
}
