import type { DatabaseSync } from "node:sqlite";
import { loadFleet, type Fleet, type FleetPlatform } from "./fleet.ts";
import { platformKeys, platformName, type PlatformKey } from "./platforms.ts";
import { parseJson } from "./json.ts";

/**
 * What to do next, and what the window's vulnerabilities are about.
 *
 * Today used to open on five counts, which say how much happened and nothing about what to do
 * with it. This builds the short ordered list a person can actually act on — a date someone
 * already committed to, a CVE CISA says is being exploited on a platform this fleet runs, a
 * control that moved in a baseline that is applied — and the tally of the window's CVEs by the
 * platform they affect, with the fleet's own platforms first.
 *
 * Every row here is a fact already in the database with a link to where it came from; nothing is
 * scored, guessed or generated.
 */

export type ActionKind = "overdue" | "kev-mine" | "kev" | "worse" | "release" | "look";

export interface Action {
  kind: ActionKind;
  /** What it is, in the words the source used. */
  title: string;
  /** Why it is on the list, which is the part a person reads. */
  why: string;
  href: string;
  /** The timeline item, when there is one, so the page can offer triage without another query. */
  itemId: number | null;
  at: string | null;
}

/** Lower sorts first: a date someone promised, then exploitation, then what got worse, then what moved. */
const order: Record<ActionKind, number> = { overdue: 0, "kev-mine": 1, kev: 2, worse: 3, release: 4, look: 5 };

export interface AgendaOptions {
  since: string;
  now: Date;
  limit?: number;
  fleet?: Fleet;
}

/** The platform ids this fleet actually runs, in src/platforms.ts' vocabulary. */
export function fleetPlatformKeys(fleet: Fleet): Set<PlatformKey> {
  const map: Record<FleetPlatform, PlatformKey | null> = {
    windows: "windows",
    macos: "apple",
    ios: "apple",
    ipados: "apple",
    linux: "linux",
    android: "android",
    // A meeting room is a display and a console, not a platform NVD names; its CVEs arrive under
    // the platform of whatever runs it (Android for the Samsung panels, Windows for Teams Rooms).
    collaboration: null,
  };
  const keys = new Set<PlatformKey>();
  for (const release of fleet.releases) {
    const key = map[release.platform];
    if (key) keys.add(key);
  }
  return keys;
}

/** The ordered list Today opens on. */
export function nextActions(db: DatabaseSync, options: AgendaOptions): Action[] {
  const { since, now } = options;
  const limit = options.limit ?? 6;
  const actions: Action[] = [];

  // 1. A date this instance's owner already committed to, past due. Nothing outranks that.
  const overdue = db
    .prepare(
      `SELECT t.due_at AS dueAt, t.state, i.id AS itemId, i.title, i.external_id AS externalId, i.kind
         FROM triage t JOIN items i ON i.id = t.subject_id AND t.subject_kind = 'item'
        WHERE t.due_at IS NOT NULL AND t.due_at <= ? AND t.state IN ('new', 'reviewing', 'affects')
        ORDER BY t.due_at LIMIT 4`,
    )
    .all(now.toISOString().slice(0, 10)) as { dueAt: string; state: string; itemId: number; title: string; externalId: string; kind: string }[];
  for (const row of overdue) {
    actions.push({
      kind: "overdue",
      title: row.title,
      why: `You marked this ${row.state === "affects" ? "as affecting us" : row.state} and gave it ${row.dueAt}, which has passed.`,
      href: row.kind === "kev" || row.kind === "vulnerability" ? `/vulnerabilities/${row.externalId}` : "/triage",
      itemId: row.itemId,
      at: row.dueAt,
    });
  }

  // 2 and 3. KEV additions in the window: the ones that touch this stack first.
  const kev = db
    .prepare(
      `SELECT i.id AS itemId, i.title, i.published_at AS at, v.cve_id AS cveId, v.kev_due_date AS dueDate,
              v.watch_hit AS watchHit, v.watch_labels_json AS labels, v.platforms_json AS platforms, v.cvss_score AS cvss
         FROM items i LEFT JOIN vulns v ON v.cve_id = i.external_id
        WHERE i.kind = 'kev' AND i.published_at >= ?
        ORDER BY v.watch_hit DESC, v.kev_due_date IS NULL, v.kev_due_date, i.published_at DESC
        LIMIT 8`,
    )
    .all(since) as {
    itemId: number;
    title: string;
    at: string | null;
    cveId: string | null;
    dueDate: string | null;
    watchHit: number | null;
    labels: string | null;
    platforms: string | null;
    cvss: number | null;
  }[];
  for (const row of kev) {
    const labels = parseJson<string[]>(row.labels, []);
    const platforms = parseJson<PlatformKey[]>(row.platforms, []).map(platformName);
    const mine = row.watchHit === 1;
    const parts = [
      "CISA has evidence this is being exploited",
      mine && labels.length ? `and it matches ${labels.slice(0, 3).join(", ")} on your watchlist` : platforms.length ? `on ${platforms.slice(0, 3).join(", ")}` : null,
      row.dueDate ? `· federal due date ${row.dueDate}` : null,
      typeof row.cvss === "number" ? `· CVSS ${row.cvss.toFixed(1)}` : null,
    ].filter(Boolean);
    actions.push({
      kind: mine ? "kev-mine" : "kev",
      title: row.title,
      why: parts.join(" "),
      href: row.cveId ? `/vulnerabilities/${row.cveId}` : "/?kind=kev",
      itemId: row.itemId,
      at: row.at,
    });
  }

  // 4. A CVE on the watchlist that got worse in the window: a score went up, EPSS jumped, KEV landed.
  const worse = db
    .prepare(
      `SELECT c.cve_id AS cveId, c.field, c.before_text AS before, c.after_text AS after, c.observed_at AS at, v.watch_labels_json AS labels
         FROM vuln_changes c JOIN vulns v ON v.cve_id = c.cve_id
        WHERE c.observed_at >= ? AND v.watch_hit = 1 AND c.field IN ('cvss', 'epss', 'kev')
        ORDER BY c.observed_at DESC LIMIT 6`,
    )
    .all(since) as { cveId: string; field: string; before: string | null; after: string | null; at: string; labels: string | null }[];
  for (const row of worse) {
    const labels = parseJson<string[]>(row.labels, []);
    actions.push({
      kind: "worse",
      title: `${row.cveId} ${row.field === "kev" ? "entered KEV" : `${row.field.toUpperCase()} changed`}`,
      why: `${row.before ? `${row.before} → ` : ""}${row.after ?? ""} on something you watch${labels.length ? ` (${labels.slice(0, 3).join(", ")})` : ""}.`,
      href: `/vulnerabilities/${row.cveId}`,
      itemId: null,
      at: row.at,
    });
  }

  // 5. A standard that moved: the controls a baseline is built from are not fixed.
  const releases = db
    .prepare("SELECT id AS itemId, title, url, summary, published_at AS at, signals_json AS signals FROM items WHERE kind = 'release' AND fetched_at >= ? ORDER BY published_at DESC LIMIT 6")
    .all(since) as { itemId: number; title: string; url: string | null; summary: string | null; at: string | null; signals: string | null }[];
  for (const row of releases) {
    const s = parseJson<{ added?: number; removed?: number; modified?: number }>(row.signals, {});
    const changed = (s.added ?? 0) + (s.removed ?? 0) + (s.modified ?? 0);
    if (changed === 0) continue;
    actions.push({
      kind: "release",
      title: row.title,
      why: `${changed} requirement(s) changed: ${s.added ?? 0} added, ${s.removed ?? 0} removed, ${s.modified ?? 0} revised. Check the ones your baseline applies.`,
      href: row.url ?? "/register",
      itemId: row.itemId,
      at: row.at,
    });
  }

  // A quiet window is the common case, and an empty list teaches nothing. When nothing is urgent,
  // the page offers what is worth a look instead: the window's new CVEs on the platforms this
  // fleet runs, by the odds of exploitation. Ranked last, so it never displaces a real finding.
  if (actions.length < 3) {
    const keys = [...fleetPlatformKeys(options.fleet ?? loadFleet())];
    if (keys.length > 0) {
      const worthALook = db
        .prepare(
          `SELECT v.cve_id AS cveId, v.description, v.cvss_score AS cvss, v.epss, v.platforms_json AS platforms
             FROM vulns v
            WHERE v.cve_id IN (SELECT cve_id FROM vuln_changes WHERE observed_at >= ?)
              AND (${keys.map(() => "v.platforms_json LIKE ?").join(" OR ")})
            ORDER BY v.epss IS NULL, v.epss DESC, v.cvss_score DESC
            LIMIT ?`,
        )
        .all(since, ...keys.map((k) => `%"${k}"%`), 3 - actions.length) as {
        cveId: string;
        description: string | null;
        cvss: number | null;
        epss: number | null;
        platforms: string | null;
      }[];
      for (const row of worthALook) {
        const platforms = parseJson<PlatformKey[]>(row.platforms, []).map(platformName);
        actions.push({
          kind: "look",
          title: `${row.cveId}${row.description ? `: ${row.description.slice(0, 90)}${row.description.length > 90 ? "…" : ""}` : ""}`,
          why: `Moved in this window on ${platforms.slice(0, 3).join(", ") || "a platform you run"}${typeof row.epss === "number" ? ` · EPSS ${(row.epss * 100).toFixed(0)}%` : ""}${typeof row.cvss === "number" ? ` · CVSS ${row.cvss.toFixed(1)}` : ""}. Nothing is urgent in this window; this is what is worth a look.`,
          href: `/vulnerabilities/${row.cveId}`,
          itemId: null,
          at: null,
        });
      }
    }
  }

  return actions.sort((a, b) => order[a.kind] - order[b.kind] || (b.at ?? "").localeCompare(a.at ?? "")).slice(0, limit);
}

export interface PlatformTally {
  key: PlatformKey;
  label: string;
  total: number;
  kev: number;
  mine: number;
  /** True when a release of this platform is in data/platforms.yaml. */
  inFleet: boolean;
}

export interface PlatformBreakdown {
  rows: PlatformTally[];
  /** CVEs in the window whose platform could not be read from their CPEs, names or description. */
  unplaced: number;
  total: number;
}

/**
 * The window's CVEs by the platform they affect, the fleet's own platforms first. A CVE that
 * touches two platforms counts in both, because a person reading the row wants every CVE that
 * could reach that platform, not a share of one.
 */
export function platformBreakdown(db: DatabaseSync, since: string, fleet: Fleet = loadFleet()): PlatformBreakdown {
  const rows = db
    .prepare(
      `SELECT v.platforms_json AS platforms, v.kev, v.watch_hit AS watchHit
         FROM vulns v
        WHERE v.cve_id IN (SELECT cve_id FROM vuln_changes WHERE observed_at >= ?)`,
    )
    .all(since) as { platforms: string | null; kev: number; watchHit: number }[];
  const mine = fleetPlatformKeys(fleet);
  const tally = new Map<PlatformKey, PlatformTally>(
    platformKeys.map((key) => [key, { key, label: platformName(key), total: 0, kev: 0, mine: 0, inFleet: mine.has(key) }]),
  );
  let unplaced = 0;
  for (const row of rows) {
    const platforms = parseJson<PlatformKey[]>(row.platforms, []);
    if (platforms.length === 0) {
      unplaced += 1;
      continue;
    }
    for (const key of platforms) {
      const entry = tally.get(key);
      if (!entry) continue;
      entry.total += 1;
      if (row.kev === 1) entry.kev += 1;
      if (row.watchHit === 1) entry.mine += 1;
    }
  }
  const all = [...tally.values()].filter((t) => t.total > 0);
  all.sort((a, b) => Number(b.inFleet) - Number(a.inFleet) || b.kev - a.kev || b.total - a.total);
  return { rows: all, unplaced, total: rows.length };
}
