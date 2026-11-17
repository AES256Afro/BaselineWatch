import type { ItemKind } from "../adapters/types.ts";
import { isPlatformChoice, type PlatformChoice } from "../platforms.ts";
import { cweOf, maxOffset, type VulnFilters } from "../vulns.ts";
import type { WireFilters } from "../wire.ts";

/**
 * Reading a request's fields the same way on every route: a string trimmed and cut to a length,
 * with control characters gone, and the two filter shapes the News and Vulnerabilities lists take
 * from their query strings. Every route module reads its input through these.
 */
export // Control characters other than tab and line breaks are stripped: a NUL in a search term would be an FTS5 syntax error.
const str = (v: unknown, max = 200): string | undefined => {
  if (typeof v !== "string") return undefined;
  const clean = v.replace(/(?![\t\n\r])\p{Cc}/gu, "").trim();
  return clean === "" ? undefined : clean.slice(0, max);
};

/** `starred` is the owner's own mark, so it is read only when the owner is asking, like the table's `watch`. */
export function wireFilters(query: Record<string, unknown>, owner = false): WireFilters {
  const kind = str(query.kind);
  const group = str(query.group);
  const before = Number(str(query.before));
  return {
    source: str(query.source),
    group: group === "news" || group === "vulnerabilities" || group === "standards" ? group : undefined,
    kind: kind === "article" || kind === "kev" || kind === "vulnerability" || kind === "release" ? (kind as ItemKind) : undefined,
    q: str(query.q),
    platform: isPlatformChoice(str(query.platform)) ? (str(query.platform) as PlatformChoice) : undefined,
    danger: str(query.danger) === "1",
    topic: str(query.topic) === "ai" ? "ai" : undefined,
    hideAi: str(query.ai) === "hide",
    unread: str(query.unread) === "1",
    starred: owner && str(query.starred) === "1",
    before: Number.isInteger(before) && before > 0 ? before : undefined,
  };
}

/**
 * The table's filters from a query string. The watchlist is the owner's, so `watch` and `label`
 * are read only when the owner is asking; a visitor's link that carries them gets the whole list.
 */
export function vulnFilters(query: Record<string, unknown>, now: Date, owner = false): VulnFilters {
  const num = (v: unknown): number | undefined => {
    const n = Number(str(v));
    return Number.isFinite(n) ? n : undefined;
  };
  const sort = str(query.sort);
  const offset = num(query.offset);
  const severity = str(query.severity)?.toLowerCase();
  // A window in hours: "1" is the 24 h the links have always carried; the Today page sends its own (72, 168).
  const hours = (v: unknown): number | undefined => {
    const s = str(v);
    if (!s) return undefined;
    if (s === "1") return 24;
    const n = Number(s);
    return Number.isInteger(n) && n >= 1 && n <= 24 * 90 ? n : undefined;
  };
  const sinceHours = (h: number | undefined): string | undefined => (h === undefined ? undefined : new Date(now.getTime() - h * 60 * 60 * 1000).toISOString());
  const changedHours = hours(query.changed);
  const newHours = hours(query.new);
  const movedHours = hours(query.moved);
  const platform = str(query.platform);
  return {
    watch: owner && str(query.watch) === "1",
    kev: str(query.kev) === "1",
    ransomware: str(query.ransomware) === "1",
    cwe: cweOf(query.cwe),
    rejected: str(query.rejected) === "1",
    exploit: str(query.exploit) === "1",
    // "Due this week": KEV entries whose CISA due date falls in the seven days starting today,
    // today to today + 6 inclusive; + 7 was eight days.
    ...(str(query.due) === "7" ? { dueFrom: now.toISOString().slice(0, 10), dueTo: new Date(now.getTime() + 6 * 86_400_000).toISOString().slice(0, 10) } : {}),
    platform: isPlatformChoice(platform) ? platform : undefined,
    danger: str(query.danger) === "1",
    // CVSS runs 0 to 10; "CVSS ≥ 99" would title a feed that can never hold an item.
    minCvss: ((n) => (n === undefined ? undefined : Math.min(10, Math.max(0, n))))(num(query.min_cvss)),
    severity: severity === "critical" || severity === "high" || severity === "medium" || severity === "low" || severity === "unscored" ? severity : undefined,
    minEpss: num(query.min_epss),
    maxEpss: num(query.max_epss),
    noEpss: str(query.epss) === "none",
    changedSince: sinceHours(changedHours),
    changedHours,
    newSince: sinceHours(newHours),
    newHours,
    movedSince: sinceHours(movedHours),
    movedHours,
    label: owner ? str(query.label, 60) : undefined,
    q: str(query.q),
    sort: sort === "modified" || sort === "published" || sort === "cvss" || sort === "epss" ? sort : "risk",
    // A whole number SQLite can bind, capped: 1e300 or 1.5 would be a datatype mismatch and a 500.
    // Ten thousand rows deep is past where anyone pages; a narrower filter finds the rest.
    offset: offset !== undefined && offset >= 0 && Number.isSafeInteger(Math.floor(offset)) ? Math.min(Math.floor(offset), maxOffset) : 0,
  };
}

/**
 * The query values the table read as no filter, as `name=value`, so the page can say so rather than
 * show an unfiltered list as if it were the one asked for: "due=30" (only 7 is a window), a
 * severity or platform it does not know, a number that is not one, a flag other than 1, or the
 * owner's own watch filters asked for by a visitor.
 */
export function ignoredVulnParams(query: Record<string, unknown>, filters: VulnFilters, owner = false): string[] {
  const out: string[] = [];
  const raw = (k: string): string | undefined => str(query[k], 40);
  const note = (k: string, ignored: boolean): void => {
    const v = raw(k);
    if (v !== undefined && ignored) out.push(`${k}=${v}`);
  };
  for (const flag of ["kev", "ransomware", "exploit", "danger", "rejected"]) note(flag, raw(flag) !== "1");
  note("watch", raw("watch") !== "1" || !owner);
  note("label", !owner);
  note("due", !filters.dueFrom);
  note("severity", !filters.severity);
  note("platform", !filters.platform);
  note("cwe", !filters.cwe);
  note("min_cvss", filters.minCvss === undefined);
  note("min_epss", filters.minEpss === undefined);
  note("max_epss", filters.maxEpss === undefined);
  note("epss", !filters.noEpss);
  note("changed", !filters.changedSince);
  note("new", !filters.newSince);
  note("moved", !filters.movedSince);
  const sort = raw("sort");
  note("sort", sort !== undefined && sort !== filters.sort);
  return out;
}
