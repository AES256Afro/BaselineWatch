import type { ItemKind } from "../adapters/types.ts";
import { isPlatformKey } from "../platforms.ts";
import type { VulnFilters } from "../vulns.ts";
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

export function wireFilters(query: Record<string, unknown>): WireFilters {
  const kind = str(query.kind);
  const group = str(query.group);
  const before = Number(str(query.before));
  return {
    source: str(query.source),
    group: group === "news" || group === "vulnerabilities" || group === "standards" ? group : undefined,
    kind: kind === "article" || kind === "kev" || kind === "vulnerability" || kind === "release" ? (kind as ItemKind) : undefined,
    q: str(query.q),
    unread: str(query.unread) === "1",
    before: Number.isInteger(before) && before > 0 ? before : undefined,
  };
}

export function vulnFilters(query: Record<string, unknown>, now: Date): VulnFilters {
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
  const platform = str(query.platform);
  return {
    watch: str(query.watch) === "1",
    kev: str(query.kev) === "1",
    exploit: str(query.exploit) === "1",
    platform: isPlatformKey(platform) ? platform : undefined,
    minCvss: num(query.min_cvss),
    severity: severity === "critical" || severity === "high" || severity === "medium" || severity === "low" || severity === "unscored" ? severity : undefined,
    minEpss: num(query.min_epss),
    maxEpss: num(query.max_epss),
    noEpss: str(query.epss) === "none",
    changedSince: sinceHours(changedHours),
    changedHours,
    newSince: sinceHours(newHours),
    newHours,
    label: str(query.label, 60),
    q: str(query.q),
    sort: sort === "modified" || sort === "published" || sort === "cvss" || sort === "epss" ? sort : "risk",
    // A whole number SQLite can bind, capped: 1e300 or 1.5 would be a datatype mismatch and a 500.
    offset: offset !== undefined && offset >= 0 && Number.isSafeInteger(Math.floor(offset)) ? Math.min(Math.floor(offset), 1_000_000) : 0,
  };
}
