import type { DatabaseSync } from "node:sqlite";
import { latestDocument, loadRequirements } from "./register.ts";

/**
 * Traces (Scan, S8): the server's half of the browser's reading of a device's saved data. The page's
 * script (public/traces.js) reads the files a person picks in their own tab; all this server
 * contributes is the indicator list it already tracks in the Register — Zero Breach's AdFection /
 * Candiru indicators, CC0 — as the version the Register holds, so a list that moved is the list
 * the next reading uses, and the page can say which version it read against.
 */

export const indicatorSourceId = "adfection-indicators";

export interface TraceIndicator {
  value: string;
  type: "domain" | "ip" | "sha256";
  tier: string;
  confidence: string | null;
  source: string | null;
}

export interface TraceIndicators {
  /** The publisher's as-of date, or the commit the Register read it at. */
  version: string | null;
  publishedAt: string | null;
  indicators: TraceIndicator[];
}

const indicatorTypes = new Set(["domain", "ip", "sha256"]);
const text = (v: unknown): string | null => (typeof v === "string" && v !== "" ? v : null);

/** The latest indicator list the Register holds; empty when it has never been fetched. */
export function traceIndicators(db: DatabaseSync): TraceIndicators {
  const document = latestDocument(db, indicatorSourceId, "indicators");
  if (!document) return { version: null, publishedAt: null, indicators: [] };
  const indicators: TraceIndicator[] = [];
  for (const r of loadRequirements(db, document.id)) {
    const type = text(r.extra.type);
    const tier = text(r.extra.tier);
    if (r.status !== "active" || !type || !indicatorTypes.has(type) || !tier) continue;
    indicators.push({ value: r.ref, type: type as TraceIndicator["type"], tier, confidence: text(r.extra.confidence), source: text(r.extra.source) });
  }
  return { version: document.version_label, publishedAt: document.published_at, indicators };
}

/** What the page says about the list before the script runs: how many of each kind, and which version. */
export function indicatorTally(list: TraceIndicators): { domains: number; ips: number; hashes: number } {
  const count = (type: TraceIndicator["type"]): number => list.indicators.filter((i) => i.type === type).length;
  return { domains: count("domain"), ips: count("ip"), hashes: count("sha256") };
}
