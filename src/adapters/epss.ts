import { gunzipSync } from "node:zlib";
import { applyEpss, type EpssScore } from "../vulns.ts";
import type { Adapter, PullOutcome } from "./types.ts";

/** Parses FIRST's daily CSV: a `#model_version:...,score_date:...` line, a header, then cve,epss,percentile. */
export function parseEpssCsv(text: string): { modelVersion: string | null; scoreDate: string | null; scores: EpssScore[] } {
  let modelVersion: string | null = null;
  let scoreDate: string | null = null;
  const scores: EpssScore[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "") continue;
    if (line.startsWith("#")) {
      modelVersion = /model_version:([^,]+)/.exec(line)?.[1] ?? modelVersion;
      scoreDate = /score_date:([^,]+)/.exec(line)?.[1] ?? scoreDate;
      continue;
    }
    if (line.startsWith("cve,")) continue;
    const [cve, epss, percentile] = line.split(",");
    const e = Number(epss);
    const p = Number(percentile);
    if (!cve || !Number.isFinite(e) || !Number.isFinite(p)) continue;
    scores.push({ cveId: cve.toUpperCase(), epss: e, percentile: p });
  }
  return { modelVersion, scoreDate, scores };
}

/** Downloads the day's scores and joins them onto every CVE BaselineWatch knows. */
export const epssAdapter: Adapter = {
  id: "epss",
  async pull(ctx): Promise<PullOutcome> {
    const response = await ctx.http(ctx.source.url, { headers: { accept: "application/gzip, */*" }, timeoutMs: 120_000, maxBytes: 100 * 1024 * 1024 });
    const bytes = response.bytes;
    const isGzip = bytes.length > 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
    // The scores file is tens of megabytes uncompressed; a cap keeps a hostile gzip from inflating without bound.
    const text = new TextDecoder("utf-8").decode(isGzip ? gunzipSync(bytes, { maxOutputLength: 512 * 1024 * 1024 }) : bytes);
    const parsed = parseEpssCsv(text);
    if (parsed.scores.length === 0) throw new Error("EPSS file had no scores");
    const scoreDate = parsed.scoreDate?.slice(0, 10) ?? ctx.now().toISOString().slice(0, 10);
    const result = applyEpss(ctx.db, parsed.scores, scoreDate, ctx.now().toISOString());
    ctx.db
      .prepare("INSERT INTO app_settings (key, value, updated_at) VALUES ('epss.date', ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at")
      .run(scoreDate, ctx.now().toISOString());
    return {
      items: parsed.scores.length,
      inserted: 0,
      updated: result.updated,
      detail: `${parsed.scores.length} scores for ${scoreDate} (${parsed.modelVersion ?? "model unknown"}); ${result.updated} CVEs updated, ${result.changes} notable jumps`,
    };
  },
};
