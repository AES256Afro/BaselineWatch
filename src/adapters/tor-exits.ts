import { isIP } from "node:net";
import type { Adapter, PullOutcome } from "./types.ts";

/**
 * The Tor Project's bulk exit list: one address per line, the exits that can reach the public
 * internet right now. Read whole once a day and swapped into tor_exits in one transaction, so a
 * lookup never sees a half-written list. The Scan page's "what this page learned" panel reads it;
 * nothing else does, and nothing about who asked is kept.
 */

/** The addresses in the list, in order, with anything that is not one left out. */
export function parseExitList(text: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || !isIP(line) || seen.has(line)) continue;
    seen.add(line);
    out.push(line);
  }
  return out;
}

export const torExitsAdapter: Adapter = {
  id: "tor-exits",
  headers: { accept: "text/plain" },
  async pull(ctx): Promise<PullOutcome> {
    const at = ctx.now().toISOString();
    const response = await ctx.http(ctx.source.url, { headers: { accept: "text/plain" }, timeoutMs: 60_000, maxBytes: 4 * 1024 * 1024 });
    const ips = parseExitList(new TextDecoder("utf-8").decode(response.bytes));
    if (ips.length < 100) throw new Error(`the exit list had ${ips.length} address(es); a real one has hundreds, so this is not it`);
    const before = (ctx.db.prepare("SELECT COUNT(*) AS n FROM tor_exits").get() as { n: number }).n;
    const insert = ctx.db.prepare("INSERT INTO tor_exits (ip, seen_at) VALUES (?, ?)");
    ctx.db.exec("BEGIN IMMEDIATE");
    try {
      ctx.db.exec("DELETE FROM tor_exits");
      for (const ip of ips) insert.run(ip, at);
      ctx.db.exec("COMMIT");
    } catch (error) {
      ctx.db.exec("ROLLBACK");
      throw error;
    }
    return { items: ips.length, inserted: Math.max(0, ips.length - before), updated: Math.min(before, ips.length), detail: `${ips.length} exit addresses` };
  },
};
