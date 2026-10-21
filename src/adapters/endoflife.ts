import { eolProducts, productLabel, replaceEolCycles, type EolCycle } from "../eol.ts";
import { upsertItems } from "../items.ts";
import { parseJson } from "../json.ts";
import type { Adapter, ParsedItem, PullOutcome } from "./types.ts";

/**
 * endoflife.date: one JSON file per product, a list of cycles with their release, support and
 * end-of-life dates (a date, or `false` for "not yet", `true` for "already, undated"). The pull
 * reads the seven products the fleet runs, swaps each product's rows in whole, and makes one Wire
 * item for a cycle inside ninety days of its end or past it within the month, so the end of a
 * release is news once, when it is near, and not every day after.
 */

export const endoflifeBase = "https://endoflife.date/api/";

/** The window in which a cycle's end is a Wire item: ninety days before, thirty after. */
export const warnDays = 90;
export const gracedDays = 30;

const dateOrFlag = (value: unknown): string | null => (typeof value === "string" ? value : typeof value === "boolean" ? String(value) : null);

/** One product's file into rows; a file that is not a list of cycles is refused. */
export function parseEolProduct(product: string, text: string): Omit<EolCycle, "seen_at">[] {
  const data = parseJson<unknown>(text, null);
  if (!Array.isArray(data)) throw new Error(`endoflife.date's ${product} file was not the list of cycles expected`);
  const rows: Omit<EolCycle, "seen_at">[] = [];
  for (const raw of data) {
    const c = (raw ?? {}) as Record<string, unknown>;
    const cycle = typeof c.cycle === "string" ? c.cycle : typeof c.cycle === "number" ? String(c.cycle) : null;
    const eol = dateOrFlag(c.eol);
    if (!cycle || eol === null) continue;
    rows.push({
      product,
      cycle,
      label: typeof c.releaseLabel === "string" ? c.releaseLabel : typeof c.codename === "string" ? c.codename : null,
      release_date: typeof c.releaseDate === "string" ? c.releaseDate : null,
      eol,
      support: dateOrFlag(c.support),
      latest: typeof c.latest === "string" ? c.latest : null,
      latest_release_date: typeof c.latestReleaseDate === "string" ? c.latestReleaseDate : null,
      lts: c.lts === true || typeof c.lts === "string" ? 1 : 0,
      link: typeof c.link === "string" ? c.link : null,
    });
  }
  if (rows.length === 0) throw new Error(`endoflife.date's ${product} file had no cycle BaselineWatch could read`);
  return rows;
}

/** The items a product's cycles make today: ends inside the window, each once. */
export function eolItems(rows: Omit<EolCycle, "seen_at">[], now: Date): ParsedItem[] {
  const items: ParsedItem[] = [];
  const day = 86_400_000;
  for (const r of rows) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(r.eol)) continue;
    const end = new Date(`${r.eol}T00:00:00Z`).getTime();
    const days = Math.round((end - now.getTime()) / day);
    if (days > warnDays || days < -gracedDays) continue;
    const name = `${productLabel[r.product] ?? r.product} ${r.label ?? r.cycle}`;
    const ended = days < 0;
    items.push({
      kind: "article",
      externalId: `${r.product}:${r.cycle}`,
      title: ended ? `${name} support ended ${r.eol}` : days === 0 ? `${name} support ends today` : `${name} support ends ${r.eol}, in ${days} day(s)`,
      url: r.link ?? `https://endoflife.date/${r.product}`,
      summary: `${ended ? "No more security updates" : "Security updates stop"} ${ended ? "since" : "on"} ${r.eol}${r.latest ? `; the last release is ${r.latest}` : ""}. Move to a supported release, or keep the device off networks that matter.`,
      publishedAt: new Date(Math.min(end - warnDays * day, now.getTime())).toISOString(),
      signals: { product: r.product, cycle: r.cycle, eol: r.eol, ended },
    });
  }
  return items;
}

export const endoflifeAdapter: Adapter = {
  id: "endoflife",
  headers: { accept: "application/json" },
  async pull(ctx): Promise<PullOutcome> {
    const now = ctx.now();
    const at = now.toISOString();
    const items: ParsedItem[] = [];
    let cycles = 0;
    for (const product of eolProducts) {
      const response = await ctx.http(`${ctx.source.url}${product}.json`, { headers: { accept: "application/json" }, timeoutMs: 30_000, maxBytes: 2 * 1024 * 1024 });
      const rows = parseEolProduct(product, new TextDecoder("utf-8").decode(response.bytes));
      replaceEolCycles(ctx.db, product, rows, at);
      cycles += rows.length;
      items.push(...eolItems(rows, now));
    }
    const counts = upsertItems(ctx.db, ctx.source.id, items, at);
    return { items: cycles, inserted: counts.inserted, updated: counts.updated, detail: `${cycles} cycles across ${eolProducts.length} products; ${items.length} ending inside the window` };
  },
};
