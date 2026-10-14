import { feedAdapter } from "./feed.ts";
import { hnAdapter } from "./hn.ts";
import { kevAdapter } from "./kev.ts";
import { redditAdapter } from "./reddit.ts";
import type { Adapter, SourceRow } from "./types.ts";

const byId: Record<string, Adapter> = {
  "cisa-kev": kevAdapter,
  "hn-algolia": hnAdapter,
  "reddit-netsec": redditAdapter,
  "reddit-cybersecurity": redditAdapter,
  "reddit-blueteamsec": redditAdapter,
};

const byFormat: Record<string, Adapter> = {
  rss: feedAdapter,
  atom: feedAdapter,
};

/** The adapter for a source, by id first and then by format; null when nothing can read it yet. */
export function adapterFor(source: Pick<SourceRow, "id" | "format">): Adapter | null {
  return byId[source.id] ?? byFormat[source.format] ?? null;
}

export { feedAdapter, hnAdapter, kevAdapter, redditAdapter };
