import { cisAdapter } from "./cis.ts";
import { disaAdapter } from "./disa.ts";
import { epssAdapter } from "./epss.ts";
import { fedrampRulesAdapter } from "./fedramp-rules.ts";
import { feedAdapter } from "./feed.ts";
import { hnAdapter } from "./hn.ts";
import { kevAdapter } from "./kev.ts";
import { nvdAdapter } from "./nvd.ts";
import { nist171Adapter, nistBaselinesAdapter, nistCatalogAdapter } from "./oscal-nist.ts";
import { osvAdapter } from "./osv.ts";
import { redditAdapter } from "./reddit.ts";
import { sctAdapter } from "./sct.ts";
import type { Adapter, SourceRow } from "./types.ts";

const byId: Record<string, Adapter> = {
  "cisa-kev": kevAdapter,
  "hn-algolia": hnAdapter,
  "nvd-cves": nvdAdapter,
  "first-epss": epssAdapter,
  osv: osvAdapter,
  "nist-sp-800-53": nistCatalogAdapter,
  "nist-sp-800-53b": nistBaselinesAdapter,
  "nist-sp-800-171": nist171Adapter,
  "fedramp-rules": fedrampRulesAdapter,
  "microsoft-sct": sctAdapter,
  "disa-stigs": disaAdapter,
  "cis-benchmarks": cisAdapter,
  "reddit-netsec": redditAdapter,
  "reddit-cybersecurity": redditAdapter,
  "reddit-blueteamsec": redditAdapter,
};

/** Whether the adapter can run on a schedule; a manual-upload adapter cannot. */
export function fetchable(adapter: Adapter | null): boolean {
  return adapter !== null && (adapter.parse !== undefined || adapter.pull !== undefined || adapter.documents !== undefined);
}

const byFormat: Record<string, Adapter> = {
  rss: feedAdapter,
  atom: feedAdapter,
};

/** The adapter for a source, by id first and then by format; null when nothing can read it yet. */
export function adapterFor(source: Pick<SourceRow, "id" | "format">): Adapter | null {
  return byId[source.id] ?? byFormat[source.format] ?? null;
}

export { cisAdapter, disaAdapter, epssAdapter, fedrampRulesAdapter, feedAdapter, hnAdapter, kevAdapter, nist171Adapter, nistBaselinesAdapter, nistCatalogAdapter, nvdAdapter, osvAdapter, redditAdapter, sctAdapter };
