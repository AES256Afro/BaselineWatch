import { appleSecurityAdapter } from "./apple-security.ts";
import { adfectionAdblockAdapter, adfectionDnsAdapter, adfectionIndicatorsAdapter, canaryAdsAdapter, canaryMalwareAdapter, canaryPhishingAdapter, canaryTrackersAdapter } from "./blocklists.ts";
import { cciAdapter } from "./cci.ts";
import { cisAdapter } from "./cis.ts";
import { cisaDirectivesAdapter } from "./cisa-directives.ts";
import { crtshAdapter } from "./crtsh.ts";
import { csrcPubsAdapter } from "./csrc-pubs.ts";
import { cvelistAdapter } from "./cvelist.ts";
import { disaAdapter } from "./disa.ts";
import { disaGpoAdapter } from "./disa-gpo.ts";
import { disaIntuneAdapter } from "./disa-intune.ts";
import { endoflifeAdapter } from "./endoflife.ts";
import { epssAdapter } from "./epss.ts";
import { exploitDbAdapter } from "./exploitdb.ts";
import { fedrampRulesAdapter } from "./fedramp-rules.ts";
import { feedAdapter } from "./feed.ts";
import { hnAdapter } from "./hn.ts";
import { kevAdapter } from "./kev.ts";
import { metasploitAdapter } from "./metasploit.ts";
import { mozillaMfsaAdapter } from "./mozilla-mfsa.ts";
import { msrcAdapter } from "./msrc.ts";
import { mscpAdapter } from "./mscp.ts";
import { nasaPolicyAdapter } from "./nasa-policy.ts";
import { nvdAdapter } from "./nvd.ts";
import { nist171Adapter, nistBaselinesAdapter, nistCatalogAdapter } from "./oscal-nist.ts";
import { osvAdapter } from "./osv.ts";
import { pocInGithubAdapter } from "./poc-in-github.ts";
import { redditAdapter } from "./reddit.ts";
import { sansNewsbitesAdapter } from "./sans-newsbites.ts";
import { sctAdapter } from "./sct.ts";
import { torExitsAdapter } from "./tor-exits.ts";
import type { Adapter, SourceRow } from "./types.ts";

/**
 * The adapter registry: a source id or format to the module that reads it, and whether that module
 * can run on a schedule or only by upload.
 */
const byId: Record<string, Adapter> = {
  "cisa-kev": kevAdapter,
  "hn-algolia": hnAdapter,
  "nvd-cves": nvdAdapter,
  "cvelist-v5": cvelistAdapter,
  "first-epss": epssAdapter,
  "exploit-db": exploitDbAdapter,
  metasploit: metasploitAdapter,
  "poc-in-github": pocInGithubAdapter,
  msrc: msrcAdapter,
  "apple-security": appleSecurityAdapter,
  "mozilla-mfsa": mozillaMfsaAdapter,
  "tor-exits": torExitsAdapter,
  endoflife: endoflifeAdapter,
  crtsh: crtshAdapter,
  osv: osvAdapter,
  "nist-sp-800-53": nistCatalogAdapter,
  "nist-sp-800-53b": nistBaselinesAdapter,
  "nist-sp-800-171": nist171Adapter,
  "nist-piv": csrcPubsAdapter,
  "nist-platform": csrcPubsAdapter,
  "fedramp-rules": fedrampRulesAdapter,
  "nasa-cyber-ref": nasaPolicyAdapter,
  "microsoft-sct": sctAdapter,
  "disa-stigs": disaAdapter,
  "disa-cci": cciAdapter,
  "disa-intune": disaIntuneAdapter,
  "disa-gpo": disaGpoAdapter,
  "nist-mscp": mscpAdapter,
  "cisa-directives": cisaDirectivesAdapter,
  "sans-newsbites": sansNewsbitesAdapter,
  "cis-benchmarks": cisAdapter,
  "reddit-netsec": redditAdapter,
  "reddit-cybersecurity": redditAdapter,
  "reddit-blueteamsec": redditAdapter,
  "reddit-asknetsec": redditAdapter,
  "reddit-malware": redditAdapter,
  "reddit-reverseengineering": redditAdapter,
  "adfection-indicators": adfectionIndicatorsAdapter,
  "adfection-dns": adfectionDnsAdapter,
  "adfection-adblock": adfectionAdblockAdapter,
  "canary-ads": canaryAdsAdapter,
  "canary-trackers": canaryTrackersAdapter,
  "canary-malware": canaryMalwareAdapter,
  "canary-phishing": canaryPhishingAdapter,
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

export { adfectionAdblockAdapter, adfectionDnsAdapter, adfectionIndicatorsAdapter, canaryAdsAdapter, canaryMalwareAdapter, canaryPhishingAdapter, canaryTrackersAdapter, cciAdapter, cisAdapter, cisaDirectivesAdapter, csrcPubsAdapter, cvelistAdapter, disaAdapter, disaGpoAdapter, disaIntuneAdapter, epssAdapter, fedrampRulesAdapter, feedAdapter, hnAdapter, kevAdapter, mscpAdapter, nasaPolicyAdapter, nist171Adapter, nistBaselinesAdapter, nistCatalogAdapter, nvdAdapter, osvAdapter, redditAdapter, sansNewsbitesAdapter, sctAdapter };
