/**
 * The hand-kept ledger (M20.1): every store of data this site shows that exists because a person
 * or a coding session typed it into the repository, rather than because the instance fetched it
 * from a publisher. Each row says what it holds, how it goes stale, what (if anything) checks it,
 * when it was last reviewed, and which part of M20 is meant to retire it — so the debt is a list
 * on the Sources page rather than something found in an outage.
 *
 * `test/curated.test.ts` holds the ledger to the code: every path exists, every file under data/
 * has a row, and a long hard-coded list in src/ is either a row here or named in `notCurated`
 * with the reason it is not data that goes stale.
 */

export interface CuratedStore {
  /** A path, or `path#name` for one constant or function in a module (src/, data/ or public/). */
  where: string;
  holds: string;
  staleWhen: string;
  /** A source id whose fetches check this store, a script that does, or null when nothing does. */
  checkedBy: { source: string } | { script: string } | null;
  /** When the data was last reviewed against its publishers: a "checked" stamp in the file, or the change that wrote it. */
  reviewed: string;
  /** The part of M20 meant to make this store unnecessary, or null when it is kept by hand on purpose. */
  retiredBy: string | null;
}

export const curatedStores: readonly CuratedStore[] = [
  {
    where: "data/platforms.yaml",
    holds: "The fleet: 32 releases on 7 platforms with dates, support ends, hardware and the baseline documents each uses",
    staleWhen: "a vendor ships or ends a release, or DISA or NIST publish a baseline for a new one",
    checkedBy: { source: "endoflife" },
    reviewed: "2026-10-19",
    retiredBy: "M20.5",
  },
  {
    where: "data/mitigations.yaml",
    holds: "Eleven CVE classes, each matched to the STIG rule that mitigates it, with the publisher's statement",
    staleWhen: "a STIG retitles the rule a phrase matches, or a new class of exploit needs an entry",
    checkedBy: null,
    reviewed: "2026-10-17",
    retiredBy: "M20.5",
  },
  {
    where: "data/test-plans",
    holds: "Twenty-five test plans: steps, expected results and the page each step cites",
    staleWhen: "a cited page moves, or a release named in the prose ends",
    checkedBy: { script: "npm run check:templates" },
    reviewed: "2026-10-21",
    retiredBy: "M20.5",
  },
  {
    where: "src/migrations",
    holds: "Every source this instance reads: its address, schedule, licence and notes",
    staleWhen: "a publisher moves or gates a feed, or a new source is worth reading",
    checkedBy: { script: "npm run check:feeds" },
    reviewed: "2026-10-28",
    retiredBy: "M20.2",
  },
  {
    where: "src/adapters/disa.ts#defaultStigs",
    holds: "The twenty STIGs followed when the watchlist names none, by product and version",
    staleWhen: "DISA publishes a STIG for the next macOS, Android, Ubuntu or Windows Server",
    checkedBy: { source: "disa-stigs" },
    reviewed: "2026-10-28",
    retiredBy: "M20.4",
  },
  {
    where: "src/adapters/mscp.ts#mscpBranches",
    holds: "The mSCP branches followed: tahoe, sequoia and ios_26",
    staleWhen: "NIST cuts a branch for the next macOS or iOS",
    checkedBy: { source: "nist-mscp" },
    reviewed: "2026-10-28",
    retiredBy: "M20.4",
  },
  {
    where: "src/baselines.ts#mscpBranchFor",
    holds: "macOS version numbers to mSCP branch names, and the DISA Intune and GPO package families",
    staleWhen: "a new macOS codename, or DISA renames a policy package",
    checkedBy: null,
    reviewed: "2026-10-21",
    retiredBy: "M20.4",
  },
  {
    where: "src/adapters/csrc-pubs.ts#publications",
    holds: "Thirty NIST publications followed by number",
    staleWhen: "NIST publishes in a followed series under a number not on the list",
    checkedBy: { source: "nist-platform" },
    reviewed: "2026-10-19",
    retiredBy: "M20.4",
  },
  {
    where: "src/eol.ts#eolProducts",
    holds: "The seven endoflife.date products the fleet is read against",
    staleWhen: "the fleet gains a platform endoflife.date covers under another name",
    checkedBy: { source: "endoflife" },
    reviewed: "2026-10-21",
    retiredBy: "M20.4",
  },
  {
    where: "src/ecosystems.ts#names",
    holds: "OSV's ecosystem names by the way people type them, which carry a release (withRelease), and the os-release ids mapped to OSV's distributions (distroEcosystem)",
    staleWhen: "OSV adds an ecosystem or a distribution, or changes how one names its releases",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: "M20.6",
  },
  {
    where: "src/inventory.ts#packageBase",
    holds: "The derivatives whose packages are another distribution's (Pop!_OS, Linux Mint, LMDE, Raspbian), with Mint's and LMDE's release numbers mapped to Ubuntu's and Debian's, for asking OSV when a report carries no ID_LIKE",
    staleWhen: "a new Linux Mint or LMDE release, or a derivative people report from",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: "M20.6",
  },
  {
    where: "src/platforms.ts#networkVendors",
    holds: "The network-device vendors by NVD's name (Cisco, Fortinet, TP-Link, HPE and the rest), for CVEs and KEV entries alike",
    staleWhen: "an edge-device vendor new to KEV or NVD",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: "M20.6",
  },
  {
    where: "src/platforms.ts#linuxVendors",
    holds: "The Linux vendors, and the product words (linuxProducts) that make one of their CVEs or KEV entries Linux's",
    staleWhen: "a new distribution, or a system component CISA names on its own",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: "M20.6",
  },
  {
    where: "src/platforms.ts#aiVendors",
    holds: "The AI tooling vendors, and the products by name (aiProducts) a general vendor ships",
    staleWhen: "a new model server, agent framework or MCP server",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: "M20.6",
  },
  {
    where: "src/platforms.ts#microsoftServers",
    holds: "CISA's Microsoft product words that are not Windows: the servers, with the browser engines (microsoftBrowsers) and Office (microsoftOffice)",
    staleWhen: "CISA names a Microsoft product neither list knows, which is then read as Windows",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: "M20.6",
  },
  {
    where: "src/platforms.ts#descriptionHints",
    holds: "The words that place a CVE NVD has not analysed by its description: macOS codenames, Windows releases, AI products",
    staleWhen: "a new macOS codename or AI product",
    checkedBy: null,
    reviewed: "2026-10-28",
    retiredBy: "M20.6",
  },
  {
    where: "src/platforms.ts#platformChoices",
    holds: "The words a news story uses for each platform on the Vulnerabilities page's choices",
    staleWhen: "a product is in the headlines under a name no list carries",
    checkedBy: null,
    reviewed: "2026-10-28",
    retiredBy: "M20.6",
  },
  {
    where: "src/topics.ts#aiTerms",
    holds: "Thirty-seven headline words that make a story part of the AI beat",
    staleWhen: "a new model or product name is in the headlines",
    checkedBy: null,
    reviewed: "2026-10-28",
    retiredBy: "M20.6",
  },
  {
    where: "src/stigs.ts#platforms",
    holds: "The STIG pages' groups, and the title words that file a STIG (platformOf) or a directive under them; KEV entries come through src/platforms.ts's reading, VMware aside",
    staleWhen: "DISA publishes for a vendor no pattern names",
    checkedBy: null,
    reviewed: "2026-10-21",
    retiredBy: "M20.6",
  },
  {
    where: "src/stigs.ts#kevPlatform",
    holds: "VMware as the one KEV vendor the STIG pages file under virtualization without src/platforms.ts's reading (kevReading has no virtualization platform)",
    staleWhen: "Broadcom's products reach KEV under another vendor name, or another hypervisor vendor does",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: "M20.6",
  },
  {
    where: "src/triage.ts#flawWords",
    holds: "The words that say a description's sentence is about a flaw, so a triage card leads with that sentence rather than the project's own blurb",
    staleWhen: "CNAs describe flaws in words the list lacks, and cards lead with the project's blurb again",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: null,
  },
  {
    where: "src/testplans.ts#patterns",
    holds: "Which STIG and mSCP checks belong to which test area",
    staleWhen: "a check's wording no longer matches its area's pattern",
    checkedBy: null,
    reviewed: "2026-10-28",
    retiredBy: "M20.6",
  },
  {
    where: "src/authorities.ts",
    holds: "Thirty-five publishers: the rung each sits on, what derives from what, and their addresses",
    staleWhen: "a new framework or a renamed publication address",
    checkedBy: null,
    reviewed: "2026-10-22",
    retiredBy: null,
  },
  {
    where: "src/pages/scan-guide",
    holds: "The manual check, platform by platform, and the vendors' help pages it links to",
    staleWhen: "a vendor moves a help page or a release moves a setting",
    checkedBy: null,
    reviewed: "2026-10-28",
    retiredBy: null,
  },
  {
    where: "src/pages/scan-traces.ts#places",
    holds: "Where each browser keeps its profile and cache on each system",
    staleWhen: "a browser moves its profile directory",
    checkedBy: null,
    reviewed: "2026-10-28",
    retiredBy: null,
  },
  {
    where: "src/inventory.ts#windowsProduct",
    holds: "How a device report's Windows build is named: Windows 11 from build 22000, Windows 10 below it (the OSV ecosystem per distribution is the src/ecosystems.ts row)",
    staleWhen: "a new Windows build line, such as a Windows 12",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: null,
  },
  {
    where: "src/inventory.ts#latestBrowser",
    holds: "Which vendor feed a browser on a device report is read against: Edge against Chrome's releases by its Chromium version",
    staleWhen: "Edge's version stops following Chromium's, or Microsoft publishes its own release feed this instance reads",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: null,
  },
  {
    where: "src/eol.ts#windowsEdition",
    holds: "The Windows EditionID read as an endoflife.date cycle suffix: Core and Professional on -w, Enterprise, Education, ServerRdsh and IoT Enterprise on -e, EnterpriseS on -e-lts, IoTEnterpriseS on -iot-lts, Server editions apart",
    staleWhen: "Microsoft adds an edition or endoflife.date renames or splits a Windows cycle",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: null,
  },
  {
    where: "src/fixlist.ts#advanceNotice",
    holds: "The title wording that marks a vendor advisory as an advance notice of an update not yet out (\"Advance Notification\", \"Advanced Notification\"), so Today does not offer it as a fix",
    staleWhen: "a vendor announces ahead of release in other words (\"pre-notification\", \"pre-release notice\")",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: null,
  },
  {
    where: "public/scan.js#appleOs",
    holds: "The browser check's reading of an iPhone's OS: the user agent's iOS token frozen at 18_6 from iOS 26, so 18_6 beside Safari Version/26 or later is read as Safari's version",
    staleWhen: "WebKit changes or unfreezes the token, or a Safari release stops following the OS's version",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: null,
  },
  {
    where: "src/adapters/oscal-nist.ts#releases",
    holds: "The commits each past 800-53 release was published at, with NIST's stated reason",
    staleWhen: "never: history; the current catalogue is fetched",
    checkedBy: { source: "nist-sp-800-53" },
    reviewed: "2026-10-26",
    retiredBy: null,
  },
  {
    where: "src/netscan.ts",
    holds: "The network check's canary categories and its resolver-identity probes",
    staleWhen: "a probe host stops answering",
    checkedBy: null,
    reviewed: "2026-10-25",
    retiredBy: null,
  },
  {
    where: "src/domaincheck.ts",
    holds: "The DKIM selectors the domain check tries",
    staleWhen: "a large mail provider adopts a selector not on the list",
    checkedBy: null,
    reviewed: "2026-10-21",
    retiredBy: null,
  },
  {
    where: "src/atlas.ts",
    holds: "Each publisher's cadence in words: DISA quarterly, NVD most weekdays",
    staleWhen: "a publisher changes its rhythm",
    checkedBy: null,
    reviewed: "2026-10-19",
    retiredBy: null,
  },
  {
    where: "src/pages/guide.ts",
    holds: "The teaching prose: KEV, EPSS, CVSS, CAT, the ladder",
    staleWhen: "a scale is revised (CVSS 4.0, an EPSS model version)",
    checkedBy: null,
    reviewed: "2026-10-28",
    retiredBy: null,
  },
  {
    where: "src/api.ts#licensedSources",
    holds: "The source ids whose text is the owner's licensed copy (CIS, Microsoft's baselines), kept out of the API, the MCP tools and the exports",
    staleWhen: "a new licensed source is added, or an existing one's id changes",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: null,
  },
  {
    where: "src/fix.ts#twoLevelSuffixes",
    holds: "The second levels under a country code read as a two-label public suffix (co.uk, com.au, ne.jp), for the domain a CVE reference or a CNA's mail address is registered under",
    staleWhen: "a CNA or vendor publishes under a country's second level not on the list (the Public Suffix List is the full answer)",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: null,
  },
  {
    where: "src/fix.ts#userContentHosts",
    holds: "The hosts that serve what their users publish (github.io, sites.google.com, *usercontent.com), never named as a vendor's own reference",
    staleWhen: "a new user-content host appears among CVE references under a vendor's name",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: null,
  },
  {
    where: "src/fix.ts#corporateSuffixes",
    holds: "The words a company adds to its name that its domain leaves out (inc, llc, ltd, gmbh, corp, systems, technologies, k.k.), read when naming a vendor's own untagged reference",
    staleWhen: "a vendor's untagged reference is missed, or a wrong domain is named, because of a suffix the list lacks or holds",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: null,
  },
  {
    where: "src/visits.ts#agents",
    holds: "The programs Visitors names by their User-Agent: AI assistants fetching for a person, AI and search crawlers, link previews, SEO crawlers, scanners, uptime monitors and feed readers",
    staleWhen: "a crawler or assistant starts sending a new name; one not on the list is still named when its User-Agent says bot, crawler or spider",
    checkedBy: null,
    reviewed: "2026-11-17",
    retiredBy: null,
  },
  {
    where: "src/pipeline.ts#cveStreamSources",
    holds: "The source ids that are the CVE stream (NVD's API, the CVE list), read for the stopped-stream notice",
    staleWhen: "a CVE source is added or renamed",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: null,
  },
  {
    where: "src/pipeline.ts#cveStreamFields",
    holds: "The vuln_changes fields only the CVE stream writes, which date when it last brought anything",
    staleWhen: "the NVD or CVE list adapter records a new field, or KEV, EPSS or OSV starts writing one of these",
    checkedBy: null,
    reviewed: "2026-11-16",
    retiredBy: null,
  },
];

/**
 * Long hard-coded lists in src/ that are not data going stale: the shape of a page, an adapter's
 * reading of a format, a palette. Named so the ledger test can tell a new curated list from these.
 */
export const notCurated: Readonly<Record<string, string>> = {
  "src/adapters/blocklists.ts#tierNames": "Zero Breach's own tier names, read from its format",
  "src/adapters/mscp.ts#sectionLabels": "mSCP's section ids as the project defines them",
  "src/adapters/nasa-policy.ts#sectionKeys": "the NASA reference's section keys, read from its format",
  "src/authorities.ts#authorities": "covered by the ledger's src/authorities.ts row",
  "src/authorities.ts#chains": "covered by the ledger's src/authorities.ts row",
  "src/authorities.ts#collisions": "covered by the ledger's src/authorities.ts row",
  "src/baselines.ts#disaPolicyFamilies": "covered by the ledger's src/baselines.ts row",
  "src/curated.ts#curatedStores": "this ledger",
  "src/pages/controls.ts#standardGroups": "the ladder's headings: the site's vocabulary, not a publisher's data",
  "src/pages/home.ts#formatLabel": "words for the formats the adapters read",
  "src/pages/layout.ts#areas": "the masthead's menus",
  "src/visits.ts#browsers": "browser families by their own User-Agent tokens; a new browser reads as Other browser, never as a wrong one",
  "src/pages/scan-guide/shared.ts#src": "covered by the ledger's src/pages/scan-guide row",
  "src/pages/scan-traces.ts#system": "covered by the ledger's src/pages/scan-traces.ts row",
  "src/platforms.ts#platformList": "the platform keys and their blurbs; the matching is the vendor-table rows",
  "src/report.ts#reportStyles": "the report's eleven looks",
  "src/scan-scripts.ts#metadata": "the scripts this repository ships, described",
  "src/seen.ts#shown": "the request facts the page shows a visitor",
  "src/testplans.ts#areas": "the test areas' names; the matching is the patterns row",
};

/** The ledger's path and constant, split. */
export function storePath(where: string): { path: string; name: string | null } {
  const [path, name] = where.split("#");
  return { path: path!, name: name ?? null };
}

/** Whole days from a YYYY-MM-DD date to now. */
export function daysSince(date: string, now: Date): number {
  return Math.max(0, Math.floor((now.getTime() - Date.parse(`${date}T00:00:00Z`)) / 86_400_000));
}
