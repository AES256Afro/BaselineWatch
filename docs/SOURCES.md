# Source register

Every feed and standard BaselineWatch tracks, with how it is fetched, how often, what we are
allowed to do with it, and how it is diffed. URLs checked 2026-10-14 unless marked *verify*.
Fixture responses for every adapter live in `test/fixtures/<adapter>/` once M1 starts.

Shape key: `article` (news), `vulnerability`, `requirement-set` (controls, rules,
recommendations), `setting-set` (configuration values), `listing` (a page we watch only to find
new downloads).

---

## A. Standards and baselines (the Register)

### NIST SP 800-53, 800-53A, 800-53B (current: Release 5.2.0, 2025-08-27)
- **Fetch**: OSCAL JSON from `https://github.com/usnistgov/oscal-content`
  (`nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json` and the four 53B baseline
  profiles). Alternative: CPRT JSON export per framework at `https://csrc.nist.gov/projects/cprt`.
- **Cadence**: poll the GitHub repo commits daily; CSRC page weekly.
- **Shape**: `requirement-set`. Control id, title, statement parts, discussion, parameters
  (ODPs), related controls, baseline membership (Low / Moderate / High / Privacy).
- **Rationale**: the publication page's Planning Note and release notes at
  `https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final` (and the matching 53A/53B pages).
  5.2.0 added SA-15(13), SA-24, SI-02(07); revised SI-07(12); updated discussion on SA-04,
  SA-05, SA-08, SA-08(14), SI-02, SI-02(05); 53B unchanged in content.
- **Licence**: US Government work, public domain.
- **Diffability**: excellent. Stable ids, structured fields.

### FedRAMP Consolidated Rules for 2026 (added 2026-10-15; current: 2026.10.13.01)
- **Fetch**: one JSON file, `fedramp-consolidated-rules.json`, from `https://github.com/FedRAMP/rules`
  (raw, branch `main`); the backfill reads four earlier commits from July to October 2026.
- **Cadence**: daily.
- **Shape**: `requirement-set`. FRR rules by family and subset (name, statement with its listed
  items, note, force word, who it affects, timeframes, mapped controls), KSI indicators (statement,
  mapped controls), FRD definitions, and CTL entries (the parameter values and guidance FedRAMP
  sets on NIST SP 800-53 controls, kept as parameters).
- **Rationale**: every entry carries dated `updated` notes; the newest is attached to the entry's
  changes, and the notes dated on the file's `last_updated` day are the release's reason.
- **Licence**: US Government work, public domain.
- **Diffability**: excellent. Stable ids, structured fields. The Rev5 OSCAL baselines the plan
  named (`GSA/fedramp-automation`) are no longer published; this file is FedRAMP's current
  machine-readable source.

### NIST SP 800-171 r3 and 800-171A r3
- **Fetch**: CPRT JSON; convert with `https://github.com/usnistgov/capordino` to OSCAL, or
  parse the CPRT JSON directly.
- **Shape**: `requirement-set`. Requirement id, statement, ODPs, 800-53 mapping.
- **Rationale**: CSRC publication page, FAQ, change analysis spreadsheet.
- **Diffability**: excellent.

### Other NIST CSRC publications (CSF 2.0, 800-61r3, 800-63-4, 800-207, drafts)
- **Fetch**: drafts open for comment feed
  `https://csrc.nist.gov/CSRC/media/feeds/pubs/drafts-open-for-comment.xml` (JSON twin at
  `.json`). Final publications: search page with `status-lg=Final` (*verify* a feed exists; else
  poll the search page as a `listing`). CPRT JSON where the publication is in CPRT; PDF text
  extraction otherwise.
- **Shape**: `article` for announcements; `requirement-set` where CPRT has it; `document`
  (paragraph diff) for PDF-only publications.
- **Diffability**: good for CPRT, fair for PDF (normalise whitespace and hyphenation first).

### DISA STIGs and SRGs
- **Fetch**: the library page `https://www.cyber.mil/stigs/downloads/` is a Salesforce
  Lightning app. Its table is filled by one Apex call that answers without a login (confirmed
  2026-10-15): `POST https://www.cyber.mil/webruntime/api/apex/execute?language=en-US&asGuest=true&htmlEncode=false`
  with body `{"classname":"@udd/01pRw0000002mOj","method":"getCyberDocumentCatalogByDocumentLibrary","params":{"documentLibrary":"STIGs"},...}`,
  returning 414 items with `FileName` ("Microsoft Windows Server 2025 STIG - Ver 1, Rel 4"),
  `DownloadLink` (zips on `dl.dod.cyber.mil/wp-content/uploads/stigs/zip/`), `UploadDate` and
  `RawDownloadType` (STIGs; Sunset; SCAP 1.3; Supplemental Automation Content; STIG
  Compilations). Each manual STIG zip holds one XCCDF 1.1.4 file plus Overview and Revision
  History PDFs. The adapter follows the STIGs named on the watchlist (kind `baseline`) or a small
  default set, since the whole library is hundreds of zips. The class id in the request is the
  one thing likely to move when DISA redeploys the site; the fixture test will say so.
- **Cadence**: DISA releases quarterly (late Jan / Apr / Jul / Oct) plus out-of-band fixes;
  poll the listing daily.
- **Shape**: `requirement-set`. Benchmark id and release, rule id (SV-xxxxxrxxx), STIG id
  (V-xxxxxx), severity (CAT I/II/III), title, discussion, check text, fix text, CCI references.
- **Rationale**: the XCCDF `plain-text id="release-info"` and the per-rule version bump; the
  "Revision History" PDF inside the zip lists each changed rule and a one-line reason.
- **Licence**: US Government work, public domain.
- **Diffability**: good once unzipped; rule ids are stable, text diffs are meaningful.

### Microsoft Security Baselines (Security Compliance Toolkit, Intune)
- **Fetch**: toolkit download page `https://www.microsoft.com/en-us/download/details.aspx?id=55319`
  (the page lists a "Date Published", last seen 2026-02-23, and the baseline zips: Windows 11
  23H2 and 25H2, Windows 10 1607 / Server 2016, Server 2025, Microsoft 365 Apps 2512, Edge).
  Announcements: Microsoft Security Baselines blog on Tech Community (RSS available from the
  blog's feed link; *verify* exact URL).
- **Cadence**: per Windows feature update and per Office/Edge channel; poll weekly.
- **Shape**: `setting-set`, read from the `.PolicyRules` file in each baseline zip (Policy
  Analyzer's format, confirmed 2026-10-15): `ComputerConfig` and `UserConfig` registry values
  (Key, Value, RegType, RegData, PolicyName), `SecurityTemplate` lines by section, and
  `AuditSubcategory` settings, each tagged with the GPO it comes from (Member Server, Domain
  Controller, Defender Antivirus, Credential Guard...). The version token in the GPO name is
  stripped so a setting keeps its ref across releases. The download page's `__DLCDetails__` JSON
  lists every zip with `datePublished`; the `.xlsx` and `Announcement.pdf` in the zip are for M5.
- **Rationale**: the blog post for the release, which walks through each changed setting (for
  example Server 2025 v2602 disabling `sudo` on member servers and domain controllers).
- **Licence**: Microsoft; redistribution of the toolkit is not permitted, so snapshots stay
  local and the UI quotes, never republishes, the files.
- **Diffability**: good from the Excel; the GPO backups are a cross-check.

### CIS Benchmarks and CIS Controls v8.1
- **Fetch**: manual upload only. PDFs are behind free registration at
  `https://www.cisecurity.org/cis-benchmarks` and licensed for internal use without
  redistribution. CIS WorkBench (free account) publishes per-benchmark change logs.
- **Shape**: `requirement-set` from PDF text: recommendation number, title, profile level,
  description, rationale, audit, remediation, default value.
- **Rationale**: the "Change History" appendix of each benchmark PDF.
- **Diffability**: fair. PDF layout noise; recommendation numbers can shift between versions.
  Implemented 2026-10-15 as an owner upload: the PDF's text is read with pdfjs, recommendations
  are found by their numbered headings (`1.1.1 (L1) Ensure ... (Automated)`) and their labelled
  sections (Description, Rationale, Audit, Remediation, Default Value, CIS Controls), and the
  Remediation is the diffed statement. A renumbered recommendation shows as removed plus added.

### ComplianceAsCode/content
- **Fetch**: `https://github.com/ComplianceAsCode/content` (git). Open-source STIG, CIS, PCI,
  ANSSI profiles as YAML rules.
- **Shape**: `requirement-set`; the git history is the diff.
- **Licence**: BSD-3.
- **Why include it**: free structured diffs of STIG and CIS content before the official drops
  are parsed, and a sanity check on our own XCCDF parsing.

---

## B. Vulnerabilities

### NVD API 2.0
- **CVE**: `https://services.nvd.nist.gov/rest/json/cves/2.0` with `lastModStartDate` /
  `lastModEndDate` (max 120-day window), paged by `startIndex` / `resultsPerPage` (max 2000).
- **CVE history**: `https://services.nvd.nist.gov/rest/json/cvehistory/2.0` with
  `changeStartDate` / `changeEndDate`; gives per-CVE change events (score added, CPE added,
  reference added) which is exactly the "what changed on this CVE" view.
- **Key**: free at `https://nvd.nist.gov/developers/request-an-api-key`, sent as `apiKey`
  header. 5 requests / 30 s without, 50 / 30 s with; sleep between calls anyway.
- **Shape**: `vulnerability`.
- **Licence**: public domain; NVD asks for attribution text in the UI.

### CVE List V5 (CVE Program)
- **Fetch**: `https://github.com/CVEProject/cvelistV5` releases. Each hourly release carries a
  `deltaCves` zip of records added or changed in the last hour; the daily and midnight releases
  carry the whole list. Use the delta as the trigger and NVD only for enrichment.
- **Shape**: `vulnerability` (CNA-provided description, affected products, references).
- **Licence**: CVE Terms of Use (free use with attribution).

### CISA Known Exploited Vulnerabilities (KEV)
- **Fetch**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  (CSV twin alongside). `catalogVersion` and `dateReleased` change on every update.
- **Cadence**: poll hourly; additions are high-priority events.
- **Shape**: `vulnerability` flag plus `article` for the addition event.
- **Licence**: public domain.

### FIRST EPSS
- **Fetch**: `https://api.first.org/data/v1/epss?cve=...` for lookups; daily bulk
  `https://epss.cyentia.com/epss_scores-current.csv.gz`.
- **Cadence**: daily.
- **Shape**: score join onto `vulnerability`.

### Vendor advisories (added 2026-10-15, all RSS, in the vulnerabilities group)
| Source | Feed |
| --- | --- |
| Ubuntu Security Notices | `https://ubuntu.com/security/notices/rss.xml` |
| Debian Security Advisories | `https://www.debian.org/security/dsa` (serves RSS) |
| Cisco Security Advisories | `https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml` |
| Palo Alto Networks | `https://security.paloaltonetworks.com/rss.xml` |
| Fortinet PSIRT | `https://www.fortiguard.com/rss/ir.xml` |
| Red Hat Security Blog | `https://www.redhat.com/en/rss/blog/channel/security` |

The Wire's "Vendor advisories" filter shows these apart from news. CVE ids in their text are
picked up as signals.

### Also planned
- OSV.dev `https://api.osv.dev/v1/`; GitHub Security Advisories (REST `/advisories`); MSRC
  CVRF `https://api.msrc.microsoft.com/cvrf/v3.0/updates`; Cisco openVuln; Red Hat CSAF/VEX;
  CERT/CC VINCE Atom `https://kb.cert.org/vuls/atomfeed/`.

---

## C. News and advisories (`article`)

Standard RSS/Atom unless noted. Dedupe by canonical URL, then by normalised title within 48 h.

| Source | Feed | Notes |
| --- | --- | --- |
| CISA advisories, alerts, ICS advisories | `https://www.cisa.gov/cybersecurity-advisories/all.xml` (confirmed 2026-10-14; `alerts.xml`, `ics-advisories.xml`, `cybersecurity-advisories.xml` and `news.xml` also answer) | Also the KEV JSON above. |
| NIST CSRC | drafts-open-for-comment feed above; NIST news RSS index `https://www.nist.gov/news-events/nist-rss-feeds`. | |
| NSA Cybersecurity Advisories | `https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/` (*verify* RSS). | |
| UK NCSC | `https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml` | |
| BleepingComputer | `https://www.bleepingcomputer.com/feed/` | |
| The Hacker News | `https://feeds.feedburner.com/TheHackersNews` | |
| Krebs on Security | `https://krebsonsecurity.com/feed/` | |
| SANS Internet Storm Center | `https://isc.sans.edu/rssfeed_full.xml` | Daily diary. |
| The Record (Recorded Future) | `https://therecord.media/feed` | |
| Schneier on Security | `https://www.schneier.com/feed/atom/` | |
| Dark Reading | `https://www.darkreading.com/rss.xml` | |
| SecurityWeek | `https://feeds.feedburner.com/securityweek` | |
| Risky Business | `https://risky.biz/feeds/risky-business/` | Newsletter and podcast. |
| Google Project Zero | `https://googleprojectzero.blogspot.com/feeds/posts/default` | |
| MSRC Security Update Guide | `https://api.msrc.microsoft.com/update-guide/rss` | Checked 2026-10-14: the MSRC blog moved to microsoft.com with no feed. This feed lists every Microsoft CVE (thousands), so it is a vulnerability source for M2, off until then. |
| Microsoft Security Baselines blog | Tech Community blog RSS (*verify*). | Doubles as the Register rationale source. |
| /r/netsec | `https://www.reddit.com/r/netsec/new.rss?limit=50` | Checked 2026-10-14: the `.json` listing answers 403 to anything but a browser or an OAuth app; the Atom feed works with a descriptive `User-Agent`. Two requests within seconds get a 429, so the scheduler spaces requests to one host. |
| /r/cybersecurity, /r/blueteamsec | same pattern | |
| Hacker News | Algolia `https://hn.algolia.com/api/v1/search_by_date?tags=story&query=<terms>` | Terms list in config (CVE, vulnerability, breach, ransomware, zero-day). |
| Georgetown CSET (if that is what "CSET" meant) | `https://cset.georgetown.edu/publications/` (*verify* RSS). | Policy research, not advisories. |

Reddit's API terms allow personal, low-volume, identified use. Do not store comment bodies;
store the link post and link to the thread.

---

## D. Attribution text to show in the UI

- "This product uses the NVD API but is not endorsed or certified by the NVD."
- "CVE and the CVE logo are registered trademarks of The MITRE Corporation."
- "Known Exploited Vulnerabilities Catalog provided by CISA."
- "EPSS scores provided by FIRST."
- CIS and Microsoft content is shown from the user's own uploaded or fetched copy under their
  own licence; BaselineWatch does not redistribute it.
