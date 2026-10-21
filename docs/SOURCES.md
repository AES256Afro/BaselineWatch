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

### NIST SP 800-171 r3 (added 2026-10-15; CMMC Level 2 is this set)
- **Fetch**: OSCAL JSON from `https://github.com/usnistgov/oscal-content`
  (`nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json`), which carries the 800-171A
  assessment objectives inside each requirement.
- **Cadence**: daily.
- **Shape**: `requirement-set`. Requirement number (03.01.01) as ref and label, family as
  "03.01 Access Control", statement items lettered a., b., organization-defined parameters,
  assessment objective; requirements withdrawn from Revision 2 kept as withdrawn.
- **Rationale**: none captured. The CSRC page's planning note only announces the HTML edition.
- **Licence**: US Government work, public domain.
- **Diffability**: good, with one caveat: the versions are NIST's OSCAL conversions, not editions
  of the publication (May 2024). OSCAL 1.0.0 (August 2025) left 29 statements empty and 1.1.0
  (May 2026) filled them in, so tracking starts at 1.1.0 and there is no backfill.

### NIST SP 800-171A r3 (not loaded)
- **Fetch**: CPRT JSON; convert with `https://github.com/usnistgov/capordino` to OSCAL, or
  parse the CPRT JSON directly.
- **Shape**: `requirement-set`. Requirement id, statement, ODPs, 800-53 mapping.
- **Rationale**: CSRC publication page, FAQ, change analysis spreadsheet.
- **Diffability**: excellent.

### NIST PIV, digital identity and platform security publications (added 2026-10-19)
- **Sources**: `nist-piv` and `nist-platform`, both read by the `csrc-pubs` adapter. Each
  source is a list of publications (`src/adapters/csrc-pubs.ts`) keyed by the part of the number
  that stays across revisions: `fips-201` covers FIPS 201-2 and 201-3, `sp-800-73-pt1` every
  revision of SP 800-73 Part 1.
- **PIV and identity**: FIPS 201-3; SP 800-73-5 Parts 1, 2 and 3; SP 800-76-2; SP 800-78-5;
  SP 800-79-2; SP 800-85A-4; SP 800-87 Rev. 2; SP 800-96; SP 800-116 Rev. 1; SP 800-156; SP 800-157
  Rev. 1 and SP 800-217 (both final public drafts of November 2024, followed to their finals when
  CSRC publishes them); IR 7863; and the Digital Identity Guidelines SP 800-63-4, 63A-4, 63B-4 and
  63C-4 (July 2025).
- **Platform security** (roots of trust, firmware, secure enclaves): FIPS 140-3; SP 800-147 and
  147B; SP 800-193; SP 800-124 Rev. 2; SP 800-219 Rev. 1 (the macOS Security Compliance Project
  guidance); SP 800-57 Part 1 Rev. 5; IR 8320, 8320A, 8320B and 8320D (hardware-enabled security
  and confidential computing; D is a draft). SP 800-155 and SP 800-164 are withdrawn drafts and are
  not followed.
- **Fetch**: each publication's CSRC page (`https://csrc.nist.gov/pubs/<series>/<number>/<status>`)
  carries the PDF link (`pub-local-download-link`), the citation date, the revision it supersedes
  (`pub-supersedes-N`), its successor once replaced (`pub-superseded-by-N`), the Document History
  (`pub-history-link-N`) and the Planning Note. The adapter reads the page daily, follows a
  successor or a draft's newer history entry (at most three hops), and downloads the PDF only when
  the file URL or date moved; a publication's first load also fetches the revision it superseded,
  so the first diff is real (FIPS 201-2 → 201-3, SP 800-63-3 → 63-4).
- **Shape**: `requirement-set`. The PDF's numbered sections, read from its text: ref `2.7.1`,
  label `2.7.1` or `Appendix E`, family the top-level section ("2 Common Identification,
  Security, and Privacy Requirements"), statement the section's text. Headings are taken only where
  they continue the outline (1, 1.1, 1.2, 2 … Appendix A, A.1), so numbered list items, the
  preamble's numbered paragraphs and cross-references stay out; a table of contents without dot
  leaders starts an outline of its own and loses to the body. Running headers, footers and page
  numbers are stripped first. A renumbered section shows as removed plus added, as with CIS.
- **Rationale**: the PDF's own Revision History or Change Log appendix (FIPS 201-3 Appendix E,
  SP 800-78-5 Appendix B, SP 800-63B-4 Appendix E), newest part kept when it is long; else the
  page's Planning Note.
- **Licence**: US Government work, public domain.
- **Diffability**: good for publications in NIST's current templates; fair across template
  generations (FIPS 201-2 of 2013 against 201-3 of 2022 reflows every paragraph, and the diff says
  so). Checked 2026-10-19 against the real FIPS 201-3, 201-2, SP 800-78-5, 800-193, 800-63B-4,
  800-96 (2006) and 800-147 (2011) PDFs; the fixtures are the 201-3 and 201-2 pages and the
  extracted text of 800-78-5.

### NASA Cybersecurity Policy Reference (added 2026-10-20)
- **Source**: `nasa-cyber-ref`, adapter `src/adapters/nasa-policy.ts`. NASA's per-OS hardening
  standards (the Agency Security Configuration Standards, enumerated by NASA-SPEC-2600) are
  written by OCIO's Cybersecurity Standards and Engineering Team (CSET) and sit behind
  cset.nasa.gov (NASA access only); the public knowledge of that world is the quarterly
  **Cybersecurity Policy Reference**, a Word document linked from
  `https://www.nasa.gov/cybersecurity-policies/`.
- **Fetch**: the page is read for the `.docx` link (the filename changes per quarter:
  `cybersecurity-policy-reference-changes-for2026-q3-update-1.docx`); the file is ~100 KB and the
  snapshot hash makes an unchanged quarter cost one page read and one small download. Weekly.
- **Shape**: `requirement-set`, one document key `reference`. Eight sections (NPD/NPR directives,
  NAIIs, handbooks, NASA standards, memoranda, other federal documents, FIPS, NIST), each listed
  document one requirement: ref is the section key plus the id's stable part (`directive:npr-2810.1`
  covers 2810.1F and a later 2810.1G; a NIST number's letter stays, SP 800-53A), label the id as
  printed, statement the dates and expiry, guidance the status note the title carried after an
  asterisk ("Comment period closed as of 8/14/26"), and each row's own hyperlink (NODIS for a
  directive, CSET or NTSS for a NASA standard, CSRC for FIPS and SP) kept as the document's
  source link. The version is the document's "Current as of last publication" date.
- **Rationale**: none published; the document states no reason for its changes.
- **Licence**: US Government work, public domain.
- **Diffability**: good. Ids are stable, dates and notes live in diffable fields, so a quarterly
  update reads as renewals, revisions and swaps. Checked 2026-10-20 against the real 2026 Q3
  document (the fixture, byte for byte): 8 sections, ~280 documents, NASA-SPEC-2600 Version 6.0
  dated January 12, 2026.
- **Where it shows**: the All standards page (`/standards`) beside the per-OS table and the NIST
  publications with CSRC's drafts open for comment.

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
  History PDFs. The adapter follows the STIGs named on the watchlist (kind `baseline`) or the
  default set (since 2026-10-19: Windows 11, Windows Server 2025 and 2022, Red Hat Enterprise
  Linux 9 and 10, Ubuntu 24.04 and 22.04, Apple macOS 26 and 15, Apple iOS/iPadOS 27 and 26, Google Android 17 and 16, Samsung Android 17 and 16 with Knox, Microsoft Edge, Google Chrome,
  Mozilla Firefox, Cisco IOS XE Router, Application Security and Development), since the whole
  library is hundreds of zips. The class id in the request is the one thing likely to move when
  DISA redeploys the site; the fixture test will say so. The same listing names the CCI list,
  the Intune policy package and the GPO package (below and in M9.3).
- **Cadence**: DISA releases quarterly (late Jan / Apr / Jul / Oct) plus out-of-band fixes;
  poll the listing daily.
- **Shape**: `requirement-set`. Benchmark id and release, rule id (SV-xxxxxrxxx), STIG id
  (V-xxxxxx), severity (CAT I/II/III), title, discussion, check text, fix text, CCI references.
- **Rationale**: the XCCDF `plain-text id="release-info"` and the per-rule version bump; the
  "Revision History" PDF inside the zip lists each changed rule and a one-line reason.
- **Licence**: US Government work, public domain.
- **Diffability**: good once unzipped; rule ids are stable, text diffs are meaningful.

### DISA Control Correlation Identifiers (CCI) (added 2026-10-17)
- **Fetch**: `https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/CCI_List.zip`, named in the
  STIG library listing as "CCI List" with an upload date (2026-07-15 when added), so a check is
  the listing call and nothing more until the date moves. The zip holds `CCI_List.xml` (5,150
  items in the 2026-07-14 list), an HTML rendering and a stylesheet.
- **Cadence**: DISA republishes a few times a year; checked weekly.
- **Shape**: `requirement-set`, one document key `cci`. Each item is a requirement: the CCI as
  ref and label, its definition as the text, its type (policy or technical) as the family, and
  the NIST SP 800-53 controls it indexes as related refs: the Revision 5 index when DISA gives
  one (3,849 items do), else the Revision 4 index, with the raw indexes ("IA-5 (2) (a) (1)")
  kept in the extras. "AC-1 a 1 (a)" indexes AC-1; "IA-5 (2) (a) (1)" indexes IA-5(2).
- **Why it is here**: every STIG rule cites CCIs and nothing else; this list is the only join
  from a rule to a control page, in both directions (the STIG pages and the control pages).
- **Licence**: US Government work, public domain.
- **Diffability**: good; ids are stable and definitions change rarely.

### DISA STIG Intune policy package and GPO package checklists (added 2026-10-17)
- **Fetch**: both are dated entries in the STIG library listing: "Intune Policy - October 2026"
  (`U_Intune_Policy_Package_October_2026.zip`, 1.1 MB) and "Group Policy Objects (GPOs) -
  October 2026" (`U_STIG_GPO_Package_October_2026.zip`, 7 MB), updated with each quarterly
  release; the listing's date gates the download.
- **Shape**: `intune:package`, a `setting-set` of every setting in the package's
  `Intune Policies/Settings Catalog/*.json` (Microsoft Graph `configurationPolicies` exports;
  18 policies and 1,019 settings in October 2026, among them "DoD Windows 11 STIG v2r11 Settings
  Catalog" with 174): the policy without its version as the family, the settings-catalog
  definition id as the ref and label, the value (choice suffix, simple value, children) as the
  text. `gpo:checklists`, a `requirement-set` of every rule in the package's
  `Support Files/Checklist Files/*.ckl` (19 STIG Viewer checklists, 3,465 rules): DISA's own
  verdict per rule, NotAFinding with "GPO - ... / Intune - ..." when its policies set it,
  Not_Applicable with "Outside scope of GPO configurations" when they cannot, Open or Not
  Reviewed otherwise. The GPO backups, ADMX files and scripts are not parsed.
- **Why they are here**: the baseline builder's Intune flavour names the definition DISA uses for
  a rule (matched by the policy's name in the STIG fix text) and quotes DISA's verdict when a rule
  is outside what Intune can set. DISA's readme says the policies carry the most restrictive STIG
  settings and must be tested before production; the pages say the same.
- **Licence**: US Government work, public domain.
- **Diffability**: good; definition ids and V-ids are stable, so a quarter's changes are the
  settings DISA changed.

### NIST macOS Security Compliance Project (mSCP) (added 2026-10-17)
- **Fetch**: `https://github.com/usnistgov/macos_security`, one branch per macOS release
  (`tahoe` for macOS 26, `sequoia` for 15; `sonoma`, `ventura` and the iOS and visionOS branches
  exist too). The GitHub commits API (`/repos/usnistgov/macos_security/commits/<branch>`, no
  token, 60 requests an hour) gives the branch's current commit, and the zip for that exact
  commit (`codeload.github.com/.../zip/<sha>`, about 1 MB) is fetched only when it moved. A
  watchlist entry of kind `baseline` written `mscp: <branch>` follows other branches.
- **Cadence**: daily; the project commits often between revisions, and every commit is a version
  here (the label is the revision from `VERSION.yaml` plus the short commit, the reason is the
  commit's first line).
- **Shape**: `requirement-set`. Each `rules/<section>/<id>.yaml` is a rule: id as ref and label,
  title, the check as the text, the discussion as guidance, the SP 800-53 r5 references as
  related controls, and in the extras the fix, the expected result, severity, the configuration
  profile payloads (`mobileconfig_info`, domain and keys), declarative management, the
  organisation-defined values per baseline (`odv`), tags, the STIG, SRG, CCI, CCE, 800-171 r3,
  CMMC and CIS references, and which `baselines/*.yaml` list it (800-53 High, Moderate and Low,
  DISA STIG, CIS Level 1 and 2, CMMC, CNSSI 1253, and the rest). Tahoe, Revision 3.0: 335 rules,
  332 with a STIG id, 141 with a payload, 217 in the High baseline, 165 in the DISA STIG baseline.
- **Why it is here**: the macOS profile and its Jamf flavour come from it: the rule id, the
  payload domain and keys, and the join to the macOS STIG by STIG id.
- **Licence**: NIST software, public domain in the United States (the repository's LICENSE).
- **Diffability**: excellent; ids are stable and the YAML is structured.

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

### Blocklists and canary sets for the Scan area (added 2026-10-19)
One adapter, `src/adapters/blocklists.ts`, seven sources in the standards group, each list a
document whose entries are its requirements (ref and label the name, the line as published the
text), diffed line by line like any standard. Nothing is ever fetched from a name on a list: the
lists are documents read from their publishers, and canary names are only ever resolved by the
network check (M12.3), never loaded and never linked from a page. Fixtures in
`test/fixtures/blocklists/` are the real responses, kept byte for byte.

- **Zero Breach: AdFection / Candiru indicators and exports** (`adfection-indicators`,
  `adfection-dns`, `adfection-adblock`). Repository `https://github.com/interplains/zero-breach`;
  `iocs/adfection_iocs.txt` (one `indicator <TAB> tier <TAB> confidence <TAB> source-tag` line per
  indicator under `#` comments; a `# Source:` comment names the report the following indicators were
  read from, kept as each entry's guidance; 405 indicators on 2026-10-18: 292 domains, 111 addresses,
  two SHA-256 hashes), `dist/adfection.domains.txt` (one domain per line, the Pi-hole and AdGuard
  Home form, 291 domains) and `dist/adfection.adblock.txt` (`||domain^` rules for a browser blocker).
  **Fetch**: the GitHub commits API (`/repos/interplains/zero-breach/commits?path=<file>&per_page=1`,
  no token) names the current commit, and the file is read at that exact commit from
  `raw.githubusercontent.com` only when it moved; the version label is the commit date and short
  sha, the commit's first line is the publisher's reason, and the commit that added the exports
  (`e36dc96`, 2026-10-18 14:01 UTC) is pinned as history so a first fetch opens on a real diff
  (adtimizer.co out, 67 domains in, by 22:36 UTC the same day). **Cadence**: daily. **Shape**:
  `requirement-set`; for indicators the tier is the family (command-and-control, validator server,
  ad delivery, historical Candiru infrastructure, spyware sample, abused signed driver, Candiru
  infrastructure and its addresses), the statement names tier, confidence and source tag, and the
  extras keep the type. **Licence**: the indicator data is CC0 1.0 (`iocs/LICENSE.md`); the software
  is Apache-2.0; the project is not affiliated with or endorsed by the researchers it cites (its
  NOTICE says so, and so do the attribution column and the footer). **Diffability**: excellent;
  names are stable and the exports are sorted.
- **Ad canaries (EasyList)** and **Tracker canaries (EasyPrivacy)** (`canary-ads`,
  `canary-trackers`). `https://easylist.to/easylist/easylist.txt` (2.2 MB, about 50,000 outright
  domain rules) and `easyprivacy.txt` (1.5 MB, about 43,000). **Derivation**: the rules that block a
  domain outright, `||domain^` with or without `$third-party` and nothing else (a `$popup` or
  `$image` rule is not one); of those names the twelve whose SHA-256 is lowest, in name order. The
  statement is the rule as published, so a rule that gains or loses `$third-party` is a revision.
  Version from `! Version:`, date from `! Last modified:`. **Cadence**: weekly; the lists move
  several times a day but the twelve rarely do. **Licence**: EasyList's dual licence, GPLv3 or
  CC BY-SA 3.0 (`https://easylist.to/pages/licence.html`); twelve rules are quoted with attribution.
- **Malware canaries (URLhaus)** (`canary-malware`). `https://urlhaus.abuse.ch/downloads/hostfile/`
  (12 KB, CRLF; the hosts of malware URLs online right now, the list a Pi-hole takes). **Derivation**:
  `127.0.0.1<TAB>host` lines reduced to registrable names (two labels once a leading `www.` is
  dropped; no addresses; no subdomain of a shared platform such as github.io or r2.dev, which a
  resolver must not sinkhole), then the twelve that hash lowest. Version and date from
  `# Last updated:`. **Cadence**: daily, because the host file turns over as sites go offline.
  **Licence**: abuse.ch Community data, free under its fair-use terms (`https://urlhaus.abuse.ch/api/`);
  commercial use may need the paid API.
- **Phishing canaries (OpenPhish)** (`canary-phishing`, restricted, registered off).
  `https://openphish.com/feed.txt` (15 KB, 300 URLs, refreshed every twelve hours; redirects to the
  `openphish/public_feed` repository). **Derivation**: the URLs' hosts reduced the same way; each
  entry keeps the origin (`https://host/`) and never a path. The feed carries no version, so the
  label is the hash of its bytes and the fetch dates it. **Licence**: the Community Feed terms
  (`https://openphish.com/terms.html`) allow non-commercial use only and forbid redistribution,
  derivative works and display to any third party, so the source is marked restricted
  (`sources.restricted`, migration 0029): the signed-in owner sees the twelve names on the Register
  as for any list; a visitor sees the versions, how many entries each holds and how many came,
  went or changed, with the names and text withheld and the licence quoted in their place; the
  JSON API and the MCP tools return neither names nor text to anyone, and no generated summary is
  made of a release. The Wire's release item counts the changes and never names them. The source
  still ships off; the owner turns it on from the Sources page (Turn on), and the adapter is
  tested against the real feed. Nothing in the code names the source: any source marked
  restricted is treated the same way.

---

## B. Vulnerabilities

### NVD API 2.0
- **CVE**: `https://services.nvd.nist.gov/rest/json/cves/2.0` with `lastModStartDate` /
  `lastModEndDate` (max 120-day window), paged by `startIndex` / `resultsPerPage` (max 2000).
- **CVE history**: `https://services.nvd.nist.gov/rest/json/cvehistory/2.0` with
  `changeStartDate` / `changeEndDate`; per-CVE change events (score added, CPE added, reference
  added). **Not used, and the row is gone** (migration 0034): BaselineWatch computes the same
  history by diffing successive sightings of a CVE, which costs no extra request, catches changes
  this endpoint does not report, and has been the only source of `vuln_changes` since M2. The
  endpoint is recorded here in case that ever stops being true.
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

### OSV.dev and the GitHub Advisory Database (added 2026-10-15)
- **Fetch**: `POST https://api.osv.dev/v1/query` with `{"package": {"name", "ecosystem"}}`, once per
  package on the watchlist (kind `package`, value `ecosystem:name`), paged by `next_page_token`.
  OSV carries the GitHub Advisory Database, PyPA, Go, RustSec and the distributions' trackers, so
  one query covers the GHSA ids too.
- **Cadence**: daily; the owner can fetch now after adding a package.
- **Shape**: `vulnerability`. An advisory is kept under its CVE id when it has one (NVD's words and
  score stay; the packages, fixed versions and advisory ids are added and the watch is marked),
  else under its GHSA or OSV id as a row of its own. Severity comes from the CVSS 3.x vector,
  scored here; CVSS 4.0-only advisories stay unscored.
- **Wire**: only an advisory published in the last thirty days, or one that changed since it was
  last seen; a package's back catalogue goes to the table alone, and a first pull never alerts.
- **Licence**: OSV data under its sources' licences; the GitHub Advisory Database is CC-BY 4.0.
  Attribution in the footer.
- **Diffability**: good. Stable ids; the affected set and fixed versions are diffed as a
  `packages` change.

### More advisory feeds (added 2026-10-15 evening, in the vulnerabilities group)
- CISA ICS Advisories, `https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml` (RSS,
  hourly): ICSA and ICSMA advisories with their CVEs and products. Public domain.
- Google Chrome stable releases, the Chrome Releases blog's "Stable updates" label (Atom, daily):
  each post lists the security fixes and CVEs of a stable channel update.
- GitLab security releases, `https://about.gitlab.com/security-releases.xml` (daily).
- Jenkins security advisories, `https://www.jenkins.io/security/advisories/rss.xml` (daily):
  core and plugin advisories.
- Not added: Amazon Linux ALAS (the feed carries every advisory ever, 2,900 items), MSRC's
  update-guide RSS (answers with no items), Oracle (refuses non-browser clients), Mozilla (no
  feed at the documented path), Broadcom/VMware (HTML).
- The Google Security Blog (Atom, daily) joins the news group.

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

### Public exploit indexes (added 2026-10-21, N5)
Three free, keyless indexes answer "is there a public exploit" on every CVE page and as a chip
in the table (`?exploit=1` filters to them). Each is read whole once a day; the bytes' hash is
kept in `app_settings` and an unchanged file is not parsed again. Rows live in `exploits`
(migration 0035): id, title, date, link to the index entry — never the exploit itself.
| Source | What is read | Licence |
| --- | --- | --- |
| Exploit Database (OffSec) | `files_exploits.csv` from the GitLab mirror: id, title, date, platform, verified flag, CVE ids (the `codes` column) | GPL-2.0; only the index, never an exploit's contents |
| Metasploit Framework (Rapid7) | `db/modules_metadata_base.json`: every module whose references cite a CVE; rank ≥ good counts as verified | BSD-3-Clause |
| PoC-in-GitHub (nomi-sec) | the README's `### CVE-…` headings and the repositories under each; a claim, never marked verified | MIT (the list) |
The adapters are `src/adapters/exploitdb.ts`, `metasploit.ts` and `poc-in-github.ts`; the
fixtures under `test/fixtures/exploits/` are the real files as served on 2026-10-21, trimmed.
Not added: VulnCheck XDB (needs a key; the plan keeps it behind an optional one), GitHub's
search API (rate-limited, and PoC-in-GitHub already does the search).

### Microsoft Security Update Guide (added 2026-10-21, N5)
`https://api.msrc.microsoft.com/cvrf/v3.0/updates` (JSON, daily, no key). The index lists every
monthly release with the date it was last revised; each release is one CVRF document
(`/cvrf/2026-Oct`, about 25 MB) of every CVE Microsoft published that month: title, product
tag, severity, exploit status ("Publicly Disclosed:No;Exploited:Yes;…"), CVSS, and the KB that
fixes it on each product. A pull reads the index, fetches the documents of the last forty days
whose revision date moved, and keeps one row per CVE in `msrc_vulns` (migration 0036); the
documents are a stream, not snapshots. The Wire gets **one item per monthly release** ("Microsoft
October 2026 Security Updates: 172 CVEs, 1 exploited, 12 critical"), with the Chromium CVEs
republished for Edge and the Azure Linux (Mariner) ones counted apart. The CVE page's Fix panel
shows "Microsoft's update": KB, products, build, restart; the table marks what Microsoft says is
exploited. Adapter `src/adapters/msrc.ts`; storage `src/msrc.ts`; fixtures `test/fixtures/msrc/`.

### Vendor pages and feeds (added 2026-10-21, N5)
| Source | What is read | Group |
| --- | --- | --- |
| Apple security releases, `https://support.apple.com/en-us/100100` (HTML, daily) | the table of every update with security content: name, devices, date; linked rows keyed by article number, unlinked ("no published CVE entries") by name and date; the newest 80 | vulnerabilities |
| Mozilla Foundation Security Advisories, `https://www.mozilla.org/en-US/security/advisories/` (HTML, daily) | each dated heading's advisories with impact and the product fixed; the newest 80 | vulnerabilities |
| Zero Day Initiative published, `https://www.zerodayinitiative.com/rss/published/` (RSS, daily) | advisories as published, each naming its CVE | vulnerabilities |
| Zero Day Initiative upcoming, `https://www.zerodayinitiative.com/rss/upcoming/` (RSS, daily) | flaws reported to a vendor and not yet published: the vendor, not the details | vulnerabilities |
| HashiCorp security bulletins, `https://discuss.hashicorp.com/c/security/52.rss` (RSS, daily) | HCSEC bulletins | vulnerabilities |
| AWS Security Bulletins, `https://aws.amazon.com/security/security-bulletins/rss/feed/` (RSS, daily) | bulletins, each naming its CVEs | vulnerabilities |
| Cisco Talos blog, `https://blog.talosintelligence.com/rss/` (RSS, hourly) | threat research | news |
Adapters `src/adapters/apple-security.ts` and `mozilla-mfsa.ts`; the feeds go through the feed
adapter. Probed and not added: NVIDIA, VMware/Broadcom, Atlassian, Kubernetes, Adobe and the
MSRC blog (HTML or bot walls at the documented feed paths), Oracle (refuses non-browser clients),
the Azure blog (marketing), Google Cloud (404 at the security feed path).

### Lookups on request (not pulled)
- **Check a domain** (`/scan/domain`, Scan 2.0 S3) asks this server's resolver about the name a
  visitor typed, asks Cloudflare's resolver over DoH (`cloudflare-dns.com`, already the network
  check's probe host) for the DNSSEC AD flag, and GETs the domain's own front page, its
  `/.well-known/security.txt` and `mta-sts.<domain>/.well-known/mta-sts.txt`, plus one TLS
  handshake on 443 and one plain-HTTP GET to see whether it redirects. Nothing is stored; answers
  are kept in memory ten minutes; an address gets a dozen checks in that time.
- **What this page learned about you** (`/scan`, S2) is computed from the request and kept
  nowhere. Two declared sources serve it: the **Tor exit list**
  (`https://check.torproject.org/torbulkexitlist`, text, daily, swapped whole into `tor_exits`,
  migration 0037) so the panel can say a visitor came through Tor; and **Shodan InternetDB**
  (`https://internetdb.shodan.io/<ip>`, JSON, no key) looked up only when the visitor presses the
  button for their own public address — ports, hostnames, CPEs, CVEs as Shodan last saw them — six
  lookups in ten minutes per address, nothing stored.
- crt.sh, for a certificate-transparency watch on the owner's domains, was probed on 2026-10-21
  and answered 502 three times; the watch waits for a captured response.

### Also planned
- OSV.dev `https://api.osv.dev/v1/`; GitHub Security Advisories (REST `/advisories`); Cisco
  openVuln; Red Hat CSAF/VEX; CERT/CC VINCE Atom `https://kb.cert.org/vuls/atomfeed/`.

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
| CISA directives (added 2026-10-17) | `https://www.cisa.gov/news-events/directives/all`, an HTML listing, ten a page (27 entries over three pages when added); `?page=N` for the rest. CISA publishes no feed for directives (`directives.xml` and `all.xml` under that path answer 404). | Binding Operational Directives and Emergency Directives with their dates, read from the teaser markup (`c-view__row`, `c-teaser__date`, `c-teaser__meta`, `c-teaser__title`). Each becomes a Wire item tagged with the platforms its title names (Cisco and F5 are network, Exchange is Windows, "security updates" or "cloud services" are every platform), so the STIG pages can show the directives that touch a platform. Every page's bytes are kept as a snapshot. A new directive alerts; the first fetch does not. Checked daily. |

Reddit's API terms allow personal, low-volume, identified use. Do not store comment bodies;
store the link post and link to the thread.

---

## C2. Platform vendors' security pages (no feeds; checked 2026-10-19)

Read by hand today and by small HTML adapters in M11.5. Each publishes on a page only:

| Vendor | Page | Notes |
| --- | --- | --- |
| Apple security releases | `https://support.apple.com/en-us/100100` | Every OS and app security release with its CVEs; Apple's only RSS is the developer releases feed, which is not security-specific. |
| Android Security Bulletins | `https://source.android.com/docs/security/bulletin` | Monthly; the patch levels (`2026-10-01`, `2026-10-05`) a device reports in `ro.build.version.security_patch`. |
| Samsung Mobile Security | `https://security.samsungmobile.com/securityUpdate.smsb` | Monthly SMR with Google's CVEs and Samsung's SVE items; per-model update scope at `workScope.smsb`. |
| Samsung TV, audio and displays | `https://security.samsungtv.com/securityUpdates` | SVP-<month>-<year> advisories, including the MagicINFO 9 Server fixes of 2025 and 2026; displays launched from 2023 get seven years of updates. |
| Microsoft Teams Rooms | `https://learn.microsoft.com/microsoftteams/rooms/rooms-release-note` | Release notes; lifecycle at `rooms-lifecycle-support`; Android device support dates at `devices/android-version-support`. |
| Zoom security bulletins | `https://www.zoom.com/en/trust/security-bulletin/` | Email subscription only. |
| Crestron, Logitech, Poly (HP) | vendor pages | No feeds found; Cisco Webex devices are covered by the Cisco PSIRT feed already on News. |

## D. Attribution text to show in the UI

- "This product uses the NVD API but is not endorsed or certified by the NVD."
- "CVE and the CVE logo are registered trademarks of The MITRE Corporation."
- "Known Exploited Vulnerabilities Catalog provided by CISA."
- "EPSS scores provided by FIRST."
- CIS and Microsoft content is shown from the user's own uploaded or fetched copy under their
  own licence; BaselineWatch does not redistribute it.
- "AdFection / Candiru indicators are the Zero Breach project's (CC0), which is not affiliated
  with the researchers it cites. Canary names are quoted from EasyList and EasyPrivacy (GPLv3 or
  CC BY-SA 3.0) and from URLhaus by abuse.ch; they are only ever resolved, never loaded, and
  nothing here links to them."
