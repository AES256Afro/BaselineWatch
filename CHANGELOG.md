# Changelog

Each version is a tag and an image: `ghcr.io/aes256afro/baselinewatch:<version>`.

## Unreleased

- **News is the home page.** The Wire, renamed News, answers at `/`; the Register moved to
  `/register` and `/wire` is a 301, so old links keep working. The masthead is grouped the way
  the leading aggregators group theirs: News · Today · Standards ▾ (Register, STIGs, Baselines,
  Atlas) · Vulnerabilities, with the owner's Desk ▾ (Triage, Watchlist, Digest, Sources, sign-in)
  as one cluster on the right — both menus plain `<details>`, no script, the CSP untouched. The
  wordmark drops its "Standards change register" subtitle; the phrase now reads as the News
  page's motto, the Standards menu's caption and the footer line, and an amber **Register
  ribbon** under the masthead on News and Today carries the three latest standards changes into
  their diffs.
- **News articles bring their pictures.** The front page leads with four image cards and the
  list shows thumbnails, BleepingComputer-fashion, with a typographic placeholder where a story
  brought no art. Images arrive passively at ingest: the feed's own media (enclosure,
  media:content, an `<img>` in content:encoded), else the article page's og:image fetched once
  per new item — never on page view, never re-crawled. The bytes are cached in the
  content-addressed blob store and served from `/img/<hash>` (only hashes an item claims;
  snapshots stay private), so `img-src 'self'` stands, readers' addresses never touch third-party
  hosts, and images are small derivatives beside headlines that always link to the source.
  `BW_NEWS_IMAGES=0` turns the whole thing off. New sidebar: the latest KEV entries and the
  owner's desk at a glance.

## 0.24.0 — 2026-10-17

- **The test plan draws one area at a time**, so a phone can use it the way 0.23.0 made the
  builder usable: authentication and SSO, browsers, disk encryption, logging and audit,
  network, updates, MDM enrolment and everything else, each behind a button. A RHEL 9 plan was
  413 KB and 439 checkboxes on one page; its largest area is now about 150 KB, and Windows 11's
  about 110 KB. The form still carries the state and nothing is stored: a hidden field names
  the area on the page and the other areas' dropped ids ride along as hidden fields, so untick
  in one area, open another, rebuild or export, and the whole plan is covered. Each procedure
  stays folded into its row. `?section=<area>` opens an area directly; "Owner's templates" and
  the GET export API (`/baselines/<platform>/tests/export?format=md&drop=...`) are unchanged.

## 0.23.0 — 2026-10-17

- **The baseline builder draws one section at a time**, so a phone can use it: the STIG's rules
  by CAT, "Microsoft's baseline adds", "mSCP adds" and the SP 800-53 High controls, each behind
  a button and each a few hundred kilobytes at most, where the whole Windows 11 profile came to a
  megabyte of HTML on one page. The form still carries the state and nothing is stored: a hidden
  field names the section on the page and the other sections' dropped ids ride along as hidden
  fields, so untick in one section, open another, rebuild or export, and the whole profile is
  covered. The "apply with" lines fold into each row, and "Show check and fix text" folds the
  rule text in on request. `?section=<id>` opens a section directly; the GET export API
  (`/baselines/<platform>/export?format=json&flavour=intune&drop=...`) is unchanged.
- The test-plan templates and the mitigations map (`data/test-plans/`, `data/mitigations.yaml`)
  are in the repository now. `.gitignore` and `.dockerignore` left the whole `data/` folder out,
  so CI failed for 0.21.0 and 0.22.0 and neither image was built: 0.23.0 is the first image with
  test plans, platform watch entries and the Fix panel. The database and snapshots under a local
  `data/` stay ignored.

## 0.22.0 — 2026-10-17

- **Platform watch entries** (M9.5): a watchlist entry of kind Platform names windows, apple,
  linux, android, chrome, firefox, edge or network, and every CVE on that platform is your
  stack: marked on the Vulnerabilities page, on the Wire however small its score, in the alerts
  ("New Apple CVE: CVE-…") and in the digest. A CVE's platform is read from its CPE criteria,
  then NVD's vendor and product, then the way its description names the platform when NVD has
  not analysed it yet, so a new macOS CVE arrives the hour it is published.
- A **Fix** panel on every CVE page, and a fix line on the Wire's CVE and KEV items: the
  remediation already published, quoted and linked. NVD's references tagged Patch, Vendor
  Advisory or Mitigation; the vendor advisories the Wire holds for the CVE; CISA KEV's required
  action and due date; the package advisories' fixed versions; and the STIG rules that mitigate
  the class of flaw, from the owner's `data/mitigations.yaml` (SMBv1, LLMNR, WDigest, NTLMv1,
  AutoPlay, PowerShell 2.0, Office macros, Gatekeeper, System Integrity Protection, Credential
  Guard, Network Level Authentication), each entry citing the publisher's statement. When
  nothing is published the panel says so. The JSON API's CVE record carries the same facts.

## 0.21.0 — 2026-10-17

- **Test plans** (`/baselines/<platform>/tests`, M9.4): what to test when a new OS release lands
  so the baseline still holds. Every check procedure of the profile's STIG and mSCP rules, filed
  by area (authentication and SSO, browsers, disk encryption, logging and audit, network,
  updates, MDM enrolment, everything else), plus the owner's templates kept as YAML in the
  repository (SSO through Intune and through Jamf with each browser, FileVault, BitLocker and
  LUKS key escrow, conditional access, enrolment), each step citing the publisher's document it
  follows and labelled as the owner's. Untick, rebuild, and export the checklist as printable
  HTML, Markdown, CSV or JSON.

## 0.20.0 — 2026-10-17

- **Baselines**, a new area (`/baselines`, M9.3): per platform, the strictest published profile
  as one form. Windows: a STIG's CAT I and CAT II rules (CAT III on request), Microsoft's
  Security Compliance Toolkit settings for the same product joined by registry path, DISA's own
  Intune settings-catalog definitions and checklist verdicts for each rule, and the NIST SP
  800-53 High baseline controls with the rules that implement them. macOS: the STIG joined to
  NIST's macOS Security Compliance Project rules with their configuration-profile payload keys.
  Linux: the STIG with its fix procedures. Untick what you cannot do, rebuild, and export the rest
  as printable HTML, Markdown, CSV or JSON in a plain, Jamf, Intune or Linux flavour; a GET with
  the same fields is an API. "Current versus next" says what the strict set gains and loses in
  the next loaded version of the STIG, the Microsoft baseline or the macOS branch.
- Three sources: NIST's **macOS Security Compliance Project** (one branch per macOS release,
  fetched at its exact commit, every rule with check, fix, payloads, severity and its 800-53,
  800-171, CCI, STIG and CIS references, plus which baselines list it); DISA's **Intune policy
  package** (the settings-catalog policies DISA ships for its STIGs, one row per setting); and
  the **checklists in DISA's GPO package** (DISA's verdict, rule by rule, on what its GPO and
  Intune policies set).
- The `yaml` package moves from a development dependency to a runtime one for the mSCP rules.

## 0.19.0 — 2026-10-17

- **STIGs**, a new area (`/stigs`, M9.2): the STIGs the Register follows by platform (Windows,
  Linux, macOS, mobile, browsers, network devices, virtualisation, applications), and one page
  per platform showing a STIG's rules grouped CAT I, II, III with the check and fix text folded
  away, the NIST SP 800-53 controls each rule maps to, what changed in the latest release with
  DISA's notes, and CISA's advice for the platform: the KEV entries whose vendor and product
  belong to it and the directives whose titles name it.
- DISA's **Control Correlation Identifier list** as a source: each CCI's definition and its
  index into SP 800-53 Revision 5 (or 4). It is the join between STIG rules and controls, in both
  directions: a rule's page in the Register names the controls it implements, and a control's
  page lists the followed rules that implement it. Found through the STIG library listing, so an
  unchanged list costs one small request a week.
- **CISA directives** as a source: Binding Operational and Emergency Directives read from
  CISA's listing (it has no feed), on the Wire under News, tagged with the platforms they name,
  with an alert when a new one appears.
- The DISA source's default followed set grows to Windows 11, Windows Server 2025 and 2022, Red
  Hat Enterprise Linux 9 and 10, Ubuntu 24.04 and 22.04, Apple macOS 26 and 15, Microsoft Edge,
  Google Chrome, Mozilla Firefox, Cisco IOS XE Router and Application Security and Development.
  Watchlist entries of kind Baseline still replace the defaults.
- `docs/PLAN.md` gains M9, Baselines, and `docs/COMPETITION.md` surveys what comparable tools do
  and what BaselineWatch borrows or leaves alone.

## 0.17.0 — 2026-10-15

- A second look, **Console**: the dense dashboard of a security console, with panels, uppercase
  mono titles, large thin figures, hexagon severity marks and charts drawn on the server, in light
  and dark. The Register's paper look stays as **Paper**. A switch in the masthead chooses the look
  and the colours (auto, light, dark) per browser with two cookies and no script; `BW_LOOK` and
  `BW_SCHEME` set the instance's defaults, and the BoxPilot manifest exposes both.
- Today gets six glance panels under its tiles: KEV additions by vendor over 30 days, Wire items
  a day over 14 days, watched CVEs that changed by CVSS severity, every CVE by EPSS band, triage
  by state, and each source's last fetch. Every chart is inline SVG with its figures in words.

## 0.16.1 — 2026-10-15

- At start, every standard's versions are put in publication order before anything is served:
  a chain an older version linked wrong is re-diffed once, and a correct one costs a query.

## 0.16.0 — 2026-10-15

- A standard's first scheduled fetch loads its published history before the current file, so a
  fresh install opens on the real NIST SP 800-53 5.1.1 to 5.2.0 diff within minutes with no
  backfill command. A back catalogue raises no alerts. `npm run backfill` remains for doing it now.
- The admin guide says what the OSV and GitHub fetches send out and how /mcp is gated; the
  BoxPilot manifest describes the current product and first run.

## 0.15.0 — 2026-10-15

- More advisories on the Wire: CISA's ICS advisories, Google Chrome stable releases, GitLab
  security releases and Jenkins security advisories, filed with the vendor advisories; and the
  Google Security Blog among the news.
- DEPLOY.md: how to roll without sudo once /opt/baselinewatch is the docker user's, and what to
  load after a version that adds a standard.

## 0.14.0 — 2026-10-15

- NIST SP 800-171 Revision 3 in the Register, from NIST's OSCAL: the CUI requirements that make up
  CMMC Level 2, numbered as the publication numbers them (03.01.01), grouped by family, with
  statement items lettered, organization-defined parameters, assessment objectives and the
  requirements withdrawn from Revision 2 kept as withdrawn. Tracking starts at OSCAL 1.1.0; the
  Sources page says why there is no backfill.

## 0.13.0 — 2026-10-15

- A read-only MCP server at `/mcp` (Streamable HTTP, stateless) for BoxPilot's agents, Claude Code
  and scripts: `list_standards`, `release`, `requirement`, `standard_changes`, `search_wire`,
  `vulnerabilities`, `vulnerability`, `triage` and `digest`, every tool marked read-only and
  answered from the instance's own database with links back. Same read gating as the pages and
  the JSON API; nothing on it writes, uploads or fetches.

## 0.12.0 — 2026-10-15

- Package advisories from OSV.dev and the GitHub Advisory Database. Add a package to the watchlist
  (kind "package", value ecosystem:name such as npm:express, PyPI:django,
  Maven:group:artifact or Debian:12:openssl) and the daily pull queries OSV for it. An advisory
  lands on its CVE when NVD has it, adding the affected packages, fixed versions and advisory ids
  and marking your watch; a GHSA or distribution entry NVD has not analysed gets a row of its own.
  Severity is scored here from the CVSS 3.x vector. Only advisories published in the last thirty
  days, or changed since last seen, reach the Wire; the back catalogue stays in the table.
- The CVE page shows affected packages with their fixed versions, the advisory ids, and links to
  the GitHub advisory and OSV; the Vulnerabilities table names the package when NVD names no vendor.

## 0.11.0 — 2026-10-15

- FedRAMP's Consolidated Rules for 2026 in the Register: the FRR rules by family and subset, the
  Key Security Indicators, the definitions and the parameter values and guidance FedRAMP sets on
  NIST SP 800-53 controls, read from FedRAMP's own JSON on GitHub and diffed entry by entry. Each
  entry's dated change note sits beside the changes it explains, and the notes dated on the
  release day are the release's reason. The backfill loads four earlier versions from July 2026.
  It takes the place of the Rev5 OSCAL baselines, whose repository is gone.
- Tag builds sign the image (Sigstore, keyless), attach an SPDX SBOM and record build provenance;
  the admin guide shows how to verify them.

## 0.10.2 — 2026-10-15

- A standard's versions are linked by publication date, whatever order they arrive in. A backfill
  run after the scheduler had already fetched the current release used to hang the history off
  that release, so the Register showed 5.1.1 as a reverse diff and 5.2.0 as "no control-level
  changes"; now the older version slots in before it and the current one is re-diffed against it.
- `npm run relink -- <source|all>` repairs a chain linked that way, re-diffing only what was wrong.
- A history entry whose bytes are already loaded still lends the release its publisher's reason.

## 0.10.1 — 2026-10-15

- Links that leave the site (articles, advisories, NVD and CVE records, publishers' rationale,
  the sources list, the footer's source link) open in a new tab; links within the site do not.

## 0.10.0 — 2026-10-15

- Vendor security advisories on the Wire, apart from news: Ubuntu, Debian, Cisco, Palo Alto
  Networks, Fortinet and Red Hat, with the CVE ids they name as signals. The Wire gains filters
  by group (news, vendor advisories) and for releases.
- A changelog.

## 0.9.1 — 2026-10-15

- Every loaded version of a standard can be read whole: a browsable, searchable list of its
  requirements by family, with the ones that changed in that release marked.

## 0.9.0 — 2026-10-15

- CIS Benchmarks by owner upload: the PDF is read, recommendations are parsed from their
  numbered headings and labelled sections, and the next upload of the same benchmark is diffed
  against the last.
- The read-only JSON API under `/api/v1/` (items, vulns, standards, changes, triage, digest).
- The Register's typefaces served from their packages, so nothing loads from Google.
- HSTS behind TLS; `docs/ADMIN.md`.

## 0.8.0 — 2026-10-15

- Today: since you last looked, phone-first (the Console direction).
- Atlas: a release timeline per standard, the SP 800-53 change-intensity map by control family,
  change velocity and what is expected next (the Atlas direction).

## 0.7.0 — 2026-10-15

- Triage on any item, CVE or requirement in a release, with notes, due dates, a board with an
  inbox, and CSV export (the Board direction).
- Alerts through ntfy, Gotify or a webhook for KEV additions, watched CVE changes and standard
  releases, never on a source's first load; every attempt logged.
- A daily or weekly digest at a local hour, sent the same way and kept on its own page.

## 0.6.0 — 2026-10-15

- The publisher's reason beside every change: NIST's Planning Note from the publication page,
  DISA's Revision History read from the PDF and attached rule by rule, Microsoft's announcement
  from the zip; a release with no captured reason says so.
- Optional Ollama summaries per release, stored as generated and badged on every page.

## 0.5.0 — 2026-10-15

- DISA STIGs: the library read through the site's own listing call, the STIGs on the watchlist
  (or six defaults) downloaded and diffed rule by rule from their XCCDF.
- Microsoft Security Baselines: every toolkit zip diffed setting by setting from its
  `.PolicyRules` file, older UTF-16 toolkits included.

## 0.4.0 — 2026-10-15

- The Register: NIST SP 800-53 and its 800-53B baselines from the OSCAL catalogs, every release
  kept as a snapshot and diffed field by field with a word-level redline; `npm run backfill`
  loads Release 5.1.1 to 5.2.0 from NIST's published history.

## 0.3.0 — 2026-10-15

- Vulnerabilities: every CVE NVD modifies, with the best CVSS, SSVC, CWEs, CPEs, references,
  CISA KEV and FIRST EPSS, a field-level change history per CVE, and the watchlist.
- Only notable CVEs reach the Wire.

## 0.2.0 — 2026-10-14

- The Wire: news feeds, Reddit, Hacker News, CISA advisories and the KEV catalog in one
  searchable timeline, with read and star state for the owner.
- The owner session, the scheduler and the `fetch` command.

## 0.1.0 — 2026-10-14

- The scaffold: Node 24 running TypeScript directly, Express 5, SQLite with migrations, the
  source register, the container, CI, and the BoxPilot catalog manifest.
