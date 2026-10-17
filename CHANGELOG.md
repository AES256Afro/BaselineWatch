# Changelog

Each version is a tag and an image: `ghcr.io/aes256afro/baselinewatch:<version>`.

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
