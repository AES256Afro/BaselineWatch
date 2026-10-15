# Changelog

Each version is a tag and an image: `ghcr.io/aes256afro/baselinewatch:<version>`.

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
