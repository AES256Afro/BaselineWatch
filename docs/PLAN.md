# BaselineWatch: plan and milestones

*Written 2026-10-14. Owner: Chris (AES256Afro). M0 to M8 shipped by 2026-10-15; M9 planned 2026-10-17.*

BaselineWatch is one page that keeps a security practitioner in tune with the whole landscape:
security news, new and changed CVEs, CISA advisories and the Known Exploited Vulnerabilities list,
NIST publications, and, the part no feed reader does, **the standards and baselines themselves**.
When NIST SP 800-53 moves from Release 5.1.1 to 5.2.0, when DISA ships a quarterly STIG drop, when
Microsoft changes a setting in the Windows Server baseline, BaselineWatch shows the control or
setting **before and after**, says **what changed**, and quotes **why** from the publisher's own
release notes.

It runs on its own (one container, one SQLite file) or on a server, and it is built from day one
to be installed from the BoxPilot catalog on BigBox.

---

## 0. Decisions

| Date | Decision |
| --- | --- |
| 2026-10-14 | The **Register** is the home page (mockup direction 2). |
| 2026-10-14 | Build follows **Path C**, the recommended middle: Register built properly, Wire and Vulnerabilities thin, server-rendered HTML first, React only if the UI outgrows it. |
| 2026-10-14 | Public home is **https://cybercard.net**, replacing the FinancialAuthority demo there. It is a read-only information, learning and teaching site: no private data, anyone may read, writes need the owner's sign-in (M7). Hosted on BigBox, published through Cloudflare. |
| 2026-10-14 | Stack: Node 24 running TypeScript directly (no build step), Express 5, `node:sqlite`, one stylesheet, strict CSP with no inline script. |
| 2026-10-17 | **M9 Baselines** turns the tracked standards into guidance: STIG pages per operating system, a baseline builder per platform with exports for Jamf, Intune and Linux, test plans for a new OS release, platform alerts and a Fix panel. No generative AI in that path: every line derives from DISA, NIST, Microsoft and CISA text and refreshes with the sources. CIS stays upload-only. Survey of comparable tools in [COMPETITION.md](COMPETITION.md). |

---

## 1. What it is, in one screen

| Area | What the user sees | Source of truth |
| --- | --- | --- |
| **Wire** | One stream of security news, advisories and vulnerability events, deduplicated, filterable by source, product, severity and "affects my stack". | RSS/Atom and JSON feeds (section 3). |
| **Vulnerabilities** | New and modified CVEs with CVSS, EPSS and KEV flags; what changed on a CVE since you last looked (score, references, CPEs). | NVD API 2.0, CISA KEV, CVE List V5, EPSS. |
| **Register** | The standards change register: every tracked baseline, every release, every changed control or setting with before/after and rationale. | OSCAL/CPRT JSON (NIST), XCCDF (DISA), GPO/Excel (Microsoft), uploaded PDFs (CIS). |
| **Watchlist** | The products, platforms and baselines you own. Everything else is dimmed. | User config. |
| **Triage** | New → Reviewing → Affects us → Done, with notes, per item. | SQLite. |
| **Digest** | Daily or weekly summary to ntfy, Gotify, email or webhook. | Scheduler. |

Non-goals for v1: multi-tenant accounts, scanning your systems, ticketing integrations, mobile app
(the web page is responsive and installable as a PWA).

---

## 2. The core idea: snapshot, normalise, diff, explain

Every source goes through the same four-stage pipeline. News only uses the first two; standards
use all four.

```
fetch ──► SNAPSHOT ──► NORMALISE ──► DIFF ──► EXPLAIN ──► timeline + notify
          (store the     (one common     (structural,   (rationale from
           exact bytes,   shape per       per control    official changelog;
           hash, time)    kind)           or setting)    optional LLM summary)
```

1. **Snapshot.** Store the exact bytes of every fetched document, keyed by source + content hash +
   fetch time. Never diff against something you did not keep. This is what makes "before" possible
   a year later.
2. **Normalise.** Convert each format into one of a few common shapes:
   - `requirement`: id, title, statement, discussion/guidance, parameters, related ids, baseline
     membership (for 800-53 controls, 800-171 requirements, STIG rules, CIS recommendations).
   - `setting`: path, value, scope, rationale (Microsoft baselines, CIS Level 1/2 values).
   - `vulnerability`: id, scores, CPEs, references, KEV status, EPSS.
   - `article`: title, link, published, source, summary.
3. **Diff.** Compare normalised shapes between consecutive snapshots of the same document.
   Output is a list of `change` rows: added / removed / modified, at the field level, with the
   before and after text. Word-level redline is rendered from those two strings in the UI.
4. **Explain.** Attach the publisher's own words: the release note, the "Planning Note", the blog
   post, the XCCDF revision history, the Excel changelog sheet. If an LLM summary is enabled it is
   a second, clearly labelled paragraph, never the only explanation.

Why this is the right spine: it is format-agnostic (a new standard is a new normaliser, nothing
else changes), it keeps every version (audit evidence), and it makes "why" a first-class field.

---

## 3. Sources

Full register with URLs, formats, cadence, licensing and diffability is in
[SOURCES.md](SOURCES.md). Summary:

**Standards and baselines (the Register)**

| Standard | Format we diff | Rationale source | Difficulty |
| --- | --- | --- | --- |
| NIST SP 800-53 / 53A / 53B (Rel 5.2.0 current) | OSCAL JSON from usnistgov/oscal-content or CPRT JSON | CSRC publication page Planning Note, release notes | Low: structured JSON, control ids stable |
| NIST SP 800-171 r3 / 171A r3 | CPRT JSON (CAPORDINO converts to OSCAL) | CSRC page, change analysis spreadsheet | Low |
| NIST CSF 2.0, SP 800-61r3, 800-63-4, other CSRC pubs | CPRT JSON where present, else PDF text | CSRC publication pages, drafts-open-for-comment feed | Medium |
| DISA STIGs and SRGs (quarterly) | XCCDF XML inside zips from cyber.mil; NIST NCP mirror | XCCDF revision history element per release | Medium: zips, no feed, many files |
| Microsoft Security Baselines (SCT, Intune) | GPO backups and the baseline .xlsx in the toolkit zip | Microsoft Security Baselines blog post per release | Medium: zips, Excel parsing |
| CIS Benchmarks and CIS Controls | PDF (registration-walled, licensed, no redistribution) | Changelog pages inside the PDF | High: manual upload mode only |
| ComplianceAsCode/content (open STIG/CIS profiles) | YAML in a git repo | Git history | Low: free diffs |

**Vulnerabilities**: NVD API 2.0 (CVE and CVE History endpoints; 5 requests per 30 s without a
key, 50 with the free key, 120-day window per query), CISA KEV JSON, CVE List V5 hourly delta
releases on GitHub (cheaper than polling NVD), FIRST EPSS, OSV.dev, GitHub Security Advisories,
MSRC CVRF, CERT/CC VINCE Atom.

**News**: BleepingComputer, The Hacker News, Krebs, SANS ISC, The Record, Schneier, Dark Reading,
SecurityWeek, Risky Business, Google Project Zero, MSRC blog, CISA advisories, NSA advisories,
UK NCSC, /r/netsec, /r/cybersecurity, /r/blueteamsec, Hacker News (Algolia search for security
terms). You wrote "CSET"; this plan reads that as CISA. If you meant Georgetown's CSET, their
publications page has a feed and slots in as one more news source.

---

## 4. Architecture

Single container, one process, one SQLite file. Same stack family as BoxPilot so pieces can be
shared later.

```
┌──────────────────────────────────────────────────────────────────┐
│ baselinewatch (Node 24, one container)                           │
│                                                                  │
│  scheduler ─► source adapters ─► snapshot store ─► normalisers  │
│  (cron-like)   (one module per     (blobs on /data,  ─► differ   │
│                 source, declares    index in SQLite)  ─► explain │
│                 cadence + parser)                                │
│                                                                  │
│  SQLite (node:sqlite, WAL, FTS5): items, snapshots, documents,   │
│  requirements, settings, changes, vulns, triage, watchlist,      │
│  notifications, settings                                         │
│                                                                  │
│  HTTP (Express 5): JSON API /api/v1/*, server-rendered pages or  │
│  React SPA (path-dependent, section 6), /health, /metrics        │
│                                                                  │
│  notifier: ntfy / Gotify / Apprise / SMTP / webhook              │
│  optional: LLM summariser via Ollama or BoxPilot model gateway   │
└──────────────────────────────────────────────────────────────────┘
          /data  (SQLite + snapshot blobs)   ◄── the only volume
```

Decisions baked in:

- **Node ≥ 24, ESM, `node:sqlite`, Express 5, TypeScript.** Matches BoxPilot's conventions so
  code review, tooling and eventually UI kit components carry across.
- **Snapshots as content-addressed blobs on disk**, index in SQLite. Simple, backup-friendly
  (the volume is the backup), no object store.
- **Adapters are data plus a parser**, not bespoke apps: each declares `id`, `kind`
  (article | vulnerability | requirement-set | setting-set), `schedule`, `fetch()`, `parse()`.
  Adding a source is one file and a fixture test.
- **No outbound calls except to declared sources and the configured notifier.** The container
  runs read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, as BoxPilot already does
  for itself.
- **Auth**: single local account (password, optional passkey) in standalone mode; behind BoxPilot
  it can also run with auth off on loopback and let BoxPilot's proxy and Tailscale do the gate.
- **LLM is optional and labelled.** Default off. When on, it only summarises text already on
  screen and the summary carries a "generated" badge next to the quoted official rationale.

---

## 5. Milestones

Each milestone ends with something you can use. Estimates assume one developer working with an
agent; the first number is the "fast" path, the second the "quality" path from section 6.

### M0: Scaffold (2 to 4 days)
- Repo layout, TypeScript, lint, vitest, GitHub Actions (build, test, container publish to GHCR).
- `Dockerfile` (multi-stage, non-root, read-only), `docker-compose.yml`, `/health`.
- `boxpilot/baselinewatch.yaml` catalog manifest validated against BoxPilot's schema.
- SQLite schema v1 and migration runner.
- **Done when**: `docker run` serves an empty timeline on BigBox and BoxPilot installs it from a
  local manifest.

### M1: Wire (1 to 2 weeks) — shipped 2026-10-14 as 0.2.0

What landed: feed, Reddit, Hacker News and KEV adapters behind one ingest pipeline with
content-addressed snapshots; an in-process scheduler with per-host spacing and a `fetch` CLI;
the Wire page with source and kind filters, FTS5 search, read and star state and cursor paging;
the owner session (password, signed cookie, same-origin guard, login throttle); `Fetch now` on
the Sources page. First live run: 15 of 16 news and advisory sources parsed on the first try.
- RSS/Atom/JSON adapters for the news list; Reddit and HN adapters with proper User-Agent and
  backoff; dedupe by canonical URL and title similarity.
- CISA KEV adapter (new additions are events), CISA advisories feed, CSRC drafts-open-for-comment.
- Timeline UI: one stream, source filter, read/unread, star, search (FTS5), keyboard navigation.
- **Done when**: you open it in the morning and nothing you care about is missing; nothing shows
  twice.

### M2: Vulnerabilities (1 to 2 weeks) — shipped 2026-10-15 as 0.3.0

What landed: an NVD API 2.0 puller (incremental from a stored cursor, 120-day windows, 2,000 a
page, polite pacing with or without a key, a backfill on first run); a vulnerabilities table with
the best CVSS (4.0, 3.1, 3.0, then 2), SSVC decisions, CWEs, vulnerable CPE criteria, vendors and
products, references, and CISA KEV fields; a field-level change history computed between
sightings (score, description, status, CPEs, references, CWEs, KEV, EPSS jumps), which makes the
NVD history endpoint unnecessary; the daily FIRST EPSS join; the KEV catalog joined onto known
CVEs; the watchlist (vendor, product, vendor:product, CPE prefix, keyword) with re-marking on
change; the Vulnerabilities list with filters and search and a per-CVE page; and "notable" CVEs
(KEV, your stack, new criticals, EPSS over 50%, active exploitation per SSVC) on the Wire.
CVE List V5 deltas are deferred: NVD's modified window every hour has been enough.
- NVD API 2.0 adapter with API key, `lastModStartDate` windows, polite rate limiting, resume
  cursor; CVE History endpoint for "what changed on this CVE".
- CVE List V5 delta releases as the primary trigger (hourly), NVD for enrichment.
- EPSS daily join; KEV flag join.
- Watchlist v1: products as CPE prefixes or keywords; "affects my stack" filter.
- **Done when**: a CVE added to KEV, or a watched product's CVE changing score, surfaces within
  the hour with its change history.

### M3: Register, structured sources (2 to 3 weeks) — shipped 2026-10-15 as 0.4.0

What landed: the OSCAL normaliser (groups, controls and enhancements into one `requirement`
shape with the printed label, parameters resolved into the text, related controls, status and
the 800-53A assessment objective), the profile normaliser (baselines as control membership), a
field-level differ with a substantive/editorial split, a word-level redline, the document
ingestion path (snapshot, store, diff against the previous version, record the explanation,
post a release to the Wire), the NIST adapters with the catalog's published history so
`npm run backfill` seeds Release 5.1.1 → 5.2.0 with NIST's verbatim Planning Note as the
rationale, and the three Register pages: a standard's versions, a release's changes, and a
control's before/after. Found on the way: NIST's note says every -01 control had related-control
updates, but the OSCAL catalog shows AC-1 unchanged, which is exactly the kind of thing the
Register exists to show.
- Snapshot store (blobs + index + retention policy).
- Normaliser for OSCAL catalogs and profiles (800-53, 53A, 53B, 171r3 via CPRT/CAPORDINO).
- Differ for `requirement` shapes: added/removed/modified controls, field-level, parameter
  changes, baseline membership changes.
- Register UI: list of tracked standards, release history per standard, change list per release,
  control page with before/after redline.
- Seed with real history: load 800-53 Rel 5.1.1 and 5.2.0 snapshots so the first diff you see is
  the real one (SA-15(13), SA-24, SI-02(07) added; SI-07(12) revised; discussion updates on
  SA-04, SA-05, SA-08, SI-02).
- **Done when**: the 5.1.1 → 5.2.0 diff on screen matches NIST's published change list exactly.

### M4: Register, semi-structured sources (2 to 3 weeks) — shipped 2026-10-15 as 0.5.0

What landed: the DISA adapter reads the STIG library through the Apex call the cyber.mil page
itself makes, follows the STIGs on the watchlist (or six defaults), downloads each zip and
normalises the XCCDF rule by rule (Group id as the stable ref, STIG id, severity as CAT, check,
discussion, fix, CCIs). The Microsoft adapter reads the toolkit page's embedded file list and
every "Security Baseline" zip's `.PolicyRules` file setting by setting (registry values,
security-template lines, audit subcategories), with the GPO version token stripped from refs so
settings keep their identity across releases. Listings are compared by file URL and publication
date, so a daily check costs one small request until something moves. First live run: six STIGs
(1,516 rules) and ten Microsoft baselines (3,764 settings) in under three seconds each; the
2016-era Windows 10 1607 zip predates the PolicyRules format and is reported, not loaded.
ComplianceAsCode is deferred.
- DISA STIG adapter: watch the downloads listing, fetch zips, extract XCCDF, normalise rules
  (rule id, severity, title, check, fix), diff per STIG per release, read the revision history
  element for rationale. Fallback mirror: NIST NCP.
- Microsoft SCT adapter: detect new toolkit version, fetch, parse the baseline .xlsx and GPO
  backups into `setting` rows, diff, link the blog post.
- ComplianceAsCode adapter: git history as the diff engine for open STIG/CIS profiles.
- **Done when**: the next quarterly STIG release and the next Microsoft baseline show up as
  per-rule and per-setting diffs without manual work.

### M5: Explain (1 to 2 weeks) — shipped 2026-10-15 as 0.6.0

What landed: PDF text extraction (pdfjs, lazily loaded); DISA's Revision History read from each
STIG zip and split into per-rule notes ("WN25-00-000020 - Updated max password age value to 180
days") that attach to the exact changes they explain, with the release-wide notes as the release
rationale; Microsoft's Announcement PDF stored as the baseline release's rationale; NIST's Planning
Note read from the CSRC publication page for any release the built-in history does not already
explain; a release with no captured reason marked as such; and an optional Ollama summary per
release with changes, stored as kind `generated` and badged on every page, built only from the
before/after text and the publisher's note. The control page shows "Why it changed, in the
publisher's words" above the redline when a note exists.
- Rationale extractors: CSRC Planning Note and release notes, XCCDF revision history, Microsoft
  blog post sections, CIS changelog pages; stored as `explanation` rows linked to changes.
- Optional LLM summary via Ollama or BoxPilot's model gateway; prompt includes only the before,
  after and official rationale; output badged "generated".
- **Done when**: every change in the Register has either a quoted official reason or an explicit
  "publisher gave no reason" marker.

### M6: Triage, watchlist v2, digest (1 to 2 weeks) — shipped 2026-10-15 as 0.7.0

What landed: triage on any timeline item, CVE or requirement-in-a-release (New, Reviewing,
Affects us, Done, Not ours) with notes and due dates, a board with an inbox of unplaced KEV
entries, notable CVEs and releases, triage controls on the Wire, CVE and control pages, and a CSV
export; alerts through ntfy, Gotify or a webhook for KEV additions, watched CVE changes and
standard releases, never on a source's first load, five singly and the rest as one line, every
attempt logged; a daily or weekly digest written at a local hour and sent the same way, kept on
its own page with the alert log. Watchlist entries of kind `baseline` choose which STIGs are
followed (M4) and control families are stored for the Register. Email stays with ntfy or Apprise.
- Triage states and notes on any item (article, CVE, change). Bulk actions. Export CSV.
- Watchlist v2: which baselines apply to you, which control families you own; the Register dims
  everything else.
- Daily and weekly digest; immediate alerts for KEV additions and watched-standard releases;
  ntfy, Gotify, Apprise, SMTP, generic webhook.
- **Done when**: Monday's digest is the thing you read instead of six sites.

### M6.5: The other three directions — shipped 2026-10-15 as 0.8.0

Chris asked for all five mockups as pages, not one. The Register is the home and the Wire is the
stream; the Board is the Triage page (M6); the Console is the Today page (`/today`): since you
last looked, with tiles, the needs-you list, releases, the latest stories, failing sources and
the last alerts, laid out for a phone first; the Atlas (`/atlas`) is the release timeline per
standard and the SP 800-53 change-intensity map by control family, both drawn as inline SVG with
positions as attributes so the strict CSP stands, plus change velocity and what is expected next
from each publisher's cadence.

### M7: Hardening and BoxPilot (1 week)
- Auth, CSRF, rate limits, backups guidance (the volume), SBOM and image signing in CI.
- Catalog PR to AES256Afro/BoxPilot with pinned image, health check, secrets for NVD key and
  notifier URL, `notes` for first run.
- Docs: README, SOURCES, ADMIN, a short "how a diff is computed" page.
- **Done when**: installed on BigBox from the BoxPilot catalog, backed up by BoxPilot, updated by
  BoxPilot.

### M7: Hardening and BoxPilot — 2026-10-15

Done: HSTS behind TLS, the admin guide (`docs/ADMIN.md`), and the catalog manifest proposed as
[AES256Afro/BoxPilot#472](https://github.com/AES256Afro/BoxPilot/pull/472) with BoxPilot's
catalog tests passing. The public site went live on 2026-10-15: BaselineWatch runs on BigBox
through a Cloudflare Tunnel at https://cybercard.net with the strict CSP, the demo is retired and
the categorisation request is in; `docs/DEPLOY.md` describes the setup and how to upgrade it.
Tag builds sign the image and attach an SBOM and provenance since 0.11.0. Still open from the
list above: the install through BoxPilot once the catalog PR is merged.

### M8: Stretch — first three shipped 2026-10-15 as 0.9.0

Shipped: CIS Benchmarks by owner upload (a multipart form, the PDF read with pdfjs, recommendations
parsed from their numbered headings and labelled sections, diffed against the previous upload of
the same benchmark); the read-only JSON API (`/api/v1/*`) for BoxPilot's agents and scripts; the
Register's typefaces served from their packages so the strict CSP stands and nothing loads from
Google. Since then: a browsable, searchable view of every requirement in a version (0.9.1);
vendor security advisories on the Wire, Ubuntu, Debian, Cisco, Palo Alto Networks, Fortinet and
Red Hat (0.10.0); off-site links in a new tab (0.10.1); versions linked by publication date and
`relink` (0.10.2); FedRAMP's Consolidated Rules for 2026 in the Register (0.11.0), in place of
the Rev5 OSCAL baselines, whose repository GSA has taken down; package advisories from OSV and
the GitHub Advisory Database for the packages on the watchlist (0.12.0); the read-only MCP
server at `/mcp` (0.13.0); NIST SP 800-171 Rev 3 in the Register, which is the CMMC Level 2 set
(0.14.0). Still open: Intune baselines (no public machine-readable source yet), multi-user.

### M8 as planned
- CIS Benchmarks in manual-upload mode (drop the PDF, get the diff against your last upload).
- Vendor PSIRTs (Cisco openVuln, Red Hat, Ubuntu USN, Debian DSA), OSV, GHSA.
- Intune baseline JSON, CMMC Level 2 mapping, FedRAMP Rev5 baselines (OSCAL).
- Public read-only API and an MCP server so BoxPilot agents can answer "what changed in 800-53
  this quarter?".
- Multi-user with roles.


### M9: Baselines (planned 2026-10-17)

M0 to M8 made BaselineWatch *watch*: news, CVEs and the standards themselves, each change with
its publisher's reason. M9 makes it *guide*. The standards the Register already tracks (DISA
STIGs, Microsoft's baselines, NIST SP 800-53 and its baselines) become, per operating system,
something a practitioner can act on: which rules apply, what they map to in 800-53, what CISA
says about that platform, a strictest-published profile to trim and export for Jamf, Intune or
a Linux shell, a test plan for the next OS release, and on every CVE the fix that has already
been published. The survey of comparable tools and what to borrow or avoid is
[COMPETITION.md](COMPETITION.md).

**Rule for the whole milestone: no generative AI in the path.** Every sentence on these pages
is quoted or derived from DISA, NIST, Microsoft or CISA text and refreshes when those sources
do. Where a mapping exists only in someone's head (which Intune setting a STIG rule becomes),
the page says so rather than inventing one. Curated lists kept in the repository (test-plan
templates, CVE-to-rule mitigations) are plain YAML, cite their source, and are labelled as the
owner's. CIS Benchmarks stay upload-only and are never exported.

**New sources** (each an adapter with a fixture test, a row in a migration, a line in
`src/adapters/index.ts`; details in [SOURCES.md](SOURCES.md)):

| Source | Format | What it gives M9 |
| --- | --- | --- |
| DISA CCI list (`disa-cci`) | zip with `CCI_List.xml`, from the STIG library listing's "CCI List" entry (dated, so an unchanged list costs one small request) | CCI → NIST SP 800-53 Rev 5 (and Rev 4) control index per CCI; the join between every STIG rule and the Register's control pages |
| CISA directives (`cisa-directives`) | the HTML listing at `cisa.gov/news-events/directives/all` (27 entries over three pages, teaser markup with date, kind and title; CISA offers no feed for it) | Binding Operational Directives and Emergency Directives as Wire items, matched to platforms by what they name (Cisco, Exchange, F5, Ivanti, cloud services, edge devices) |
| NIST macOS Security Compliance Project (`nist-mscp`) | one GitHub branch zip per macOS release (`tahoe`, `sequoia`; about 1 MB each), `VERSION.yaml` for the version and date, `rules/**/*.yaml` and `baselines/*.yaml` | 335 rules with check and fix, mobileconfig payload keys, 800-53 r5, 800-171 r3, CCI, STIG and CIS references; which rules sit in the 800-53 High, 800-171 and DISA STIG baselines |
| DISA Intune policy package (`disa-intune`) | zip from the listing's "Intune Policy - <month year>" entry; `Settings Catalog/*.json` are Graph `configurationPolicies` exports (Windows 11 v2r11: 174 settings) | the Intune settings-catalog definition ids and values DISA itself ships for each Windows STIG |
| DISA GPO package checklists (`disa-gpo`) | zip from the listing's "Group Policy Objects (GPOs) - <month year>" entry (7 MB); `Support Files/Checklist Files/*.ckl` | per STIG rule, DISA's own statement of whether its GPO and Intune policies cover it ("GPO - DoD Windows 11 Computer STIG v2r11 / Intune - DoD Windows 11 STIG v2r11 Settings Catalog") or it is "Outside scope of GPO configurations" |

The DISA source's default followed list grows to what a practitioner expects: Windows 11,
Windows Server 2025 and 2022, Red Hat Enterprise Linux 9 and 10, Ubuntu 24.04 and 22.04,
Apple macOS 26 and 15, Microsoft Edge, Google Chrome, Mozilla Firefox, plus the Cisco IOS XE
Router and Application Security and Development STIGs already followed. Watchlist entries of
kind `baseline` still replace the defaults.

#### M9.1: Plan and survey — this document and COMPETITION.md

#### M9.2: STIG pages (`/stigs`) — 0.19.0

- `/stigs`: the operating systems the Register follows (Windows, Linux, macOS; then network
  devices, browsers, applications and anything else DISA publishes that is followed), each with
  its STIGs, their latest version and date, rule counts by CAT, and the last release's change
  summary.
- `/stigs/<os>`: one STIG at a time (a select), its rules grouped CAT I, CAT II, CAT III, each
  with the STIG id, title, check text and fix text (collapsed), and the NIST SP 800-53 controls
  it maps to through its CCIs, linked to the control's page in the Register. "What changed":
  the latest release's added, removed and revised rules, with DISA's Revision History note where
  the Register has one. "CISA on this platform": KEV entries whose vendor and product belong to
  the platform (newest first, due dates), and the directives that name it.
- The Register's control page gains the reverse view: the STIG rules, across the followed STIGs,
  whose CCIs map to that control.
- **Done when**: every Windows 11 rule shows its controls, the control page for AC-11 lists the
  screen-lock rules of every followed STIG, and the CISA panel for macOS shows Apple's KEV
  entries and no Cisco directive.

#### M9.3: Baseline builder (`/baselines`) — 0.20.0

- `/baselines/<platform>` for `windows`, `macos` and `linux`. The **strictest published
  profile**: every CAT I and CAT II rule of the chosen STIG; for Windows, the Microsoft SCT
  baseline settings for the same product (joined to STIG rules by registry path where the
  check text names one, the rest listed as "Microsoft's baseline adds"); for macOS, the mSCP
  rules in the 800-53 High and DISA STIG baselines joined to the STIG rules by STIG id; and
  the NIST SP 800-53 High baseline controls, each with the rules that implement it and the
  controls no technical rule reaches (the organisational layer).
- Ordinary forms: selects for the STIG version, the SCT baseline, the mSCP branch and whether
  CAT III joins; a checkbox per item; a POST that redraws with the unticked items dropped.
  Nothing is stored; the form carries the state. (The urlencoded body limit is raised for these
  routes: a Windows profile is a few hundred fields.)
- **Exports** of the trimmed profile: printable HTML, Markdown, CSV and JSON, each in an
  "apply with" flavour: **Jamf** (mSCP rule id, the mobileconfig payload domain and keys, the
  STIG id), **Intune** (DISA's settings-catalog definition id and value where its package has
  one for the rule, the GPO path from the STIG fix text, and DISA's checklist verdict when the
  rule is outside what Intune can set), **Linux** (the STIG fix procedure, verbatim), and a
  plain flavour. Every export carries the publisher attributions; CIS text never appears and
  Microsoft text appears only as the page already quotes it. Exports also answer to GET with
  the same fields, so a JSON export is an API.
- **Current versus next**: when the Register holds a newer version of the STIG, SCT baseline or
  mSCP branch than the one chosen (or the next macOS release's branch), the page lists what the
  strict profile gains and loses: rules added, removed, moved into or out of CAT I/II, settings
  whose value changed.
- **Done when**: the Windows 11 export in Intune flavour names DISA's settings-catalog
  definition for SMBv1 and says which rules Intune cannot set; the macOS export in Jamf flavour
  lists the payload keys for FileVault enforcement; a CSV opens in a spreadsheet with one row
  per item.

#### M9.4: Test plans (`/baselines/<platform>/tests`) — 0.21.0

- What to test when a new OS release lands so the baseline still holds, derived from the STIG
  and mSCP check procedures and grouped by area: authentication and SSO, browsers, disk
  encryption, logging and audit, network, updates, MDM enrolment, and the rest. Each item is
  the rule's check text with its id and severity.
- Curated templates in `data/test-plans/*.yaml` (SSO through Intune or Jamf with each browser,
  FileVault and BitLocker key escrow, conditional access, MDM enrolment), each step citing the
  publisher's document it comes from; the owner extends them by adding YAML. Labelled on the
  page as the owner's templates, not the publisher's text.
- Export as a checklist in the same four formats.
- **Done when**: the macOS plan for Tahoe lists the smart-card and FileVault checks under their
  areas, the browser area holds the Edge, Chrome and Firefox STIG checks, and a Markdown export
  ticks like a checklist.

#### M9.5: Platform alerts and the fix — 0.22.0

- A watchlist entry of kind `platform` names one of the product's platform ids
  (`src/platforms.ts`: windows, apple, linux, android, chrome and the rest). A CVE whose vendor,
  product or CPE belongs to that platform is marked as the person's stack, reaches the Wire,
  the alert channel and the digest as "new Apple CVE" (or changed), like a product entry does.
- A **Fix** panel on every CVE page and Wire item: the remediation already published, quoted
  and linked: NVD references tagged Patch, Vendor Advisory or Mitigation; the vendor advisory
  items the Wire holds for that CVE (Ubuntu, Debian, Red Hat, Cisco, Palo Alto, Fortinet,
  Chrome, GitLab, Jenkins, CISA ICS); CISA KEV's required action and due date; the package
  advisories' fixed versions; and the STIG or baseline rule that mitigates it when a mapping
  exists (`data/mitigations.yaml`, curated, each entry naming the rule and the source that
  connects them). When nothing is published the panel says so.
- **Done when**: a KEV entry for Windows shows CISA's required action, Microsoft's advisory link
  and the due date in one panel; an Apple platform entry alerts on a new macOS CVE; a CVE with
  no published fix says "nothing published yet".

**Out of scope for M9**: scanning or assessing a host (that is SCAP, CIS-CAT, Nessus), storing
per-host state, generating remediation scripts beyond quoting the publisher's, and any model in
the loop. Multi-user profiles and saved named baselines are M10 candidates.

---

## 6. Three ways to build it

### Path A: hard but quality (10 to 14 weeks to M7)

Everything in section 4 as described. React 19 + Vite + TypeScript front end on the BoxPilot UI
kit conventions, so BaselineWatch can later be embedded as a BoxPilot page rather than only a
catalog app. Full adapter test suite with recorded fixtures from each real source. Property-based
tests on the differ. Structured logging, metrics, SBOM, signed images. A plugin boundary for
adapters so other people can add standards.

Choose this if BaselineWatch is a product you will keep for years and might share.

### Path B: fast and simple (1 weekend to 1 week)

Do not write a feed reader. Install from the BoxPilot catalog what already exists:

- **Miniflux or FreshRSS** for every news, Reddit, CISA and CSRC feed.
- **changedetection.io** pointed at the STIG downloads page, the SCT download page, the CSRC
  800-53 page and the Microsoft baselines blog; it notifies on change and shows a text diff.
- **Glance** as the one-page dashboard pulling the reader's unread items, KEV JSON and the
  changedetection alerts into tiles.

Add one script (Node or Python, ~300 lines) on a daily timer that fetches the OSCAL catalogs, KEV
JSON and the CVE List V5 delta into a **git repository**; git gives you history, diff and blame
for free, and a tiny static page renders `git diff` per control. No database, no UI framework.

Choose this to be in tune by next Monday. You lose: control-level diffs for STIG and Microsoft,
the "why" field, one unified timeline, triage, and anything you could hand to someone else.

### Path C: the recommended middle (3 to 5 weeks to a daily-use v0.3)

Build only the differentiator properly and keep everything else thin:

- **The Register is the product.** Snapshot store, OSCAL normaliser and differ, before/after
  redline, rationale quote (M3 and the OSCAL half of M5) get full quality.
- **Wire and Vulnerabilities are thin.** Feeds and KEV into the same SQLite timeline with a
  simple list, source filter, read state and search. No React: server-rendered HTML with htmx for
  the few interactive bits. Add the SPA later only if the UI outgrows it.
- **One container, SQLite, Express, TypeScript**, the BoxPilot manifest from day one. Ship
  v0.1 (M0 + M1) in week one, v0.2 (M3 with 800-53 history loaded) by week three, then STIG and
  Microsoft adapters one at a time.

This gets the thing no existing tool does into your hands in a month, on an architecture that
can grow into Path A without a rewrite. The plan above is written so Path C's milestones are the
first half of Path A's.

### Other suggestions worth weighing

- **Git as the snapshot store** even in Path A: commit every fetched document to a bare repo in
  the data volume. You get history, diff, blame, compression and an escape hatch (clone it) for
  nothing. SQLite still holds the normalised rows and the index.
- **OSCAL as the canonical requirement model.** NIST already publishes it, CAPORDINO converts
  CPRT to it, and mapping STIG rules and CIS recommendations into OSCAL `control` shapes means one
  differ and one UI for every standard.
- **Python instead of Node** if parsing dominates: `feedparser`, `lxml`, `openpyxl`,
  `pdfplumber` and `python-docx` are more mature than their Node counterparts. The cost is a
  second language next to BoxPilot. Node is still the recommendation because of BoxPilot.
- **Go** for a true single static binary with no runtime. Best "runs alone" story, worst fit with
  BoxPilot's codebase. Only if standalone matters more than the catalog.
- **Prioritise with EPSS and KEV, not CVSS alone.** The Wire should sort watched-product CVEs by
  EPSS, flag KEV, and show CVSS as a secondary number.
- **Record fixtures from day one.** Every adapter test replays a real captured response. Sources
  change their HTML and feeds silently; fixtures make that a failing test rather than a quiet gap.
- **Let BoxPilot's agents read it.** A read-only JSON API now, an MCP server later, and the
  morning digest on BoxPilot's Today page can say "800-53 changed: 3 new controls" with a link.

---

## 7. Risks and how the plan handles them

| Risk | Mitigation |
| --- | --- |
| Sources without feeds (STIG downloads, SCT page) change their HTML | Listing adapters have fixture tests and a "listing parse failed" alert; NIST NCP is a mirror for STIGs. |
| NVD rate limits and outages | CVE List V5 deltas are the trigger; NVD enrichment is a queue with backoff and a resume cursor. |
| CIS licensing forbids redistribution | Manual upload only; snapshots stay in your volume; nothing CIS leaves the box. |
| Reddit blocks unidentified clients | Proper User-Agent, low cadence, `.json` endpoint, cached. |
| Diff noise (whitespace, reflowed PDFs) | Normalise whitespace and hyphenation before diff; diff on structured fields first, free text last. |
| "Why" is missing from the publisher | Store an explicit `no stated rationale` marker; never fill the gap with a generated guess unlabelled. |
| Scope creep into a GRC tool | Non-goals list in section 1; triage is states and notes, not a workflow engine. |

---

## 8. First week, concretely

1. M0 scaffold with the manifest in `boxpilot/baselinewatch.yaml` and a container that serves
   `/health` on BigBox.
2. SQLite schema: `items`, `sources`, `snapshots`, `documents`, `requirements`, `changes`,
   `explanations`, `triage`, `watchlist`.
3. Three adapters end to end: BleepingComputer RSS, CISA KEV JSON, NIST OSCAL 800-53 catalog.
4. Load the 800-53 Rel 5.1.1 and 5.2.0 catalogs and get the first real diff on screen.
5. Pick the mockup direction (see `docs/mockups/`) and set the tokens.
