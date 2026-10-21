# BaselineWatch: plan and milestones

*Written 2026-10-14. Owner: Chris (AES256Afro). M0 to M9 shipped by 2026-10-17; M10 to M12 in part by
2026-10-20. The forward plan, written 2026-10-21, is the last part of section 5: where it stands, a
ledger of what every earlier milestone left open, and M13 to M19 ending at 1.0. Sections 6 to 8 are
the original planning and stay as written.*

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
| 2026-10-19 | **News is the home page**, the way the leading aggregators land on the feed (docs/mockups/masthead.html, news-home.html): the Wire renamed News and served at `/`, the Register at `/register` with `/wire` as a 301. The top is grouped — News · Today · Standards ▾ (Register, STIGs, Baselines, Atlas) · Vulnerabilities, with the owner's Desk ▾ (Triage, Watchlist, Digest, Sources) on the right. The wordmark drops "Standards change register"; the phrase lives as the News motto, the Standards menu caption, the footer line, and an amber Register ribbon of the latest changes on News and Today. Article images are pulled passively at ingest (feed media, then og:image once per new item; `BW_NEWS_IMAGES` turns it off), cached in the blob store and served from `/img/<hash>` — the CSP's `img-src 'self'` stands. |
| 2026-10-14 | Build follows **Path C**, the recommended middle: Register built properly, Wire and Vulnerabilities thin, server-rendered HTML first, React only if the UI outgrows it. |
| 2026-10-14 | Public home is **https://cybercard.net**, replacing the FinancialAuthority demo there. It is a read-only information, learning and teaching site: no private data, anyone may read, writes need the owner's sign-in (M7). Hosted on BigBox, published through Cloudflare. |
| 2026-10-14 | Stack: Node 24 running TypeScript directly (no build step), Express 5, `node:sqlite`, one stylesheet, strict CSP with no inline script. |
| 2026-10-19 | **Decisions beside the recommendation**: each baseline item carries the owner's decision (apply as published, apply modified with the organisation's value, not applied) with a reason and an owner, stored and shown on a board per platform; the test plan tests only what is applied (templates may `require` a rule), and the reports carry the decisions in one of eleven looks drawn from the export mockups. |
| 2026-10-19 | **M12 Scan** (planned): the ad, DNS, router and firewall checks, keeping a public scan page's browser technique and adding what a LAN-resident server can see; one page with a self-hosted script under its own CSP; nothing fetched from ad or malware domains; ten mockups in `docs/mockups/scan/`. |
| 2026-10-19 | **M11 Platform engineering**: the fleet (each OS release, its support dates and the hardware it runs on) drives the test plans; templates carry success and failure branches and apply by release and hardware; areas are chosen per run; exports add LaTeX, Word and PDF; iOS, iPadOS, Android and the Samsung meeting rooms get template plans. NIST's PIV and platform-security publications join the Register. |
| 2026-10-20 | **All standards in one place** (`/standards`, "All standards" in the Standards menu, 0.36.0): per operating system the current, new and draft standards from the sources already tracked; the NIST publications with CSRC's drafts open for comment; and NASA's cybersecurity document set. Chris's "CSET" is NASA OCIO's Cybersecurity Standards and Engineering Team: its ASCS standards are NASA-internal, so the public layer — the quarterly Cybersecurity Policy Reference on nasa.gov, which lists every NASA cybersecurity document with dates and status notes — joins the Register as source `nasa-cyber-ref` and is diffed like any standard. |
| 2026-10-17 | **M9 Baselines** turns the tracked standards into guidance: STIG pages per operating system, a baseline builder per platform with exports for Jamf, Intune and Linux, test plans for a new OS release, platform alerts and a Fix panel. No generative AI in that path: every line derives from DISA, NIST, Microsoft and CISA text and refreshes with the sources. CIS stays upload-only. Survey of comparable tools in [COMPETITION.md](COMPETITION.md). |
| 2026-10-21 | **The forward plan**: every open item of M10, M11 and M12 is re-homed in a ledger (end of section 5) and the work from here is M13 to M19, ending at a 1.0 a stranger can install and run for a week. M13 comes first because two of its items are losses rather than gaps: nothing in the code prunes anything (138 MB in five days), and three tags shipped with no changelog entry. A milestone is finished when its "Done when" can be shown on the live instance; the dates are the least load-bearing part of the plan, and each milestone names the thin slice that ships if a week slips. Multi-user waits for a second person to need it, and because that may never happen, 1.0 does not wait for multi-user: M18 is off the 1.0 path and ships as 1.1. The plan's claims about the code were verified against it on the day it was written. |

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

#### M9.2: STIG pages (`/stigs`) — shipped 2026-10-17 as 0.19.0

What landed: the CCI list and CISA's directive listing as sources (fixture tests replay the real
zip and pages), the STIGs area with its index and platform pages, the join in both directions on
the Register's control pages, the wider default set of followed STIGs, and CISA's KEV entries
matched to platforms by vendor and product. Checked against the real Windows 11 (257 rules), macOS
26 (160 rules) and CCI (5,150 items) files; the fixtures are excerpts of them.

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

#### M9.3: Baseline builder (`/baselines`) — shipped 2026-10-17 as 0.20.0

What landed: the three sources (mSCP at its exact commit, DISA's Intune package, the GPO
package's checklists), the builder for Windows, macOS and Linux with the joins by registry path
and STIG id, DISA's definitions matched by policy name, the four formats in four flavours, and
"current versus next". Against the real October 2026 data the Windows 11 profile is 242 rules,
108 with a DISA settings-catalog definition and all 242 with DISA's checklist verdict (190 set
by its policy, 40 outside its scope), 50 joined to a Microsoft baseline value, 373 settings
Microsoft adds, and 370 High controls. Not done: a named profile the owner can save (the form
carries the state instead), and the Intune flavour cannot name a definition where DISA's package
has none (account lockout and password policies are not in its Windows 11 policy).

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

#### M9.4: Test plans (`/baselines/<platform>/tests`) — shipped 2026-10-17 as 0.21.0

What landed: the area filing (by the words in a check's title, then its procedure), the derived
checks from the strict profile's STIG and mSCP rules, seven templates under `data/test-plans`
(SSO through Intune and through Jamf with each browser, FileVault, BitLocker and LUKS key
escrow, conditional access, enrolment) read on every request so the owner extends them by adding
a file, and the checklist exports. The data folder ships in the image.

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

#### M9.5: Platform alerts and the fix — shipped 2026-10-17 as 0.22.0

What landed: `src/platforms.ts` (windows, apple, linux, android, chrome, firefox, edge, network;
a CVE's platform from its CPEs, then NVD's names, then the description), the watchlist kind
`platform` with the alert worded "New Apple CVE", the Fix panel on the CVE page with its line on
the Wire and its facts in the JSON API, and `data/mitigations.yaml` with eleven owner's entries
that find the mitigating rules by title across the followed STIGs. The other session's
`src/platforms.ts` for 0.18.0 was not on main when this shipped; whoever merges it reconciles
the two files (the watchlist and the Fix panel import `platformsOf`, `isPlatformKey`,
`platformKeys` and `platformName` from it).

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

### M10: A platform that runs itself (planned 2026-10-19)

M7 put the app on BigBox; the week after taught the real lessons: NVD stalled for three days on
an invalid key and nothing said so until a person went looking; a BoxPilot settings change
snapped the app back two versions because hand-pinned images never reached BoxPilot's records;
the release chain is five hops with two human clicks; and two seeded sources (`cvelist-v5`,
`nvd-cve-history`) still have no adapter, so the CVE pipeline leans entirely on one API that is
free but fragile. M10 makes the platform resilient and self-reporting, so the owner reads the
digest instead of debugging the pipeline.

- **CVE aggregation that survives an NVD outage.** The `cvelist-v5` adapter: pull the CVE
  Program's hourly delta releases from GitHub (free, keyless, bulk) as the backbone record, with
  NVD enrichment (CVSS, CPE) layered on when it arrives, and the `nvd-cve-history` adapter for
  per-CVE change events. Done when a three-day NVD outage costs enrichment lag, not coverage.
- **The pipeline reports its own health.** Today (`/today`) and the digest carry a "pipeline"
  line: sources failing with their hint (the Sources page's failure translations, surfaced
  instead of buried), days since the newest CVE, the image-cache rate, and the running version
  against the latest tag. An alert when a source has failed for more than a day, through the
  existing notifier. Done when the next invalid key is a morning digest line, not an
  investigation.
- **Releases with one click or none.** BoxPilot's daily catalog-updates workflow opens the bump
  PR; CI merges it when BaselineWatch's tag run is green; a post-deploy check hits `/health` and
  compares versions. The only human step left is BoxPilot's own System-page update, and the app's
  card never disagrees with what runs (no more hand-pinned images — the lesson of 0.25.0's
  snap-back). Done when a tagged release reaches cybercard.net with at most one click and the
  card always tells the truth.
- **Sources that need bespoke adapters, by worth.** SANS NewsBites (email/web only — a small
  HTML adapter over its newsletter pages, since SANS publishes no feed beyond ISC's), CISA's
  alerts pages where feeds lag, and a probe step in `npm run check` that validates every seeded
  feed URL still answers XML, so dead URLs (Ars, Sophos) and bot-blocked forms (Reddit's JSON)
  are caught before a release ships them.
- **Image pipeline follow-through.** Attempt tracking so the backfill and ingest never re-fetch
  a permanent miss; Cloudflare cache rules for `/img/<hash>` and `/assets/`; a weekly orphan
  sweep for blobs no item references.
- **The teaching site earns the name.** A short "how to read this" page for cybercard.net's
  audience (what KEV, EPSS, CAT I mean, linked from the masthead's Standards caption), the FTS5
  search promoted into the masthead (the NVD lesson of M6.5's mockups), and an accessibility
  pass over the new News front page (featured cards, strip, menus) with keyboard and
  screen-reader checks.
- **Out of scope**, still: scanning hosts, per-host state, multi-user accounts, any model in the
  ingest path. Saved named baselines move to M11 candidates.
- **Done when**: a month passes in which every incident the platform has is one the owner first
  learned about from the platform itself.

---

### M11: Platform engineering (started 2026-10-19)

The place a platform engineer goes first. The team runs Windows, macOS, Linux, iOS, iPadOS and
Android, and Samsung displays in every meeting room; each has releases, each release runs on
some hardware and not other, and each has baselines published for it and a way it is tested.
M9 built the baseline and the test plan per platform; M11 adds the two axes a real fleet has,
**release** and **hardware**, makes the plan say what success looks like and what to do when a
step fails, lets the tester choose the categories to test, and exports the result in every
form a review wants. The same rules apply as M9: no model in the path, every fact carries its
vendor source, CIS stays upload-only.

**Shipped 2026-10-19 (unreleased, on main after 0.30.0):**

- **The fleet** (`data/platforms.yaml`, read by `src/fleet.ts`): each platform's releases with
  the vendor's release and support dates, status, the hardware families each runs on, the models
  in the vendor's words, the baselines published for it, the Register documents it maps to, and
  what changed in it that a plan should know. Hardware families carry whether they hold a secure
  element. Seeded with what shipped this autumn (macOS 27 Golden Gate on Apple silicon only;
  Windows 11 26H2 and the new-devices-only 26H1; iOS and iPadOS 27 on the iOS 26 device list;
  Android 17 with Samsung's One UI 9 rollout; RHEL 10 and Ubuntu 26.04) and with the earlier
  releases still in service or just out of it. Every date has the vendor page it came from;
  "verify" marks the few inferred from the vendor's practice.
- **The Platforms page** (`/platforms`, in the Standards menu): every platform, release and
  hardware family, with what the Register already holds for each release (the STIG, the mSCP
  branch, the Microsoft baseline), leading to the release's test plan and the platform's builder.
- **Applicability.** A template, or one step of it, says which releases and hardware it is for
  (`applies: { versions: { macos: [">=14"] }, hardware: [apple-silicon, intel-t2] }`). The plan's
  version and hardware selects (hardware a release cannot run is greyed: no Intel Mac on
  Golden Gate) rule steps in or out, and every export lists what was left out and why.
- **Success and failure branches.** Each template step carries `expect` (what success looks
  like) and `fail` (what to do when it does not), drawn on the page and in every export.
- **Areas to test.** Three new areas (hardware root of trust and secure enclave; Platform SSO and
  identity; collaboration and meeting rooms) beside the eight of M9, and checkboxes to test only
  some this time; the rest stay on the page marked not tested and out of the exports.
- **Templates-only platforms.** iOS, iPadOS, Android and Collaboration have test plans from the
  owner's templates alone, until their STIGs join the builder (M11.2).
- **Twelve templates** from the vendors' documents: the hardware root of trust on each platform
  (Secure Enclave and boot policy, TPM and VBS, verified boot and Knox, Secure Boot and LUKS and
  FIPS, supervision and attestation), Platform SSO with Entra ID on macOS and the brokers on
  mobile, Entra join and Windows Hello, what a Windows feature update or a macOS release changes,
  and the meeting rooms: Samsung displays first (the interactive WAD and WAF series run Android
  and take Knox Manage; the Tizen signage takes MagicINFO, whose 2025 and 2026 server advisories
  are a test of their own), then Teams Rooms.
- **Exports.** LaTeX, Word and PDF join the printable checklist, Markdown, CSV and JSON
  (`src/report.ts`: one block model, three renderers, no library beyond the zip a .docx is).
  Every export carries the release facts, the branches, the not-tested list, a findings table
  and a sign-off.
- In the Register: NIST's PIV and digital identity publications and its platform-security set
  (FIPS 140-3, SP 800-147, 800-193, 800-124, 800-219, IR 8320) as section-by-section documents.

**Next, in order:**

#### M11.2: Mobile in the builder, plan defaults from the release — shipped 2026-10-19

What landed: iOS, iPadOS and Android are builder platforms. DISA's Apple iOS/iPadOS 27 and 26,
Google Android 17 and 16, and Samsung Android 17 and 16 with Knox STIGs join the default
followed list (the "mobile" STIG platform, told apart by product name), and NIST mSCP's
`ios_26` branch joins the followed branches, its "os" section labelled iOS/iPadOS and its
`ios_stig` baseline counted as the strict set beside `800-53r5_high`. The builder page, the
Baselines index and the test plans draw the three like the others (Jamf flavour for Apple, the
mSCP select for iOS and iPadOS). A test plan whose release names Register documents in
`data/platforms.yaml` (`documents: { stig, mscp, sct }`) starts from them, so the macOS 26 plan
opens on the Tahoe STIG and `mscp:tahoe` and the Windows 25H2 plan on the v25H2 baseline; a
person can still pick another. Collaboration stays templates-only: no publisher writes a STIG
for a Samsung display, and a Teams Rooms Windows console takes the Windows 11 STIG. The fixture
test adds an Apple iOS/iPadOS 26 STIG derived from the Windows one.

#### M11.3: Decisions, and plans that test only what is applied
The owner's decision per baseline item (apply as published, apply with the organisation's own
value, do not apply) with the reason and an owner, stored, shown on a board per platform and in
every export; the test plan tests only what is applied, a template may `require` a rule, and a
modified rule is tested for the organisation's value. An earlier branch built this on 0.24.0;
it is rebuilt on main.

#### M11.4: Mine: tracking without a sign-in
A visitor picks the platforms, releases and hardware they run and the areas they test; the
choice lives in a signed cookie (no account, no row, gone when the browser's cookies are) and
filters News, Vulnerabilities, Today and the plan pages to "my stack". "Make this a link" puts
the profile in a URL to bookmark or share; a per-profile feed URL (Atom, and an ntfy-shaped
JSON) lets a reader or a phone take the alerts. The owner's sign-in and the later multi-user
work (M8) reuse the same profile shape, so sign-up is an upgrade, not a different thing.

#### M11.5: CVEs by release
`src/platforms.ts` already names a CVE's platform; the fleet adds the release. Join NVD's CPE
version ranges to the fleet's release ids so a CVE page says "affects Windows 11 24H2 and
25H2" or "iOS 26 only", the Platforms page shows the open CVEs per release, and a Mine profile
alerts on its releases. Apple's security releases page, the Android Security Bulletins, Samsung's
monthly SMR and its display advisories have no feeds: small HTML adapters, like the SANS one,
so each becomes a News item tagged with its platform and release.

#### M11.6: Keeping the fleet file honest
The endoflife.date API as a source for support dates, diffed into the Register like any
standard, with `data/platforms.yaml` as the curated layer over it; a `check:templates` probe
(network, beside `check:feeds`) that every template source URL still answers; and a quarterly
review line in the digest naming templates whose cited page changed.

#### M11.7: Results and history
A run of a plan captured as data (pass, fail, not applicable, evidence, tester, date per step)
rather than a printed sign-off; runs compared across releases ("what broke moving to 26H2");
saved named plans for the owner; results in the JSON API and the MCP server so an agent can
answer "did we test Platform SSO on Golden Gate yet".

**Quality of life, as they fit:** a Today tile for releases ending support within ninety days
(shipped 2026-10-19 in 0.33.0, with the same list and an "ends in N days" chip on Platforms, and a
URL for a plan as drawn); per-platform sections in the digest; a print stylesheet for the plan page;
"what changed in this template since you last exported it"; Zoom Rooms and Webex templates beside
Teams Rooms.

**Done when**: a teammate opens Platforms, picks macOS 27 on Apple silicon, keeps only the
secure-enclave area, exports a Word plan, and every step in it cites Apple or Microsoft, says
what success looks like and what to do when it fails, and the Intel steps are listed as left out
with the reason.

---

### M12: Scan: ads, DNS, router, firewall (planned 2026-10-19)

A public scan page (archivegenocide.com/scan) runs three browser-side checks for ad filtering and
is honest that a web page can see one browser and nothing else. The technique is worth having;
the rest of that site is not ours to carry. BaselineWatch keeps the technique and adds the three
eyes a page cannot have, because this server sits on the LAN: the network's resolver, the router,
and the firewall from both sides. Ten mockups in `docs/mockups/scan/` (sample data, the app's
own look). Chris's goal in one line: find ads and firewall problems, and know why each matters.

**What the page does, in its own script** (read 2026-10-19, `scan.js?v=22`):

- *Ad hiding*: twenty invisible elements named the way ad slots are named (`adsbox`,
  `ad-banner`, `adsbygoogle`, `#ad`, …) and two neutral controls; after two frames it reads
  which were hidden by a blocker's generic cosmetic rules. A zero is "not observed", not
  "unprotected": some blockers hide nothing and block everything.
- *Ad requests*: images on paths that match EasyList's request rules (`/ad_images/`,
  `/adsbanner-`, `/ad_skyscraper.gif`) on its own origin and on one cross-site host, each
  between control images with identical bytes; no cookies, no referrer, never displayed; a
  timeout is unknown, a CSP failure is reported as such, one retry. A load difference is the
  signal. No advertising domain is contacted.
- *Filtering DNS*: a fresh random name under `-dnscheck.adguard-dns.com` resolves only through
  AdGuard's resolvers and the JSON names the server group (regular, family, unfiltered); only
  AdGuard is tested. A DNS-layer canary (a blocklisted hostname loaded as an image) is written
  but switched off, because the name is not yet on the public lists and the site's own CSP would
  block it.
- Rows it cannot test: other apps on the device, every device on the network. It says so and
  points at the router's DNS setting and a Pi-hole or AdGuard Home dashboard.
- Platform and in-app-browser detection (Instagram and Facebook views have no blockers and
  cannot install a profile), a Brave hint, a VPN question, per-platform DNS setup guides
  (AdGuard profile, Android Private DNS, Windows adapter DNS), Lockdown Mode, the advertising
  identifier, and a link to Zero Breach: an offline Python scanner that reads browser history,
  cookies, cache and storage, file hashes, Windows per-user COM persistence, the DNS cache and
  the hosts file against 405 indicators (292 domains, 111 addresses) from the Citizen Lab,
  Confiant, Recorded Future, Microsoft, ESET, Avast, Google TAG and Amnesty reports on
  Candiru and ad-delivered spyware, exported as blocklists.

**What is worth keeping**: the three signals exactly as designed (bait elements, controlled
test images, resolver self-checks, with NextDNS's `test.nextdns.io` added beside AdGuard's);
the honesty about limits; the indicator and blocklist exports as a tracked source; the guides'
substance, rewritten in this product's voice and tied to their primary documents.

**What this product adds**: network-wide canaries resolved by the server through the LAN
resolver (the row the page says no page can test); the router's firmware against the CVE
database and KEV this product already keeps current, its UPnP mappings and exposure; the
firewall from the internet side (Shodan's InternetDB, a lookup, never a scan from here) and
the LAN side (DNS interception, DNS bypass, SMB out, IPv6); device scripts that read what a
browser cannot; history, alerts and a digest line, because a daily scan is only useful when a
change is news; and a "why" page per check with breadcrumbs and direct links to the sources.

**Decisions:**

- *The one page with a script.* Every page runs with `script-src 'none'`. The browser check
  cannot exist without a script in the tab, so `/scan` alone carries its own policy:
  `script-src 'self'` for one self-hosted file, `img-src` adding the probe origin,
  `connect-src` adding the two self-check hosts. No inline script anywhere, ever.
- *Nothing fetched from an ad or malware domain, by anyone.* Canaries are resolved (DNS only)
  by the server, never fetched, and never by a visitor's browser.
- *The server's LAN checks are opt-in* (a setting), because they send packets on the owner's
  network; they run daily once on.
- *The router is never signed in to and never changed.* Default credentials are a manual step
  in the guide.
- *Exposure is read from a public index*, not scanned from here.
- *Lists are Register sources*: the adfection list and the canary sets, so a change is a diff
  with a date; the scripts are rebuilt from them and their checksums change with them.
- *Every "why" rests on a primary document and links to it*; nothing is generated by a model.

#### M12.1: The browser check (`/scan`) — shipped 2026-10-19
The page, the one self-hosted script, the per-route CSP, the probe images served from this
instance (same-site) and from a second origin when `BW_PROBE_ORIGIN` names one (cross-site),
the AdGuard and NextDNS self-checks, in-app-browser and platform detection, the limits box.
Results are drawn by the script into the page and never uploaded. Done when the three rows
match the public page's on the same browser, with the same blocker on and off.

*Landed*: `/scan` (a Scan area in the masthead after Vulnerabilities) with the three rows at
"not run", the two rows a page cannot test, the Run button, the limits, privacy and environment
boxes, and `/scan/why` with the primary sources; `public/scan.js`, one ES module under
`script-src 'self'` that plants the twenty baits and two controls (read after two frames and again
half a second later), loads the three EasyList-path test images between controls (anonymous, no
referrer, never shown, one retry, timeouts unknown, policy failures named), and asks AdGuard's
`a<random>-dnscheck.adguard-dns.com/dnscheck/test` and NextDNS's `<random>.test.nextdns.io` (the
bare host redirects there without CORS headers, which a page's fetch may not follow, so the
script picks the name and `*.test.nextdns.io` is in `connect-src`); the probe GIFs
at `/scan/probe/*` with `no-store` and open CORS; `BW_PROBE_ORIGIN` validated as a bare origin;
tests for the page, the headers, the probes and the script's logic with fakes. The script runs
only when the button is pressed. The per-platform guides followed in M12.2.

#### M12.2: Why, guide, lists — shipped 2026-10-19
`/scan/why` (mockup 08) and `/scan/guide/<platform>` (mockup 07) with breadcrumbs and sources;
the adfection list and the canary sets as Register sources (`src/adapters/blocklists.ts`,
diffed line by line like any standard; the Zero Breach `dist/` exports and the EasyList,
EasyPrivacy, URLhaus and OpenPhish-derived canary sets). Done when the list's next release
shows as a diff and every guide step links to the vendor page it follows.

*Landed*: `/scan/guide` and `/scan/guide/{windows,macos,linux,ios,android}`
(`src/pages/scan-guide.ts`): one page per platform, each section one thing the area checks
(filter DNS for every app, a blocker in the browser, the device's firewall and what listens,
the router, the network's exposure and DNS bypass, Lockdown Mode and the advertising
identifier, the past), each step saying what to open or run, what a clean result looks like,
what a finding means, with a link to the vendor page it follows and to the why page's section;
the router and network sections are the same on every platform. Two scripts under
`public/scan/`, `bw-check.ps1` (Windows PowerShell 5.1 or 7) and `bw-check.sh` (POSIX sh for
macOS and Linux), do the computer checks in one go (resolver and DoH or DoT, two ad canaries
looked up and never fetched, the hosts file, the firewall and listeners, SMB out on Windows, the
gateway's admin page and its UPnP description and mapping table, DNS bypass over plain 53 and
DoH, IPv6, the advertising setting, Lockdown Mode and the DNS-Client log), upload nothing, need
no administrator rights, and say so in their headers; they are served as plain text at
`/scan/scripts/<name>` with their SHA-256 beside every link and `SHA256SUMS` beside them
(`scripts/scan-sums.mjs` rewrites it; the test fails when it is stale). `/scan/why` gains the
router, UPnP, exposure, bypass and device sections with their primary documents, and the
browser check, the why page and the guides link each other. Tests: the routes, every step's
source and why anchor, the scripts' bytes against the sums, `sh -n` and PowerShell's parser
where present. *Left*: the scripts' indicator matching against the lists (M12.6).

*Lists landed 2026-10-19* (`src/adapters/blocklists.ts`, migration 0027): seven standards
sources, each a document whose entries are its requirements, diffed line by line. Zero Breach's
indicator list (`iocs/adfection_iocs.txt`: 405 indicators, 292 domains and 111 addresses, each with
its tier, confidence and the report it was read from as its guidance) and its DNS and ad blocklist
exports (`dist/adfection.domains.txt`, `dist/adfection.adblock.txt`, 291 domains), the current
commit read from the GitHub commits API so an unchanged list costs one small request, the commit's
first line kept as the release's reason, and the commit that added the exports pinned as history
so the first diff is real (adtimizer.co out, 67 domains in). Four canary sets of twelve names:
EasyList and EasyPrivacy's outright domain rules (`||domain^`, with or without `$third-party`,
weekly), URLhaus's host file and OpenPhish's feed reduced to registrable names (two labels once
`www.` is dropped, no addresses, no shared-platform subdomains, daily); the twelve whose names hash
lowest under SHA-256, so the pick is deterministic and moves only when the list drops one or gains
a name that hashes lower. Each requirement's text is the line as published (OpenPhish keeps the
origin, never a path), so a changed rule is a revision and a dropped name a removal. OpenPhish's
Community Feed terms forbid showing any part of the feed to third parties, so that source is
registered off; a private instance's owner may turn the row on. *Restricted sources* (migration
0029, `sources.restricted`): the OpenPhish set is marked restricted, so once the owner turns it on
from the Sources page a visitor sees its versions and counts with the names withheld under the
quoted licence, the owner sees the names, and the API and MCP tools return neither names nor text
to anyone, which lets the set run on the public instance. Fixtures are the real responses
(two Zero Breach commits of 2026-10-18 and the four lists as served on 2026-10-20), replayed in
`test/blocklists.test.ts`, with a modified EasyList showing a line-level diff. Left for M12.3 and
M12.6: resolving the canaries and matching the scripts against the lists.

#### M12.3: This network — shipped 2026-10-20
Resolver discovery from the server's own lease and `resolv.conf`; forty-eight canaries in four
categories resolved through it (and the upstream named by a resolver-identity query); Pi-hole
and AdGuard Home client counts through their APIs when the owner gives a token; the DoH-from-LAN
test. Done when adding the adfection list to the Pi-hole flips the category from resolved to
sinkholed on the next run.

*Landed*: `src/netscan.ts` and `/scan/network` (mockup 03, `src/pages/scan-network.ts`), with
the scan's rows in `net_scans` and `net_canaries` (migration 0030). The resolver is read from
the dhclient lease first (the router's answer), then `resolv.conf`, following systemd-resolved's
127.0.0.53 stub through to the real upstream and keeping a bare loopback (a Pi-hole on this
host). The canaries are the four sets' names plus twelve of the adfection list's domains picked
by the same lowest-hash rule, read from the Register at scan time, resolved only (A records) and
classified sinkholed (0.0.0.0, loopback, the resolver's own address, NXDOMAIN or no data),
resolved, or timeout, with the answer kept verbatim; `whoami.akamai.net` is the control and
names the upstream, one DoH GET to a public endpoint says whether a browser can bypass the
resolver from this LAN, and a Pi-hole (`api.php?summaryRaw`) or AdGuard Home (`/control/stats`)
client count rides along when the owner saves a token at `/scan/network` (stored in
`app_settings`, shown as set or not set, never rendered). Opt-in: nothing runs until the owner
turns it on; then daily, once per local date, from the scheduler's ticks. Day-over-day changes
ride the scan row as JSON: a canary newly resolving or a changed resolver notifies right away
(kind `network`, KEV priority), everything changed is a digest line, and `/scan`'s row 05 shows
the latest tally. DNS, the clock, the filesystem and HTTP are injected; `test/netscan.test.ts`
replays the captured lists and proves the milestone's done: adding the adfection list to the
Pi-hole flips its category from 12 resolved to 12 sinkholed on the next run, alerting nobody,
while the reverse direction is one alert.

#### M12.4: Router
Gateway from the lease; UPnP device description for model and firmware; SSDP and the IGD
`GetGenericPortMappingEntry` walk for mappings; TLS and redirect of the admin page; DNS handed
out by DHCP; firmware matched to the CVE database and KEV by vendor and product (`platforms.ts`
gains the network vendors' CPE names). Done when a router on the KEV list is a finding the
hour CISA adds it, with the vendor advisory from the CVE's Fix panel.

#### M12.5: Firewall and exposure
InternetDB for the public address (ports, hostnames, CVEs, cached, once a day); DNS interception
by resolver identity against 8.8.8.8 and 1.1.1.1; DNS bypass (plain 53 and DoH from the LAN);
SMB and NetBIOS egress against a probe; IPv6 reachability through a small endpoint this
product's public instance runs (or omitted when none is configured); the hosts table from the
device scripts. Done when turning UPnP off and adding the Pi-hole redirect rule turn two
findings green on the next run.

#### M12.6: Device scripts
`bw-scan.ps1`, `bw-scan.sh` (zsh) and `bw-scan.sh` (bash) generated from the lists at fetch
time, served with SHA-256 and a signature, source viewable; each reads resolver, hosts file,
firewall state, DNS cache and browser traces against the list, Windows persistence paths, the
advertising identifier, and prints a report; `/scan/devices` takes the report back by paste or
upload. MVT pointers for phones. Done when a report pasted back fills the hosts table and the
scripts' checksums change with the list.

#### M12.7: History, alerts, Today
Every run stored as the facts observed and diffed against the last; alerts through the notifier
(right away: KEV firmware, a new mapping, a category that stops being sinkholed, WAN remote
management; in the digest: the rest); a Today tile; the Console look (mockup 09); the phone
layout. Done when a canary that starts resolving is a notification within the day and nothing
alerts on an unchanged run.

**Out of scope**: scanning hosts or your public address from this product; signing in to the
router; contacting any advertising or malware domain; any model in the path.

---

**From here on: the forward plan, written 2026-10-21.** M0 to M12 above are the record of what
shipped, in the order it shipped, each milestone's notes left as they were written. What follows is
the plan from here — where it stands, a ledger that re-homes every item those milestones left open,
M13 to M19 ending at 1.0, and the standing work that keeps the platform from rotting between them.

### Where it stands, 2026-10-21

Seven days took the product from an empty timeline to thirty-seven tags. The forward plan below
is written against what is actually running, not against what the sections above hoped for.

| Thing | Where it is on 2026-10-21 |
| --- | --- |
| Live | 0.37.0 at https://cybercard.net: BigBox, installed from the BoxPilot catalog since 2026-10-16, published through the Cloudflare Tunnel, strict CSP, public read with the owner's sign-in for writes. |
| Data | 73 sources, 1,712 snapshots, 1,591 changes, 4,990 timeline items, 34,276 CVEs, 30 migrations, 138 MB (`/health`, 12:33 UTC). |
| Code | About 19,000 lines of TypeScript in `src`, 24 adapters, 49 test files, 351 tests, no build step. |
| Shipped whole | M0 to M9. |
| Shipped in part | M10 (the keyless CVE backbone and the digest's health lines), M11 (through M11.3), M12 (through M12.3). |
| Not started | M11.4 to M11.7, M12.4 to M12.7, multi-user. |

Every claim in this section and the ledger below was re-read against the code on 2026-10-21,
not taken from the milestone notes: `src/` and `scripts/` hold no match for `vacuum`,
`retention`, `prune`, `orphan` or `pragma optimize`; `ci.yml` runs `typecheck`, `test` and
`lint` and never `check:manifest`, and nothing in the repository runs on a schedule; the
CHANGELOG's newest heading is 0.35.0 against a newest tag of v0.37.0; there is no `/metrics`
route, no `robots.txt`, no sitemap, no canonical or OpenGraph tags, no dependency-update
mechanism and no `LICENSE` file; `nvd-cve-history` is seeded by migration 0002 and disabled by
0005. Where a ledger row below turned out to be smaller or larger than its milestone note
assumed, the row says so.

Two things the numbers say that no milestone note does. **Nothing prunes anything**: there is no
retention rule, no orphan sweep, no `VACUUM` and no size budget anywhere in the code, and five
days of operation is 138 MB. **The release ritual already loses steps**: 0.36.0, 0.36.1 and 0.37.0
are tags and images with no CHANGELOG entry, and CI runs `typecheck`, `test` and `lint` but never
`check:manifest`. Both are M13's first work, because they are losses rather than gaps.

### The carry-over ledger

Every open item from an earlier milestone, and the milestone that now owns it. Nothing is left
orphaned in a "next, in order" list.

| Open item | Left from | Where it goes |
| --- | --- | --- |
| Pipeline tile, an alert when a source has failed for a day, `/metrics`, running version against the newest tag | M10 | M13 |
| A release in one command; the three tags with no changelog entry | M10 | M13 |
| `check:feeds` and `check:manifest` not in CI, no template probe | M10 | M13 |
| Retention, orphan blob sweep, the `/img/` and `/assets/` cache rules | M10 | M13 |
| `nvd-cve-history` seeded with no adapter | M10 | M13, settled and nearly free: migration 0005 already disabled the row, so what is left is dropping it and saying in SOURCES.md that the history computed between sightings has been better than the endpoint |
| Search in the masthead, the accessibility pass | M10 | M17 |
| Router; firewall and exposure; device scripts; scan history and alerts | M12.4 to M12.7 | M14 |
| Mine: the profile in a signed cookie, the shareable link, per-profile feeds | M11.4 | M15 |
| CVEs by release; the Apple, Android and Samsung pages that have no feed | M11.5 | M15 |
| Plan runs as data, runs compared, saved named plans, results in the API and MCP | M11.7 | M16 |
| endoflife.date as a source, `check:templates`, the quarterly template review | M11.6 | M16 |
| Saved named baseline profiles | M9.3 | M16, beside saved plans |
| Multi-user with roles | M8 | M18, gated on a second person needing it |
| Intune baselines | M8 | Standing backlog: blocked until Microsoft publishes a machine-readable baseline. DISA's Intune package already covers Windows. |
| ComplianceAsCode adapter | M4 | Standing backlog: free diffs, little left to win now that STIG and mSCP are read directly. |

### M13: The platform keeps itself (close M10)

M10 named the right lesson and shipped half of it: `cvelist-v5` is the keyless coverage backbone
with NVD as enrichment, so an NVD outage now costs enrichment lag and not coverage, and the digest
names a failing source and a stale CVE pull. What it did not do is the half that shows in the
numbers above. This milestone makes growth bounded, the backup proven, and a release one command.

- **Growth with a policy, per kind.** Standards snapshots are the product and are kept for good;
  vulnerability payloads, image blobs, scan rows and digests are not. A retention rule per source
  kind, a weekly housekeeping pass in the scheduler that sweeps blobs no row references, runs
  `ANALYZE`, `PRAGMA optimize` and the FTS `optimize`, and rewrites the file with `VACUUM INTO`
  when free pages pass a threshold; the bytes, the blob count and the oldest kept snapshot on
  `/health`, on the Sources page and in the digest; a budget in ADMIN.md saying what the owner
  does at 1 GB and at 5 GB.
- **A restore that has been done.** Restore BoxPilot's backup into a throwaway instance on the
  box, compare its `/health` counts with the live one, and write the date, the steps and what
  differed into DEPLOY.md, with a quarterly line in the digest so the next rehearsal is not a
  year away.
- **A release that cannot drift.** `npm run release <version>` bumps `package.json` and the
  manifest, opens the CHANGELOG heading from the commits since the last tag, and refuses a version
  the changelog does not carry; CI runs `npm run check` whole (so the manifest check runs there
  too) and refuses a tag whose version disagrees with the manifest or the changelog; a post-deploy
  step compares `/health` with the tag. The milestone's first commit writes the three missing
  entries from their commits.
- **The pipeline on screen.** A sixth Today tile — sources failing with the Sources page's
  translation of the failure, days since the newest CVE change, the image-cache rate, and the
  running version against the newest tag; an alert through the notifier when a source has failed
  for more than a day, because a digest line was not enough the last time; `/metrics` in the plain
  text format section 4 promised, so BoxPilot can draw it.
- **Probes on a schedule, not by hand.** `check:feeds` and a new `check:templates` (every
  template's cited source URL still answers) run nightly in CI as the one network job, and a
  failure opens an issue; dead URLs and bot-blocked forms stop being something a person finds.
  This is a second workflow, not a job in `ci.yml`: nothing in the repository runs on a
  `schedule:` trigger today, and opening an issue needs `issues: write`, which the current
  read-only `permissions` block does not grant.
- **An upgrade that cannot strand the database.** Migrations are forward-only and each one runs
  in its own transaction, so a failure leaves the file at the previous version — but nothing
  proves the thirty migrations still apply to a *populated* database rather than an empty one,
  and that is the only case that matters to someone upgrading. A test that applies every
  migration to a fixture database holding rows of each kind; the restore rehearsal above done
  from the running version to the next tag, not into an empty instance; and the rollback written
  into DEPLOY.md — which image tag to go back to, and the rule that a database a newer version
  has already migrated does not go back with it.
- **Depends on**: nothing. **Thin slice**: retention and the release script — both stop a loss,
  the rest stops an annoyance.
- **Done when**: the database's size is a number the owner chose rather than one that happens, a
  restore has been done and dated, a tag that forgets its changelog entry fails CI, and the next
  stuck source is a notification within the day.

*Shipped 2026-10-21, the day this was written.* The three missing changelog entries were written
from their commits. `src/housekeeping.ts` carries the retention policy by source kind and the
weekly pass (sweep, free the blobs nothing references, `ANALYZE`, `PRAGMA optimize`, the FTS
`optimize`, `VACUUM` when a tenth of the file is free), surfaced on `/health`, on the Sources
page under "What this instance keeps" and as a digest line, with the budget in ADMIN.md. The
release is `npm run release <version>`, with `npm run check` and CI refusing a tree whose newest
changelog entry is missing, still the draft or for another version, and a tag that names a
version this tree is not; CI runs `npm run check` whole, so the manifest check runs there too.
`docs/DEPLOY.md` carries the restore rehearsal as five steps that touch nothing live,
`scripts/health-diff.ts` gives the verdict, and `npm run rehearsal -- today "…"` records it, with
the digest asking until one is recorded and again ninety days later. Of the rest, only the
rehearsal itself is still open, and it is a person's job on BigBox; the reporting half is
M13.2 below.

#### M13.2: The platform reports itself — shipped 2026-10-21

The half of M10 that was never built. The digest had named a failing source since M13, but a
digest line is read once a day if it is read at all, and nothing knew *how long* a source had
been failing: the status column says a source is failing now, never since when, so a feed that
403s for an hour looked exactly like an API key that died on Tuesday — the NVD stall, exactly.

What landed: `sources.failing_since` and `failing_alerted_at` (migration 0033), set when a source
first fails after a success and cleared the moment one answers, which makes a *failure episode* a
thing the code can reason about. From them, a sixth tile on Today — green while every source
answers, amber while something is failing, red once a failure passes a day or the CVE stream
passes 36 hours, saying the worst thing true in the fewest words — and **one notification per
episode** through the existing notifier, after a day, never once a tick. `/metrics` serves the
same figures in Prometheus's text format (rows, bytes, CVE age, the housekeeping pass's last
result, the pipeline's own verdict), gated like `/health` so a closed instance gives a monitor
the running version and nothing else; the tile, the digest and `/metrics` read the same rows and
cannot disagree. A nightly workflow asks every seeded feed and every page a test-plan step cites
whether it still answers, keeping one issue open rather than opening one a night. Migration 0034
retires `nvd-cve-history`: seeded in 0002, off since 0005, adapterless ever since, because the
history computed between sightings costs no extra request and says more.

**The decision this milestone turned on**: "the running version against the newest tag" cannot be
a background check, because this instance promises no outbound call except to its declared
sources and the configured notifier, and this product's own releases are neither. So nothing
polls: the Sources page carries an owner-only **Check now**, the answer is kept until the next
press, and a check that gets no answer forgets the old version rather than showing a stale one.

*Found on the way*: the template probe's first run named three cited pages that no longer answer,
which is the whole point of having it. The mSCP FileVault citation was repointed at the branch its
siblings already use; Microsoft's brokered-auth page became "How to enable cross-app SSO on
Android using MSAL", which was read to confirm it still covers the broker apps the step's failure
text names; and Ubuntu's Secure Boot wiki page became the security documentation's UEFI Secure
Boot page, which carries the shim and MOK enrolment the step checks. Each replacement was read
before it was written down — a step citing a page that does not say the same thing is worse than
one whose citation is known to be stale — and the probe now reports every cited page answering.

### M14: The scan's other eyes (close M12.4 to M12.7)

The browser check, the guides, the lists and the network check shipped in three days. The three
rows this product exists to add — the router, the firewall from both sides, and what a device can
report that a browser cannot — are still mockups. The data they need is already here: the CVE
database, KEV, the Fix panel and the blocklists as Register sources.

- **The router** (M12.4): gateway from the lease, the UPnP device description for model and
  firmware, SSDP and the IGD `GetGenericPortMappingEntry` walk, TLS and the redirect on the admin
  page, the DNS handed out by DHCP, and the firmware matched to the CVE database and KEV by vendor
  and product, with `platforms.ts` gaining the network vendors' CPE names.
- **Firewall and exposure** (M12.5): InternetDB for the public address once a day; DNS
  interception by resolver identity against 8.8.8.8 and 1.1.1.1; bypass over plain 53 and DoH;
  SMB and NetBIOS egress against a probe; IPv6 reachability through a small endpoint the public
  instance runs, omitted when none is configured.
- **Device scripts** (M12.6): `bw-scan.ps1` and the two `bw-scan.sh` generated from the Register's
  lists at fetch time, served with their SHA-256 and their source viewable, and `/scan/devices`
  taking a report back by paste or upload; MVT pointers for phones.
- **History and alerts** (M12.7): every run stored as the facts observed and diffed against the
  last; right away for KEV firmware, a new port mapping, a category that stops being sinkholed and
  WAN remote management; the rest in the digest; a Today tile, the Console look, the phone layout.
- **Depends on**: M13's housekeeping — scan runs are the first data with a natural expiry.
  **Thin slice**: M12.4 and M12.7. A KEV'd router is the finding that justifies the area, and
  history is what makes a daily run worth running.
- **Done when**: turning UPnP off and adding the Pi-hole redirect rule turn two findings green on
  the next run, a router whose firmware reaches KEV is a finding the same hour with the vendor
  advisory beside it, and an unchanged run alerts nobody.

### M15: Mine, a visitor's own stack (M11.4 and M11.5)

The public site is read-only and anonymous, which is right, and so it shows everyone everything.
A signed-cookie profile makes a teaching site personal without becoming an account system, and it
is the shape multi-user upgrades later rather than replaces.

- **The profile**: platforms, releases, hardware and test areas chosen on one page, kept in a
  signed cookie — no account, no row, gone with the browser's cookies — filtering News,
  Vulnerabilities, Today and the plan pages to "my stack"; "Make this a link" puts it in a URL to
  bookmark or send; a per-profile Atom feed and an ntfy-shaped JSON feed so a reader or a phone
  can take the alerts.
- **CVEs by release**: NVD's CPE version ranges joined to the fleet's release ids, so a CVE page
  says "affects Windows 11 24H2 and 25H2" or "iOS 26 only", the Platforms page counts the open
  CVEs per release, and a profile alerts on its own releases.
- **The releases with no feed** get small HTML adapters, like the SANS one: Apple's security
  releases page, the Android Security Bulletins, Samsung's monthly SMR and its display advisories,
  each a News item tagged with its platform and release.
- **Depends on**: the fleet (shipped) and `platforms.ts`. **Thin slice**: the profile without the
  feeds — the filter is the value, the feed is the convenience.
- **Done when**: a stranger picks macOS 27 and Windows 11 26H2, gets a News page and a
  Vulnerabilities page about their fleet, can bookmark the link, and a new Apple CVE names the
  releases it affects.

### M16: Evidence — runs, results, and a fleet file that is checked (M11.7 and M11.6)

The plans export beautifully and prove nothing. A plan that ends in a signed PDF cannot answer
"what broke moving to 26H2", which is the question the release axis was built for. And
`data/platforms.yaml` is curated dates: a hand-kept file is wrong the quarter nobody re-reads it.

- **A run as data**: pass, fail, not applicable, evidence, tester and date per step; runs compared
  across releases; saved named plans and saved baseline profiles for the owner; the results in the
  JSON API and the MCP tools, so an agent answers "did we test Platform SSO on Golden Gate yet"
  without a person opening a page.
- **The fleet file checked against a source**: endoflife.date as an adapter, diffed into the
  Register like any standard, with `platforms.yaml` as the curated layer over it and a digest line
  when the two disagree; M13's `check:templates` extended to name a template whose cited page
  changed; a quarterly review line in the digest.
- **Quality of life as it fits**: per-platform sections in the digest, a print stylesheet for the
  plan page, "what changed in this template since you last exported it", Zoom Rooms and Webex
  templates beside Teams Rooms.
- **Depends on**: M13 (retention covers run history), M15 (the profile decides whose runs they
  are). **Thin slice**: runs and the comparison. The fleet check can wait a quarter; a plan
  without results cannot.
- **Done when**: last month's macOS run and this month's sit side by side with what changed
  between them, and the MCP server answers the Golden Gate question.

### M17: The teaching site earns the name

cybercard.net is the public mission and its audience is people learning. `/guide` shipped and is
good; the rest of the site still assumes the reader knows what OSCAL, a CCI, CAT II, EPSS and a
baseline are. The accessibility pass promised in M10 never happened, and eleven looks across two
colour schemes is a lot of contrast to leave unchecked.

- **Accessibility**: keyboard order and visible focus everywhere, the menus and the builder's
  hundreds of checkboxes included; a screen-reader pass over News, the Register's redline and the
  builder; contrast checked in every look and both schemes; captions and scopes on the tables;
  titles and text alternatives on the inline SVG charts; a test that fails on a missing label.
- **Reading**: the FTS5 search promoted into the masthead; a short explainer beside each area's
  first heading, linking into `/guide`; `/guide` extended with CCIs, OSCAL, SSVC, the severity
  scales and what a baseline is; and a plain "what this is not" line — it does not scan your
  systems and it does not tell you whether you comply.
- **Weight and cache**: a page-weight and render budget for the heaviest pages (the builder, a
  release's change list, Vulnerabilities), measured and recorded; the Cloudflare cache rules for
  `/img/<hash>` and `/assets/` written into DEPLOY.md; `robots.txt`, a sitemap and per-page
  canonical and OpenGraph tags, which a public teaching site needs and this one has none of.
*Shipped 2026-10-21, out of order, because the owner asked for it:* the ladder — standard,
baseline, control, configuration setting — is taught on `/guide#ladder` with a worked example and
where an agency's own layer (NASA's CSET) fits, and both menus are built from it: Standards is
Standards · Baselines · Controls, each with the line that says what it is, with STIGs, the change
register and the Atlas under a rule; the Desk holds the owner's fleet and work, then the instance,
then how it is drawn. `/controls` is new (one search across every standard's current version),
Platforms is renamed Fleet at `/fleet`, and the masthead's look switch moved to an Appearance
page. Today opens on what to do next and groups the window's CVEs by the platform they affect
(migration 0032 stores it on the CVE). **Still open here**: the accessibility pass, the masthead
search, the weight budget, and `robots.txt`, a sitemap and the canonical and OpenGraph tags.

- **Depends on**: nothing, but it is worth taking after M15 so the personalised pages are in the
  pass. **Thin slice**: the accessibility pass and the masthead search.
- **Done when**: every page is usable by keyboard and by a screen reader in both schemes and all
  eleven looks, the heaviest page stays inside its budget, and a reader who has never heard of
  OSCAL can follow an 800-53 diff from the News item to the control.

### M18: More than one person (the last of M8)

The one milestone to defer deliberately. There is one owner, and the public read-only site serves
everyone else. Roles touch every write path, so the work starts when a second person needs to
record a decision, not before.

- Roles: owner, editor (triage, decisions, uploads) and reader (what the public sees, signed in
  for their own profile); M15's profile upgraded into an account rather than a second shape;
  per-user triage, decisions and watchlists; every write audited with who and when; one
  owner-issued invitation link, no mail server.
- **Depends on**: M15's profile shape. **Gate**: a real second user asks — and because that gate
  may never open, this is the one milestone that is **not** a gate on 1.0: M19 ships with one
  owner and the public read, and roles land afterwards as 1.1. **Thin slice**: editor and reader
  with the owner creating the accounts.
- **Done when**: two people sign in with different roles, the reader cannot write, the editor's
  decisions carry their name, and the owner's existing data came across untouched.

### M19: 1.0 — freeze, prove, document

Thirty-seven releases in seven days is the right pace for building and the wrong pace for handing
something over. 1.0 is the version a stranger installs from the catalog and runs for a week
without the author.

- **Scope freeze**: no new areas, and only the gates above closed — M13 to M17, not M18.
- **A written threat model and a sweep against it**: the one page that carries a script, the two
  upload paths (the CIS PDF and the branding mark) and the hand-rolled multipart reader, the
  session and cookie handling, the per-route CSP, SSRF in every adapter that follows a URL out of
  a document, the restricted-source path (that no URL confirms a name is on a list), and the
  scan's outbound behaviour.
- **Dependency and image hygiene**: a weekly dependency PR, which this repo has no mechanism for
  today; the base image rebuilt on its own schedule; a verify step that checks the signature and
  SBOM the tag builds already produce.
- **A licence for this work.** There is no `LICENSE` file in the repository. The plan is careful
  about every publisher's licence and silent about its own, which makes "a stranger installs 1.0
  and runs it" a thing nobody is actually permitted to do. Choose it, add the file, name it in
  README, `package.json` and the BoxPilot card, and keep it separate on screen from the
  publishers' terms, which it does not cover.
- **A fixture refresh across every adapter**, so the suite replays this quarter's real responses,
  and the licence position of all 73 sources re-read and recorded in SOURCES.md.
- **Docs that agree with each other**: README, AGENTS, ADMIN, DEPLOY, SOURCES and this plan each
  checked against the code, and the BoxPilot card's copy refreshed.
- **Done when**: a fresh BoxPilot install of 1.0 runs a week unattended — fetching, digesting,
  alerting, no manual backfill, no stuck source that nothing reported — and every claim on the
  public site is either sourced to a publisher or covered by a fixture test.

### The order, and what the dates are worth

```
M13 keep itself ──┬──► M14 the scan's other eyes ───────────┐
                  ├──► M15 Mine ──────► M16 evidence ───────┤
                  └──► M17 teaching site ───────────────────┴──► M19 1.0

                        M15 ──► M18 more than one person
                                (gated on demand, off the 1.0 path, ships as 1.1)
```

| Milestone | Target | Size | Gate to the next |
| --- | --- | --- | --- |
| M13 The platform keeps itself | 2026-10-25 | 3 days | A dated restore, a bounded database, one release command. |
| M14 The scan's other eyes | 2026-10-31 | 4 days | The four scan sub-milestones closed and alerting only on change. |
| M15 Mine | 2026-11-05 | 4 days | A profile that filters four areas and survives a share. |
| M16 Evidence | 2026-11-11 | 4 days | Two runs of one plan compared, answerable through MCP. |
| M17 The teaching site | 2026-11-16 | 3 days | Keyboard and screen reader across looks and schemes. |
| M18 More than one person | when a second person needs it | 4 days | Roles enforced on every write. Not a gate on 1.0. |
| M19 1.0 | 2026-11-30 | 5 days | The unattended week. |

The dates assume the pace of the first week — a sub-milestone a day with an agent — and they are
the least load-bearing part of this plan. **The gate matters and the date does not**: a milestone
is finished when its "Done when" can be shown on the live instance, not when its week is up. If a
week slips, the thin slice named in each milestone is what ships; the rest moves to the next pass.

**Definition of done, from here on, for every milestone**: `npm run check` green; a fixture test
replaying a real response for every new source; a CHANGELOG entry written before the tag; the
document that describes the area updated in the same commit; the tag deployed and `/health`
showing it; and the milestone's own "Done when" demonstrated on cybercard.net rather than only in
a test.

### Standing commitments

The plan above is work that ends. This is the work that does not, and it is what keeps the
platform from quietly rotting between milestones.

| When | What |
| --- | --- |
| Every release | The changelog entry before the tag, the manifest version matched, `npm run check` green, `/health` compared with the tag after the deploy. |
| Weekly | The housekeeping pass (orphan blobs, optimize, size); the feed and template probes read; the digest read as a user rather than as a developer. |
| Monthly | Fixtures refreshed for the listing adapters (DISA, SCT, CSRC, NASA, the blocklists); dependencies bumped; the image rebuilt. |
| Quarterly | The restore rehearsal; the licence review of every source; the DISA quarterly drop followed end to end, from the listing through the diff and the explanation to the builder and the plan; an accessibility spot-check; every template's cited page re-read. |

### Still out of scope

Unchanged from M9 and M12, and worth repeating because each one gets asked for: scanning or
assessing a host; per-host state beyond a report a person pastes in; remediation scripts beyond
the publisher's own words; any model in the ingest, diff or explain path, except the optional
summary that is labelled and sits beside the quoted rationale; ticketing integrations;
multi-tenant hosting; and redistributing CIS or any licence-restricted source.

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
| Data outgrows the box (138 MB in the first five days, and nothing prunes) | M13: a retention rule per source kind, a weekly sweep of blobs nothing references, the size on `/health` and in the digest, and a written budget for 1 GB and 5 GB. |
| The release ritual loses a step (0.36.0, 0.36.1 and 0.37.0 are tags with no changelog entry) | M13: one release command that refuses a version the changelog does not carry, and CI that runs `npm run check` whole and checks the tag against the manifest. |
| A backup nobody has ever restored | M13: a dated rehearsal written into DEPLOY.md and a quarterly line in the digest. |
| Fixtures rot as publishers change their markup | Nightly `check:feeds` and `check:templates` in CI, a monthly fixture refresh, and a listing parse failure that alerts. |
| No `LICENSE` file, while the catalog card invites installs | M19: pick one, add it, name it in README, `package.json` and the card; the publishers' terms stay separate on screen. |
| A migration that fails on a populated database during an upgrade | Each migration runs in its own transaction, so the file stays at the previous version; M13 adds a test that applies all of them to a database holding rows of each kind, and a written rollback in DEPLOY.md. |
| One maintainer at agent pace | Every milestone names a thin slice; `npm run check` and the fixtures are the handover; the ledger says where each open item went, so nothing survives only in someone's memory. |

---

## 8. First week, concretely

1. M0 scaffold with the manifest in `boxpilot/baselinewatch.yaml` and a container that serves
   `/health` on BigBox.
2. SQLite schema: `items`, `sources`, `snapshots`, `documents`, `requirements`, `changes`,
   `explanations`, `triage`, `watchlist`.
3. Three adapters end to end: BleepingComputer RSS, CISA KEV JSON, NIST OSCAL 800-53 catalog.
4. Load the 800-53 Rel 5.1.1 and 5.2.0 catalogs and get the first real diff on screen.
5. Pick the mockup direction (see `docs/mockups/`) and set the tokens.
