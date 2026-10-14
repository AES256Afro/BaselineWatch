# BaselineWatch: plan and milestones

*Written 2026-10-14. Owner: Chris (AES256Afro). Status: scoping, nothing built yet.*

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

### M5: Explain (1 to 2 weeks)
- Rationale extractors: CSRC Planning Note and release notes, XCCDF revision history, Microsoft
  blog post sections, CIS changelog pages; stored as `explanation` rows linked to changes.
- Optional LLM summary via Ollama or BoxPilot's model gateway; prompt includes only the before,
  after and official rationale; output badged "generated".
- **Done when**: every change in the Register has either a quoted official reason or an explicit
  "publisher gave no reason" marker.

### M6: Triage, watchlist v2, digest (1 to 2 weeks)
- Triage states and notes on any item (article, CVE, change). Bulk actions. Export CSV.
- Watchlist v2: which baselines apply to you, which control families you own; the Register dims
  everything else.
- Daily and weekly digest; immediate alerts for KEV additions and watched-standard releases;
  ntfy, Gotify, Apprise, SMTP, generic webhook.
- **Done when**: Monday's digest is the thing you read instead of six sites.

### M7: Hardening and BoxPilot (1 week)
- Auth, CSRF, rate limits, backups guidance (the volume), SBOM and image signing in CI.
- Catalog PR to AES256Afro/BoxPilot with pinned image, health check, secrets for NVD key and
  notifier URL, `notes` for first run.
- Docs: README, SOURCES, ADMIN, a short "how a diff is computed" page.
- **Done when**: installed on BigBox from the BoxPilot catalog, backed up by BoxPilot, updated by
  BoxPilot.

### M8: Stretch
- CIS Benchmarks in manual-upload mode (drop the PDF, get the diff against your last upload).
- Vendor PSIRTs (Cisco openVuln, Red Hat, Ubuntu USN, Debian DSA), OSV, GHSA.
- Intune baseline JSON, CMMC Level 2 mapping, FedRAMP Rev5 baselines (OSCAL).
- Public read-only API and an MCP server so BoxPilot agents can answer "what changed in 800-53
  this quarter?".
- Multi-user with roles.

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
