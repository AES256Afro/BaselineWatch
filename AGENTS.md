# Working on BaselineWatch

Read this before changing anything. It applies to humans and coding agents alike.

## What it is

One page that keeps a security practitioner in tune: news, advisories and CVEs in a timeline,
and a **change register for the standards themselves** (NIST SP 800-53, DISA STIGs, Microsoft
baselines, CIS by upload): each control or setting before and after, what changed, and the
publisher's stated reason. The plan is `docs/PLAN.md`; the sources are `docs/SOURCES.md`; the
Learning section has its own plan in `docs/LEARN.md`.

Decisions so far (2026-10-19): News is the home page at `/` (the Wire renamed; the Register at
`/register`, `/wire` a 301), with the top grouped as News · Today · Standards ▾ · Vulnerabilities
plus the owner's Desk ▾ on the right; build follows the "middle path" in the plan (Register done
properly, Wire and Vulnerabilities thin, server-rendered HTML first); public home is
https://cybercard.net as a read-only information and teaching site, with writes behind the
owner's sign-in (M7); installable from the BoxPilot catalog on BigBox. Article images arrive
passively at ingest (feed media, else og:image once per new item), live in the blob store and
are served from `/img/<hash>`; nothing is ever hot-linked.

**The ladder** (2026-10-21) is the vocabulary the whole interface is built from, and `/guide#ladder`
teaches it: a **standard** is the rulebook (NIST SP 800-53, a STIG, a CIS Benchmark); a **baseline**
is the set of its rules chosen for a kind of system (800-53 High, a platform's STIG baseline,
Microsoft's for a Windows release); a **control** is one rule in that set (AC-2, IA-2); a
**configuration setting** is how the control is enforced on a device (a registry value, a payload
key, an Intune definition). The Standards menu is those three words in that order, each with the
line that says what it is, and STIGs, the change register and the Atlas sit under a rule as the
tools that cut across them. The owner's Desk holds their own fleet and work (**Fleet** — the page
formerly called Platforms, now at `/fleet`, `/platforms` a 301 — Triage, Watchlist), then the
instance (Sources, Digest), then how it is drawn (Appearance, which the masthead's look switch
moved into, and Branding). Use those words in that sense everywhere; do not reintroduce
"Platforms" for the fleet, and do not put a bare label in a menu without its line.

**Where the rulebook came from** (2026-10-22) is the rung above the ladder, taught at `/learn` and
held in `src/authorities.ts`: law and contract → policy → framework → control catalogue → baseline →
configuration setting → check and evidence, with every publisher placed on a rung and against an
audience (US federal civilian, US defense, NASA, private business, outside the US), so the same step
can be read across the bodies that answer it. A body carries what it derives from, every address its
own words live at, and the access that address asks for — `public`, `registration`, `agency`,
`licence`. An `agency` link is public knowledge of where a document lives and never the document:
NASA's ASCS specifications stay internal, and nothing restricted is reproduced. Add a publisher by
adding one entry to that registry — rung, audiences, `derivesFrom`, links, and `tracked` when this
instance follows it as a source — never by writing a second list of links into a page.

The forward plan (2026-10-21) is the last part of `docs/PLAN.md`: a ledger that re-homes every
open item of M10 to M12, then M13 to M19 ending at 1.0. Take M13 first — retention and a weekly
housekeeping pass, a restore that has been done and dated, one release command that refuses a
version the CHANGELOG does not carry, the pipeline on Today and in `/metrics` — because two of
its items are losses, not gaps. A milestone is done when its "Done when" can be shown on
cybercard.net, not when its dates are up.

## Conventions

- **Stack**: Node ≥ 24 running TypeScript directly (type stripping, so `erasableSyntaxOnly`: no
  enums, namespaces or parameter properties; relative imports carry the `.ts` extension; type-only
  imports use `import type`). Express 5. `node:sqlite`. No build step. Server-rendered HTML through
  the `html` tagged template in `src/html.ts`; no template engine, no inline script or style (the
  CSP forbids both).
- **One pipeline**: fetch → snapshot (exact bytes, content-addressed under the data dir) →
  normalise (one of `requirement`, `setting`, `vulnerability`, `article`) → diff (field-level
  rows in `changes`) → explain (`explanations`, kind `publisher`, `generated` or `none`).
  Vulnerability data is a stream, not a document: NVD records are normalised into `vulns` on
  arrival and their history into `vuln_changes`; they are not kept as raw snapshots.
- **A new source** is one adapter module in `src/adapters/` with an `id` and either `parse()`
  (one document in, timeline items out; the ingester does the GET, the snapshot and the upsert)
  or `pull()` (the adapter runs its own requests against a stream such as the NVD API), a row in
  a migration, a line in `src/adapters/index.ts`, and a fixture test that replays a real captured
  response. No bespoke code paths per source outside the adapter.
- **The Wire is for what matters.** Every CVE goes in the Vulnerabilities table; only notable
  ones (`isNotable` in `src/vulns.ts`: KEV, watchlist, new criticals, EPSS over 50%, active
  exploitation per SSVC) become timeline items.
- **Schema** changes are new files in `src/migrations/NNNN_name.sql`; never edit an applied one.
- **Generated text is always labelled.** A model may summarise a change only beside the quoted
  official rationale, and the badge is not optional.
- **Licensing**: CIS and Microsoft content is the user's own copy; it is quoted on screen and
  never redistributed or exposed through the API. NVD, CVE, CISA and FIRST attributions stay in
  the footer.
- **Secrets** (NVD key, notifier URL) are read from the environment and never rendered or
  logged; pages say "set" or "not set".
- **Version**: `package.json` is the only source; import `productVersion` from `src/version.ts`.
- **No personal host data** in committed files: no real hostnames, LAN layouts or device lists.
- **Tests**: `npm run check` must pass (typecheck, vitest, eslint, manifest check). Inject clocks
  rather than reading the wall clock against dated fixtures.
- **Commits**: imperative subject, short body saying why.

## Layout

```
src/server.ts        start: config, data dir, migrations, listen
src/app.ts           Express app: headers, body limits, the MCP endpoint, assets, API, health, sign-in, the read gate; then the mounts
src/routes/          one module per area (news, today, standards, scan, baselines, vulnerabilities, desk), each a mount function taking RouteContext
src/json.ts          the one reader for a column that should hold JSON
src/config.ts        BW_* environment variables
src/db.ts            open, migrate, counts
src/blobs.ts         content-addressed snapshot store
src/html.ts          html`` template with escaping
src/pages/           server-rendered pages (layout, home, sources, not-found); pages/scan-guide/ holds the manual guide's prose, one module per platform
src/authorities.ts   where a rule comes from: the publishers, the rung each sits on, what derives from what (/learn)
src/fleet.ts         the fleet: each OS release and the hardware it runs on (data/platforms.yaml)
src/netscan.ts       the network check: canaries through the LAN resolver, daily, opt-in (M12.3)
src/domaincheck.ts   check a domain: DNS, mail and web posture by lookups alone, each record quoted (Scan 2.0)
src/domainfix.ts     what to do about a domain finding: the record to publish or the header to send, with its caution
src/seen.ts          what this page learned about you: the request's facts, Tor exits, an InternetDB lookup on request
src/exposure.ts      router and exposure: the public address, what Shodan sees of it, the router's admin page and firmware, daily, owner-only
src/eol.ts           endoflife.date's cycles, and which of them a fleet release is
src/ct.ts            the certificates the transparency logs hold for the owner's domains
src/scanhistory.ts   the scans over time: every network run with its tallies and changes, Today's tile for the area
src/smtp.ts          the notifier's mail transport: one message, STARTTLS or TLS, AUTH PLAIN
src/saved.ts         saved searches: a named list page with its filters, kept on the desk and on Today
src/inventory.ts     is this device affected: the inventory script's report read against the guide, the vendors, endoflife.date and OSV
src/versions.ts      dotted version numbers compared as people read them
src/traces.ts        traces: the indicator list the Register holds, served to the page that reads a device's saved data in the tab (public/traces.js)
src/devices.ts       the owner's devices over time: each reading's verdicts and CVE ids, never the report
src/testplans.ts     test plans by area from STIG and mSCP checks plus data/test-plans/*.yaml
src/report.ts        one block model rendered as LaTeX, Word (.docx) and PDF, in eleven looks
src/decisions.ts     the owner's decision on each baseline item beside the publisher's recommendation
src/housekeeping.ts  what is kept, what goes, and the weekly pass that does it (M13)
src/agenda.ts        what to do next, and the window's CVEs by the platform they affect
src/fixlist.ts       the window's work keyed by the remedy that ends it: what Today is built from
src/feeds.ts         the News and the table as RSS, sources as OPML, KEV due dates as a calendar, robots and sitemap
src/trending.ts      which CVEs the News is talking about, counted by source
src/sbom.ts          a CycloneDX or SPDX document's components as watchlist package entries
src/msrc.ts          Microsoft's Security Update Guide per CVE: the KB per product, exploited, disclosed
src/migrations/      NNNN_name.sql
public/app.css       the one stylesheet (Register look)
public/scan.js       the browser check's script; public/traces.js reads picked files against the indicator list, in the tab
test/                vitest; fixtures under test/fixtures/<adapter>/ from M1
boxpilot/            the BoxPilot catalog manifest; scripts/validate-manifest.mjs checks it
docs/                plan, the Learning section's plan (LEARN.md), sources, mockups
```
