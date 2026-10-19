# Working on BaselineWatch

Read this before changing anything. It applies to humans and coding agents alike.

## What it is

One page that keeps a security practitioner in tune: news, advisories and CVEs in a timeline,
and a **change register for the standards themselves** (NIST SP 800-53, DISA STIGs, Microsoft
baselines, CIS by upload): each control or setting before and after, what changed, and the
publisher's stated reason. The plan is `docs/PLAN.md`; the sources are `docs/SOURCES.md`.

Decisions so far (2026-10-19): News is the home page at `/` (the Wire renamed; the Register at
`/register`, `/wire` a 301), with the top grouped as News · Today · Standards ▾ · Vulnerabilities
plus the owner's Desk ▾ on the right; build follows the "middle path" in the plan (Register done
properly, Wire and Vulnerabilities thin, server-rendered HTML first); public home is
https://cybercard.net as a read-only information and teaching site, with writes behind the
owner's sign-in (M7); installable from the BoxPilot catalog on BigBox. Article images arrive
passively at ingest (feed media, else og:image once per new item), live in the blob store and
are served from `/img/<hash>`; nothing is ever hot-linked.

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
src/app.ts           Express app, routes, security headers, /health
src/config.ts        BW_* environment variables
src/db.ts            open, migrate, counts
src/blobs.ts         content-addressed snapshot store
src/html.ts          html`` template with escaping
src/pages/           server-rendered pages (layout, home, sources, not-found)
src/fleet.ts         the fleet: each OS release and the hardware it runs on (data/platforms.yaml)
src/testplans.ts     test plans by area from STIG and mSCP checks plus data/test-plans/*.yaml
src/report.ts        one block model rendered as LaTeX, Word (.docx) and PDF
src/migrations/      NNNN_name.sql
public/app.css       the one stylesheet (Register look)
test/                vitest; fixtures under test/fixtures/<adapter>/ from M1
boxpilot/            the BoxPilot catalog manifest; scripts/validate-manifest.mjs checks it
docs/                plan, sources, mockups
```
