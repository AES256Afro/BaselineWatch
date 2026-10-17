# Running BaselineWatch

What an owner needs to know: where the data lives, how a diff is computed, what the scheduler
does, how to recover, and what reaches the outside world.

## Data

Everything is under the data directory (`BW_DATA_DIR`, `/data` in the container):

| Path | What |
| --- | --- |
| `baselinewatch.db` (+ `-wal`, `-shm`) | SQLite, WAL mode: sources, snapshots index, documents, requirements, changes, explanations, vulnerabilities, items, triage, watchlist, alerts, digests. |
| `blobs/<aa>/<sha256>` | Every fetched document, as received, named by its SHA-256. A document fetched twice with the same bytes is stored once. |

Back up the directory. Restoring it on another machine is the whole restore. In BoxPilot the
app's volume is backed up with the app.

Sizes to expect: a day of NVD modifications is 4,000 to 5,000 CVEs; a month is roughly 100 MB
of database. Standards snapshots are a few MB per release (the 800-53 catalog is 10 MB). EPSS is
joined daily without being stored.

## How a diff is computed

1. **Snapshot.** The adapter names the versioned documents of a standard (the 800-53 catalog, the
   four 800-53B profiles, each followed STIG zip, each Microsoft baseline zip). Each is fetched
   and hashed. A listing that gives a file URL and a publication date is compared first, so an
   unchanged release costs one small request. Same bytes as a stored snapshot: nothing happens.
2. **Normalise.** The bytes become one `document` row and one `requirement` row per control,
   enhancement, rule or setting: a stable `ref` (800-53 control id, STIG Group id `V-nnnnnn`,
   GPO-scope plus setting path), the printed label, title, control text with parameters
   resolved, discussion, related controls, status, and format-specific extras (check and fix
   text, CCIs, registry type and data, the 800-53A assessment objective).
3. **Diff.** The new document is compared with the previous document of the same key, by `ref`,
   field by field, with whitespace ignored. Each difference is one `changes` row: added,
   removed, or modified with the field and the before/after text. A requirement whose control
   text, title, parameters or status moved is *substantive*; one whose discussion, related
   controls or assessment text moved is *editorial*. The pages draw a word-level redline from
   the two texts, splitting punctuation from words so "software." and "software" match.
4. **Explain.** The publisher's reason is stored as an `explanation` of kind `publisher`: NIST's
   Planning Note from the publication page, DISA's Revision History split per rule and attached to
   the exact changes it names, Microsoft's Announcement from the zip. When none is found the
   release is marked `none`. If a local model is configured, a summary of kind `generated` is
   added beside it, and every page badges it.
5. **Announce.** A release with changes becomes a `release` item on the Wire and an alert; a
   republication of the same version with no control-level change is kept but not announced.

Vulnerabilities take a shorter path: NVD records are normalised into `vulns` on arrival, the
differences from the last sighting into `vuln_changes`, and only notable CVEs (KEV, the
watchlist, new criticals, EPSS over 50%, active exploitation per SSVC) reach the Wire.

## The scheduler

In-process, one tick a minute. A source is due when its interval (hourly, daily, weekly) has
passed since its last fetch; a failed source is retried after thirty minutes; the first fetch of
each source happens ten seconds after start. Requests to one host go one after another with a
pause between (Reddit answers 429 to a burst); different hosts run three at a time. The digest
runs on the same ticks at the configured local hour.

Switch the scheduler off with `BW_SCHEDULER=false` and run the same work from cron:

```bash
npm run fetch -- due
```

The owner can fetch any source immediately from the Sources page. A standard's first fetch loads
its published history before the current file, without alerts; `npm run backfill -- <source>`
does the same on demand. Order does not matter: a version that
arrives after a newer one is slotted into its place by publication date and the newer one is
re-diffed against it. A chain linked before 0.10.2 (a backfill run after the scheduler had
already fetched the current release) is repaired by `npm run relink -- <source>` or
`npm run relink -- all`, which re-diffs only what was linked wrong and is safe to run again.

## What leaves the box

- Requests to the sources on the Sources page, with the User-Agent
  `BaselineWatch/<version> (+https://cybercard.net; ...)`.
- Alerts and the digest to `BW_NOTIFY_URL` (ntfy, Gotify or a webhook), with titles, short
  bodies and links back to this instance.
- Prompts to `BW_LLM_URL` when a local model is configured: the before/after text and the
  publisher's note of a release, nothing else.
- For each package on the watchlist, a query to OSV.dev naming that package and its ecosystem
  (`POST https://api.osv.dev/v1/query`), once a day. Nothing else from the watchlist leaves.
- The standards' files from `raw.githubusercontent.com` (NIST's OSCAL, FedRAMP's rules) and the
  publishers' own sites, as the Sources page lists them. DISA's listing call is made once for the
  STIGs and once for the CCI list; a zip is downloaded only when the listing's date has moved.
- CISA's directive listing (`cisa.gov/news-events/directives/all`, three pages), once a day.

Nothing is sent anywhere else. CIS and Microsoft content stays in the data directory under the
owner's own licence; the pages quote it and the API never serves it whole.

## The STIG pages

`/stigs` lists the STIGs the Register follows by platform (Windows, Linux, macOS, mobile,
browsers, network devices, virtualisation, applications; the platform is read from the product
name). `/stigs/<platform>` shows one STIG at a time: its rules grouped CAT I, II, III, each with
the check and fix text folded away, and the NIST SP 800-53 controls it maps to. That mapping is
DISA's own: each rule cites CCIs, and DISA's CCI list indexes each CCI to a control (Revision 5
when DISA gives one, else Revision 4). Until the CCI list has been fetched the pages show the
CCIs alone and say so. The control pages in the Register show the reverse: the followed rules
whose CCIs index that control. The aside shows what changed in the STIG's latest release, with
DISA's Revision History notes, and "CISA on this platform": KEV entries whose vendor and product
belong to the platform (CISA's words, matched by vendor and product name) and the directives
whose titles name it. Nothing on these pages is generated; a rule without a CCI, or a CCI
without an index, is shown as such.

## Looks

Pages come in two looks, each in light and dark: **console**, the dense dashboard with panels,
charts and large figures, and **register**, the paper look with a serif masthead. `BW_LOOK` and
`BW_SCHEME` set the instance's defaults (`console` and `system`, where `system` follows the
device's own light or dark setting). The switch in the masthead lets each browser choose for
itself: two cookies, `bw_look` and `bw_scheme`, a year long, holding one of a few fixed words
and nothing else. No script is involved; the stylesheet reads `data-look` and `data-scheme` on
the page, so the content security policy stays as strict as before.

## Access

Reading is open when `BW_PUBLIC_READ` is true (the default; the public site holds no private
data). Every write needs the owner: marking items, triage, the watchlist, fetching sources,
writing a digest, the CSV export. The owner signs in with `BW_ADMIN_PASSWORD`; the session is a
signed HttpOnly SameSite=Strict cookie for thirty days, Secure behind TLS. Five wrong passwords
from one address wait ten minutes. Every POST must come from the site's own pages, except
`/mcp`: the MCP endpoint takes JSON-RPC posts from programs, follows the same read gating as the
pages and the API, and offers no tool that writes. Without a password the instance is in
single-user mode and writes are open: only for a machine nobody else reaches.

Behind a reverse proxy or a Cloudflare Tunnel, the proxy terminates TLS and the app trusts
`X-Forwarded-*` from loopback and private addresses only.

## The image

Every tag builds `ghcr.io/aes256afro/baselinewatch:<version>` in GitHub Actions and signs it
keylessly through Sigstore: the signature names the workflow in this repository as the signer, and
the record is in the public transparency log. The same run attaches an SPDX software bill of
materials and a build-provenance attestation to the image. Before running a version, check the
signature with [cosign](https://docs.sigstore.dev/cosign/system_config/installation/):

```bash
cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp '^https://github.com/AES256Afro/BaselineWatch/' ghcr.io/aes256afro/baselinewatch:0.10.3
```

The SBOM comes back with `cosign verify-attestation --type spdxjson` and the same two flags, or
with `cosign download attestation`. GitHub's own provenance check is
`gh attestation verify oci://ghcr.io/aes256afro/baselinewatch:0.10.3 --owner AES256Afro`.

## Recovery

- **A source keeps failing.** The Sources page shows the last error. Feed URLs move; a 403 or
  429 from Reddit is a pacing problem; a parse error after a publisher changes a format needs an
  adapter change (the fixture tests in `test/` are where it shows).
- **A bad release loaded.** Delete its `documents` row (requirements and changes cascade) and
  the matching `snapshots` row; the next fetch reloads it.
- **Start over on vulnerabilities.** Delete the `nvd.cursor` row from `app_settings`; the next
  pull backfills `BW_NVD_BACKFILL_DAYS` again.
- **Lost the owner password.** Set a new `BW_ADMIN_PASSWORD`; changing `BW_SESSION_SECRET`
  signs every browser out.
