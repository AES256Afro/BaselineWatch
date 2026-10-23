# BaselineWatch

One page that keeps you in tune with security: news, advisories, CVEs, and the standards and
baselines themselves. When NIST SP 800-53, a DISA STIG, a Microsoft Security Baseline or a CIS
Benchmark changes, BaselineWatch shows each control or setting before and after, what changed,
and why, quoted from the publisher's own release notes.

Runs on its own (one container, one SQLite volume) or from the
[BoxPilot](https://github.com/AES256Afro/BoxPilot) catalog.

**Public home**: https://cybercard.net, a read-only information and teaching site; writes are the
owner's, behind a sign-in. The plan and the ledger of what shipped are in
[docs/PLAN.md](docs/PLAN.md); every source with its terms is in [docs/SOURCES.md](docs/SOURCES.md).

## What it does today

**Reading.** [News](https://cybercard.net/) is the timeline: the feeds, Reddit, Hacker News, the
vendor advisories, CISA's advisories and the KEV catalog, and the CVEs worth an entry of their
own, one card per story however many sources carry it. [Today](https://cybercard.net/today) is the
last day in one glance: what to do next, CVEs by the platform they touch, what the News is
talking about, the pipeline's own health. [Vulnerabilities](https://cybercard.net/vulnerabilities)
is every CVE NVD modifies with CVSS, EPSS, KEV, the platform it touches, whether a **public
exploit** exists (Exploit-DB, Metasploit, PoC-in-GitHub), and on each CVE page a **Fix** panel:
the patch, advisory, KEV action, fixed package version, mitigating STIG rule and **Microsoft's
update** (the KB per product from the Security Update Guide) already published, or "nothing
published yet". [Patch Tuesday](https://cybercard.net/vulnerabilities/microsoft) lays each month
out by update and product, your own Windows releases first. One search from the masthead covers
CVEs, the News, every standard's controls, Microsoft's updates and the sources.

**The standards themselves.** A *standard* is the rulebook, a *baseline* the set of its rules
chosen for a kind of system, a *control* one rule in that set, a *configuration setting* how the
control is enforced on a device — the ladder the [guide](https://cybercard.net/guide#ladder)
teaches and the menu is built from. The Register keeps every release of NIST SP 800-53 and its
800-53B baselines (OSCAL), SP 800-171, FedRAMP's rules, the DISA STIGs you follow (rule by rule),
every Microsoft Security Baseline (setting by setting), NIST's macOS rules and the CIS Benchmarks
from your own copy, diffs each against the last with a word-level redline, and sets the
publisher's own reason beside it; a local model may add a summary, always badged as generated.
The Baselines area builds the strictest published profile per platform and exports it; the test
plans say what to test on a new release; the Fleet page holds each release with the vendor's
support dates and endoflife.date's beside them.

**Scan.** What a page can honestly test and what a server on the LAN can: *this browser* (ad
hiding, ad requests, filtering DNS, the privacy signals it sends, WebRTC addresses, the
fingerprint surface, the referrer as received, its own version against the vendor's newest, and
what this server learned from the request); *a domain* (SPF, DMARC, DKIM, MTA-STS, TLS-RPT,
DNSSEC, CAA, HSTS, the certificate, `security.txt`, every record quoted beside its verdict, with
a certificate-transparency watch on your own domains); *a device* (an inventory script's report,
pasted, read against the Security Update Guide's builds, the vendors' releases, endoflife.date
and OSV, kept as verdicts and CVE ids per device so the next reading says what moved); *your
network* (canary names through the LAN resolver daily, and once a day what the internet sees of
your public address and what the router gives away); *history*; and the manual guide with the
scripts, each served with its sum. Nothing here contacts an advertising or malware host, and no
packet goes to a device that did not ask.

**The desk.** Triage any item, CVE or control change; a watchlist of products, packages (an SBOM
in one upload), platforms, baselines and control families that marks the table as your stack;
saved searches; alerts through ntfy, Gotify, a webhook or mail for KEV additions, watched CVE
changes, standard releases and the Scan area's changes; a daily or weekly digest.

**What leaves with you.** RSS for the News and the table under any filter, OPML of every source,
the KEV due dates as a calendar, `/api/v1/` as JSON, `/mcp` as tools, `/metrics` for a dashboard.

## Run it

Needs Node 24 or newer. No build step: Node runs the TypeScript directly.

```bash
npm install
npm run dev
```

Then open http://localhost:8790. The database and snapshot store live in `./data`
(`BW_DATA_DIR`). `npm run check` runs the typecheck, tests, lint and, when a BoxPilot checkout
is next to this repository, the catalog manifest validation.

With Docker:

```bash
docker compose up -d
```

Fetch one source, every enabled source, or whatever is due, from the shell:

```bash
npm run fetch -- cisa-kev
```

The first scheduled fetch of each standard loads its published history too, so the Register
starts with a real diff (NIST SP 800-53 Release 5.1.1 to 5.2.0 takes about a minute). To load it
right away instead of waiting for the scheduler, which also works after the first fetch because
versions are linked by publication date:

```bash
npm run backfill -- nist-sp-800-53 && npm run backfill -- nist-sp-800-53b
```

Sources are fetched hourly, daily or weekly as the Sources page shows; a failed source is retried
after thirty minutes. Every fetched document is kept as a content-addressed snapshot under the
data directory, and the Sources page shows each source's last status. The owner can fetch any
source immediately from that page.

| Variable | Default | What it does |
| --- | --- | --- |
| `BW_PORT` | `8790` | Port to listen on. |
| `BW_HOST` | `127.0.0.1` (`0.0.0.0` in the container) | Interface to bind. |
| `BW_DATA_DIR` | `./data` (`/data` in the container) | SQLite database and snapshot blobs. |
| `BW_BASE_URL` | `http://localhost:8790` | The address people use, for links in digests. |
| `BW_PUBLIC_READ` | `true` | Anyone who can reach the page may read it. Writes need the owner. |
| `BW_ADMIN_PASSWORD` | unset | The owner's password. Unset means single-user mode: no sign-in, writes open. |
| `BW_SESSION_SECRET` | random per start | Signs the owner's session cookie. Set it so sessions survive restarts. |
| `BW_TRUSTED_PROXIES` | `loopback, linklocal, uniquelocal` | Whose `X-Forwarded-For` is believed, in Express's trust-proxy words. The default believes every private address so a tunnel published through Docker's bridge works; where LAN visitors also connect directly, name the proxy's own address. |
| `BW_SCHEDULER` | `true` | Fetch sources in-process on their schedule. Set false to run `npm run fetch -- due` from cron instead. |
| `BW_NVD_API_KEY` | unset | Free from nvd.nist.gov/developers; 50 requests per 30 s instead of 5. |
| `BW_NVD_BACKFILL_DAYS` | `7` | How many days of NVD modifications the first pull loads. Later pulls continue from the stored cursor. |
| `BW_NOTIFY_URL` | unset | `ntfy://host/topic`, `gotify://host/token`, an `https://` webhook, or `mailto://user:pass@host:587/you@example.org` (`mailtos://` for TLS from the first byte, `?from=` to set the sender). Receives KEV additions, watched CVE changes, standard releases, the Scan area's changes and the digest. |
| `BW_DIGEST` | `daily` | `daily`, `weekly` (Mondays) or `off`. |
| `BW_DIGEST_HOUR` | `7` | Local hour, in `TZ`, at which the digest is written. |
| `BW_LOOK` | `console` | How pages are drawn unless a browser chooses otherwise: `console` (dense panels and charts) or `register` (paper). |
| `BW_SCHEME` | `system` | `light`, `dark`, or `system` for whatever the device says. Each browser can pick its own from the masthead. |
| `BW_LLM_URL` | unset | Ollama address. When set, each release with changes also gets a short summary badged as generated, beside the publisher's own words. |
| `BW_LLM_MODEL` | `llama3.2:3b` | The Ollama model for those summaries. |
| `BW_PROBE_ORIGIN` | unset | A second origin serving the Scan page's probe images (another BaselineWatch instance, or this one on another hostname), so the ad-request check covers a cross-site load as well as a same-site one. An origin only: `https://probe.example.net`. |
| `TZ` | `Etc/UTC` | Time zone for digests. |

## API

Read-only JSON, same read gating as the pages, for BoxPilot's agents and your own scripts:

| Route | Returns |
| --- | --- |
| `/api/v1/items?kind=&source=&q=&since=&limit=` | Timeline items with their signals. |
| `/api/v1/vulns?watch=1&kev=1&min_cvss=&min_epss=&since=&q=&sort=&limit=&offset=` | CVEs with CVSS, EPSS, KEV, SSVC, vendors and watchlist hits. |
| `/api/v1/vulns/<CVE>` | One CVE with CPEs, references and its change history. |
| `/api/v1/standards` | Every tracked standard and its loaded versions; one flagged `restricted` yields versions and counts only. |
| `/api/v1/changes?source=&since=&limit=` | Control-level changes with before/after text and the publisher's note; a restricted source's are left out. |
| `/api/v1/triage?state=` | The board. |
| `/api/v1/digest` | The latest digest. |

The same reads are an MCP server at `/mcp` (Streamable HTTP, stateless, no sessions), with the
tools `list_standards`, `release`, `requirement`, `standard_changes`, `search_wire`,
`vulnerabilities`, `vulnerability`, `triage` and `digest`, every one marked read-only. From
Claude Code: `claude mcp add --transport http baselinewatch https://cybercard.net/mcp`. Nothing
on it writes, uploads or fetches, and neither the API nor the tools return the entries of a
licence-restricted source (`sources.restricted`): those are shown to the signed-in owner on the
pages alone, while everyone else sees the versions and counts.

Every loaded version can also be read whole: each release page links to a browsable, searchable
list of all its requirements, filtered by family, with the ones that changed in that release
marked.

## CIS Benchmarks

CIS Benchmarks are licensed for internal use, so they are not fetched. The owner uploads a
benchmark PDF on its page under the Register; the next upload of the same benchmark is diffed
recommendation by recommendation. The PDF stays in the data directory.

## Docs

- [docs/PLAN.md](docs/PLAN.md): the plan, milestones and the three ways to build it.
- [docs/ADMIN.md](docs/ADMIN.md): where the data lives, how a diff is computed, the scheduler,
  what leaves the box, access and recovery.
- [docs/SOURCES.md](docs/SOURCES.md): every feed and standard we track, with URL, format,
  cadence, licensing and how it is diffed.
- [docs/COMPETITION.md](docs/COMPETITION.md): what comparable tools do, and what BaselineWatch
  borrows or leaves alone.
- [docs/mockups/](docs/mockups/): five design directions for the app.
- [boxpilot/baselinewatch.yaml](boxpilot/baselinewatch.yaml): the BoxPilot catalog manifest
  (draft).
