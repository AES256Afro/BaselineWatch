# BaselineWatch

One page that keeps you in tune with security: news, advisories, CVEs, and the standards and
baselines themselves. When NIST SP 800-53, a DISA STIG, a Microsoft Security Baseline or a CIS
Benchmark changes, BaselineWatch shows each control or setting before and after, what changed,
and why, quoted from the publisher's own release notes.

Runs on its own (one container, one SQLite volume) or from the
[BoxPilot](https://github.com/AES256Afro/BoxPilot) catalog.

**Status**: M9 in progress. The STIGs area (`/stigs`) shows, per platform, every followed
STIG's rules by CAT with check and fix text, the NIST SP 800-53 controls each rule maps to
through DISA's CCI list (and, on each control's page, the rules that implement it), what changed
in the latest release, and CISA's known-exploited entries and directives for that platform. The
plan for the rest of M9 (baseline builder, test plans, platform alerts and a Fix panel) is in
[docs/PLAN.md](docs/PLAN.md); what comparable tools do is in [docs/COMPETITION.md](docs/COMPETITION.md).
Before that: triage any item, CVE or control change (New, Reviewing, Affects us, Done), get
alerts through ntfy, Gotify or a webhook for KEV additions, watched CVE changes and standard
releases, and a daily or weekly digest. The Register tracks NIST SP 800-53 and its 800-53B baselines (OSCAL), NIST SP 800-171 Rev 3 (the CMMC Level 2 set), FedRAMP's Consolidated Rules for 2026, the
DISA STIGs you follow (XCCDF, rule by rule) and every Microsoft Security Baseline in the
Security Compliance Toolkit (setting by setting). Every release is kept as a snapshot and diffed
against the last with a word-level redline, and the publisher's own reason sits beside it: NIST's
Planning Note from the publication page, DISA's Revision History read out of the PDF and attached
rule by rule, Microsoft's announcement from the zip. A local model can add a short summary, always
badged as generated. The Wire (M1) carries news feeds, Reddit, Hacker News, CISA advisories and
the KEV catalog; the Vulnerabilities page (M2) pulls every CVE NVD modifies with EPSS, KEV and
your watchlist, and the advisories OSV and GitHub publish for the packages you watch. All five
mockup directions are now pages: the Register (home), the Wire, the Board (Triage), the Console
(Today, phone-first) and the Atlas (release timeline and the SP 800-53 family heatmap). The
public instance is https://cybercard.net; the BoxPilot catalog entry is proposed.
Public home will be https://cybercard.net, a read-only information and teaching site.

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
| `BW_SCHEDULER` | `true` | Fetch sources in-process on their schedule. Set false to run `npm run fetch -- due` from cron instead. |
| `BW_NVD_API_KEY` | unset | Free from nvd.nist.gov/developers; 50 requests per 30 s instead of 5. |
| `BW_NVD_BACKFILL_DAYS` | `7` | How many days of NVD modifications the first pull loads. Later pulls continue from the stored cursor. |
| `BW_NOTIFY_URL` | unset | `ntfy://host/topic`, `gotify://host/token` or an `https://` webhook. Receives KEV additions, watched CVE changes, standard releases and the digest. Email goes through ntfy or Apprise rather than SMTP here. |
| `BW_DIGEST` | `daily` | `daily`, `weekly` (Mondays) or `off`. |
| `BW_DIGEST_HOUR` | `7` | Local hour, in `TZ`, at which the digest is written. |
| `BW_LOOK` | `console` | How pages are drawn unless a browser chooses otherwise: `console` (dense panels and charts) or `register` (paper). |
| `BW_SCHEME` | `system` | `light`, `dark`, or `system` for whatever the device says. Each browser can pick its own from the masthead. |
| `BW_LLM_URL` | unset | Ollama address. When set, each release with changes also gets a short summary badged as generated, beside the publisher's own words. |
| `BW_LLM_MODEL` | `llama3.2:3b` | The Ollama model for those summaries. |
| `TZ` | `Etc/UTC` | Time zone for digests. |

## API

Read-only JSON, same read gating as the pages, for BoxPilot's agents and your own scripts:

| Route | Returns |
| --- | --- |
| `/api/v1/items?kind=&source=&q=&since=&limit=` | Timeline items with their signals. |
| `/api/v1/vulns?watch=1&kev=1&min_cvss=&min_epss=&since=&q=&sort=&limit=&offset=` | CVEs with CVSS, EPSS, KEV, SSVC, vendors and watchlist hits. |
| `/api/v1/vulns/<CVE>` | One CVE with CPEs, references and its change history. |
| `/api/v1/standards` | Every tracked standard and its loaded versions. |
| `/api/v1/changes?source=&since=&limit=` | Control-level changes with before/after text and the publisher's note. |
| `/api/v1/triage?state=` | The board. |
| `/api/v1/digest` | The latest digest. |

The same reads are an MCP server at `/mcp` (Streamable HTTP, stateless, no sessions), with the
tools `list_standards`, `release`, `requirement`, `standard_changes`, `search_wire`,
`vulnerabilities`, `vulnerability`, `triage` and `digest`, every one marked read-only. From
Claude Code: `claude mcp add --transport http baselinewatch https://cybercard.net/mcp`. Nothing
on it writes, uploads or fetches.

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
