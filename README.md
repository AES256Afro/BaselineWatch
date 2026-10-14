# BaselineWatch

One page that keeps you in tune with security: news, advisories, CVEs, and the standards and
baselines themselves. When NIST SP 800-53, a DISA STIG, a Microsoft Security Baseline or a CIS
Benchmark changes, BaselineWatch shows each control or setting before and after, what changed,
and why, quoted from the publisher's own release notes.

Runs on its own (one container, one SQLite volume) or from the
[BoxPilot](https://github.com/AES256Afro/BoxPilot) catalog.

**Status**: M0 scaffold. The container, the database schema, the source register and the
Register home page exist; nothing is fetched yet (M1 adds news and KEV, M3 the first OSCAL diff).
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

| Variable | Default | What it does |
| --- | --- | --- |
| `BW_PORT` | `8790` | Port to listen on. |
| `BW_HOST` | `127.0.0.1` (`0.0.0.0` in the container) | Interface to bind. |
| `BW_DATA_DIR` | `./data` (`/data` in the container) | SQLite database and snapshot blobs. |
| `BW_BASE_URL` | `http://localhost:8790` | The address people use, for links in digests. |
| `BW_PUBLIC_READ` | `true` | Anyone who can reach the page may read it. Writes need the owner (M7). |
| `BW_NVD_API_KEY` | unset | Free from nvd.nist.gov/developers; 50 requests per 30 s instead of 5. |
| `BW_NOTIFY_URL` | unset | Apprise-style URL for KEV additions and standard releases (M6). |
| `BW_LLM_URL` | unset | Ollama address. When set, changes also get a summary badged as generated (M5). |
| `TZ` | `Etc/UTC` | Time zone for digests. |

## Docs

- [docs/PLAN.md](docs/PLAN.md): the plan, milestones and the three ways to build it.
- [docs/SOURCES.md](docs/SOURCES.md): every feed and standard we track, with URL, format,
  cadence, licensing and how it is diffed.
- [docs/mockups/](docs/mockups/): five design directions for the app.
- [boxpilot/baselinewatch.yaml](boxpilot/baselinewatch.yaml): the BoxPilot catalog manifest
  (draft).
