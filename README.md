# BaselineWatch

One page that keeps you in tune with security: news, advisories, CVEs, and the standards and
baselines themselves. When NIST SP 800-53, a DISA STIG, a Microsoft Security Baseline or a CIS
Benchmark changes, BaselineWatch shows each control or setting before and after, what changed,
and why, quoted from the publisher's own release notes.

Runs on its own (one container, one SQLite volume) or from the
[BoxPilot](https://github.com/AES256Afro/BoxPilot) catalog.

**Status**: scoping. Nothing runs yet.

- [docs/PLAN.md](docs/PLAN.md): the plan, milestones and the three ways to build it.
- [docs/SOURCES.md](docs/SOURCES.md): every feed and standard we track, with URL, format,
  cadence, licensing and how it is diffed.
- [docs/mockups/](docs/mockups/): five design directions for the app.
- [boxpilot/baselinewatch.yaml](boxpilot/baselinewatch.yaml): the BoxPilot catalog manifest
  (draft).
