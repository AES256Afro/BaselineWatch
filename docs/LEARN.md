# The Learning section: plan and milestones

cybercard.net's stated mission is a public information and teaching site, and the teaching is the
part that has been built last. This is the plan for finishing it. The milestones are numbered L1 to
L6 so they can be taken in any order against the main plan's M13 to M19; where they overlap M17
("The teaching site earns the name"), this document is the detail and `PLAN.md` keeps the gate.

## Two jobs, kept apart

The section has two pages and they are not the same page, which is the first thing to hold on to:

- **`/learn` teaches the field.** Where a rule comes from. Law and contract, policy, framework,
  control catalogue, baseline, configuration setting, check and evidence; thirty-five publishers;
  what derives from what. True whether or not this site exists.
- **`/guide` teaches this instrument.** What the Register is, what a KEV chip means, what each Scan
  check can and cannot prove, how to read a redline. True only here.

A reader needs both and needs them in that order, because the guide's vocabulary is borrowed from
the field. Nothing below merges them.

## Where it stands, 2026-10-22

Shipped: `/guide` with the ladder (2026-10-21) and `/learn` with the chain (2026-10-22) — the seven
rungs, the matrix of rungs against audiences, thirty-five publishers in `src/authorities.ts` with
their addresses and access levels, the same control traced three ways, the normalisation section
and the names-that-collide box; plus "Where this comes from" on every standard's own page.

What is honestly missing, verified against the code rather than remembered:

- **No glossary.** The word does not appear in the repository. CCI, OSCAL, XCCDF, OVAL, CPE, SSVC,
  overlay, tailoring, ATO, POA&M, CUI, FCI, NSS and a dozen more are used on public pages with no
  entry to send a reader to. M17 promised "a short explainer beside each area's first heading" and
  it has never been written.
- **The teaching prose is not searchable.** `/search` covers CVEs, the News, every standard's
  controls, Microsoft's updates and the sources. It does not cover a word of `/guide` or `/learn`,
  so the masthead box cannot answer "what is a CCI".
- **The traces are prose, not data.** The three ladders on `/learn` are hand-written, while the
  instance is holding the real article: the catalogue, the CCI index, the STIGs, the mSCP rules.
  `cciMap()` in `src/stigs.ts` already joins a STIG rule's CCIs to SP 800-53 controls and the STIG
  pages already use it. A teaching site that can show you *your* data and shows you an example
  instead is leaving its one real advantage on the table.
- **Nothing checks the registry's addresses.** The nightly probe (`.github/workflows/probes.yml`)
  asks the seeded feeds and the test-plan citations whether they still answer. It knows nothing
  about the eighty-odd publisher addresses added on 2026-10-22. A dead link on a teaching page is
  worse than no link, because it teaches that the document is gone.
- **The registry is not readable by a tool.** `/api/v1/` serves items, vulns, standards, changes,
  triage, digest and health. The chain is HTML only, and the MCP server cannot answer a question
  about it.
- **The directory buries the lesson.** Thirty-five cards sit under the teaching prose on one page.
  The narrative and the reference are different reading modes and should not share a scroll.

M17's own note lists four items still open. Three of them have since shipped — the masthead search,
`robots.txt` and the sitemap, and the canonical and OpenGraph tags — leaving **the accessibility
pass** and **the page-weight budget**, both of which L6 takes.

---

## L1: The section has a shape

One long page is not a section. A reader arriving cold is given no order, no sense of how much
there is, and no idea whether the guide comes before or after.

- `/learn` becomes a short index: what the section teaches, in what order, and roughly how long
  each part takes to read. Nothing else on it.
- The chain moves to `/learn/chain` and the thirty-five cards to `/learn/publishers`, so the
  narrative and the reference stop competing. The anchors the standard pages already link
  (`/learn?rung=catalog#body-sp-800-53`) redirect rather than break.
- A foot strip on every page in the section: previous, the index, next.
- One lede sentence per page saying who it is for and what it assumes you already know.
- `/guide` and `/learn` cross-link explicitly, with the sentence that says which is which.
- **Depends on**: nothing. **Thin slice**: the index and the split; the foot strip can wait.
- **Done when**: a reader entering at `/learn` is carried through the section in a stated order and
  never meets a term the section has not already defined.

## L2: The glossary, and nothing left unexplained

The largest single gap, and the one M17 promised. Every acronym this site uses on a public page
gets one entry, and every page points at it.

- `/learn/glossary`: one entry per term — a one-line definition, the publisher that defines it
  where there is one, and where the term is used on this site.
- A `term()` helper in the html layer so any page links a word to its entry without copying a URL,
  and the first use of a term on a page is the linked one.
- A test that renders every page in the accessibility sweep's list, looks for a list of known
  acronyms in visible text, and fails when one appears unlinked. That test is what keeps this from
  rotting the week after it ships.
- This absorbs M17's "a short explainer beside each area's first heading": the explainer is one
  sentence with its terms linked, not a second essay.
- **Depends on**: L1 for where it lives. **Thin slice**: the twenty terms the chrome itself uses
  (CCI, OSCAL, KEV, EPSS, CVSS, SSVC, CAT I–III, baseline, overlay, tailoring, CUI, STIG, SRG).
- **Done when**: the acronym test passes on every public page, and no term in the masthead, the
  chips or any area's first paragraph is unexplained.

## L3: Traced from the data this instance holds

The heart of it, and the one thing a book cannot do. Replace the worked example with the real
walk, drawn from what has actually been loaded.

- `/learn/trace/<control>`: take a control and walk it down — the catalogue version held, its
  membership in the SP 800-53B baselines, DISA's CCI index (`cciMap()`, already written), the STIG
  rule for a platform in the fleet, that rule's check and fix text, the mSCP rule and the setting
  it writes.
- Every step names the document and version it came from and links into the Register, so the trace
  is evidence rather than illustration.
- A step that cannot be filled says why — the CCI list is not loaded, no STIG is held for that
  platform — rather than leaving a silent gap. This is the honest half of the feature and the half
  that is easy to skip.
- A starting set of controls chosen because every rung exists for them, linked from `/learn/chain`
  beside the hand-written traces, which stay: the example teaches the shape, the trace proves it.
- **Depends on**: nothing in this section, but it wants the fleet's STIGs and the CCI list loaded,
  which they are. **Thin slice**: one control, one platform, every step cited.
- **Done when**: two controls trace end to end across two platforms from loaded data alone, every
  step cites its version, and a missing step explains itself.

## L4: Searchable, quotable, answerable

The section is currently a destination. It should be something the rest of the site can reach into.

- The teaching prose joins the masthead search, so "CCI" from any page finds the glossary entry and
  the chain's section on it, not only the CCI list as a source.
- `/api/v1/authorities`: the registry as JSON — rungs, audiences, derivations, addresses and access
  levels — so a tool can read the chain, and the MCP server can answer "what does a STIG derive
  from?" and "who else publishes at that step?".
- Stable anchors for every rung, publisher and definition, all of them in the sitemap, so a reader
  can link a colleague to one paragraph rather than to a page.
- **Depends on**: L1 (where things live) and L2 (there has to be a glossary to index).
  **Thin slice**: the search index; the API can follow.
- **Done when**: the masthead answers a vocabulary question, and the MCP server answers a chain
  question without the asker opening a page.

## L5: The links stay alive

Eighty-odd publisher addresses were added in one day and nothing on earth is watching them. CSRC
has already renumbered its publication URLs once; cyber.mil has moved its STIG downloads twice.

- `scripts/probe-authorities.mjs`, on the existing nightly probe beside the feed and test-plan
  checks, asking every address in `src/authorities.ts` whether it still answers, and folded into
  the one issue the workflow already keeps open.
- A last-confirmed date on `/learn/publishers`, and an address that stopped answering marked on the
  page rather than left to mislead.
- The registry added to SOURCES.md's quarterly licence-and-address review, so it is re-read on the
  same rhythm as the sources.
- **Depends on**: nothing. It can ship the same week as L1. **Thin slice**: the probe script and
  the issue; the on-page date can follow.
- **Done when**: the nightly run covers every address in the registry, failures land in the
  existing issue, and the page says when each address was last confirmed.

## L6: Off the screen, and usable by everyone

The last gate, and where M17's two remaining items land.

- The section as a handout through `src/report.ts` — the chain, the matrix and the glossary as
  LaTeX, Word and PDF in the eleven looks the reports already draw. A teaching site whose material
  cannot be handed out is a website, not a course.
- **The accessibility pass over the section**: keyboard order and visible focus; a screen-reader
  pass over the chain, the matrix and the publisher cards; contrast checked in every look and both
  schemes; and a text alternative for the flow strip that carries more than its `aria-label` does.
  The strip is already hidden below 700px because seven boxes squeezed onto a phone are seven boxes
  nobody can read — the numbered list beneath it is what carries the picture there, and that is the
  pattern to extend.
- A measured page-weight budget for `/learn/publishers`, the heaviest page in the section, recorded
  beside the other budgets.
- **Depends on**: L1 to L4, since there is no sense passing a section that is still moving.
  **Thin slice**: the accessibility pass alone, which is the part with a deadline attached to it
  (M19).
- **Done when**: a teacher hands the chain and the glossary out on paper, and every page in the
  section is usable by keyboard and by a screen reader in both schemes and all eleven looks.

---

## The order

```
L1 shape ──┬──► L2 glossary ──┬──► L4 searchable ──┐
           │                  │                    ├──► L6 off the screen
           └──► L3 traced ────┘                    │
                                                   │
L5 links alive ── independent, any week ───────────┘
```

| Milestone | Size | Why it is where it is |
| --- | --- | --- |
| L1 The section has a shape | small | Everything else needs an address to live at. |
| L2 The glossary | medium | The largest gap, and M17's oldest unkept promise. |
| L3 Traced from live data | large | The one thing no book can do; worth the week. |
| L4 Searchable and answerable | small | Cheap once there is something to index. |
| L5 The links stay alive | small | Independent, and the only one that is a loss rather than a gap. |
| L6 Off the screen | medium | A gate on 1.0 through M17's accessibility pass. |

L5 first if a week is short: it is the only milestone here fixing something that is already
degrading. L3 is the one worth protecting from being cut, because it is the only one a reader could
not get from a textbook.

## Weighed, and where it would go

- **Check yourself.** Questions drawn from the registry and the database — which body publishes the
  Operating System SRG, which baseline a moderate system gets, which control a given CCI indexes.
  The CSP forbids inline script and only the Scan page carries any, but a `<details>` reveal needs
  none, so this is cheaper than it sounds. It belongs after L3, because a question is only worth
  asking once the answer can be shown from real data. Not scheduled: nothing here stores what a
  reader did, and a quiz that remembers nothing is a modest thing to spend a week on.
- **Per-country chains.** The matrix names the ACSC and the NCSC but traces neither. Worth doing
  only if somebody outside the US reads this site, which nothing currently tells us.
- **A reading time or progress bar.** Both imply the site is watching, and it is not.

## Still out of scope

Accounts, progress tracking, anything stored about a reader. Video or audio. Translation. And the
line `/learn` already draws and must keep drawing: this is not legal advice and not a compliance
determination — whether a given system must meet a given baseline is a question for the people who
authorise it, and no page here will answer it.
