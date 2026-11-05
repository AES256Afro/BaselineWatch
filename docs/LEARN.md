# The Learning section: plan and milestones

cybercard.net's stated mission is a public information and teaching site, and the teaching is the
part that has been built last. This is the plan for finishing it. The milestones are numbered L1 to
L7 so they can be taken in any order against the main plan's M13 to M19; where they overlap M17
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

## Where it stands, 2026-10-22 (L7 added 2026-10-26)

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
- **The catalogue is loaded and undrawn** (added 2026-10-26). The database holds 1,196 SP 800-53
  controls and enhancements with their families, baselines and CCI joins, and the only ways to meet
  them are a search box and a two-hundred-row browse. There is no view of a family, no view of all
  the controls at once, and no view of one control's life across releases — and only two releases
  of the catalogue are loaded, so a life could not be drawn yet in any case. L7 is that gap, and it
  is the largest one here.

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

## L7: The catalogue, seen whole

The change register answers *what moved last Tuesday*. It cannot answer *what is AC-2, where did
it come from, and what has happened to it since* — and the second question is the one somebody
learning the field actually arrives with. This instance holds 1,196 controls and enhancements of
SP 800-53 Release 5.2.0 in `requirements` — twenty families, 182 of them withdrawn and carrying
what absorbed them — with the four 800-53B baselines beside them and the CCI join to the STIG
rules that implement them. No page shows more than a search result's worth of that at once; no
page draws a family; no page shows one control's life across releases. The article is loaded and
unseen, which makes this the largest single thing left in the section and the one a reader would
notice first.

This is the reference tool the mission implies: every control, at a glance and in depth, with its
history, the publisher's stated reason, and — on every version of every control — a link both to
the change as this instance recorded it and to the publisher's own document.

### What the data can already carry, and what it cannot

Written against the schema rather than remembered, because three of these rows decide the order
of the work.

| What the reader asks | What answers it today | What is missing |
| --- | --- | --- |
| What are all the controls? | `requirements` for `nist-sp-800-53/catalog`: every control and enhancement, family, statement, discussion, parameters, related list, the 800-53A objective | Nothing. It is held and undrawn. |
| What does this one say? | `/standards/nist-sp-800-53/<doc>/<ref>`, field by field | Nothing. |
| Which baselines pick it? | The four 800-53B profiles, loaded and diffed as membership | Nothing. |
| What changed in it? | Field-level `changes` rows | Every release before 5.1.1, and Revision 4 entirely. Four catalogue documents are loaded and three of them are the same release republished, so there are two versions to compare, not four. |
| Why did it change? | Release level: NIST's Planning Note, quoted, via `extractPlanningNote` | Control level: nothing. NIST publishes a per-control analysis of updates and this instance does not load it. |
| When did it first appear? | Not derivable | One revision is held, so "new" cannot be told from "always been there". |
| Why does it exist at all? | Half of it is already normalised and shown nowhere: `status` and `incorporated-into` come out of OSCAL on every parse | The introduction half, which needs Revision 4 and NIST's analysis. |

So L7.1 is not groundwork for a nicer page; it is the difference between a view and a claim.

### L7.1: The history the question needs

- `releases` in `src/adapters/oscal-nist.ts` names two commits of `usnistgov/oscal-content`.
  Extend it to every release of the Rev 5 catalogue the repository has published, from 5.0.0 to
  5.2.0, each pinned by commit sha as the two already are, each carrying the publication page that
  explains it. The adapter's `history()` and `npm run backfill` already do the rest; the cost is
  the shas, the fixtures and reading the diffs, not new machinery.
- **Tell a NIST release from an OSCAL content update.** The version labels carry both — the
  catalogue already loaded as `5.1.1+u4` is NIST's 5.1.1 as the fourth content revision of it — and
  a `+uN` that fixes a conversion is not NIST changing SP 800-53. Keep both, show the NIST release
  as the heading and the content update as the provenance, or the life strip in L7.4 will show
  marks that NIST never made.
- Revision 4 as its own document key (`catalog-rev4`) under the same source, from the Rev 4 OSCAL
  in the same repository, loaded once and never expected to move. **A revision is not a release**:
  diffing Rev 4 into Rev 5 as one more field-level step would read as a publication changing its
  mind overnight, when what happened was a new book. Keep the keys apart and let L7.4 join them by
  control id.
- The same for the four 800-53B profiles, so baseline membership has the same depth as the text.
- A fixture test per release replaying the captured file, asserting the control count and one known
  change, the way M1 set the pattern.
- **Tell M13's retention rules about this.** The catalogue's history is the evidence the whole
  milestone rests on and must be exempt from pruning; five catalogues of fat rows is a few
  thousand rows and a few megabytes, which is nothing, but the housekeeping pass should say so
  deliberately rather than leave it to a `WHERE` clause written for the News.
- **Depends on**: nothing. **Thin slice**: the Rev 5 releases; Rev 4 can follow a week later.
- **Done when**: the Atlas's family map has a row per release rather than two, the standard's own
  page lists every release NIST has published of Rev 5 with the changes between each, and Rev 4 is
  held as its own revision.

*Shipped 2026-10-26.* Eight versions of the catalog instead of two, and Revision 4 beside them
under its own key. The chain runs Revision 5 (December 2020 errata, 1,189) → 5.1.1 → +u2 → +u3 →
+u4 (1,193) → 5.2.0 (1,196) → the two republications of 5.2.0, each release diffed against the one
before it and each carrying the publisher's own words for that step. Revision 4 holds 922 controls
in eighteen families — no PT and no SR — against Revision 5's 1,196 in twenty, so the 274 controls
Revision 5 introduced and the whole privacy family are now a query rather than a claim. The
pinning had to be chosen from evidence rather than from dates, and three things came out of that:
the November 2020 conversion carries no withdrawal status and incomplete statements, so it is not
the floor; the OSCAL content versions do not run in the same order as NIST's releases (5.1.2 of
August 2022 is NIST's errata'd Revision 5, a year older than NIST's own 5.1.1); and NIST's new
control **IA-13** arrived in 5.1.1+u2, which is why every content update is pinned rather than
only the settled one — the release page for +u2 now shows IA-13 and its three enhancements added
beside NIST's note, instead of the addition being folded into +u4 four months later.

Two things this turned up that belong to the milestones after it:

- **Intensity has to mean substance.** Two of the new rows on the Atlas's family map are bright
  across nearly every family — 1,008 controls at 5.1.1 and 538 at +u3 — and neither is NIST
  revising the catalog: both are the conversion re-emitting the SP 800-53A assessment text, which
  is what the publisher's note on each of them says. The map counts controls touched, which is
  true and misleading. **L7.2's by-change lens must count the substantive fields** — statement,
  title, parameters, status, added and removed — and show the editorial ones separately. The data
  is already there: `changes.field` has carried the distinction since M3, and `ChangeSummary`
  already splits substantive from editorial for the release pages.
- **A scraped reason goes stale.** The catalog loaded in 2024 as 5.1.1+u4 was carrying CSRC's
  Planning Note about Release 5.2.0, because the note is read off the publication page at fetch
  time and the page moves on. `adoptRationale` now lets a reason pinned to a release replace one
  scraped earlier, which is the rule L7.4 needs anyway: a version's reason is about that version.

### L7.2: The map — every control on one screen

The visual centrepiece, and the page somebody would send a colleague.

- `/standards/nist-sp-800-53/map`: twenty family blocks, one cell per control, enhancements nested
  as smaller cells under their parent, all 1,196 on one page. Inline SVG with positions as
  attributes — the pattern `src/pages/atlas.ts` already proves against the strict CSP, so there is
  no script and no inline style to argue with.
- Four lenses, each a plain link (`?by=…`), never a widget: **by change** — how recently and how
  heavily the control moved, on the Atlas's intensity scale; **by baseline** — low, moderate, high,
  privacy; **by status** — active, withdrawn, incorporated into another control; **by what this
  instance can check** — whether a followed STIG rule reaches the control through its CCI, which
  `cciMap()` already computes. That last lens is the one no other reference site can draw, and it
  is the reason this is cybercard.net's page and not a copy of somebody else's.
- Every cell is a link, with a `<title>` carrying the label, the title and the lens's number. The
  Atlas's lesson about a four-pixel mark needing a twelve-pixel target applies here too.
- A legend that states the scale **in words**, and a count per family.
- Below 700px the map is replaced rather than shrunk: the twenty families as a list with their
  counts and their most recently changed controls, which is the pattern the flow strip already set
  on `/learn`.
- **Depends on**: L7.1, for the change lens to say more than "5.2.0". **Thin slice**: the
  by-change lens alone.
- **Done when**: every control in the current release is on one page, every cell reachable by
  keyboard, and each lens's scale stated in words beside its colour.

### L7.3: The twenty families, each taught

Policy and procedures, account management, audit, configuration management — the twenty families
are how practitioners actually hold the catalogue in their heads, and this site has no page for
one.

- `/standards/nist-sp-800-53/family/<code>`: what the family is for in one paragraph in this
  site's own words, its count of controls and enhancements, the full list with each control's
  baseline chips and change state, and the family's own arc — what it gained and lost across the
  loaded releases.
- **The `-1` pattern taught once**: every family's first control is its policy and procedures
  control, and the reason — it is the control that makes the other nineteen auditable — belongs in
  one paragraph on `/learn/chain` that all twenty family pages link, not in twenty paragraphs.
- The enhancement tree drawn as a tree: AC-2 with its enhancements indented beneath it, a withdrawn
  one struck through and followed by what absorbed it. **182 of the 1,196 entries loaded are
  withdrawn** and `extra.incorporatedInto` is parsed on every catalogue load and has never been
  rendered in a list — a seventh of the catalogue is history that the site already holds and has
  never shown.
- A control's `related` list becomes the links it always was, so the catalogue can be read sideways
  as well as down.
- **Depends on**: nothing beyond what is loaded; deeper with L7.1. **Thin slice**: the list, the
  chips and the tree; the family prose can land a family at a time.
- **Done when**: twenty families each have a page that says what the family is for, and no
  withdrawn control appears anywhere without what replaced it.

### L7.4: A control's life, and two sources on every version

- On the control page, above the redline: a life strip, one mark per loaded release from the
  revision the control first appears in to the current one, each mark naming what happened —
  introduced, text changed, parameters changed, related list changed, moved between baselines,
  withdrawn — and linking to that release's redline for that control, which the page already knows
  how to render.
- First appearance stated plainly: "Introduced in Revision 4", "New in Release 5.2.0". And the
  footnote that keeps it honest: NIST's OSCAL begins at Revision 4, so the page says **"held from
  Revision 4 onward"** rather than implying it has looked back to 2005.
- **The rule this milestone adds, and the one the reader asked for by name.** Every version of a
  control the site shows carries three addresses, not one:
  1. **As changed here** — the release, the snapshot's sha256 and the date this instance fetched
     it, linking to the Register's redline. This is the diff, and it is ours.
  2. **As published** — the publisher's own address for *that* version: the CSRC publication page
     for the release and the exact OSCAL file at the pinned commit the bytes came from. A redline
     with no path back to the document it came from is an assertion.
  3. **The whole book as it stands** — the current catalogue's publication page and download, so a
     reader who arrived at one control can leave with SP 800-53 entire.
  Once it ships for 800-53 it becomes a convention in AGENTS.md and applies to every standard the
  Register holds, because the argument for it does not depend on the publisher.
- **Depends on**: L7.1 — a life needs more than two dates. **Thin slice**: the strip across the
  Rev 5 releases, with the three addresses, before Rev 4 lands.
- **Done when**: a control page shows every release this instance holds of that control, each mark
  links to that release's redline, and every version carries both its local provenance and the
  publisher's own address for it.

### L7.5: Why it exists, in NIST's words or not at all

The hardest part, and the one with the most ways to get it wrong.

- A new source: NIST's **analysis of updates** workbook for SP 800-53, published beside the
  catalogue, which explains the Rev 4 → Rev 5 change control by control in NIST's own words. One
  adapter in `src/adapters/`, parsed into control-level `explanations` rows of kind `publisher`
  with the workbook's URL as `source_url`. An `.xlsx` is a zip of XML and both `fflate` and
  `fast-xml-parser` are already dependencies, so this needs no new package: read
  `sharedStrings.xml` and the one sheet.
- Those rows are what the control page and the family page quote under "Why", beside the release's
  Planning Note. Where the workbook says nothing, the page says nothing and says that it says
  nothing: `kind = 'none'` exists in the schema for exactly this, and an unexplained control is a
  fact about NIST's publishing, not a hole to fill.
- **A model may not invent a control's origin.** The standing convention holds — generated text is
  labelled and sits beside the quoted official rationale, never in place of it. A control whose
  creation NIST never explained gets "NIST published no stated reason for this control" and a link
  to the revision's front matter. That is the honest answer, and a teaching site that fabricates
  provenance is worse than one that admits the record is thin.
- Withdrawals cost nothing and close half the question: `status` and `incorporated-into` are
  already normalised, so "withdrawn in Revision 5; incorporated into AC-2(1)" with the link is a
  rendering job, not a sourcing one.
- **Depends on**: L7.1 for the Rev 4 side to mean anything. **Thin slice**: withdrawals and the
  release notes, which need no new source at all; the workbook follows.
- **Done when**: every control page answers "why is this here, and why did it change" with a
  quoted publisher reason, a dated withdrawal, or an explicit statement that no reason was
  published — and never with an unlabelled guess.

### L7.6: The privacy half

Revision 5 is where privacy stopped being an appendix, and a tool that calls itself a security and
privacy reference has to show that rather than mention it.

- The PT family taught as the other nineteen are, plus the thing particular to privacy: the
  **privacy baseline is not a severity tier but a selection across every family**, and it is
  already loaded as `profile:privacy`. `?by=baseline&which=privacy` on the map draws it — the
  controls a privacy programme owns, most of which live outside PT, which is the point and is
  invisible in a list.
- `/learn/privacy`: how Rev 4's Appendix J became Rev 5's PT family and the privacy overlay, who
  publishes at each rung for privacy (NIST, and OMB above it — both already in
  `src/authorities.ts`, so this is a reading of the registry rather than a second list of links),
  and the line the section already draws: this is the control vocabulary, not legal advice about
  any privacy regime.
- **Depends on**: L7.2 for the lens. **Thin slice**: the privacy lens on the map.
- **Done when**: a reader can see every control the privacy baseline selects, in its family, and
  read where that baseline came from.

### L7.7: Beautiful, and still a page

"Visually beautiful" is a requirement of this milestone and not a flourish on it. The constraints
are what make it achievable rather than what stand in its way: no script, no inline style, one
stylesheet, eleven looks, two colour schemes, inline SVG with everything as attributes.

- The map, the family tree and the life strip drawn with the Atlas's restraint: one accent per
  state, type doing most of the work, and the scale always stated in words beside the colour so
  that colour is never the only thing carrying the meaning.
- Contrast checked for every new state in all eleven looks and both schemes — L6's sweep, extended
  rather than repeated.
- A text alternative that carries the picture and not just a label: the map's `aria-label` says
  what it is, and the per-family list beneath it says what it shows. That list is what a screen
  reader gets and what a phone gets, and they are the same list.
- A measured page-weight budget for the map, which becomes the heaviest page in the section,
  recorded beside the others. 1,196 cells of attribute-only SVG is tens of kilobytes rather than
  hundreds, but it is measured rather than assumed.
- **Depends on**: L7.2 to L7.6. **Thin slice**: none. This is the gate.
- **Done when**: every new view passes the section's accessibility sweep in all eleven looks and
  both schemes, the map stays inside a recorded budget, and the phone gets the lesson rather than a
  smaller copy of the picture.

### What L7 is not

- **Not a compliance tool.** It says what a control is, what it said before, and who changed it. It
  does not say whether a system meets it, and the line `/learn` draws stays drawn.
- **Not drawn for every standard.** SP 800-53, 800-53B and 800-171 are public domain and can be
  mapped and quoted whole. CIS and Microsoft content remains the owner's own copy, quoted on screen
  and never redistributed, so there is no CIS map and no CIS family page — the licence note says
  why, where a reader would look for it.
- **Not Revisions 1 to 3.** NIST's OSCAL begins at Revision 4. Parsing the older PDFs would produce
  a worse diff than no diff, and a bad diff on a teaching page teaches something false. Out of
  scope, and said on the page rather than left as an absence.
- **Not a second register.** The change register stays the record of what moved; L7 is a reading of
  it. Nothing here computes a diff of its own.

---

## The order

```
L1 shape ──┬──► L2 glossary ──┬──► L4 searchable ──┐
           │                  │                    ├──► L6 off the screen
           └──► L3 traced ────┘                    │
                                                   │
L5 links alive ── independent, any week ───────────┤
                                                   │
L7.1 history ──► L7.2 map ──┬──► L7.3 families ────┤
                            ├──► L7.4 a life ──────┤
                            ├──► L7.5 why ─────────┤
                            └──► L7.6 privacy ─────┴──► L7.7 beautiful
```

| Milestone | Size | Why it is where it is |
| --- | --- | --- |
| L1 The section has a shape | small | Everything else needs an address to live at. |
| L2 The glossary | medium | The largest gap, and M17's oldest unkept promise. |
| L3 Traced from live data | large | The one thing no book can do; worth the week. |
| L4 Searchable and answerable | small | Cheap once there is something to index. |
| L5 The links stay alive | small | Independent, and the only one that is a loss rather than a gap. |
| L6 Off the screen | medium | A gate on 1.0 through M17's accessibility pass. |
| L7 The catalogue, seen whole | large | The reference tool the mission implies, over data already loaded. |

L5 first if a week is short: it is the only milestone here fixing something that is already
degrading. L3 is the one worth protecting from being cut, because it is the only one a reader could
not get from a textbook.

L7 is the biggest and the most visible, and the two are related: it is the page a visitor would
show somebody else, which no other milestone here produces. Take **L7.1 early whatever else is
running** — the catalogue's history is a backfill, it is cheap, and every other part of L7 is a
claim without it. Take the rest of L7 after L2, so the map and the family pages can link their
terms rather than explain them again. If L7 has to be cut to one week, the cut is L7.5's workbook
and L7.6, not L7.7: an inaccessible map in one look is not a smaller version of this milestone, it
is a different and worse one.

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
