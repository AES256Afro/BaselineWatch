# Changelog

Each version is a tag and an image: `ghcr.io/aes256afro/baselinewatch:<version>`.

## 0.54.0 — 2026-10-26

- **Today is the work, keyed by the fix that ends it.** It used to open on five counts and close
  on two charts: fifteen blocks, eight tiles, most of them reading zero on a quiet morning. A count
  says how much happened and nothing about what to do with it, and a line of news items a day
  answers a question nobody has at seven in the morning. Nobody patches a CVE either — they install
  an update, and one cumulative is one evening's work and nine rows in the table. So the remedy is
  the row now and the CVEs it closes are its contents (`src/fixlist.ts`), in four groups a person
  can act on in order: an update to install, a fix published without a version named, a mitigation
  the publisher asked for, and the honest "nothing published yet". Every figure is printed with the
  comparison that gives it meaning, in words. An install row ends in a verb, so it ends in a button:
  **Mark done** writes every CVE it clears to the same triage board the CVE page uses. And a
  **Cleared** count, because nothing on this page ever used to say that something got better.
- **A commit is not an update you can install.** The first cut of that page counted every NVD
  reference tagged `Patch` as a fix and announced "122 updates close 130 of this window's 150 CVEs".
  Most of those references are git commits and bug-tracker entries: they prove a fix exists
  somewhere, and you cannot install one. They have their own group now, grouped by the host that
  holds them, so thirty kernel commits are one line rather than thirty rows, and only a named
  artefact — a KB, a fixed package version, a vendor's own release — counts as an update.
- **Today asked for the wrong CVEs, twice.** It reported 803 as having moved in a day; two of them
  had. A row in `vuln_changes` with field `new` means *this instance* saw a CVE for the first time,
  which on a backfill is eleven thousand CVEs from earlier years, none of which moved that day —
  and both the fix list and the platform tally read any such row as movement. The window now means
  what it says: published inside it, or something other than its arrival here changed. The second
  half was worse: a CVE earned a row by naming a platform the fleet runs, and the Linux kernel
  publishes hundreds a week whose only reference is a commit, so 117 of the 150 rows drawn were
  kernel entries — which is why the install group read zero while the database held three thousand
  CVEs with Microsoft KB numbers against them. `isNotable` already drew the line this needed, so
  Today asks it too, in SQL that `test/vulns.test.ts` holds to the function row for row. The
  twenty-four hour window went from 803 CVEs to thirteen, and a truncated list says what it is a
  prefix of rather than "more than".
- **Smaller**: `src/charts.ts` and its stylesheet go with the charts they drew, and the half of
  its tests that held the four palettes to defining the same token names — the contract every page
  depends on and none of them states — moves to `test/palettes.test.ts`, now with one fewer
  exception than it had. A bare `.dot` rule that nothing drew was giving the Register ribbon's
  separators an 8px box and a colour that resolved to nothing. `docs/mockups/today.html` keeps the
  five directions this page was chosen from, each with its thesis and what it would have cost.

## 0.53.0 — 2026-10-25

- **The sweeps, closed.** Five security sweeps and five bug sweeps, each on its own ground, then
  three more rounds until one came back empty. Every finding is in `test/audit-2026-10-25.test.ts`
  and `test/restricted-channels.test.ts` so it stays found. The two that mattered most were both
  reachable from a third party: **one control character broke every feed** — `plainText` decoded
  `&#1;` to a character XML 1.0 cannot carry, and a conformant parser rejects the whole document,
  so one bad title from one source broke every subscriber's reader for the entire feed — and **a
  feed could stall the process**, because `/<[^>]+>/g` backtracks at every start position when the
  `>` never comes: 400 KB of `<` took 49 seconds, against 0.7 ms with `[^<>]`, which means the
  same thing for a tag. The same shape was in thirty places.
- **The owner's own words are the owner's.** `/digest` and `/api/v1/digest` are gated for reading,
  not for the owner, and the digest named the devices with something open on them, the
  certificates logged for the owner's domains, their watchlist's products and the LAN's sinkhole
  changes — while the three pages those facts come from each hide them from a visitor. A digest is
  now written in two halves (migration 0044). A triage note, and a baseline decision's reason and
  the name of whoever signed it, were public the same way and are not now; the decision itself,
  which is the teaching value, still is.
- **Twenty-one pages that differ for the owner said nothing about caching**, on an app built to
  sit behind a tunnel or a proxy. They are `private, no-cache` and `Vary: Cookie` now; the feeds
  keep their public cache. The `Secure` flag on the session cookie comes from the owner's
  configuration rather than an `X-Forwarded-Proto` any believed LAN peer could write.
- **Smaller**: the two second hops that take a URL from remote content get `publicOnly`; the
  Pi-hole token no longer follows a redirect; a weekly digest catches up instead of skipping a
  week when the instance was down on the Monday; the calendar folds at 75 octets without splitting
  a code point and escapes a lone CR; the two public routes that cost an outbound request have a
  ceiling as well as a per-address allowance; a download's filename is made header-safe.

- **The Vulnerabilities table opens on what matters.** Ordering twenty-nine thousand CVEs by when
  NVD last touched them put a page of unscored, zero-EPSS, single-vendor records at the top — the
  least useful list the data can produce, on the page a practitioner opens first. The default is
  now **risk**: known exploited, then a public exploit, then EPSS, then CVSS, then recency. The
  table still holds every CVE and the old order is one click away. On a real instance the first
  page went from five unscored Chrome records to five KEV'd criticals with public exploits.
- **Every domain finding now says what to do about it.** The check said what was wrong and quoted
  the record; a reader who learnt their domain publishes no CAA record was left to go and find out
  what one looks like. Each row that is not already good carries the record to publish or the
  header to send, written for the domain that was checked, with the caution that goes with it and
  a link to the RFC. Three rules: nothing is generated that could break something silently (the
  SPF fix is a shape with the senders marked as yours to fill, never a finished record), a setting
  that is not a record says so (DNSSEC and DKIM come from the registrar and the mail provider),
  and every fix cites the body that defines it.
- **The table downloads.** `/vulnerabilities.csv` under the same filters and in the same order, up
  to a thousand rows, with CVSS and EPSS as numbers because something else is going to do
  arithmetic on them. This instance could already export a baseline, a test plan and the triage
  board but not the table its own name is about.
- **Interface**: the News page called itself "a change register for the security standards
  themselves", which is the Register; the EPSS date was a giant display figure beside six counts,
  wrapping onto three lines, and is now on the provenance line with the NVD cursor where it
  belongs; a stat row of seven tiles left five sixths of a row empty on both Today and
  Vulnerabilities, and now fills it; the Register strip hid the fact that it scrolls, so the
  releases past the fold were simply gone — it is a labelled, focusable region with a fade and a
  way out; a Hacker News story with no text of its own printed its score and comment count twice;
  product names broke mid-word in the table ("adaptive_sec" / "urity_applian"); and on a phone the
  masthead's search box took a whole row of its own two rows above the page's own search box, and
  is a link there instead.

## 0.52.0 — 2026-10-25

- **The code audit of 25 October, closed.** A fresh read of the whole surface, then a throwaway
  script that attacked every function that reads input from outside. What it found, in the order
  it matters: a link of the form `/\example.net` passed the "a path on this site" test, and a
  browser reads that the way it reads `//example.net` — `new URL("/\\x", "https://site/")` is
  `https://x/` — so a feed could put a link on the page that looked like one of this instance's
  own and walked the reader off it. Microsoft's `Remediation.URL` went from its JSON into an
  `href` with nothing checking the scheme. Two hundred interpolations draw a link somewhere here,
  and every one of them relied on its author having remembered; now **the `html` template is the
  gate**: a whole `href` or `src` coming from a string the code did not write goes through one
  rule in `src/paths.ts`, and an address that is not one becomes `#`. The rule refuses the
  backslash the way `safeBack` always did, and migration 0043 drops what was already stored.
- **A repeated cookie name now reads as the first, not the last.** A browser sends the host-only
  cookie this app set before any a sibling host set for the shared parent domain, so taking the
  last let a neighbour on the same domain shadow the session, the look or the notice with one of
  its own. (It could never forge a valid signature; it could sign the owner out.)
- **The guard on a host this app may fetch** refuses two more of IANA's special-purpose ranges
  that a network really can carry a host on — protocol assignments (192.0.0.0/24) and
  benchmarking (198.18.0.0/15) — plus Teredo (2001::/32) and the discard-only 100::/64. The three
  documentation ranges are deliberately still public: they route nowhere, so refusing them stops
  nothing, and they are this project's own stand-in for a public address in every test and guide.
- **A notice too long to carry** is cut until it fits whichever field ran long. The shrink only
  ever cut `detail`, so a payload without that field ran the loop to nothing and handed the
  browser a hundred-kilobyte `Set-Cookie` it drops — the notice simply never arrived.
- **A CSV cell is not a formula behind a leading control character or space.** A spreadsheet skips
  those on its way to deciding, and only a leading tab or return was being taken off, so
  `"\u0000=1+1"` from a feed title was written as a formula. The cell keeps every byte it was
  given now; the apostrophe is what makes it text.
- **Smaller things**: a report of five thousand packages read the same advisory row three times
  for each of its findings, once for the link and twice for the note beside it; the scan area read
  and hashed every downloadable script twice at start; `boundary=""` was taken as a boundary of
  two quote characters, and the space a client may put before the parameter was refused; a blob
  hash that is not one reads as nothing instead of throwing out of a route, as `parseJson` already
  does for a JSON column; the CVE search and the News search now share one FTS reader, which two
  copies of could have come to disagree about what counts as syntax.
- **`/mcp` carries its own allowance** — a hundred and twenty calls a minute per address, the
  owner uncounted — because it is the one route an anonymous caller can make the database work
  hard on and it sits ahead of the same-origin guard; and it takes a request the size a tool call
  is (256 KB) rather than the SDK's four megabytes.
- **`/api/v1/vulns` reaches every filter the page has**: severity, platform, a watchlist label,
  having a public exploit, an EPSS band, and the "new" and "changed" windows in hours. It reads
  them through the same validated reader the Vulnerabilities page uses, so the two cannot come to
  disagree about what a filter means, and a loose second copy of that parsing is gone.

## 0.51.0 — 2026-10-23

- **The code audit of 23 October, closed.** A fresh read of the modules the night's security
  read had not covered found four things worth changing: the sign-in brake could be started
  afresh from the LAN by forging `X-Forwarded-For`, since every private address was a believed
  proxy — it now counts the connection's own address too, and the proxies to believe are a
  setting, `BW_TRUSTED_PROXIES`, with the former behaviour as its default; one malformed NVD
  record failed its page on every run and stalled the stream — it is skipped and logged; a
  licensed source's release entry named the settings that moved in the API and the feeds — it
  is withheld there, as that content already is; the LaTeX escaper doubled up on a backslash.
- **Dependencies**: express's body-parser (a denial of service through a compressed body) and
  fast-uri under ajv, both fixed within their declared ranges; the MCP SDK's patch release; the
  test runner moved to vitest 5, whose predecessor's tool chain carried two critical advisories.
  `npm audit` reports nothing at any severity.

## 0.50.0 — 2026-10-22

- **Learn, at `/learn`: where a rule comes from.** The ladder says what a standard, baseline,
  control and setting are; it never said where the rulebook itself came from. A new page draws the
  whole chain — law and contract, policy, framework, control catalogue, baseline, configuration
  setting, check and evidence — as a strip and then as a matrix whose rows are those steps and
  whose columns are who the publisher writes for: US federal civilian, US defense, NASA, private
  business, outside the US. Reading across one row gives the same job as NIST, DISA, CNSS, NASA's
  CSET, CIS, Microsoft, the NSA, the ACSC and the NCSC each answer it, and two filters narrow to
  one audience or one step. Last in the Standards menu, under "Where it all comes from".
- **Thirty-five publishers, each with its own address and what it takes to read it.** Every body
  carries what it derives from, what derives from it, and every address its own words live at,
  marked public, free account, agency sign-in or your own licence. An agency-only link is public
  knowledge of where a document lives and never the document: NASA's ASCS specifications stay
  internal, and nothing restricted is reproduced. Where this instance tracks a body, its card
  shows the version held beside the publisher's own address.
- **The same control, traced three ways.** A device locking after a period of inactivity, carried
  down a federal ladder, a DoD ladder and a private-business ladder. The control barely changes;
  everything above and below it does, and the private chain's empty policy rung is the point.
- **Every standard's page now says where it comes from**: its publisher, the step it sits on, what
  it derives from, what derives from it, and — the question the page was silent about — the other
  bodies answering the same step. The STIG library page now names the GPO and Intune packages,
  Microsoft's baselines, CIS Benchmarks and the NSA's information sheets as the alternatives.
- **A names-that-collide box**, because most of the difficulty in learning this field is that
  several real things share a name: the three CSETs (NASA's standards team, CISA's assessment
  tool, Georgetown's research centre), FISMA against FISA, CSI against CIS, NIST against CSRC
  against NVD, and 800-53 against 53A against 53B.
- The Learning section has a plan of its own, [docs/LEARN.md](docs/LEARN.md), L1 to L6: the
  section's shape, a glossary, traces drawn from loaded data rather than written by hand, a
  searchable and tool-readable chain, a nightly probe over the registry's addresses, and the
  handout and accessibility pass that close M17's last two items.

## 0.49.0 — 2026-10-22

- **Mail from this site is named by this site.** The notifier's SMTP client gave EHLO and its
  Message-ID the container's hostname, which under Docker is the container id; it now gives the
  host of the site's own address, read from the notification's link. After STARTTLS the plain
  socket's reader is detached before the secure one takes over.
- **The InternetDB lookup says what happened in plain words**: "InternetDB answered 503", or "no
  answer from InternetDB", never the URL asked or the error's own text.
- The deploy notes describe the release chain as it is actually run: the catalog pull request's
  checks started by hand, the local tag check before them, the two tools that answer a moved pin,
  and the owner's two clicks.

## 0.48.0 — 2026-10-22

- **Housekeeping knows the night's tables.** The weekly pass (M13) had seven tables it had never
  heard of. Six need no sweep and the Sources page's policy now says why: Microsoft's update rows,
  the exploit indexes, the certificates seen for your domains and the saved searches are kept; the
  Tor exit list and endoflife.date's cycles are swapped whole on each read. A device's readings
  are history, one row per paste, and grew without bound: they go after a year, except each
  device's newest, which the next reading is compared with and which keeps a long-silent machine
  on the list. The pass reports the count.
- **The guide teaches "Is this device affected?"** at `/guide#devices`: what the script reads,
  which source answers each line and by what rule, and what a reading cannot say — "up to date"
  is the sources' last word, not the machine's health. The device page points at it.
- **A security read of the night's additions, closed.** The public domain check's TLS probe
  handshook with whatever address the typed name resolved to — a name pointed at a LAN address
  had this server, on the owner's LAN, read port 443 of that host and quote its certificate. The
  probe now resolves first, answers a private address without a packet, and connects to the
  address it vetted. The InternetDB lookup and the domain check share one rate window keyed by
  the visitor's /64, swept so many addresses cannot grow it. The LAN resolver's address, its
  upstream and a run's error text are the owner's to see; a visitor reads that there is one. The
  router model is matched as letters, not a pattern; a bill of materials is read 32 levels deep.
- **Fixed**: a real Linux device report was refused before it was read — the form limit was
  16 kB and a dpkg list is a hundred — so `/scan/devices` takes two megabytes; the other forms
  keep theirs.
- **A public-only fetch connects to the address that was vetted.** The name was resolved and
  refused if private, then resolved again by the fetch itself; a short-lived name answering
  public once and private the next slipped through (DNS rebinding). The socket now goes where
  the check looked, with the name kept on the wire for the Host header, the SNI and the
  certificate.

## 0.47.0 — 2026-10-22

- **A phone's iOS, judged on its own line.** The browser check's version row reads an iPhone's
  iOS from the user agent and asks Apple's releases about it: a phone kept on 26.x is told
  26.7.1 is newest for it and that 27 exists for devices that support it; the row's verdict is
  the worse of the browser's and the OS's. The device page's wording is plainer, and each
  missing Windows KB links to its Patch Tuesday page.
- **The digest carries the Scan area's open findings**: devices whose last reading left
  something open, the exposure run's findings, and the certificates the transparency logs showed
  for your domains in the window — each absent when there is nothing to say.
- The README says what the site does today, in five short sections.

## 0.46.0 — 2026-10-22

- **Is this device affected?** (`/scan/devices`). No web page can see what a computer runs and
  this site installs nothing, so an inventory script per platform (`bw-inventory.ps1`,
  `bw-inventory.sh`, served with sums beside the check scripts) reads version numbers only — the
  Windows build, the macOS or distribution release, the browsers, the packages — and prints one
  report; the owner pastes it and sees which CVEs apply to those versions: the Windows build
  against the Security Update Guide's fixed build per KB for its own version (the CVEs the
  missing updates fix, and which of them Microsoft says are exploited), browsers and macOS
  against the vendors' newest releases, the version against endoflife.date, and a Linux
  distribution's packages by one batch question to OSV, which compares the installed version
  with each advisory's range by the distribution's own rules. Each reading is kept under the
  device's name as its verdicts and CVE ids, never the report (migration 0042), so the next one
  says what moved; Today counts the devices with something open.
- **This browser's version** is the browser check's eleventh row: the full version through
  client hints on Chromium browsers, against the vendor's newest announced release.
- The Security Update Guide's fixes are now keyed by KB **and** build, since one KB is a
  different build on each Windows version.

## 0.45.0 — 2026-10-21

- **Seven more feeds**, from what the security aggregators carry: CERT/CC Vulnerability Notes
  (vulnerabilities group); the Microsoft Security Blog, the Rapid7 blog, SentinelLABS, GreyNoise,
  the Wiz blog and the Huntress blog (news). Each answers real RSS or Atom and replays its real
  file in a test; the Sources page says which two carry their whole archive on the first read.

## 0.44.0 — 2026-10-21

- **Saved searches.** The owner names a filtered list once — the Vulnerabilities table under a
  filter, a News filter, a search, a Patch Tuesday component — and it waits under the Desk at
  `/saved` and in a box on Today (migration 0040). A saved search is a path on this site with
  its query string and nothing more; the page it names does the work. The list pages show the
  owner a one-line Save box when a filter is on, and say so once the list is kept.

## 0.43.0 — 2026-10-21

- **Mail as a notifier transport.** `BW_NOTIFY_URL` takes
  `mailto://user:pass@host:587/you@example.org` (`mailtos://` for TLS from the first byte,
  `?from=` to set the sender): the digest, KEV additions, watched-CVE changes, standard releases
  and the network and exposure alerts reach an inbox at any ordinary provider without ntfy or a
  webhook. A small SMTP client of the product's own — STARTTLS when offered, AUTH PLAIN when a
  password is given and never without STARTTLS, a failure logged as its step and code, never the
  credentials.
- **Scan history** (`/scan/history`): every network run newest first with the resolver it used,
  canaries sinkholed over total and what moved since the run before; for the owner the last two
  exposure runs side by side. Today gets a **Network check** tile; the Scan menu a History entry.
- **The guide teaches the night's areas**: public exploits and Microsoft's own word, what the
  News is talking about, feeds and the calendar and search, the Scan area and what each check can
  prove, the watchlist and an SBOM.
- Three empty states — the Register, the watchlist, the CVE table — now say what fills them and
  where to start it, in today's words.

## 0.42.0 — 2026-10-21

- **Router and exposure** (Scan 2.0, S4), on the network page, owner-only and opt-in: once a day,
  the public address from Cloudflare's trace, what Shodan's InternetDB last saw of it (ports,
  hostnames, software, CVEs), the router's front page over plain HTTP and TLS (does it redirect;
  its title and Server header, never its contents), and the vendor and model the owner typed
  matched against the CVE table and the KEV. The last two runs are kept; a new open port, a new
  KEV match or a changed address is **one notification**, an unchanged run silence.
- **Certificate transparency** for the owner's domains: crt.sh read once a day for each domain
  listed on the domain check (migration 0039); a certificate issued since the last read is one
  News item — a lookalike's, or one you did not expect — and the domain page lists the newest.
- **endoflife.date** for the releases the fleet runs (migration 0038): the vendor's end beside
  the owner's date on the Fleet page, Windows per edition, with the latest build; a release inside
  ninety days of its end, or past it within the month, is one News item.
- **The API** carries the public exploit rows and Microsoft's update under `fix` on
  `/api/v1/vulns/<id>`, the same rows the Fix panel draws.
- **Fixed**: the usability sweep's header-scope pass had turned every `<thead>` into a
  `<th scope="col"ead>` tag on ten tables (0.41.0); browsers recovered by implying a body row, so
  header cells read as data. Put back, and the accessibility test now insists on a real `thead`.
- The plan closes the night with a ledger of what landed, what was left and why.

## 0.41.0 — 2026-10-21

- **Scan 2.0 — check a domain** (`/scan/domain`). Type a domain and the server reads it the way
  internet.nl, Hardenize and MXToolbox do, by lookups alone: addresses and name servers, the
  DNSSEC flag from Cloudflare's validating resolver, CAA; the mail chain the way a receiver reads
  it — MX and the null MX, SPF with its ending and lookup count, DMARC's policy and reporting,
  DKIM at twelve common selectors or the ones named, MTA-STS and its policy file, TLS-RPT; the
  web side — the front page over HTTPS, whether plain HTTP redirects, HSTS, CSP and the other
  headers, the handshake and certificate, `security.txt`. **Every verdict quotes the record it
  rests on.** Ten-minute cache, a dozen checks per address, nothing stored; the owner can list
  their own domains. **Scan is now a menu**: this browser, a domain, your network, by hand.
- **What this page learned about you**, on the Scan page: the address the request came from and
  what kind it is, whether it is a **Tor exit** (the Tor Project's exit list, a daily source,
  migration 0037), the transport, Global Privacy Control and Do Not Track as sent, the referrer,
  and every header the browser volunteered — computed from the request, kept nowhere. One
  Shodan InternetDB lookup of the visitor's own public address on their say-so: ports, hostnames,
  software, CVEs, a 404 read as the good answer.
- **What this browser gives away**: five rows in the same run of the browser check — GPC and
  DNT; WebRTC candidates gathered with no STUN server (an mDNS name is the good answer, a LAN
  address a warning, a public one a leak); the fingerprint surface, a canvas drawn twice and
  hashed, twelve fonts, screen, time zone, languages and cores, two different hashes read as
  randomised; the Referer as this server received it against the page's policy; the transport.
  `/scan/echo` answers what it received. The why page gains a section per row, with sources.
- **Usability**: a skip link to the one main landmark on every page; a caption and header scopes
  on all eighteen tables; a description and OpenGraph tags on every page, and a canonical
  address on the pages a reader lands on; a test that fails on a missing label, caption, scope,
  alt or text alternative before a page reaches anyone. Checked at phone width.

## 0.40.0 — 2026-10-21

- **"Is there a public exploit?"** — answered on every CVE from three keyless indexes read whole
  once a day: Exploit-DB's CSV, Metasploit's module list, nomi-sec's PoC-in-GitHub (migration
  0035). Nothing from an exploit itself is stored or linked; each line under **Fix** names the
  index entry, whether it is verified (Exploit-DB's flag, a Metasploit rank of good or better)
  or a repository's claim. The table carries an `exploit` chip per row, a **Public exploit**
  figure and filter (`?exploit=1`), and the one-line fix summary leads with the count.
- **Microsoft's Security Update Guide**, through its CVRF API (no key): the monthly documents of
  the last forty days whose revision date moved, one row per CVE (migration 0036) with Microsoft's
  severity and exploit status, CVSS, and the KB per product. The Wire gets **one item per monthly
  release**, Microsoft's own CVEs counted apart from the Chromium and Azure Linux ones it
  republishes; the CVE page's Fix panel shows **Microsoft's update** (KB, products, build,
  restart); the table marks what Microsoft says is exploited. **Patch Tuesday**
  (`/vulnerabilities/microsoft`) lays the month out by update and product, the owner's own Windows
  releases from the fleet first, then CVE by CVE with component filters and search.
- **Apple and Mozilla**, which publish no feeds, read from their pages: Apple's security releases
  table and the MFSA index. Five feeds by row: ZDI published and *upcoming* (what is coming, which
  no other source has), HashiCorp, AWS Security Bulletins, Cisco Talos.
- **Feeds out.** The News and the table as RSS under the same filters their pages take
  (`/feed.xml`, `/vulnerabilities/feed.xml`), every feed source as OPML, CISA's KEV due dates as a
  calendar (`/vulnerabilities/kev.ics`, `?watch=1` for your stack), a sitemap, and a `robots.txt`
  that answers ahead of the reading gate so a closed instance tells a crawler the truth. A
  **Feeds** page writes every address out in full; **Vulnerabilities** is now a menu.
- **What the News is talking about.** The CVE ids the articles name, counted by distinct source
  over seven days: a `news ×3` chip in the table, **In the news** on the CVE page, **Talked
  about** on Today — whatever the score.
- **One search from the masthead** across CVEs, the News, the controls of every standard you may
  read, Microsoft's rows and the sources; a CVE id typed whole opens its page. **One card per
  story** on the News, the other sources named on it. An **SBOM** (CycloneDX or SPDX JSON) into
  the watchlist: each component's package URL becomes the `ecosystem:name` entry the advisories
  match; versions are not kept, nothing else from the file is stored.
- **Sweeps.** Publisher-derived URLs are fetched from public hosts only; a request that is the
  client's fault answers with its own status (413 for a body too large, not a 500); one JSON
  reader; `app.ts` split into route modules by area and the scan guide by platform; every module
  carries the header that says what it is and why; exports pruned to what another module reads.

## 0.39.0 — 2026-10-21

- **The pipeline says when it has stopped.** The digest has named a failing source since 0.38.0,
  but nothing knew *how long* one had been failing: the status column says a source is failing
  now, never since when, so a feed that answers 403 for an hour looked exactly like an API key
  that died on Tuesday — which is how three days of missing CVEs once went unnoticed. A failure
  episode is now a thing this instance keeps (migration 0033): when it began, and whether it has
  been reported. From it, a sixth tile on **Today**, green while every source answers, amber while
  something is failing, red once a failure passes a day or the CVE stream passes 36 hours, saying
  the worst thing true in the fewest words — "NVD CVE API 2.0 has failed for 50 h". And **one
  notification per episode** through the notifier already configured, after a day, never once a
  tick: a feed that recovers by itself is not news, and a source still dead tomorrow has already
  been reported. A source that answers clears both marks, so the next outage speaks again. The
  digest now says how long each failing source has been failing, so it and the tile tell the same
  story.
- **`/metrics`.** The figures a dashboard can scrape, in Prometheus's text format: rows and bytes
  held, seconds since the newest CVE change, how long each failing source has been failing, what
  the weekly housekeeping pass last let go, and the pipeline's own verdict. It is gated like
  `/health`, so an instance closed to readers tells a monitor the running version and nothing
  else. No new queries: the tile, the digest and `/metrics` read the same rows and cannot
  disagree.
- **Is a newer version published?** The Sources page says what this instance runs, and the
  owner's **Check now** asks GitHub once and keeps the answer until the next press. Nothing polls
  for it: this instance makes no outbound call except to its declared sources and the configured
  notifier, and this product's own releases are neither. A check that gets no answer forgets the
  old version rather than showing a stale one, and the Today tile mentions a newer release only
  while nothing worse is true — a stuck source outranks an upgrade.
- **A nightly probe, so a dead source is found before a release ships it.** Once a night, a
  workflow asks every seeded feed whether it still answers XML and every page a test-plan step
  cites whether it still answers at all, and keeps one issue open with the result rather than
  opening one a night. Its first run found three cited pages that had moved: the macOS Security
  Compliance Project's FileVault rule, Microsoft's brokered-authentication guide (now "How to
  enable cross-app SSO on Android using MSAL") and Ubuntu's UEFI Secure Boot page (now in the
  security documentation). Each successor was read before it was written down, because a step
  citing a page that does not say the same thing is worse than one whose citation is known to be
  stale.
- **One source fewer.** `nvd-cve-history` is gone (migration 0034). It was registered on the
  first day and switched off a day later, because this product computes a CVE's history by
  diffing successive sightings of it, which costs no extra request and catches changes that
  endpoint does not report. It has had no adapter for a month, so the Sources page was carrying a
  source that would never run; `docs/SOURCES.md` records the endpoint and why it is unused.

## 0.38.0 — 2026-10-21

- **The menus are built from the ladder, and the ladder is written down.** Four words do most of
  the work in this field and are used loosely nearly everywhere, so `/guide#ladder` now says what
  each means here and links it to the page that shows it: a **standard** is the rulebook (NIST
  SP 800-53, a DISA STIG, a CIS Benchmark), a **baseline** is the set of its rules chosen for a
  kind of system (800-53 High, a platform's STIG baseline, Microsoft's for a Windows release), a
  **control** is one rule in that set (AC-2, IA-2), and a **configuration setting** is how that
  rule is enforced on a device (a registry value, a mobileconfig payload key, an Intune
  definition). The same ladder is drawn twice, as a house and as a federal system, and a closing
  note says where an agency's own layer fits: NASA's OCIO Cybersecurity Standards and Engineering
  Team issues approved configuration specifications from NIST, CIS, DISA and vendor guidance, and
  those are internal, so this site tracks the public quarterly policy reference instead. The
  Standards menu is now those three words in that order, each with the line that says what it is,
  with STIGs, the change register and the Atlas under a rule as the tools that cut across them.
- **Controls** (`/controls`) is a new page: one search across the current version of every
  standard at once — by label (`AC-2`), by title, or by words in the control's text — then each
  standard's controls to open, what changed lately, and where the technical end continues. A
  source whose licence forbids showing its entries is counted and never quoted, as the Register
  already treats it.
- **The Desk holds what is yours.** Your own fleet and work (Fleet, Triage, Watchlist), then the
  instance (Sources, Digest), then how it is drawn (Appearance, Branding). **Platforms is renamed
  Fleet** and served at `/fleet`, with `/platforms` a permanent redirect; the name is what the
  code always called it. The look and colour-scheme switch leaves the masthead for an
  **Appearance** page, which has room to say what each look and scheme is for and to be plain
  that the choice lives in two cookies on that device and nowhere else.
- **Today says what to do, not how much happened.** It opens on a short ordered list: an overdue
  promise first, then a KEV addition that touches your fleet, then one that does not, then a
  watched CVE that got worse, then a standard release with changes. When nothing is urgent — the
  common case — it offers the window's CVEs on the platforms your fleet runs, by the odds of
  exploitation, so a quiet day still says something. Under it, **the window's vulnerabilities
  grouped by the platform they affect**, your fleet's platforms first and marked, each row leading
  to the table filtered the same way. The platform is read from a CVE's CPEs, then its vendor and
  product names, then its description, and is now stored on the CVE (migration 0032, backfilled
  once at start) so the Vulnerabilities table can filter on it; the ones whose platform cannot be
  read are counted apart rather than quietly dropped. Four of the six chart panels gave their room
  to those lists.
- **What this instance keeps, and what it lets go.** Nothing pruned anything before this release,
  and the public instance reached 138 MB in its first five days. One rule decides it now: a
  standard's snapshot is the product — the exact bytes NIST, DISA or Microsoft served are the
  "before" in every diff a year from now — so snapshots of a requirement-set or setting-set
  source, and any snapshot a document points at, are kept for good, while a news or vulnerability
  feed's bytes are a delivery: each document's newest fetch is kept and older ones go after
  fourteen days. Network scans keep 180 days and the alert log 180; no timeline item, CVE,
  requirement, change or explanation is ever deleted. A weekly pass runs last on the scheduler's
  tick, sweeps what is past its window, frees blob files nothing references any more (leaving
  anything written in the last day alone, because a fetch in flight writes its bytes before the
  row that points at them), runs `ANALYZE`, `PRAGMA optimize` and the FTS `optimize`, and rewrites
  the file when a tenth of it is free pages. What is held and what the last pass let go is on the
  Sources page under **What this instance keeps**, in `/health` under `storage`, and as a line in
  the digest; `docs/ADMIN.md` carries the policy and what to do at 1 GB and at 5 GB.
- **A release is one command, and it cannot forget the changelog.** `npm run release <version>`
  bumps `package.json`, the lock and the catalog manifest together and opens the changelog entry
  from the commits since the last tag; `npm run check` and CI then refuse a tree whose newest
  entry is missing, still the draft, or for a different version than everything else carries, and
  a tag run refuses a tag naming a version this tree is not. CI runs `npm run check` whole rather
  than its three parts, so the manifest check runs there too — it never did. After a deploy,
  `npm run release -- --verify https://cybercard.net` asks the address what it is running and
  compares it with what was released. The entries for 0.36.0, 0.36.1 and 0.37.0, which were tagged
  and shipped with none, were written from their commits.
- **A backup nobody has restored is a hope.** `docs/DEPLOY.md` carries the restore rehearsal as
  five steps that touch nothing live — take the newest BoxPilot archive, unpack it, run the copy
  on a spare port with the scheduler off, compare it with the live instance, record what happened
  — and `scripts/health-diff.ts` gives the verdict: a restored copy may be behind by up to a
  tenth, may never be ahead, must carry the same migrations, and an empty table is its own
  finding. `npm run rehearsal -- today "…"` records the date and a note; until one is recorded,
  and again ninety days after the last, the digest asks for one.
- The side rail keeps its 320px and the page steps up at laptop widths, so the News front page no
  longer squeezes its lead story on a 13-inch screen.

## 0.37.0 — 2026-10-20

- **Brand the instance from the Desk.** A page at `/branding` puts any of the marks kept in
  `docs/mockups/logo` on the masthead or in the browser tab with one click, or takes an uploaded
  image. The bytes land in the content-addressed blob store the way article images do and
  `app_settings` carries each image's hash and its served type, so nothing new lands on disk and
  there is no migration. The type is read from the file's own magic numbers and never from the
  upload's declared Content-Type, and an SVG qualifies only as one of the repository's own marks,
  because an SVG can carry a script. The logo and favicon routes sit before the read gate, so a
  closed instance's sign-in page wears the brand too; the masthead's URLs carry the image's hash
  and are cached hard, while the fixed `/favicon.ico` is cached for an hour, or a replacement would
  never reach the tab.
- The container copies only `src`, `public` and `data`, so the Branding page first deployed with an
  empty gallery. `docs/mockups/logo` now ships in the image, re-included through the same
  `.dockerignore` exception pattern `data/test-plans` uses.

## 0.36.1 — 2026-10-20

- **Every catalog row leads to its publisher.** Clicking a document on `/standards` had nowhere to
  go but this site. The NASA reference now keeps each row's own hyperlink from the quarterly Word
  document — NODIS for a directive, CSET or NTSS for a NASA standard, CSRC for a FIPS or SP — and
  the catalog's ids lead there; the per-operating-system and NIST tables gain a Source column
  linking the file each document was read from (the STIG zip, the mSCP commit, the CSRC PDF); a
  control page shows "Published at" when its row carries a link; and the drafts list shows up to a
  hundred, each linked to its CSRC page.

## 0.36.0 — 2026-10-20

- **All the standards in one place.** `/standards` is now the all-standards catalog ("All
  standards" in the Standards menu, in place of the redirect to `/register`): per operating system
  the current, new and draft standards already tracked, the NIST publications with CSRC's drafts
  open for comment, and NASA's cybersecurity document set. Chris's "CSET" is NASA OCIO's
  Cybersecurity Standards and Engineering Team, and its ASCS standards are NASA-internal, so the
  public layer joins the Register instead: the quarterly Cybersecurity Policy Reference on nasa.gov,
  which lists every NASA cybersecurity document with its dates and status notes, is source
  `nasa-cyber-ref` (migration 0031) and each quarterly edition diffs like any standard. The fixture
  replays the real 2026 Q3 document, 271 rows.
- **The digest's links are links.** The Digest page stored its URLs as plain text, so nothing under
  Digest was clickable and an old digest carried localhost addresses; the body's URLs are now
  links, and this instance's own (and localhost's) are written as paths.

## 0.35.0 — 2026-10-20

- **M12.3, the network check.** Once a day, opt-in (`netscan.enabled`; it sends packets on the
  owner's network, so nothing runs until the owner turns it on), the scan finds the LAN resolver,
  resolves canary names drawn from the Register's blocklist sources — resolved only, never
  fetched — asks the resolver to identify its upstream, tests whether DoH answers from the LAN,
  and reads the client count from a Pi-hole or AdGuard Home when the owner saved a token (kept in
  app_settings, never rendered; errors keep a status word, never the message). Results land on
  `/scan/network` and day-over-day movement — a name newly resolving, a resolver change — reaches
  the digest and the alerts.
- **Licence-restricted sources: entries for the owner, counts for everyone else.** A source whose
  licence forbids showing its content to third parties can now run on a public instance. A new
  column, `sources.restricted` (migration 0029), marks it; nothing in the code names a source. On
  the Register a visitor sees a restricted source's versions, how many entries each holds and how
  many came, went or changed, with the names and text withheld and the licence quoted in their
  place (the entry page draws the same thing for every address, so a URL says nothing about what
  is on the list); the signed-in owner sees everything as before. The Wire's release item counts
  the changes and never names them, no generated summary is made of such a release, a triaged
  entry is named on the board for the owner alone, and the JSON API and the MCP tools return
  neither names nor text to anyone: `/api/v1/standards` and `list_standards` flag the source
  `restricted`, `/api/v1/changes` and `standard_changes` leave its changes out, `release` counts
  them, and `requirement` refuses before looking the ref up. The OpenPhish canary set is the first
  such source: it still ships off, but the owner can now turn it on. The Sources page gained the
  switch: Turn on and Turn off beside Fetch now, owner-only, same-origin like every other write,
  and the scheduler picks the change up on its next pass.
- **Scan: do it by hand** (M12.2). A manual guide at `/scan/guide` with one page per platform
  (`/scan/guide/windows`, `macos`, `linux`, `ios`, `android`): each section is one thing the
  Scan area checks (filter DNS for every app, a blocker in the browser, the device's firewall and
  what listens, the router, the network's exposure and DNS bypass, Lockdown Mode and the
  advertising identifier, the past), and each step says what to open or run, what a clean result
  looks like and what a finding means, with a link to the vendor page it follows and to the why
  page's section on it. The router and network sections are the same from every platform.
- **Two scripts that do the computer checks in one go.** `bw-check.ps1` (Windows PowerShell 5.1
  or 7) and `bw-check.sh` (POSIX sh for macOS and Linux) read the resolver and its encryption,
  look up two ad canaries (never fetched), the hosts file, the firewall and what listens, SMB out
  on Windows, the gateway's admin page and its UPnP description and port mappings, whether plain
  DNS and DNS over HTTPS bypass the network's filter, IPv6, the advertising setting, Lockdown Mode
  on a Mac and the DNS-Client log on Windows, and print a report. They upload nothing, change
  nothing and need no administrator rights, and their headers say what they contact. Served as
  plain text at `/scan/scripts/<name>` with the SHA-256 beside every link and a `SHA256SUMS` file
  beside them; `scripts/scan-sums.mjs` rewrites the sums and the check fails when they are stale.
- `/scan/why` gains the router, UPnP, exposure, DNS bypass and device sections with their primary
  documents, and the browser check, the why page and the guides now link each other, with
  breadcrumbs on every Scan page.

- **The lists behind the Scan area are Register sources** (M12.2, the lists half). Seven new
  standards sources read by one adapter, `src/adapters/blocklists.ts`, each list a document whose
  entries are its requirements, diffed line by line, so a list's next release shows on `/register`
  as a diff with a date like any standard. From the Zero Breach project: the AdFection / Candiru
  indicator list (every domain, address and file hash with its tier, confidence and the report it
  was read from) and its DNS and ad blocklist exports; the current commit comes from the GitHub
  API, so an unchanged list costs one small request, and the commit's first line is the release's
  stated reason. Four canary sets of twelve names each, derived from public lists the way their
  Sources notes describe: ad domains from EasyList and tracker domains from EasyPrivacy (the rules
  that block a domain outright, weekly), malware hosts from URLhaus and phishing hosts from OpenPhish
  (registrable names only, daily); the twelve are the names that hash lowest under SHA-256, so
  nobody chose them and the set moves only when the list does. Names on a list are quoted and never
  fetched, linked or loaded; the network check (M12.3) will resolve the canaries and nothing more.
  The OpenPhish set is registered off, because the feed's terms forbid showing any part of it to
  third parties, which a public instance would do. Licences and attributions are on the Sources
  page and in the footer; the fixtures are the real responses of 2026-10-19 and 2026-10-20.

## 0.34.0 — 2026-10-19

- **Decisions beside the recommendation.** Every item of a platform's baseline (a STIG rule, an
  mSCP rule, a Microsoft setting, an SP 800-53 High control) now carries the owner's decision next
  to what the publisher recommends: apply as published, apply modified with the organisation's
  own value, or not applied, each with a reason and an owner. A chip on each builder row opens the
  item's decide page (the recommendation, its controls, payload keys, check and fix on the left,
  the decision on the right, with previous and next to walk the rules); `/baselines/<platform>/decisions`
  lays them out as a board in three columns and downloads every item and its decision as CSV.
  The builder starts from the decisions (an item not applied starts unticked), and the owner can
  record every unticked item as not applying in one go, with one reason. Stored in
  `baseline_decisions` (migration 0026); writes need the owner's sign-in.
- **The test plan tests what is applied.** A rule the owner does not apply leaves the plan and is
  listed as not tested with the reason; a modified rule stays and is tested for the organisation's
  value. A template can name the rules it needs (`requires: [ssh, sshd]`): it joins the plan only
  when an applied rule names one of them, and the plan says why when it does not. New templates:
  Jamf Connect at the login window, the Kerberos SSO extension (macOS, iOS, iPadOS), smart card
  sign-in, SSH hardening and the application firewall on macOS (each requiring its rule), and
  Shared iPad. Every export carries a **Baseline decisions** table: publisher recommends, our
  decision, reason, owner.
- **Eleven report looks.** The Word, PDF, LaTeX and printable exports take a look from a select
  beside the export buttons: Plain (as before) or one of the ten mockups now kept in
  `docs/mockups/exports` (formal assessment, engineering runbook, executive, compact checklist,
  modern, dark console, board, audit workpaper, Markdown-native, Word). A look sets colours,
  typefaces (Times, Helvetica or Courier in the PDF), a cover page and numbered sections; the
  content is the same in all of them, and the plan's link keeps the look chosen.

## 0.33.0 — 2026-10-19

- **Scan: the browser check** (M12.1). A new **Scan** area at `/scan` runs three checks in the
  tab and sees that browser only: ad hiding (twenty bait elements named like ad slots beside two
  neutral controls, read back after two frames), ad requests (test images on paths EasyList's
  request rules match, each between control images with identical bytes, from this instance and
  from a second origin when `BW_PROBE_ORIGIN` names one; anonymous, no referrer, never shown; a
  timeout is unknown, a policy failure is named, a failed image is tried once more), and filtering
  DNS (AdGuard's and NextDNS's own self-checks). Two more rows say what no page can test. Results
  are drawn into the page by one self-hosted script, `/assets/scan.js`, and never uploaded; the
  script runs only when the Run button is pressed. `/scan/why` explains each check with its primary
  sources. `/scan` is the one page served with `script-src 'self'` (plus the probe origin in
  `img-src` and the two self-check hosts in `connect-src`); every other page keeps `script-src
  'none'`, and nothing is ever inline.
- **Support ending, in view.** Today gets a fifth tile counting the releases whose vendor support
  ends within ninety days and naming the nearest; the Platforms page carries the same list as a
  notice and marks each such release's Support cell with an "ends in N days" chip beside the clause
  that ends. The dates are the vendors', read from `supportEnds` in `data/platforms.yaml` against
  the app's clock (`endingSupport` in `src/fleet.ts`).
- **A plan has a URL.** The test plan's export panel links the plan as drawn (release, hardware,
  the areas chosen and whether templates are in), so a plan can be bookmarked or sent and reopened
  the same.
- `npm run check` no longer runs the copies of the suite under `.claude/worktrees`.

## 0.32.0 — 2026-10-19

- **iOS, iPadOS and Android join the baseline builder** (M11.2). DISA's Apple iOS/iPadOS 27 and
  26, Google Android 17 and 16, and Samsung Android 17 and 16 with Knox STIGs are on the default
  followed list; NIST mSCP's `ios_26` branch is followed beside tahoe and sequoia, its rules
  labelled iOS/iPadOS and its `ios_stig` baseline treated as the strict set. The three platforms
  get the builder, the Jamf flavour (Apple) and derived checks in their test plans; Collaboration
  stays templates-only.
- **A test plan starts from its release.** When the chosen release names Register documents in
  `data/platforms.yaml`, the plan's STIG, mSCP branch and Microsoft baseline default to them
  (macOS 26 opens on the Tahoe STIG and `mscp:tahoe`, Windows 25H2 on the v25H2 baseline); the
  selects still let a person choose another.

## 0.31.0 — 2026-10-19

- **NIST's PIV, digital identity and platform security publications join the Register.** Two
  sources read the publications that exist only as PDFs through their CSRC pages: `nist-piv`
  (FIPS 201-3, SP 800-73-5 Parts 1 to 3, 76-2, 78-5, 79-2, 85A-4, 87r2, 96, 116r1, 156, the 157r1
  and 217 drafts, IR 7863, and SP 800-63-4 with 63A, 63B and 63C) and `nist-platform` (FIPS
  140-3, SP 800-147 and 147B, 800-193, 800-124r2, 800-219r1, 800-57 Part 1, IR 8320 A, B and D).
  Each publication is one document whose numbered sections are the requirements, so a revision is
  diffed section by section with the PDF's own change log as the publisher's reason (else the
  page's Planning Note). The page is checked daily and the PDF fetched only when its file or date
  moves; the first load also fetches the revision each one superseded, so the Register opens on the
  real FIPS 201-2 → 201-3 and SP 800-63-3 → 63-4 diffs. Searching the Register for PIV or Secure
  Enclave now finds something.
- A document's own change log is preferred over the listing's note as the release rationale.
- **Platform engineering begins (M11).** A fleet file, `data/platforms.yaml`, names each operating
  system's releases with the vendor's dates and status, the hardware each runs on and the models
  in the vendor's words, seeded with this autumn's releases (macOS 27 Golden Gate on Apple silicon
  only, Windows 11 26H2 and 26H1, iOS and iPadOS 27, Android 17, RHEL 10, Ubuntu 26.04) and the
  earlier ones still in service. A **Platforms** page in the Standards menu lists it all with what
  the Register holds per release and leads to each release's test plan.
- **Test plans know the release and the hardware.** The plan page gains a version and a hardware
  select (hardware a release cannot run is greyed), templates and their steps carry `applies`
  rules, and what does not apply is left out with the reason, on the page and in every export.
  Each step now says what success looks like and what to do when it does not (`expect` and
  `fail`). Three new areas: the hardware root of trust and secure enclave, Platform SSO and
  identity, collaboration and meeting rooms; a checkbox per area chooses what to test this time.
  iOS, iPadOS, Android and Collaboration have template-only plans. Twelve templates join the
  seven of M9, from Apple's, Microsoft's, Google's, Samsung's, Red Hat's and Canonical's documents.
- **LaTeX, Word and PDF exports** of a test plan, beside the checklist, Markdown, CSV and JSON,
  each with the release facts, the branches, the not-tested list, a findings table and a sign-off.

## 0.30.0 — 2026-10-19

- **The CVE backbone no longer leans on NVD alone.** The cvelist-v5 adapter pulls the CVE
  Program's hourly delta releases from GitHub — keyless, rate-limit aware, cursor in
  app_settings, first pull starting at the newest delta and never loading the historic baseline.
  New CVEs are inserted as they are published; rows NVD has enriched are never overwritten, and
  no Wire items are created (notability stays with the NVD path). A three-day NVD outage now
  costs enrichment lag, not coverage.
- **SANS NewsBites is a source.** SANS publishes no feed for it, so the adapter parses the
  newsletter web pages themselves: the index for new issues, each issue page fetched once, one
  item per story with its outbound link.
- **A guide for the reading public.** /guide explains the Register, KEV, EPSS, CVSS and the CAT
  severities in plain words, each term linking to the page that shows it — linked from the
  Standards menu caption and the footer.

## 0.29.0 — 2026-10-19

- **M10 begins: the pipeline tells on itself.** The digest adds a staleness line when the newest
  CVE change is over a day and a half old — the three-day NVD stall would have been a morning
  headline, not an investigation. The digest's "Wire:" line becomes "News:".
- **`npm run check:feeds`** probes every feed-style source's URL (network, so separate from
  `npm run check`) and fails on any that no longer answers with its format, so dead URLs and
  bot-blocked forms are caught before a release ships them.
- **Image attempts are remembered** (`image_checked_at`): a page that yields no og:image is never
  asked again, by ingest or by the backfill; a network failure stays unmarked for the next run.

## 0.28.0 — 2026-10-19

- **`images` backfill command.** Images arrive with new items by design, which left everything
  from before 0.25.0 imageless and let the per-fetch cap trim big first loads. `node src/cli.ts
  images <count|all>` fetches og:image once for existing imageless news articles, newest first,
  politely paced, safe to re-run; documented in ADMIN.md. Feed-supplied media no longer counts
  against the per-fetch cap (each is one image GET the publisher offered), so large first loads
  keep their pictures; the cap still bounds og:image page fetches.

## 0.27.0 — 2026-10-19

- **The three new subreddits work.** 0.19's seeds copied the JSON listing form that Reddit
  refuses to non-browser clients (403, immediately and always); they now point at the Atom feed
  the way the older three have since 0004, a migration clears their error state, and a test holds
  every subreddit to the Atom form. The scheduler also gives reddit.com a 12-second pause between
  requests in a sweep — six subreddits and article-image fetches share one tight
  unauthenticated limit.

## 0.26.0 — 2026-10-19

- **Thirteen more news sources**: The Register (security), Cisco Talos, Unit 42, Securelist,
  WeLiveSecurity, Troy Hunt, Graham Cluley, watchTowr Labs, Security Affairs, The Citizen Lab,
  and the r/AskNetsec, r/Malware and r/ReverseEngineering subreddits — every feed verified
  answering before seeding (Ars Technica's and Sophos's feed URLs answer 404 and stayed out).
- **The Sources page now says what to do when a feed fails.** A known failure draws a hint under
  the raw error: NVD answering 404 means the API key is invalid or expired (with the link to
  request a free one, and the note that the cursor backfills the gap by itself); 403/429 means
  the publisher is rate-limiting and the scheduler retries on its own; a source with no adapter
  says it is planned, not broken. The CIS row and the upload page both point at CIS WorkBench as
  the place to get benchmark PDFs.
- **A readability sweep after the News rename**: user-facing "Wire" wording became "News"
  everywhere, and the Vulnerabilities footer links to Sources when no NVD pull has run.
- **One broken link fixed, none left**: the Register ribbon listed KEV catalog versions whose
  standard page answered 404; the ribbon now carries standards releases only, and
  `/standards/<id>` answers for any source that keeps versions. A crawl of 5,873 internal URLs
  finds no broken links.

## 0.25.0 — 2026-10-19

- **News is the home page.** The Wire, renamed News, answers at `/`; the Register moved to
  `/register` and `/wire` is a 301, so old links keep working. The masthead is grouped the way
  the leading aggregators group theirs: News · Today · Standards ▾ (Register, STIGs, Baselines,
  Atlas) · Vulnerabilities, with the owner's Desk ▾ (Triage, Watchlist, Digest, Sources, sign-in)
  as one cluster on the right — both menus plain `<details>`, no script, the CSP untouched. The
  wordmark drops its "Standards change register" subtitle; the phrase now reads as the News
  page's motto, the Standards menu's caption and the footer line, and an amber **Register
  ribbon** under the masthead on News and Today carries the three latest standards changes into
  their diffs.
- **News articles bring their pictures.** The front page leads with four image cards and the
  list shows thumbnails, BleepingComputer-fashion, with a typographic placeholder where a story
  brought no art. Images arrive passively at ingest: the feed's own media (enclosure,
  media:content, an `<img>` in content:encoded), else the article page's og:image fetched once
  per new item — never on page view, never re-crawled. The bytes are cached in the
  content-addressed blob store and served from `/img/<hash>` (only hashes an item claims;
  snapshots stay private), so `img-src 'self'` stands, readers' addresses never touch third-party
  hosts, and images are small derivatives beside headlines that always link to the source.
  `BW_NEWS_IMAGES=0` turns the whole thing off. New sidebar: the latest KEV entries and the
  owner's desk at a glance.

## 0.24.0 — 2026-10-17

- **The test plan draws one area at a time**, so a phone can use it the way 0.23.0 made the
  builder usable: authentication and SSO, browsers, disk encryption, logging and audit,
  network, updates, MDM enrolment and everything else, each behind a button. A RHEL 9 plan was
  413 KB and 439 checkboxes on one page; its largest area is now about 150 KB, and Windows 11's
  about 110 KB. The form still carries the state and nothing is stored: a hidden field names
  the area on the page and the other areas' dropped ids ride along as hidden fields, so untick
  in one area, open another, rebuild or export, and the whole plan is covered. Each procedure
  stays folded into its row. `?section=<area>` opens an area directly; "Owner's templates" and
  the GET export API (`/baselines/<platform>/tests/export?format=md&drop=...`) are unchanged.

## 0.23.0 — 2026-10-17

- **The baseline builder draws one section at a time**, so a phone can use it: the STIG's rules
  by CAT, "Microsoft's baseline adds", "mSCP adds" and the SP 800-53 High controls, each behind
  a button and each a few hundred kilobytes at most, where the whole Windows 11 profile came to a
  megabyte of HTML on one page. The form still carries the state and nothing is stored: a hidden
  field names the section on the page and the other sections' dropped ids ride along as hidden
  fields, so untick in one section, open another, rebuild or export, and the whole profile is
  covered. The "apply with" lines fold into each row, and "Show check and fix text" folds the
  rule text in on request. `?section=<id>` opens a section directly; the GET export API
  (`/baselines/<platform>/export?format=json&flavour=intune&drop=...`) is unchanged.
- The test-plan templates and the mitigations map (`data/test-plans/`, `data/mitigations.yaml`)
  are in the repository now. `.gitignore` and `.dockerignore` left the whole `data/` folder out,
  so CI failed for 0.21.0 and 0.22.0 and neither image was built: 0.23.0 is the first image with
  test plans, platform watch entries and the Fix panel. The database and snapshots under a local
  `data/` stay ignored.

## 0.22.0 — 2026-10-17

- **Platform watch entries** (M9.5): a watchlist entry of kind Platform names windows, apple,
  linux, android, chrome, firefox, edge or network, and every CVE on that platform is your
  stack: marked on the Vulnerabilities page, on the Wire however small its score, in the alerts
  ("New Apple CVE: CVE-…") and in the digest. A CVE's platform is read from its CPE criteria,
  then NVD's vendor and product, then the way its description names the platform when NVD has
  not analysed it yet, so a new macOS CVE arrives the hour it is published.
- A **Fix** panel on every CVE page, and a fix line on the Wire's CVE and KEV items: the
  remediation already published, quoted and linked. NVD's references tagged Patch, Vendor
  Advisory or Mitigation; the vendor advisories the Wire holds for the CVE; CISA KEV's required
  action and due date; the package advisories' fixed versions; and the STIG rules that mitigate
  the class of flaw, from the owner's `data/mitigations.yaml` (SMBv1, LLMNR, WDigest, NTLMv1,
  AutoPlay, PowerShell 2.0, Office macros, Gatekeeper, System Integrity Protection, Credential
  Guard, Network Level Authentication), each entry citing the publisher's statement. When
  nothing is published the panel says so. The JSON API's CVE record carries the same facts.

## 0.21.0 — 2026-10-17

- **Test plans** (`/baselines/<platform>/tests`, M9.4): what to test when a new OS release lands
  so the baseline still holds. Every check procedure of the profile's STIG and mSCP rules, filed
  by area (authentication and SSO, browsers, disk encryption, logging and audit, network,
  updates, MDM enrolment, everything else), plus the owner's templates kept as YAML in the
  repository (SSO through Intune and through Jamf with each browser, FileVault, BitLocker and
  LUKS key escrow, conditional access, enrolment), each step citing the publisher's document it
  follows and labelled as the owner's. Untick, rebuild, and export the checklist as printable
  HTML, Markdown, CSV or JSON.

## 0.20.0 — 2026-10-17

- **Baselines**, a new area (`/baselines`, M9.3): per platform, the strictest published profile
  as one form. Windows: a STIG's CAT I and CAT II rules (CAT III on request), Microsoft's
  Security Compliance Toolkit settings for the same product joined by registry path, DISA's own
  Intune settings-catalog definitions and checklist verdicts for each rule, and the NIST SP
  800-53 High baseline controls with the rules that implement them. macOS: the STIG joined to
  NIST's macOS Security Compliance Project rules with their configuration-profile payload keys.
  Linux: the STIG with its fix procedures. Untick what you cannot do, rebuild, and export the rest
  as printable HTML, Markdown, CSV or JSON in a plain, Jamf, Intune or Linux flavour; a GET with
  the same fields is an API. "Current versus next" says what the strict set gains and loses in
  the next loaded version of the STIG, the Microsoft baseline or the macOS branch.
- Three sources: NIST's **macOS Security Compliance Project** (one branch per macOS release,
  fetched at its exact commit, every rule with check, fix, payloads, severity and its 800-53,
  800-171, CCI, STIG and CIS references, plus which baselines list it); DISA's **Intune policy
  package** (the settings-catalog policies DISA ships for its STIGs, one row per setting); and
  the **checklists in DISA's GPO package** (DISA's verdict, rule by rule, on what its GPO and
  Intune policies set).
- The `yaml` package moves from a development dependency to a runtime one for the mSCP rules.

## 0.19.0 — 2026-10-17

- **STIGs**, a new area (`/stigs`, M9.2): the STIGs the Register follows by platform (Windows,
  Linux, macOS, mobile, browsers, network devices, virtualisation, applications), and one page
  per platform showing a STIG's rules grouped CAT I, II, III with the check and fix text folded
  away, the NIST SP 800-53 controls each rule maps to, what changed in the latest release with
  DISA's notes, and CISA's advice for the platform: the KEV entries whose vendor and product
  belong to it and the directives whose titles name it.
- DISA's **Control Correlation Identifier list** as a source: each CCI's definition and its
  index into SP 800-53 Revision 5 (or 4). It is the join between STIG rules and controls, in both
  directions: a rule's page in the Register names the controls it implements, and a control's
  page lists the followed rules that implement it. Found through the STIG library listing, so an
  unchanged list costs one small request a week.
- **CISA directives** as a source: Binding Operational and Emergency Directives read from
  CISA's listing (it has no feed), on the Wire under News, tagged with the platforms they name,
  with an alert when a new one appears.
- The DISA source's default followed set grows to Windows 11, Windows Server 2025 and 2022, Red
  Hat Enterprise Linux 9 and 10, Ubuntu 24.04 and 22.04, Apple macOS 26 and 15, Microsoft Edge,
  Google Chrome, Mozilla Firefox, Cisco IOS XE Router and Application Security and Development.
  Watchlist entries of kind Baseline still replace the defaults.
- `docs/PLAN.md` gains M9, Baselines, and `docs/COMPETITION.md` surveys what comparable tools do
  and what BaselineWatch borrows or leaves alone.

## 0.17.0 — 2026-10-15

- A second look, **Console**: the dense dashboard of a security console, with panels, uppercase
  mono titles, large thin figures, hexagon severity marks and charts drawn on the server, in light
  and dark. The Register's paper look stays as **Paper**. A switch in the masthead chooses the look
  and the colours (auto, light, dark) per browser with two cookies and no script; `BW_LOOK` and
  `BW_SCHEME` set the instance's defaults, and the BoxPilot manifest exposes both.
- Today gets six glance panels under its tiles: KEV additions by vendor over 30 days, Wire items
  a day over 14 days, watched CVEs that changed by CVSS severity, every CVE by EPSS band, triage
  by state, and each source's last fetch. Every chart is inline SVG with its figures in words.

## 0.16.1 — 2026-10-15

- At start, every standard's versions are put in publication order before anything is served:
  a chain an older version linked wrong is re-diffed once, and a correct one costs a query.

## 0.16.0 — 2026-10-15

- A standard's first scheduled fetch loads its published history before the current file, so a
  fresh install opens on the real NIST SP 800-53 5.1.1 to 5.2.0 diff within minutes with no
  backfill command. A back catalogue raises no alerts. `npm run backfill` remains for doing it now.
- The admin guide says what the OSV and GitHub fetches send out and how /mcp is gated; the
  BoxPilot manifest describes the current product and first run.

## 0.15.0 — 2026-10-15

- More advisories on the Wire: CISA's ICS advisories, Google Chrome stable releases, GitLab
  security releases and Jenkins security advisories, filed with the vendor advisories; and the
  Google Security Blog among the news.
- DEPLOY.md: how to roll without sudo once /opt/baselinewatch is the docker user's, and what to
  load after a version that adds a standard.

## 0.14.0 — 2026-10-15

- NIST SP 800-171 Revision 3 in the Register, from NIST's OSCAL: the CUI requirements that make up
  CMMC Level 2, numbered as the publication numbers them (03.01.01), grouped by family, with
  statement items lettered, organization-defined parameters, assessment objectives and the
  requirements withdrawn from Revision 2 kept as withdrawn. Tracking starts at OSCAL 1.1.0; the
  Sources page says why there is no backfill.

## 0.13.0 — 2026-10-15

- A read-only MCP server at `/mcp` (Streamable HTTP, stateless) for BoxPilot's agents, Claude Code
  and scripts: `list_standards`, `release`, `requirement`, `standard_changes`, `search_wire`,
  `vulnerabilities`, `vulnerability`, `triage` and `digest`, every tool marked read-only and
  answered from the instance's own database with links back. Same read gating as the pages and
  the JSON API; nothing on it writes, uploads or fetches.

## 0.12.0 — 2026-10-15

- Package advisories from OSV.dev and the GitHub Advisory Database. Add a package to the watchlist
  (kind "package", value ecosystem:name such as npm:express, PyPI:django,
  Maven:group:artifact or Debian:12:openssl) and the daily pull queries OSV for it. An advisory
  lands on its CVE when NVD has it, adding the affected packages, fixed versions and advisory ids
  and marking your watch; a GHSA or distribution entry NVD has not analysed gets a row of its own.
  Severity is scored here from the CVSS 3.x vector. Only advisories published in the last thirty
  days, or changed since last seen, reach the Wire; the back catalogue stays in the table.
- The CVE page shows affected packages with their fixed versions, the advisory ids, and links to
  the GitHub advisory and OSV; the Vulnerabilities table names the package when NVD names no vendor.

## 0.11.0 — 2026-10-15

- FedRAMP's Consolidated Rules for 2026 in the Register: the FRR rules by family and subset, the
  Key Security Indicators, the definitions and the parameter values and guidance FedRAMP sets on
  NIST SP 800-53 controls, read from FedRAMP's own JSON on GitHub and diffed entry by entry. Each
  entry's dated change note sits beside the changes it explains, and the notes dated on the
  release day are the release's reason. The backfill loads four earlier versions from July 2026.
  It takes the place of the Rev5 OSCAL baselines, whose repository is gone.
- Tag builds sign the image (Sigstore, keyless), attach an SPDX SBOM and record build provenance;
  the admin guide shows how to verify them.

## 0.10.2 — 2026-10-15

- A standard's versions are linked by publication date, whatever order they arrive in. A backfill
  run after the scheduler had already fetched the current release used to hang the history off
  that release, so the Register showed 5.1.1 as a reverse diff and 5.2.0 as "no control-level
  changes"; now the older version slots in before it and the current one is re-diffed against it.
- `npm run relink -- <source|all>` repairs a chain linked that way, re-diffing only what was wrong.
- A history entry whose bytes are already loaded still lends the release its publisher's reason.

## 0.10.1 — 2026-10-15

- Links that leave the site (articles, advisories, NVD and CVE records, publishers' rationale,
  the sources list, the footer's source link) open in a new tab; links within the site do not.

## 0.10.0 — 2026-10-15

- Vendor security advisories on the Wire, apart from news: Ubuntu, Debian, Cisco, Palo Alto
  Networks, Fortinet and Red Hat, with the CVE ids they name as signals. The Wire gains filters
  by group (news, vendor advisories) and for releases.
- A changelog.

## 0.9.1 — 2026-10-15

- Every loaded version of a standard can be read whole: a browsable, searchable list of its
  requirements by family, with the ones that changed in that release marked.

## 0.9.0 — 2026-10-15

- CIS Benchmarks by owner upload: the PDF is read, recommendations are parsed from their
  numbered headings and labelled sections, and the next upload of the same benchmark is diffed
  against the last.
- The read-only JSON API under `/api/v1/` (items, vulns, standards, changes, triage, digest).
- The Register's typefaces served from their packages, so nothing loads from Google.
- HSTS behind TLS; `docs/ADMIN.md`.

## 0.8.0 — 2026-10-15

- Today: since you last looked, phone-first (the Console direction).
- Atlas: a release timeline per standard, the SP 800-53 change-intensity map by control family,
  change velocity and what is expected next (the Atlas direction).

## 0.7.0 — 2026-10-15

- Triage on any item, CVE or requirement in a release, with notes, due dates, a board with an
  inbox, and CSV export (the Board direction).
- Alerts through ntfy, Gotify or a webhook for KEV additions, watched CVE changes and standard
  releases, never on a source's first load; every attempt logged.
- A daily or weekly digest at a local hour, sent the same way and kept on its own page.

## 0.6.0 — 2026-10-15

- The publisher's reason beside every change: NIST's Planning Note from the publication page,
  DISA's Revision History read from the PDF and attached rule by rule, Microsoft's announcement
  from the zip; a release with no captured reason says so.
- Optional Ollama summaries per release, stored as generated and badged on every page.

## 0.5.0 — 2026-10-15

- DISA STIGs: the library read through the site's own listing call, the STIGs on the watchlist
  (or six defaults) downloaded and diffed rule by rule from their XCCDF.
- Microsoft Security Baselines: every toolkit zip diffed setting by setting from its
  `.PolicyRules` file, older UTF-16 toolkits included.

## 0.4.0 — 2026-10-15

- The Register: NIST SP 800-53 and its 800-53B baselines from the OSCAL catalogs, every release
  kept as a snapshot and diffed field by field with a word-level redline; `npm run backfill`
  loads Release 5.1.1 to 5.2.0 from NIST's published history.

## 0.3.0 — 2026-10-15

- Vulnerabilities: every CVE NVD modifies, with the best CVSS, SSVC, CWEs, CPEs, references,
  CISA KEV and FIRST EPSS, a field-level change history per CVE, and the watchlist.
- Only notable CVEs reach the Wire.

## 0.2.0 — 2026-10-14

- The Wire: news feeds, Reddit, Hacker News, CISA advisories and the KEV catalog in one
  searchable timeline, with read and star state for the owner.
- The owner session, the scheduler and the `fetch` command.

## 0.1.0 — 2026-10-14

- The scaffold: Node 24 running TypeScript directly, Express 5, SQLite with migrations, the
  source register, the container, CI, and the BoxPilot catalog manifest.
