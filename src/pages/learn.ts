import type { DatabaseSync } from "node:sqlite";
import {
  accessLabels,
  ancestors,
  authorities,
  authorityById,
  authorityForSource,
  chains,
  collisions,
  feedsInto,
  isRung,
  isSector,
  onRung,
  peers,
  rungs,
  sectors,
  type Access,
  type Authority,
  type Rung,
  type Sector,
} from "../authorities.ts";
import { html, newTab, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import type { SourceLink } from "../sourcelinks.ts";
import { relativeTime } from "../time.ts";
import { page } from "./layout.ts";

/**
 * Learn, at /learn: where every rule on this site comes from. The guide teaches the four words;
 * this page teaches the chain behind them — a law obliges a policy, a policy directs a framework, a
 * framework structures a catalogue, a catalogue is cut to a baseline, a baseline becomes a setting,
 * and a check proves it — then shows every publisher on that chain with the address its own words
 * live at, what it takes to read them, and which version this instance is holding. The sector and
 * rung filters are the "option of checking which": the same rung, as NIST, DISA, NASA, CIS and the
 * ACSC each answer it.
 */

interface Who {
  owner: boolean;
  open: boolean;
  look: LookState;
}

export interface LearnOptions extends Who {
  db: DatabaseSync;
  now?: Date;
  /** ?sector= narrows every table and card to one audience. */
  sector?: string | undefined;
  /** ?rung= narrows the directory to one step of the chain. */
  rung?: string | undefined;
}

/** What this instance is holding for a tracked body: its newest version, and how many it has seen. */
interface Held {
  documentId: number | null;
  versionLabel: string | null;
  publishedAt: string | null;
  parsedAt: string | null;
  versions: number;
  sourceName: string;
}

function heldBySource(db: DatabaseSync): Map<string, Held> {
  const rows = db
    .prepare(
      `SELECT s.id AS sourceId, s.name AS sourceName,
              (SELECT COUNT(*) FROM documents x WHERE x.source_id = s.id) AS versions,
              d.id AS documentId, d.version_label AS versionLabel, d.published_at AS publishedAt, d.parsed_at AS parsedAt
       FROM sources s
       LEFT JOIN documents d ON d.id = (SELECT MAX(y.id) FROM documents y WHERE y.source_id = s.id)
       ORDER BY s.id`,
    )
    .all() as unknown as ({ sourceId: string } & Held)[];
  return new Map(rows.map((r) => [r.sourceId, r]));
}

const accessChip = (access: Access): Html =>
  html`<span class="chip acc-${access}" title="${accessLabels[access].line}">${accessLabels[access].label}</span>`;

const sectorChips = (list: Sector[]): Html =>
  html`${list.map((id) => html`<a class="chip sect" href="/learn?sector=${id}">${sectors.find((s) => s.id === id)?.label ?? id}</a>`)}`;

const bodyLink = (id: string): Html => {
  const a = authorityById(id);
  return a ? html`<a href="#body-${a.id}">${a.name}</a>` : html`${id}`;
};

/** The chain in one picture: seven stages, left to right, each the step a rule passes through. */
function flowDiagram(sector: Sector | undefined): Html {
  const boxW = 122;
  const gap = 20;
  const height = 104;
  const width = rungs.length * boxW + (rungs.length - 1) * gap;
  const words = rungs.map((r) => r.label).join(" → ");
  const boxes = rungs.map((r, i) => {
    const x = i * (boxW + gap);
    // Two lines of label inside the box, because "Control catalogue" does not fit on one.
    const parts = r.label.split(" ");
    const first = parts.length > 1 ? parts.slice(0, -1).join(" ") : r.label;
    const second = parts.length > 1 ? parts[parts.length - 1]! : "";
    const arrow =
      i < rungs.length - 1
        ? html`<path class="flow-arrow" d="M ${x + boxW + 4} 48 L ${x + boxW + gap - 6} 48 M ${x + boxW + gap - 11} 44 L ${x + boxW + gap - 6} 48 L ${x + boxW + gap - 11} 52"></path>`
        : html``;
    return html`<g>
      <rect class="flow-box r-${r.id}" x="${x}" y="22" width="${boxW}" height="52" rx="7"></rect>
      <text class="flow-n" x="${x + 10}" y="16">${i + 1}</text>
      <text class="flow-t" x="${x + boxW / 2}" y="${second ? 44 : 52}">${first}</text>
      ${second ? html`<text class="flow-t" x="${x + boxW / 2}" y="60">${second}</text>` : ""}
      <text class="flow-c" x="${x + boxW / 2}" y="94">${countOn(r.id, sector)}</text>
      ${arrow}
    </g>`;
  });
  return html`<svg class="flow" viewBox="0 0 ${width} ${height}" role="img" aria-label="The chain a rule travels down: ${words}">${boxes}</svg>`;
}

function countOn(rung: Rung, sector: Sector | undefined): string {
  const n = onRung(rung, sector).length;
  return `${n} ${n === 1 ? "publisher" : "publishers"}`;
}

/** Rows are the rungs, columns the audiences: the same job, as each body answers it. */
function matrix(sector: Sector | undefined): Html {
  const columns = sector ? sectors.filter((s) => s.id === sector) : sectors;
  return html`<div class="table-wrap"><table class="matrix"><caption class="visually-hidden">Which body publishes at each step of the chain, by who it writes for</caption>
    <thead><tr><th scope="col">Step</th>${columns.map((s) => html`<th scope="col"><a href="/learn?sector=${s.id}">${s.label}</a><small>${s.line}</small></th>`)}</tr></thead>
    <tbody>${rungs.map(
      (r) => html`<tr>
        <th scope="row"><a href="/learn?rung=${r.id}">${r.label}</a><small>${r.line}</small></th>
        ${columns.map((s) => {
          const here = onRung(r.id, s.id);
          return html`<td>${here.length === 0 ? html`<span class="small mute-t">—</span>` : html`<span class="chips">${here.map((a) => html`<a class="chip" href="#body-${a.id}">${a.name}</a>`)}</span>`}</td>`;
        })}
      </tr>`,
    )}</tbody>
  </table></div>`;
}

/** One traced chain: the same control, carried down one kind of system's ladder. */
function chainBlock(chain: (typeof chains)[number]): Html {
  return html`<section class="box trace" id="trace-${chain.id}">
    <h3><a href="#trace-${chain.id}">${chain.title}</a></h3>
    <p class="small">${chain.line}</p>
    <ol class="ladder">${chain.steps.map((step) => {
      const rung = rungs.find((r) => r.id === step.rung)!;
      const a = step.authority ? authorityById(step.authority) : undefined;
      return html`<li>
        <b>${rung.label}</b> <span class="rung">${a ? bodyLink(a.id) : "nobody"}</span>
        <p>${step.says}</p>
      </li>`;
    })}</ol>
  </section>`;
}

/** One body's card: what it is, who it rests on, who rests on it, and where to read it. */
function bodyCard(a: Authority, held: Map<string, Held>, now: Date): Html {
  const up = a.derivesFrom;
  const down = feedsInto(a.id);
  const sources = a.links.filter((l) => (l.kind ?? "source") === "source");
  const crosswalks = a.links.filter((l) => l.kind === "crosswalk");
  const mine = a.tracked ? held.get(a.tracked) : undefined;
  const far = ancestors(a.id).filter((p) => !up.includes(p.id));
  return html`<section class="box body" id="body-${a.id}">
    <div class="body-head">
      <h3><a href="#body-${a.id}">${a.name}</a></h3>
      <span class="chips"><a class="chip rung-chip" href="/learn?rung=${a.rung}">${rungs.find((r) => r.id === a.rung)?.label}</a>${sectorChips(a.sectors)}</span>
    </div>
    <p class="body-pub">${a.publisher}</p>
    <p>${a.what}</p>
    <p class="small why">${a.because}</p>
    <dl class="derive">
      <dt>Derives from</dt>
      <dd>${up.length === 0 ? html`<span class="mute-t">nothing on this page — it is a root</span>` : html`${up.map((id, i) => html`${i > 0 ? ", " : ""}${bodyLink(id)}`)}`}${far.length > 0 ? html` <span class="small mute-t">(and further up: ${far.map((p, i) => html`${i > 0 ? ", " : ""}${bodyLink(p.id)}`)})</span>` : ""}</dd>
      <dt>Feeds into</dt>
      <dd>${down.length === 0 ? html`<span class="mute-t">nothing here derives from it yet</span>` : html`${down.map((p, i) => html`${i > 0 ? ", " : ""}${bodyLink(p.id)}`)}`}</dd>
      <dt>Read it at</dt>
      <dd><ul class="plain srcs">${sources.map(
        (l) => html`<li><a href="${l.href}" ${newTab}>${l.label}</a> ${accessChip(l.access)}${l.note ? html` <span class="small mute-t">${l.note}</span>` : ""}</li>`,
      )}</ul></dd>
      ${crosswalks.length > 0
        ? html`<dt>Mapped to others</dt>
          <dd><ul class="plain srcs">${crosswalks.map(
            (l) => html`<li><a href="${l.href}" ${newTab}>${l.label}</a> ${accessChip(l.access)}${l.note ? html` <span class="small mute-t">${l.note}</span>` : ""}</li>`,
          )}</ul></dd>`
        : ""}
      ${a.tracked
        ? html`<dt>On this instance</dt>
          <dd>${mine && mine.documentId !== null
            ? html`<a href="/standards/${a.tracked}/${mine.documentId}"><b>${mine.versionLabel ?? "the loaded version"}</b></a> · ${mine.versions} version${mine.versions === 1 ? "" : "s"} held · <a href="/standards/${a.tracked}">every version and what changed</a>${mine.parsedAt ? html` <span class="when">loaded ${relativeTime(mine.parsedAt, now)}</span>` : ""}`
            : html`<a href="/standards/${a.tracked}">tracked as a source</a>, <span class="mute-t">nothing loaded yet</span>`}</dd>`
        : ""}
    </dl>
  </section>`;
}

/**
 * The addresses a control's own page ends at, drawn the way the authority box draws a publisher's
 * links: the rule at the publisher, the document it was read from, then the body that wrote it.
 * Every page that shows a rule carries this, so no rule is a dead end; an empty list draws a line
 * saying so rather than nothing, since silence reads as an oversight.
 */
export function sourceBox(links: SourceLink[], options: { heading?: string; lede?: string } = {}): Html {
  const heading = options.heading ?? "Read it at the publisher";
  return html`<section class="box authority" id="at-publisher">
    <div class="std-head"><b>${heading}</b><span class="small">${links.length} address${links.length === 1 ? "" : "es"}</span></div>
    ${options.lede ? html`<p class="small">${options.lede}</p>` : ""}
    ${links.length
      ? html`<ul class="plain srcs">${links.map(
          (l) => html`<li><a href="${l.href}" ${newTab}>${l.label}</a> ${accessChip(l.access)}${l.note ? html` <span class="small mute-t">${l.note}</span>` : ""}</li>`,
        )}</ul>`
      : html`<p class="small">This publisher gives no public address for its text; what is on this page was read from the copy named above it.</p>`}
  </section>`;
}

/**
 * The block a standard's own page carries: who published it, which step of the chain it is, what it
 * rests on, what rests on it, and — the question the page is otherwise silent about — who else
 * answers the same step. A source this registry does not know draws nothing.
 */
export function authorityBox(sourceId: string): Html {
  const a = authorityForSource(sourceId);
  if (!a) return html``;
  const rung = rungs.find((r) => r.id === a.rung)!;
  const up = a.derivesFrom.map((id) => authorityById(id)).filter((p): p is Authority => p !== undefined);
  const down = feedsInto(a.id);
  const others = peers(a.id);
  const link = (p: Authority): Html => html`<a href="/learn?rung=${p.rung}#body-${p.id}">${p.name}</a>`;
  const joined = (list: Authority[]): Html => html`${list.map((p, i) => html`${i > 0 ? ", " : ""}${link(p)}`)}`;
  return html`<section class="box authority">
    <div class="std-head"><b><a href="/learn#body-${a.id}">Where this comes from</a></b><span class="small"><a href="/learn?rung=${a.rung}">${rung.label}</a> · ${a.sectors.map((id, i) => html`${i > 0 ? ", " : ""}${sectors.find((s) => s.id === id)?.label ?? id}`)}</span></div>
    <p class="small">Published by <b>${a.publisher}</b>. ${a.what}</p>
    <dl class="derive">
      ${up.length > 0 ? html`<dt>Derives from</dt><dd>${joined(up)}</dd>` : ""}
      ${down.length > 0 ? html`<dt>Feeds into</dt><dd>${joined(down)}</dd>` : ""}
      <dt>At the publisher</dt>
      <dd><ul class="plain srcs">${a.links.map(
        (l) => html`<li><a href="${l.href}" ${newTab}>${l.label}</a> ${accessChip(l.access)}${l.note ? html` <span class="small mute-t">${l.note}</span>` : ""}</li>`,
      )}</ul></dd>
      ${others.length > 0
        ? html`<dt>The same step, another body</dt>
          <dd>${joined(others)} <span class="small mute-t">— the other answers to the same job, on <a href="/learn">Learn</a></span></dd>`
        : ""}
    </dl>
  </section>`;
}

export function renderLearn(options: LearnOptions): string {
  const { db, owner, open, look } = options;
  const now = options.now ?? new Date();
  const sector = options.sector && isSector(options.sector) ? options.sector : undefined;
  const rung = options.rung && isRung(options.rung) ? options.rung : undefined;
  const held = heldBySource(db);

  const shown = authorities.filter((a) => (sector === undefined || a.sectors.includes(sector)) && (rung === undefined || a.rung === rung));
  const sectorName = sector ? sectors.find((s) => s.id === sector)!.label : null;
  const rungName = rung ? rungs.find((r) => r.id === rung)!.label : null;
  const filtered = sector !== undefined || rung !== undefined;

  const filters = html`<nav class="filters learn-filters" aria-label="Narrow by audience or step">
    <span class="cap">Written for</span>
    <a${sector === undefined ? html` class="on"` : ""} href="/learn${rung ? `?rung=${rung}` : ""}">Everyone</a>${sectors.map(
      (s) => html`<a${sector === s.id ? html` class="on"` : ""} href="/learn?sector=${s.id}${rung ? `&rung=${rung}` : ""}">${s.label}</a>`,
    )}
    <span class="cap">Step</span>
    <a${rung === undefined ? html` class="on"` : ""} href="/learn${sector ? `?sector=${sector}` : ""}">Every step</a>${rungs.map(
      (r) => html`<a${rung === r.id ? html` class="on"` : ""} href="/learn?rung=${r.id}${sector ? `&sector=${sector}` : ""}">${r.label}</a>`,
    )}
  </nav>`;

  const directory = rungs
    .filter((r) => rung === undefined || r.id === rung)
    .map((r) => {
      const here = shown.filter((a) => a.rung === r.id);
      if (here.length === 0) return html``;
      return html`<section class="rung-band" id="rung-${r.id}">
        <div class="std-head"><b><a href="#rung-${r.id}">${r.label}</a></b><span class="small">${r.line}</span></div>
        <div class="bodies">${here.map((a) => bodyCard(a, held, now))}</div>
      </section>`;
    });

  const content = html`
    <h1>Learn: where a rule comes from</h1>
    <p class="lede">
      The <a href="/guide#ladder">ladder</a> gives you the four words — standard, baseline, control,
      setting. This page answers the next question: who wrote the rulebook, and under whose
      authority. Every control on this site arrived by the same route. A law obliges somebody to act;
      a policy says what acting looks like; a framework structures the work; a catalogue holds the
      controls; a baseline picks the ones your kind of system gets; a setting is how one of them is
      enforced on a real device; and a check proves it was. Each step below names its publishers,
      with the address their own words live at and what it takes to read them.
    </p>

    <section class="box wide" id="chain">
      <h2><a href="#chain">The chain, in one picture</a></h2>
      ${flowDiagram(sector)}
      <ol class="rung-list">${rungs.map(
        (r) => html`<li><b><a href="/learn?rung=${r.id}">${r.label}</a></b> <span class="rung">${r.line}</span></li>`,
      )}</ol>
      <p class="small">
        Nothing is obliged to use the whole chain. A private business usually joins at the framework
        or the setting and has no policy rung at all; a DoD system has every rung and a second
        committee besides. That is what "normalised" means in practice, and the three traces below
        walk it.
      </p>
    </section>

    ${filters}

    <section id="who">
      <h2><a href="#who">Who publishes what, and for whom</a></h2>
      <p class="small">
        The rows are the steps of the chain; the columns are who the publisher writes for. Reading
        across one row answers the question this page exists for: the same job, as NIST, DISA, NASA,
        CIS and the ACSC each answer it. ${sectorName ? html`Showing <b>${sectorName}</b> alone.` : ""}
      </p>
      ${matrix(sector)}
    </section>

    <section id="traced">
      <h2><a href="#traced">The same control, traced three ways</a></h2>
      <p class="small">
        One control — a device that locks itself after a period of inactivity — carried down three
        different ladders. The control barely changes. Everything above and below it does.
      </p>
      <div class="traces">${chains.filter((c) => sector === undefined || c.sector === sector).map((c) => chainBlock(c))}</div>
      ${sector !== undefined && chains.every((c) => c.sector !== sector)
        ? html`<p class="small mute-t">No trace written for ${sectorName} yet; <a href="/learn">all three</a> are above.</p>`
        : ""}
    </section>

    <section class="box wide" id="normalised">
      <h2><a href="#normalised">How they are normalised</a></h2>
      <p>
        Four mechanisms do nearly all the work of turning one body's rules into another's, and each
        one is public.
      </p>
      <ul class="normal">
        <li>
          <b>${bodyLink("disa-cci")}</b> — DISA breaks each ${bodyLink("sp-800-53")} control statement
          into single testable assertions and numbers them. A STIG rule cites the CCI, the CCI names
          the control, and a pile of findings about registry values becomes an answer about controls.
          This is the one joint that makes a DoD scan report legible to a civilian assessor.
        </li>
        <li>
          <b>${bodyLink("oscal")}</b> — a catalogue, a profile and a baseline as data rather than
          prose. A baseline becomes a document that says "this catalogue, these controls, these
          parameters", which a program resolves. It is how this instance reads 800-53 and 800-171 at
          all.
        </li>
        <li>
          <b>${bodyLink("scap-ncp")}</b> — XCCDF for the checklist, OVAL for the test, and the
          National Checklist Program as the public shelf. The same STIG exists twice: as prose for a
          person and as content for a scanner.
        </li>
        <li>
          <b>${bodyLink("mscp")}</b> — the worked example. Each macOS rule carries its references to
          800-53, 800-171, the STIG, CIS and CMMC at once, and the build emits whichever baseline you
          asked for. One rule, many citations: that is normalisation done at the source instead of
          afterwards.
        </li>
      </ul>
      <h3>And the two paths into private business</h3>
      <p>
        Nothing on this page obliges a company by itself. Federal rules reach private business two
        ways. By <b>contract</b>: ${bodyLink("dfars-7012")} flows ${bodyLink("sp-800-171")} down to
        every defense supplier, and ${bodyLink("cmmc")} audits it; ${bodyLink("far-52-204-21")} sets a
        fifteen-requirement floor in almost every other federal contract. By <b>market</b>:
        ${bodyLink("fedramp")} is met once and sold to every agency. Everything else — ${bodyLink("csf")},
        ${bodyLink("cis-controls")}, ${bodyLink("iso-27001")} — is adopted because a customer asked or
        because it is a good idea, and a company can leave at any time. Which of those applies to you
        is the first thing to settle, because it decides whether the rest of this page is a
        requirement or a reading list.
      </p>
      <h3>What this site does with all of it</h3>
      <p class="small">
        One pipeline, the same for every publisher: fetch, keep the exact bytes, normalise into
        requirements or settings, diff field by field against the previous version, and record the
        publisher's own stated reason where there is one. So the
        <a href="/register">change register</a> can show a control before and after; <a href="/controls">Controls</a>
        searches every tracked catalogue at once; and <a href="/baselines">Baselines</a> builds the
        strictest published set for a platform and lets you trim it. A machine-generated summary is
        always labelled as one, and never replaces the publisher's words.
      </p>
    </section>

    <section id="bodies">
      <h2><a href="#bodies">Every body, with its source</a></h2>
      <p class="small">
        ${filtered
          ? html`<b>${shown.length}</b> of ${authorities.length} publishers${sectorName ? html`, writing for ${sectorName}` : ""}${rungName ? html`, at the ${rungName} step` : ""} · <a href="/learn">show all</a>`
          : html`All <b>${authorities.length}</b> publishers, grouped by the step they sit on. An <span class="chip acc-agency">agency sign-in</span> link is public knowledge of where a document lives, not the document: NASA's own specifications are internal, and this site neither holds nor quotes them.`}
      </p>
      ${shown.length === 0 ? html`<div class="empty"><b>Nothing at that combination.</b><p>No publisher on this page writes at the ${rungName} step for ${sectorName}. <a href="/learn">Clear the filters</a>.</p></div>` : directory}
    </section>

    <section class="box wide" id="names">
      <h2><a href="#names">Names that collide</a></h2>
      <p class="small">
        Most of the difficulty in learning this field is that several different things share a name.
        Each reading below is real; none of them is the wrong answer, so the thing to do is say which
        one you mean.
      </p>
      <dl class="collide">${collisions.map(
        (c) => html`<dt>${c.name}</dt>
        <dd><ul class="plain">${c.readings.map(
          (r) => html`<li><b>${r.who}</b> — ${r.what}. <a href="${r.href}" ${newTab}>source</a> ${accessChip(r.access)}</li>`,
        )}</ul></dd>`,
      )}</dl>
    </section>

    <section class="box wide" id="not">
      <h2><a href="#not">What this page is not</a></h2>
      <p class="small">
        It is not legal advice, and it is not a compliance determination: whether a given system is
        obliged to meet a given baseline is a question for the people who authorise it. Every link
        here goes to a publisher's own address, and the access chip says what that publisher requires
        of a reader — this site adds no access to anything. Nothing restricted is reproduced here.
        For the vocabulary, see <a href="/guide">how to read this site</a>; for what this instance is
        actually holding, <a href="/standards">All standards</a> and the
        <a href="/register">change register</a>.
      </p>
    </section>`;

  return page({
    title: "Learn: where a rule comes from",
    active: "learn",
    content,
    owner,
    open,
    look,
    canonical: "/learn",
    description: "Where security standards, baselines, controls and STIGs come from: the chain from law to setting, every publisher on it, and what each body derives from.",
    meta: html`${shown.length} publisher${shown.length === 1 ? "" : "s"}${filtered ? " shown" : ""}`,
  });
}
