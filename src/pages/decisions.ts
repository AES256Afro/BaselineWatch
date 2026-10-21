import { platformName, type Profile, type ProfileItem } from "../baselines.ts";
import { decisionKinds, decisionLabel, recommends, type DecisionKind } from "../decisions.ts";
import { html, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { lines } from "../redline.ts";
import { controlLabel } from "../stigs.ts";
import { page } from "./layout.ts";

/**
 * The decisions pages: the board of every item's decision per platform in three columns, and the
 * decide page that puts one item's recommendation beside the owner's answer to it.
 */
interface Who {
  owner: boolean;
  open: boolean;
  look: LookState;
}

const who = (i: ProfileItem): string => (i.kind === "stig" ? "DISA STIG" : i.kind === "mscp" ? "NIST mSCP" : i.kind === "sct" ? "Microsoft baseline" : "NIST SP 800-53 High");
const kindOf = (i: ProfileItem): DecisionKind => i.decision?.decision ?? "apply";
const decideUrl = (p: string, i: ProfileItem): string => `/baselines/${p}/decide?item=${encodeURIComponent(i.id)}`;

/** The chip a row of the builder shows for the owner's decision. */
export function decisionChip(platform: string, i: ProfileItem): Html {
  const k = kindOf(i);
  const cls = k === "exclude" ? "del" : k === "modify" ? "mod" : "ins";
  const text = k === "apply" ? (i.decision ? "Apply (decided)" : "Recommended: apply") : k === "modify" ? `Modified${i.decision?.value ? `: ${i.decision.value.length > 40 ? `${i.decision.value.slice(0, 39)}…` : i.decision.value}` : ""}` : "Not applying";
  return html`<a class="chip ${cls}" href="${decideUrl(platform, i)}">${text}</a>`;
}

/** One card: what the publisher recommends against what the organisation does. */
function card(platform: string, i: ProfileItem): Html {
  const d = i.decision;
  return html`<li class="dcard ${kindOf(i)}">
    <div class="dcard-head"><a href="${i.url}"><b>${i.label}</b></a>${i.severity ? html` <span class="chip">${i.severity}</span>` : ""} <span class="small">${who(i)}</span></div>
    <div class="dcard-title">${i.title}</div>
    <dl class="kv">
      <dt>Recommends</dt><dd>${i.sctValue ? html`${i.sctValue}` : i.kind === "control" ? "Implement the control" : "Apply as published"}${i.controls.length ? html` <span class="small">(${i.controls.slice(0, 6).map(controlLabel).join(", ")}${i.controls.length > 6 ? "…" : ""})</span>` : ""}</dd>
      <dt>Our decision</dt><dd><b>${decisionLabel(kindOf(i))}</b>${d?.value ? html`: ${d.value}` : ""}</dd>
      ${d?.reason ? html`<dt>Reason</dt><dd>${d.reason}</dd>` : ""}
      ${d?.owner ? html`<dt>Owner</dt><dd>${d.owner}</dd>` : ""}
      ${d ? html`<dt>Decided</dt><dd>${d.decidedAt.slice(0, 10)}</dd>` : ""}
    </dl>
    <a class="small" href="${decideUrl(platform, i)}">Open</a>
  </li>`;
}

export function renderDecisionBoard(options: { profile: Profile; saved?: number } & Who): string {
  const { profile, owner, open, look } = options;
  const p = profile.platform;
  const name = platformName(p);
  const c = profile.components;
  const counts = profile.counts.decisions;
  const col = (k: DecisionKind, items: ProfileItem[], note: Html) => html`<section class="dcol ${k}">
      <h2>${decisionLabel(k)} <span class="count">${counts[k]}</span></h2>
      <p class="small">${note}</p>
      ${items.length ? html`<ol class="dcards">${items.map((i) => card(p, i))}</ol>` : html`<p class="small">None.</p>`}
    </section>`;
  const decided = profile.items.filter((i) => i.decision);
  const modified = decided.filter((i) => kindOf(i) === "modify");
  const excluded = decided.filter((i) => kindOf(i) === "exclude");
  const appliedNoted = decided.filter((i) => kindOf(i) === "apply");
  const content = html`
    <div class="rel">
      <h1>${name} <span class="arrow">baseline decisions</span></h1>
      <div class="when">${c.stig ? html`${c.stig.label}${c.mscp ? html` + ${c.mscp.label}` : ""}${c.sct ? html` + ${c.sct.label}` : ""}${c.controls ? " + SP 800-53 High" : ""}` : "nothing to decide on yet"}: what the publishers recommend, and what this organisation applies</div>
    </div>
    <p class="lede">Every item of the <a href="/baselines/${p}">${name} baseline</a> starts as the publisher recommends. ${owner ? "Open an item (from the builder or a card here) to apply it modified or not at all, with the reason and its owner." : "The owner records where the organisation departs from the recommendation, with the reason."} Items not applied leave the baseline's exports and the <a href="/baselines/${p}/tests">test plan</a>; modified items are tested for the organisation's value.</p>
    <p class="small">${options.saved !== undefined ? html`<span class="chip ins">Saved ${options.saved} decision${options.saved === 1 ? "" : "s"}</span> ` : ""}<a href="/baselines/${p}/decisions.csv">Download every item and its decision as CSV</a> · <a href="/baselines/${p}/tests">The ${name} test plan</a></p>
    <div class="dboard">
      ${col("apply", appliedNoted, html`${counts.apply} items apply as published${appliedNoted.length ? html`; these ${appliedNoted.length} carry a note or an owner` : ""}.`)}
      ${col("modify", modified, html`Applied with the organisation's own value.`)}
      ${col("exclude", excluded, html`Left out; the reason is the risk acceptance.`)}
    </div>`;
  return page({ title: `${name} decisions`, active: "baselines", content, meta: html`${counts.modify} modified · ${counts.exclude} not applied`, owner, open, look });
}

export function renderDecide(options: { profile: Profile; item: ProfileItem; saved?: boolean } & Who): string {
  const { profile, item: i, owner, open, look } = options;
  const p = profile.platform;
  const name = platformName(p);
  const d = i.decision;
  const k = kindOf(i);
  const payloads = i.mscp?.payloads ?? [];
  // Walk the rules in builder order without going back to the list; controls are decided on their own page too.
  const at = profile.items.findIndex((x) => x.id === i.id);
  const prev = at > 0 ? profile.items[at - 1] : undefined;
  const next = at >= 0 && at < profile.items.length - 1 ? profile.items[at + 1] : undefined;
  const left = html`<section class="box">
      <h2>${who(i)} recommends</h2>
      <p><a href="${i.url}"><b>${i.label}</b></a>${i.severity ? html` <span class="chip">${i.severity}</span>` : ""}</p>
      <p>${i.title}</p>
      ${i.sctValue ? html`<p>Value: <b>${i.sctValue}</b></p>` : ""}
      ${i.controls.length ? html`<p class="small">NIST SP 800-53: ${i.controls.map(controlLabel).join(", ")}</p>` : ""}
      ${i.mscp ? html`<p class="small">mSCP rule ${i.mscp.id}${i.mscp.baselines.length ? html` · in ${i.mscp.baselines.slice(0, 8).join(", ")}${i.mscp.baselines.length > 8 ? "…" : ""}` : ""}</p>` : ""}
      ${payloads.length ? html`<h3 class="small">Configuration profile</h3><pre>${payloads.map((pl) => `${pl.domain}\n${Object.entries(pl.keys).map(([key, v]) => `  ${key} = ${JSON.stringify(v)}`).join("\n")}`).join("\n")}</pre>` : ""}
      ${i.check ? html`<details><summary>Check</summary><p class="prose">${lines(i.check)}</p></details>` : ""}
      ${i.fix ? html`<details><summary>Fix</summary><p class="prose">${lines(i.fix)}</p></details>` : ""}
    </section>`;
  const right = owner
    ? html`<form method="post" action="/baselines/${p}/decide" class="box decide">
        <h2>Our decision</h2>
        ${options.saved ? html`<p class="chip ins">Saved</p>` : ""}
        <input type="hidden" name="item" value="${i.id}">
        <fieldset>
          <legend>Decision</legend>
          ${decisionKinds.map((dk) => html`<label class="inline-check"><input type="radio" name="decision" value="${dk.id}" ${dk.id === k ? "checked" : ""}> <b>${dk.label}</b> <span class="small">${dk.blurb}</span></label><br>`)}
        </fieldset>
        <label for="value">Our value (when modified)</label>
        <input id="value" name="value" value="${d?.value ?? ""}" maxlength="500">
        <label for="reason">Reason</label>
        <textarea id="reason" name="reason" rows="4" maxlength="2000">${d?.reason ?? ""}</textarea>
        <label for="owner">Owner</label>
        <input id="owner" name="owner" value="${d?.owner ?? ""}" maxlength="120">
        <button type="submit">Save</button>
        <p class="small">Applying as published with no reason or owner clears the decision. ${d ? `Last decided ${d.decidedAt.slice(0, 10)}.` : "No decision recorded: the recommendation stands."}</p>
      </form>`
    : html`<section class="box">
        <h2>Our decision</h2>
        <p><b>${decisionLabel(k)}</b>${d?.value ? html`: ${d.value}` : ""}</p>
        ${d?.reason ? html`<p>${d.reason}</p>` : ""}
        ${d?.owner ? html`<p class="small">Owner: ${d.owner}</p>` : ""}
        <p class="small">${d ? `Decided ${d.decidedAt.slice(0, 10)}.` : "No decision recorded: the recommendation stands."} The owner signs in to change it.</p>
      </section>`;
  const content = html`
    <div class="rel">
      <h1>${name} <span class="arrow">${i.label}</span></h1>
      <div class="when">${recommends(i)}</div>
    </div>
    <div class="decide-cols">${left}${right}</div>
    <nav class="small decide-nav">${prev ? html`<a href="${decideUrl(p, prev)}" rel="prev">Previous: ${prev.label}</a>` : ""}${prev && next ? " · " : ""}${next ? html`<a href="${decideUrl(p, next)}" rel="next">Next: ${next.label}</a>` : ""}</nav>
    <p class="small"><a href="/baselines/${p}/decisions">All ${name} decisions</a> · <a href="/baselines/${p}">The ${name} baseline</a> · <a href="/baselines/${p}/tests">The ${name} test plan</a></p>`;
  return page({ title: `${i.label} · ${name} decision`, active: "baselines", content, meta: html`${decisionLabel(k)}`, owner, open, look });
}
