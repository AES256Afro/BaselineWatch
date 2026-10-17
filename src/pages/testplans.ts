import type { DatabaseSync } from "node:sqlite";
import { builderPlatforms, type BuilderPlatform, type DocChoice } from "../baselines.ts";
import { html, newTabIf, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { lines } from "../redline.ts";
import { areas, planAreas, type Area, type PlanItem, type TestPlan } from "../testplans.ts";
import { page } from "./layout.ts";

interface Who {
  owner: boolean;
  open: boolean;
  look: LookState;
}

const platformName = (p: BuilderPlatform): string => builderPlatforms.find((b) => b.id === p)?.label ?? p;
const choiceValue = (c: DocChoice): string => `${c.key}@${c.documentId}`;

/**
 * One check: the checkbox, the label and title, the source, and the procedure folded away. Kept
 * tight: an area draws up to a couple of hundred of these and a phone loads them all.
 */
function item(i: PlanItem): Html {
  const sev = i.severity ? html` <span class="chip sev ${i.severity === "CAT I" || i.severity === "high" ? "critical" : i.severity === "CAT II" || i.severity === "medium" ? "high" : "medium"}">${i.severity}</span>` : html``;
  return html`<li class="pitem ${i.included ? "" : "off"} ${i.source}"><label class="pitem-head"><input type="checkbox" name="keep" value="${i.id}" ${i.included ? "checked" : ""}> ${i.source === "template" ? html`<span class="chip">owner's template</span>` : html`<a href="${i.url ?? "#"}"><b>${i.label}</b></a>`}${sev} <span class="pitem-title">${i.title}</span></label>${i.sourceTitle ? html`<div class="pitem-meta"><span class="small">${i.url ? html`<a href="${i.url}" ${newTabIf(i.url)}>${i.sourceTitle}</a>` : i.sourceTitle}</span></div>` : ""}${i.expected ? html`<div class="pitem-meta"><span>Expect: ${i.expected}</span></div>` : ""}${i.procedure ? html`<details><summary>Procedure</summary><p class="prose">${lines(i.procedure)}</p></details>` : ""}</li>
`;
}

export interface TestPlanOptions extends Who {
  db: DatabaseSync;
  plan: TestPlan;
  /** The area to draw; the first with checks when absent or empty. */
  area?: Area | undefined;
}

export function renderTestPlan(options: TestPlanOptions): string {
  const { plan, owner, open, look } = options;
  const p = plan.platform;
  const name = platformName(p);
  const c = plan.profile.components;
  const sections = planAreas(plan);
  const current = sections.find((s) => s.id === options.area) ?? sections[0];
  // The other areas' drops ride along as hidden fields; the current area's are its unticked boxes.
  const carried = current ? plan.items.filter((i) => !i.included && i.area !== current.id) : [];

  const main = !c.stig
    ? html`<div class="empty"><b>No ${name} STIG loaded.</b><p>${owner ? html`Follow one through the <a href="/watchlist">watchlist</a> and fetch the DISA library from <a href="/sources">Sources</a>.` : "The owner can follow one through the watchlist."}</p></div>`
    : html`<form method="post" action="/baselines/${p}/tests" class="builder">
        <input type="hidden" name="applied" value="1">
        ${current ? html`<input type="hidden" name="shown" value="${current.id}">` : ""}
        ${carried.map((i) => html`<input type="hidden" name="drop" value="${i.id}">`)}
        <fieldset class="build-from">
          <legend>Derive from</legend>
          <label for="stig">STIG</label>
          <select id="stig" name="stig">${plan.profile.choices.stigs.map((s) => html`<option value="${choiceValue(s)}" ${c.stig && s.documentId === c.stig.documentId ? "selected" : ""}>${s.label}${s.publishedAt ? ` (${s.publishedAt.slice(0, 10)})` : ""}</option>`)}</select>
          ${p === "macos" && plan.profile.choices.mscps.length ? html`<label for="mscp">mSCP branch</label><select id="mscp" name="mscp">${plan.profile.choices.mscps.map((m) => html`<option value="${choiceValue(m)}" ${c.mscp && m.documentId === c.mscp.documentId ? "selected" : ""}>${m.label}</option>`)}</select>` : ""}
          <label class="inline-check"><input type="checkbox" name="cat3" value="1" ${plan.options.cat3 ? "checked" : ""}> Include CAT III</label>
          <label class="inline-check"><input type="checkbox" name="templates" value="1" ${plan.options.templates === false ? "" : "checked"}> Owner's templates</label>
          <button type="submit" name="action" value="rebuild">Rebuild</button>
        </fieldset>
        <fieldset class="export-row">
          <legend>Export the kept checks</legend>
          <button type="submit" formaction="/baselines/${p}/tests/export" name="format" value="html">Printable checklist</button>
          <button type="submit" formaction="/baselines/${p}/tests/export" name="format" value="md">Markdown</button>
          <button type="submit" formaction="/baselines/${p}/tests/export" name="format" value="csv">CSV</button>
          <button type="submit" formaction="/baselines/${p}/tests/export" name="format" value="json">JSON</button>
          <span class="small">Untick a check, then Rebuild or export; the form carries the state and nothing is stored. One area is drawn at a time; what you untick in one is kept when you open another, and every export covers the whole plan.</span>
        </fieldset>
        <nav class="ptabs" aria-label="Areas of the plan">${sections.map((s) => html`<button type="submit" name="section" value="${s.id}" class="${s.id === current?.id ? "on" : ""}" ${s.id === current?.id ? html`aria-current="true"` : ""}>${s.label} <span class="count">${s.kept} of ${s.items.length}</span></button>`)}</nav>
        ${current ? html`<h2>${current.label} <span class="count">${current.kept} kept</span></h2><ol class="pitems">${current.items.map(item)}</ol>` : html`<p class="small">The plan has no checks to draw.</p>`}
      </form>`;

  const aside = html`
    <section class="box">
      <h2>Derived from</h2>
      <dl class="kv">
        ${c.stig ? html`<dt>STIG</dt><dd><a href="/standards/disa-stigs/${c.stig.documentId}">${c.stig.label}</a></dd>` : ""}
        ${c.mscp ? html`<dt>mSCP</dt><dd><a href="/standards/nist-mscp/${c.mscp.documentId}">${c.mscp.label}</a></dd>` : ""}
        <dt>Checks</dt><dd>${plan.counts.included} kept: ${plan.counts.derived} from the publishers' procedures, ${plan.counts.template} from the owner's templates${plan.counts.dropped ? html`; ${plan.counts.dropped} dropped` : ""}</dd>
        <dt>By area</dt><dd>${areas.filter((a) => plan.counts.byArea[a.id]).map((a, i) => html`${i ? ", " : ""}${a.label} ${plan.counts.byArea[a.id]}`)}</dd>
      </dl>
    </section>
    <section class="box">
      <h2>Templates <span class="count">${plan.templates.length}</span></h2>
      ${plan.templates.length
        ? html`<ul class="change-list">${plan.templates.map((t) => html`<li><b>${t.title}</b> <span class="small">${t.steps.length} steps · ${areas.find((a) => a.id === t.area)?.label ?? t.area} · ${t.file}</span>${t.notes ? html`<div class="note">${t.notes}</div>` : ""}</li>`)}</ul>`
        : html`<p class="small">No template applies to ${name}.</p>`}
      ${plan.templateErrors.length ? html`<p class="small">Could not read: ${plan.templateErrors.join("; ")}</p>` : ""}
      <p class="small">Templates are YAML files under <code>data/test-plans</code> in the repository; the owner extends them by adding a file. They are labelled as the owner's, not the publisher's, and each step cites the document it follows.</p>
    </section>
    <section class="box">
      <h2>How the areas are chosen</h2>
      <p class="small">Each check is filed by the words in its title (then its procedure): BitLocker, FileVault and LUKS under disk encryption; passwords, smart cards, session lock and sudo under authentication and SSO; audit and logs under logging; firewall, SMB, SSH, TLS, Bluetooth and sharing under network; updates and supported versions under updates; enrolment and management under MDM; browsers by name. The rest is "everything else". The words are the publishers'; only the filing is this product's.</p>
      <p class="small"><a href="/baselines/${p}">The ${name} baseline</a> · <a href="/baselines">All platforms</a></p>
    </section>`;

  const content = html`
    <div class="rel">
      <h1>${name} <span class="arrow">test plan</span></h1>
      <div class="when">What to test on a new ${name} release so the baseline still holds${c.stig ? html`: the checks of ${c.stig.label}${c.mscp ? html` and ${c.mscp.label}` : ""}, by area` : ""}</div>
    </div>
    <div class="cols">
      <section class="main">${main}</section>
      <aside class="side">${aside}</aside>
    </div>`;
  return page({ title: `${name} test plan`, active: "baselines", content, meta: html`${plan.counts.included} checks`, owner, open, look });
}
