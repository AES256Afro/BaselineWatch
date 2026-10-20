import type { DatabaseSync } from "node:sqlite";
import { usesMscp, type DocChoice } from "../baselines.ts";
import { runsOn } from "../fleet.ts";
import { html, newTabIf, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { lines } from "../redline.ts";
import { areas, planAreas, planFormats, planPlatformName, type Area, type PlanItem, type TestPlan } from "../testplans.ts";
import { reportStyles } from "../report.ts";
import { page } from "./layout.ts";

interface Who {
  owner: boolean;
  open: boolean;
  look: LookState;
}

const choiceValue = (c: DocChoice): string => `${c.key}@${c.documentId}`;

/**
 * One check: the checkbox, the label and title, the source, what success looks like, what to do
 * when it fails, and the procedure folded away. A check that does not apply to the chosen release
 * or hardware is drawn greyed with the reason and cannot be ticked. Kept tight: an area draws up
 * to a couple of hundred of these and a phone loads them all.
 */
function item(i: PlanItem): Html {
  const sev = i.severity ? html` <span class="chip sev ${i.severity === "CAT I" || i.severity === "high" ? "critical" : i.severity === "CAT II" || i.severity === "medium" ? "high" : "medium"}">${i.severity}</span>` : html``;
  const na = !i.applicable.ok;
  return html`<li class="pitem ${i.included ? "" : "off"} ${na ? "na" : ""} ${i.source}"><label class="pitem-head"><input type="checkbox" name="keep" value="${i.id}" ${i.included ? "checked" : ""}${na ? " disabled" : ""}> ${i.source === "template" ? html`<span class="chip">owner's template</span>` : html`<a href="${i.url ?? "#"}"><b>${i.label}</b></a>`}${sev} <span class="pitem-title">${i.title}</span></label>${na ? html`<div class="pitem-meta"><span class="chip na">not applicable</span> <span class="small">${i.applicable.reason}</span></div>` : ""}${i.sourceTitle ? html`<div class="pitem-meta"><span class="small">${i.url ? html`<a href="${i.url}" ${newTabIf(i.url)}>${i.sourceTitle}</a>` : i.sourceTitle}</span></div>` : ""}${i.expected ? html`<div class="pitem-meta"><span><b>Success looks like:</b> ${i.expected}</span></div>` : ""}${i.fail ? html`<div class="pitem-meta"><span><b>If it does not:</b> ${i.fail}</span></div>` : ""}${i.ourValue ? html`<div class="pitem-meta"><span class="chip mod">modified</span> <span><b>Test for our value:</b> ${i.ourValue}</span></div>` : ""}${i.procedure ? html`<details><summary>Procedure</summary><p class="prose">${lines(i.procedure)}</p></details>` : ""}</li>
`;
}

/** The plan's release, hardware and areas as a GET URL, so a plan can be bookmarked or sent without the form. */
export function planLink(plan: TestPlan): string {
  const q = new URLSearchParams();
  if (plan.release) q.set("version", plan.release.id);
  if (plan.hardware) q.set("hardware", plan.hardware.id);
  if (plan.options.templates === false) q.set("templates", "0");
  if (plan.options.style && plan.options.style !== "plain") q.set("style", plan.options.style);
  const present = planAreas(plan).map((a) => a.id);
  if (plan.areasChosen.length !== present.length) {
    q.set("areas", "1");
    for (const a of plan.areasChosen) q.append("area", a);
  }
  const s = q.toString();
  return `/baselines/${plan.platform}/tests${s ? `?${s}` : ""}`;
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
  const name = planPlatformName(p);
  const c = plan.profile?.components ?? null;
  const sections = planAreas(plan);
  const current = sections.find((s) => s.id === options.area) ?? sections[0];
  // The other areas' drops ride along as hidden fields; the current area's are its unticked boxes.
  const carried = current ? plan.items.filter((i) => !i.included && i.applicable.ok && i.area !== current.id) : [];
  const release = plan.release;
  const hardwareChoices = plan.choices.hardware;

  const deriveFrom = plan.profile
    ? html`<fieldset class="build-from">
        <legend>Derive from</legend>
        ${c?.stig
          ? html`<label for="stig">STIG</label>
            <select id="stig" name="stig">${plan.profile.choices.stigs.map((s) => html`<option value="${choiceValue(s)}" ${c.stig && s.documentId === c.stig.documentId ? "selected" : ""}>${s.label}${s.publishedAt ? ` (${s.publishedAt.slice(0, 10)})` : ""}</option>`)}</select>`
          : html`<span class="small">No ${name} STIG loaded${owner ? html`: follow one through the <a href="/watchlist">watchlist</a> and fetch the DISA library from <a href="/sources">Sources</a>` : ""}; the plan is the owner's templates alone.</span>`}
        ${usesMscp(plan.profile.platform) && plan.profile.choices.mscps.length ? html`<label for="mscp">mSCP branch</label><select id="mscp" name="mscp">${plan.profile.choices.mscps.map((m) => html`<option value="${choiceValue(m)}" ${c?.mscp && m.documentId === c.mscp.documentId ? "selected" : ""}>${m.label}</option>`)}</select>` : ""}
        <label class="inline-check"><input type="checkbox" name="cat3" value="1" ${plan.options.cat3 ? "checked" : ""}> Include CAT III</label>
        <label class="inline-check"><input type="checkbox" name="templates" value="1" ${plan.options.templates === false ? "" : "checked"}> Owner's templates</label>
      </fieldset>`
    : html`<fieldset class="build-from">
        <legend>Derive from</legend>
        <span class="small">${name} has no STIG checks in the Register yet; the plan is the owner's templates, with the release and hardware you choose ruling steps in or out.</span>
        <label class="inline-check"><input type="checkbox" name="templates" value="1" ${plan.options.templates === false ? "" : "checked"}> Owner's templates</label>
      </fieldset>`;

  const releaseFacts = release
    ? html`<span class="small">${release.status === "ended" ? html`<b>Out of support.</b> ` : release.status === "upcoming" ? html`<b>Not yet released.</b> ` : ""}${release.supportEnds ? html`Support: ${release.supportEnds}.` : ""}${release.hardware.length && release.hardware.length < hardwareChoices.length ? html` Runs on ${release.hardware.map((h) => hardwareChoices.find((x) => x.id === h)?.label ?? h).join("; ")} only.` : ""}</span>`
    : html``;

  const underTest = html`<fieldset class="build-from">
    <legend>The release under test</legend>
    ${plan.choices.releases.length
      ? html`<label for="version">Version</label>
        <select id="version" name="version"><option value="">Any release</option>${plan.choices.releases.map((r) => html`<option value="${r.id}" ${release && r.id === release.id ? "selected" : ""}>${r.label}${r.status === "current" ? " (current)" : r.status === "ended" ? " (support ended)" : r.status === "upcoming" ? " (upcoming)" : ""}</option>`)}</select>`
      : html`<span class="small">No releases for ${name} in data/platforms.yaml yet.</span>`}
    ${hardwareChoices.length
      ? html`<label for="hardware">Hardware</label>
        <select id="hardware" name="hardware"><option value="">Any hardware</option>${hardwareChoices.map((h) => {
          const cannot = release ? !runsOn(release, h) : false;
          return html`<option value="${h.id}" ${plan.hardware && h.id === plan.hardware.id ? "selected" : ""} ${cannot ? "disabled" : ""}>${h.label}${cannot ? ` (cannot run ${release!.label})` : ""}</option>`;
        })}</select>`
      : ""}
    ${releaseFacts}
    <button type="submit" name="action" value="rebuild">Rebuild</button>
  </fieldset>`;

  const areaPick = html`<fieldset class="build-from areas-pick">
    <legend>Areas to test</legend>
    <input type="hidden" name="areas" value="1">
    ${sections.map((s) => html`<label class="inline-check"><input type="checkbox" name="area" value="${s.id}" ${s.tested ? "checked" : ""}> ${s.label} <span class="count">${s.kept}</span></label>`)}
    <span class="small">Untick an area to leave it out of the exports; it stays on the page, marked as not tested this time.</span>
  </fieldset>`;

  const main = html`<form method="post" action="/baselines/${p}/tests" class="builder">
        <input type="hidden" name="applied" value="1">
        ${current ? html`<input type="hidden" name="shown" value="${current.id}">` : ""}
        ${carried.map((i) => html`<input type="hidden" name="drop" value="${i.id}">`)}
        ${deriveFrom}
        ${underTest}
        ${sections.length ? areaPick : ""}
        <fieldset class="export-row">
          <legend>Export the kept checks</legend>
          <label for="style">Report look</label>
          <select id="style" name="style">${reportStyles.map((s) => html`<option value="${s.id}" ${s.id === (plan.options.style ?? "plain") ? "selected" : ""}>${s.label}</option>`)}</select>
          ${planFormats.map((f) => html`<button type="submit" formaction="/baselines/${p}/tests/export" name="format" value="${f.id}">${f.label}</button>`)}
          <span class="small">Untick a check, then Rebuild or export; the form carries the state and nothing is stored. One area is drawn at a time; what you untick in one is kept when you open another, and every export covers the whole plan: the checks kept, what was left out and why, a findings table and a sign-off.</span>
          <details class="small"><summary>The report looks</summary><dl class="kv">${reportStyles.map((s) => html`<dt>${s.label}</dt><dd>${s.blurb}${s.cover ? " Cover page." : ""}${s.numbered ? " Numbered sections." : ""}</dd>`)}</dl><p>The look applies to Word, PDF, LaTeX and the printable checklist; Markdown, CSV and JSON stay plain. Each follows one of the mockups in <code>docs/mockups/exports</code>.</p></details>
          <span class="small"><a href="${planLink(plan)}">Link to this plan</a>: the release, hardware and areas as a URL to bookmark or send; unticked checks do not travel with it.</span>
        </fieldset>
        ${sections.length
          ? html`<nav class="ptabs" aria-label="Areas of the plan">${sections.map((s) => html`<button type="submit" name="section" value="${s.id}" class="${[s.id === current?.id ? "on" : "", s.tested ? "" : "untested"].filter(Boolean).join(" ")}" ${s.id === current?.id ? html`aria-current="true"` : ""}>${s.label} <span class="count">${s.kept} of ${s.items.length}</span></button>`)}</nav>
            ${current ? html`<h2>${current.label} <span class="count">${current.kept} kept</span>${current.tested ? "" : html` <span class="chip na">not tested this time</span>`}</h2><ol class="pitems">${current.items.map(item)}</ol>` : ""}`
          : html`<div class="empty"><b>Nothing to test yet.</b><p>No STIG is loaded for ${name} and no template applies to it${release ? html` on ${release.label}` : ""}${plan.hardware ? html` with ${plan.hardware.label}` : ""}.</p></div>`}
      </form>`;

  const releaseBox = release
    ? html`<section class="box">
        <h2>${release.label}</h2>
        <dl class="kv">
          ${release.released ? html`<dt>Released</dt><dd>${release.released}</dd>` : ""}
          ${release.supportEnds ? html`<dt>Support</dt><dd>${release.supportEnds}</dd>` : ""}
          ${plan.hardware ? html`<dt>Hardware</dt><dd>${plan.hardware.label}${plan.hardware.note ? html`<div class="note">${plan.hardware.note}</div>` : ""}</dd>` : ""}
          ${release.models ? html`<dt>Models</dt><dd>${release.models}</dd>` : ""}
          ${release.baselines.length ? html`<dt>Baselines</dt><dd>${release.baselines.map((b) => html`<div>${b}</div>`)}</dd>` : ""}
        </dl>
        ${release.notes.length ? html`<ul class="change-list">${release.notes.map((n) => html`<li>${n}</li>`)}</ul>` : ""}
        ${release.sources.length ? html`<p class="small">${release.sources.map((s, i) => html`${i ? " · " : ""}<a href="${s.url}" ${newTabIf(s.url)}>${s.title}</a>`)}</p>` : ""}
      </section>`
    : html`<section class="box"><h2>Any release</h2><p class="small">Choose a version and hardware above and the plan leaves out what does not apply to them, saying why. <a href="/platforms">Every platform's releases and hardware</a> are listed on the Platforms page.</p></section>`;

  const aside = html`
    ${releaseBox}
    ${c
      ? html`<section class="box">
          <h2>Derived from</h2>
          <dl class="kv">
            ${c.stig ? html`<dt>STIG</dt><dd><a href="/standards/disa-stigs/${c.stig.documentId}">${c.stig.label}</a></dd>` : ""}
            ${c.mscp ? html`<dt>mSCP</dt><dd><a href="/standards/nist-mscp/${c.mscp.documentId}">${c.mscp.label}</a></dd>` : ""}
            <dt>Checks</dt><dd>${plan.counts.included} tested: ${plan.counts.derived} from the publishers' procedures, ${plan.counts.template} from the owner's templates${plan.counts.dropped ? html`; ${plan.counts.dropped} dropped` : ""}${plan.counts.inapplicable ? html`; ${plan.counts.inapplicable} not applicable` : ""}${plan.counts.untested ? html`; ${plan.counts.untested} in areas not tested` : ""}</dd>
            <dt>By area</dt><dd>${areas.filter((a) => plan.counts.byArea[a.id]).map((a, i) => html`${i ? ", " : ""}${a.label} ${plan.counts.byArea[a.id]}`)}</dd>
          </dl>
        </section>`
      : html`<section class="box">
          <h2>Checks</h2>
          <dl class="kv">
            <dt>Tested</dt><dd>${plan.counts.included} from the owner's templates${plan.counts.dropped ? html`; ${plan.counts.dropped} dropped` : ""}${plan.counts.inapplicable ? html`; ${plan.counts.inapplicable} not applicable` : ""}${plan.counts.untested ? html`; ${plan.counts.untested} in areas not tested` : ""}</dd>
            <dt>By area</dt><dd>${areas.filter((a) => plan.counts.byArea[a.id]).map((a, i) => html`${i ? ", " : ""}${a.label} ${plan.counts.byArea[a.id]}`)}</dd>
          </dl>
        </section>`}
    <section class="box">
      <h2>Templates <span class="count">${plan.templates.length}</span></h2>
      ${plan.templates.length
        ? html`<ul class="change-list">${plan.templates.map((t) => html`<li><b>${t.title}</b> <span class="small">${t.steps.length} steps · ${areas.find((a) => a.id === t.area)?.label ?? t.area} · ${t.file}</span>${t.notes ? html`<div class="note">${t.notes}</div>` : ""}</li>`)}</ul>`
        : html`<p class="small">No template applies to ${name}${release ? html` on ${release.label}` : ""}.</p>`}
      ${plan.notApplied.length ? html`<h3 class="small">Rules not applied <span class="count">${plan.notApplied.length}</span></h3><ul class="change-list">${plan.notApplied.slice(0, 20).map((i) => html`<li><b>${i.label}</b> <span class="chip del">not applied</span> <span class="small">${i.title}</span></li>`)}${plan.notApplied.length > 20 ? html`<li class="small">and ${plan.notApplied.length - 20} more</li>` : ""}</ul><p class="small">The owner's <a href="/baselines/${p}/decisions">decisions</a> keep these out of the plan; a modified rule stays in and is tested for the organisation's value.</p>` : ""}
      ${plan.skippedTemplates.length ? html`<h3 class="small">Left out</h3><ul class="change-list">${plan.skippedTemplates.map((s) => html`<li><b>${s.template.title}</b> <span class="small">${s.reason}</span></li>`)}</ul>` : ""}
      ${plan.templateErrors.length ? html`<p class="small">Could not read: ${plan.templateErrors.join("; ")}</p>` : ""}
      ${plan.fleetErrors.length ? html`<p class="small">data/platforms.yaml: ${plan.fleetErrors.join("; ")}</p>` : ""}
      <p class="small">Templates are YAML files under <code>data/test-plans</code> in the repository; the owner extends them by adding a file. Each says which releases and hardware it applies to, what success looks like and what to do when a step fails, and cites the document it follows. They are labelled as the owner's, not the publisher's.</p>
    </section>
    <section class="box">
      <h2>How the areas are chosen</h2>
      <p class="small">Each check is filed by the words in its title (then its procedure): Secure Enclave, TPM, secure boot and attestation under the hardware root of trust; Platform SSO, Entra, Kerberos and passkeys under SSO; BitLocker, FileVault and LUKS under disk encryption; passwords, smart cards, session lock and sudo under authentication; audit and logs under logging; firewall, SMB, SSH, TLS, Bluetooth and sharing under network; updates and releases under updates; enrolment and management under MDM; browsers by name; meeting rooms under collaboration. The rest is "everything else". The words are the publishers'; only the filing is this product's.</p>
      <p class="small">${plan.profile ? html`<a href="/baselines/${p}">The ${name} baseline</a> · ` : ""}<a href="/platforms">Platforms</a> · <a href="/baselines">All baselines</a></p>
    </section>`;

  const content = html`
    <div class="rel">
      <h1>${name} <span class="arrow">test plan</span>${release ? html` <span class="arrow">${release.label}</span>` : ""}</h1>
      <div class="when">What to test on a ${name} release so the baseline still holds${c?.stig ? html`: the checks of ${c.stig.label}${c.mscp ? html` and ${c.mscp.label}` : ""}, by area` : html`: the owner's templates, by area`}${plan.hardware ? html`, on ${plan.hardware.label}` : ""}</div>
    </div>
    <div class="cols">
      <section class="main">${main}</section>
      <aside class="side">${aside}</aside>
    </div>`;
  return page({ title: `${name} test plan`, active: "baselines", content, meta: html`${plan.counts.included} checks`, owner, open, look });
}
