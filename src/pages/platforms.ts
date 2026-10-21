import type { DatabaseSync } from "node:sqlite";
import { isBuilderPlatform } from "../baselines.ts";
import { eolFor, eolWord } from "../eol.ts";
import { endingSupport, fleetPlatforms, hardwareOf, loadFleet, releasesOf, type Fleet, type Release } from "../fleet.ts";
import { html, newTab, newTabIf, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { latestDocument } from "../register.ts";
import { loadTemplates, type Template } from "../testplans.ts";
import { repositoryUrl } from "../version.ts";
import { page } from "./layout.ts";

/**
 * The Fleet page: every platform's releases with the vendor's dates and status, the hardware each
 * runs on, and what the Register holds for each, leading to the test plan and the builder.
 */
interface Who {
  owner: boolean;
  open: boolean;
  look: LookState;
}

/** What the Register holds for a release: the STIG, mSCP branch and Microsoft baseline its fleet entry names. */
function held(db: DatabaseSync, r: Release): Html[] {
  const out: Html[] = [];
  const stig = r.documents.stig ? latestDocument(db, "disa-stigs", r.documents.stig) : null;
  const mscp = r.documents.mscp ? latestDocument(db, "nist-mscp", r.documents.mscp) : null;
  const sct = r.documents.sct ? latestDocument(db, "microsoft-sct", r.documents.sct) : null;
  if (stig) out.push(html`<a href="/standards/disa-stigs/${stig.id}">STIG ${stig.version_label ?? ""}</a>`);
  else if (r.documents.stig) out.push(html`<span class="small">STIG not loaded</span>`);
  if (mscp) out.push(html`<a href="/standards/nist-mscp/${mscp.id}">mSCP ${mscp.version_label ?? ""}</a>`);
  else if (r.documents.mscp) out.push(html`<span class="small">mSCP not loaded</span>`);
  if (sct) out.push(html`<a href="/standards/microsoft-sct/${sct.id}">Microsoft baseline ${sct.version_label ?? ""}</a>`);
  else if (r.documents.sct) out.push(html`<span class="small">Microsoft baseline not loaded</span>`);
  return out;
}

const statusLabel: Record<Release["status"], string> = { current: "current", supported: "supported", ended: "support ended", upcoming: "upcoming" };

export function renderPlatforms(options: { db: DatabaseSync; now?: Date; fleet?: Fleet; templates?: Template[] } & Who): string {
  const { db, owner, open, look } = options;
  const fleet = options.fleet ?? loadFleet();
  const templates = options.templates ?? loadTemplates().templates;
  const ending = endingSupport(fleet, options.now ?? new Date(), 90);
  const soon = (r: Release): Html => {
    const hits = ending.filter((e) => e.release === r);
    return hits.length ? html`${hits.map((e) => html`<div><span class="chip na">${e.days === 0 ? "ends today" : `ends in ${e.days} day${e.days === 1 ? "" : "s"}`}</span> <span class="small">${e.clause}</span></div>`)}` : html``;
  };
  const sections = fleetPlatforms.map((p) => {
    const releases = releasesOf(fleet, p.id);
    const hardware = hardwareOf(fleet, p.id);
    const forPlatform = templates.filter((t) => t.platforms.includes("all") || t.platforms.includes(p.id));
    return html`<section class="std platform" id="${p.id}">
      <div class="std-head"><b><a href="#${p.id}">${p.label}</a></b><span class="small"><a href="#${p.id}">${releases.length} release${releases.length === 1 ? "" : "s"}</a> · <a href="#${hardware.length ? `${p.id}-hardware` : p.id}">${hardware.length} hardware famil${hardware.length === 1 ? "y" : "ies"}</a> · <a href="/baselines/${p.id}/tests">${forPlatform.length} template${forPlatform.length === 1 ? "" : "s"}</a></span></div>
      <p class="std-note">${p.blurb}</p>
      <div class="std-meta">${isBuilderPlatform(p.id) ? html`<a href="/baselines/${p.id}">Baseline builder</a>` : ""}<a href="/baselines/${p.id}/tests">Test plan</a></div>
      ${releases.length
        ? html`<div class="table-wrap"><table class="fleet"><caption class="visually-hidden">The fleet's releases</caption>
            <thead><tr><th scope="col">Release</th><th scope="col">Status</th><th scope="col">Released</th><th scope="col">Support</th><th scope="col">Runs on</th><th scope="col">In the Register</th><th scope="col"></th></tr></thead>
            <tbody>${releases.map(
              (r) => html`<tr class="${r.status}">
                <td><b>${r.label}</b>${r.models ? html`<div class="note">${r.models}</div>` : ""}${r.notes.length ? html`<ul class="note">${r.notes.map((n) => html`<li>${n}</li>`)}</ul>` : ""}</td>
                <td><span class="state ${r.status === "current" || r.status === "supported" ? "ok" : r.status === "ended" ? "err" : "wait"}">${statusLabel[r.status]}</span></td>
                <td>${r.released ?? "—"}</td>
                <td class="small">${soon(r)}${r.supportEnds ?? "—"}${(() => {
                  const cycles = eolFor(db, p.id, r.id);
                  return cycles.length ? html`<div class="note">endoflife.date: ${cycles.map((c, i) => html`${i ? " · " : ""}${c.edition ? `${c.edition} ` : ""}${eolWord(c.eol)}${c.support && c.support !== c.eol && c.support !== "true" ? ` (support ${eolWord(c.support)})` : ""}${c.latest ? ` · latest ${c.latest}` : ""}`)}</div>` : "";
                })()}</td>
                <td class="small">${r.hardware.length ? r.hardware.map((h) => hardware.find((x) => x.id === h)?.label ?? h).join("; ") : "every family"}</td>
                <td class="small">${held(db, r).map((h, i) => html`${i ? " · " : ""}${h}`)}${r.baselines.length ? html`<details><summary>Published baselines</summary><ul class="note">${r.baselines.map((b) => html`<li>${b}</li>`)}</ul></details>` : ""}</td>
                <td><a href="/baselines/${p.id}/tests?version=${encodeURIComponent(r.id)}">Plan</a>${r.sources.length ? html`<div class="note">${r.sources.map((s, i) => html`${i ? " · " : ""}<a href="${s.url}" ${newTabIf(s.url)}>source</a>`)}</div>` : ""}</td>
              </tr>`,
            )}</tbody>
          </table></div>`
        : html`<p class="small">No releases in data/platforms.yaml yet.</p>`}
      ${hardware.length
        ? html`<ul class="hw" id="${p.id}-hardware">${hardware.map((h) => html`<li><b>${h.label}</b>${h.secureElement ? html` <span class="chip ok">secure element</span>` : html` <span class="chip na">no secure element</span>`}${h.note ? html`<div class="note">${h.note}</div>` : ""}</li>`)}</ul>`
        : ""}
    </section>`;
  });

  const content = html`
    <div class="cols">
      <section class="main">
        <h1>Fleet</h1>
        <p class="lede">Platform engineering, one place: each operating system the team runs, each release of it with the vendor's support dates, the hardware each release runs on, the baselines published for it, and what the Register already holds. Every row leads to a test plan for that release; the builder platforms lead to their baseline too. The facts are the vendors', kept in <code>data/platforms.yaml</code> with the page each came from.</p>
        ${fleet.errors.length ? html`<div class="notice error">data/platforms.yaml: ${fleet.errors.join("; ")}</div>` : ""}
        ${ending.length ? html`<div class="notice warn"><b>Support ending within 90 days:</b> ${ending.map((e, i) => html`${i ? " · " : ""}<a href="#${e.release.platform}">${e.release.label}</a> (${e.clause}, ${e.days === 0 ? "today" : `in ${e.days} day${e.days === 1 ? "" : "s"}`})`)}</div>` : ""}
        <ul class="stds">${sections}</ul>
      </section>
      <aside class="side">
        <section class="box">
          <h2><a href="/guide">How to use it</a></h2>
          <p class="small">Pick the platform, then the release and the hardware on its test plan. Steps a release or a device cannot take are left out with the reason (a Secure Enclave check on an Intel Mac without a T2 chip; an Administrator protection check on 23H2). Choose the areas to test, untick what you will not test this time, and export the plan as a printable checklist, Markdown, CSV, JSON, LaTeX, Word or PDF, with the checks left out listed and why.</p>
        </section>
        <section class="box">
          <h2><a href="${repositoryUrl}/tree/main/data/test-plans" ${newTab}>Extending it</a></h2>
          <p class="small">A new release or device family is a few lines in <a href="${repositoryUrl}/blob/main/data/platforms.yaml" ${newTab}><code>data/platforms.yaml</code></a>; a new test is a YAML file under <a href="${repositoryUrl}/tree/main/data/test-plans" ${newTab}><code>data/test-plans</code></a> with <code>applies</code> rules for the releases and hardware it is for. Both are read on every request. Nothing here is generated by a model: every date and model list carries its vendor source, and every step cites the document it follows.</p>
        </section>
        <section class="box">
          <h2><a href="/register">In the Register</a></h2>
          <p class="small">The publications the platforms answer to: <a href="/standards/nist-platform">NIST's platform security set</a> (FIPS 140-3, SP 800-147, 800-193, 800-124, 800-219, IR 8320) and <a href="/standards/nist-piv">PIV and digital identity</a> (FIPS 201, SP 800-73, 800-63-4), beside the <a href="/stigs">STIGs</a> and <a href="/baselines">baselines</a>.</p>
        </section>
      </aside>
    </div>`;
  return page({ title: "Fleet", active: "fleet", content, meta: html`${fleet.releases.length} releases`, owner, open, look });
}
