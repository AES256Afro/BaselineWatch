import type { DatabaseSync } from "node:sqlite";
import { html, newTabIf, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import type { NormalizedRequirement } from "../oscal.ts";
import { lines } from "../redline.ts";
import { changeSummaryFor, changeSummaryText, loadRequirements, notesFor, releaseChanges } from "../register.ts";
import { relativeTime } from "../time.ts";
import {
  cats,
  cciMap,
  controlLabel,
  controlPageBase,
  controlsFor,
  directivesForPlatform,
  kevForPlatform,
  platformLabel,
  platforms,
  platformsWithStigs,
  rulesByCat,
  stigsFor,
  type Cat,
  type CciMap,
  type PlatformId,
  type StigSummary,
} from "../stigs.ts";
import { page } from "./layout.ts";

interface Who {
  owner: boolean;
  open: boolean;
  look: LookState;
}

const catMeaning: Record<Cat, string> = {
  "CAT I": "Any vulnerability, the exploitation of which will directly and immediately result in loss of confidentiality, availability or integrity.",
  "CAT II": "Any vulnerability, the exploitation of which has a potential to result in loss of confidentiality, availability or integrity.",
  "CAT III": "Any vulnerability, the existence of which degrades measures to protect against loss of confidentiality, availability or integrity.",
};

function catChip(cat: string | null): Html {
  const level = cat === "CAT I" ? "critical" : cat === "CAT II" ? "high" : cat === "CAT III" ? "medium" : "";
  return html`<span class="chip sev ${level}">${cat ?? "unrated"}</span>`;
}

/** "AC-11(1)" links to the control's page in the latest SP 800-53 catalog when one is loaded. */
function controlLinks(refs: string[], base: string | null): Html {
  return html`${refs.map((ref, i) => html`${i ? ", " : ""}${base ? html`<a href="${base}/${ref}">${controlLabel(ref)}</a>` : html`<code>${controlLabel(ref)}</code>`}`)}`;
}

/** What a rule maps to, in words: the controls through its CCIs, or why there are none. */
export function mappingLine(rule: NormalizedRequirement, map: CciMap, base: string | null): Html {
  const ccis = rule.related.filter((r) => /^CCI-/i.test(r));
  if (ccis.length === 0) return html`<span class="small">No CCI on this rule.</span>`;
  if (map.documentId === null) return html`<span class="small">CCIs ${ccis.join(", ")}; the CCI list is not loaded yet, so no control mapping.</span>`;
  const controls = controlsFor(rule, map);
  const unknown = ccis.filter((c) => !map.controls.has(c.toUpperCase()));
  return html`${controls.length ? html`Maps to ${controlLinks(controls, base)}` : html`<span class="small">CCIs ${ccis.join(", ")} have no SP 800-53 index in the CCI list</span>`}${unknown.length && controls.length ? html` <span class="small">(${unknown.join(", ")} not in the list)</span>` : ""} <span class="small">via ${ccis.join(", ")}</span>`;
}

export function renderStigsIndex(options: { db: DatabaseSync; now: Date } & Who): string {
  const { db, now, owner, open, look } = options;
  const groups = platformsWithStigs(db);
  const map = cciMap(db);
  const total = groups.reduce((n, g) => n + g.stigs.length, 0);

  const sections = groups.map(
    ({ platform, stigs }) => html`<section class="box">
      <h2><a href="/stigs/${platform.id}">${platform.label}</a> <span class="count">${stigs.length} STIG${stigs.length === 1 ? "" : "s"}</span></h2>
      <p class="small">${platform.blurb}</p>
      <div class="table-wrap"><table>
        <thead><tr><th>STIG</th><th>Version</th><th>Published</th><th>CAT I</th><th>CAT II</th><th>CAT III</th><th>Against the previous version</th></tr></thead>
        <tbody>${stigs.map((s) => {
          const summary = s.previous ? changeSummaryText(changeSummaryFor(db, s.latest.id)) : "first version loaded";
          return html`<tr>
            <td><a href="/stigs/${platform.id}?stig=${encodeURIComponent(s.key)}"><b>${s.product}</b></a></td>
            <td><a href="/standards/disa-stigs/${s.latest.id}">${s.latest.version_label ?? "version unknown"}</a></td>
            <td>${s.latest.published_at ? s.latest.published_at.slice(0, 10) : "—"}</td>
            <td class="n">${s.counts["CAT I"]}</td>
            <td class="n">${s.counts["CAT II"]}</td>
            <td class="n">${s.counts["CAT III"]}</td>
            <td>${s.previous ? html`<a href="/standards/disa-stigs/${s.latest.id}">${summary}</a>` : summary} <span class="small">· loaded ${relativeTime(s.latest.parsed_at, now)}</span></td>
          </tr>`;
        })}</tbody>
      </table></div>
    </section>`,
  );

  const content = html`
    <div class="cols">
      <section class="main">
        <h1>STIGs</h1>
        <p class="lede">DISA's Security Technical Implementation Guides for the operating systems and products the Register follows: every rule by severity with its check and fix, what it maps to in NIST SP 800-53 through DISA's Control Correlation Identifiers, what changed in the latest release, and what CISA says about the platform.</p>
        ${total === 0
          ? html`<div class="empty"><b>No STIG loaded yet.</b><p>${owner ? html`Fetch the DISA STIG library from the <a href="/sources">Sources</a> page; the default set covers Windows 11 and Server, Red Hat and Ubuntu, macOS, the three browsers and more.` : "The owner can fetch the DISA STIG library from the Sources page."}</p></div>`
          : sections}
      </section>
      <aside class="side">
        <section class="box">
          <h2>Rules to controls</h2>
          <p class="small">${map.documentId !== null ? html`Each rule's CCIs are indexed to NIST SP 800-53 by DISA's <a href="/standards/disa-cci">CCI list</a>, version ${map.version ?? "unknown"} (${map.controls.size} identifiers). The control pages in the Register show the reverse: the rules that implement each control.` : html`DISA's CCI list has not loaded yet, so rules show their CCIs without the control they index. ${owner ? html`Fetch it from the <a href="/sources">Sources</a> page.` : ""}`}</p>
        </section>
        <section class="box">
          <h2>Platforms</h2>
          <ul class="src-list">${platforms.map((p) => {
            const n = groups.find((g) => g.platform.id === p.id)?.stigs.length ?? 0;
            return html`<li><a href="/stigs/${p.id}">${p.label}</a><b>${n}</b></li>`;
          })}</ul>
        </section>
        <section class="box">
          <h2>Follow another STIG</h2>
          <p class="small">The library holds over four hundred documents; only the followed ones are downloaded. ${owner ? html`Add a <a href="/watchlist">watchlist</a> entry of kind Baseline with the product's name as DISA writes it ("Oracle Linux 9", "VMware vSphere 8.0") and fetch the library again. Entries replace the default set.` : "The owner follows more through the watchlist."}</p>
        </section>
      </aside>
    </div>`;

  return page({ title: "STIGs", active: "stigs", content, meta: html`${total} STIGs`, owner, open, look });
}

export interface StigPlatformOptions extends Who {
  db: DatabaseSync;
  platform: PlatformId;
  stigKey: string | undefined;
  cat: Cat | undefined;
  now: Date;
}

function ruleItem(rule: NormalizedRequirement, stig: StigSummary, map: CciMap, base: string | null, changed: Set<string>): Html {
  const fix = typeof rule.extra.fix === "string" ? rule.extra.fix : null;
  return html`<li class="rule" id="${rule.ref}">
    <div class="rule-head">
      <a href="/standards/disa-stigs/${stig.latest.id}/${rule.ref}"><b>${rule.label}</b></a>
      ${catChip(rule.family)}
      ${changed.has(rule.ref) ? html`<span class="chip mod">changed in ${stig.latest.version_label ?? "this version"}</span>` : ""}
      ${rule.status === "withdrawn" ? html`<span class="chip del">withdrawn</span>` : ""}
      <span class="small">${rule.ref.toUpperCase()}${typeof rule.extra.srg === "string" ? html` · ${rule.extra.srg}` : ""}</span>
    </div>
    <h3>${rule.title}</h3>
    <div class="rule-controls">${mappingLine(rule, map, base)}</div>
    ${rule.statement ? html`<details><summary>Check</summary><p class="prose">${lines(rule.statement)}</p></details>` : ""}
    ${fix ? html`<details><summary>Fix</summary><p class="prose">${lines(fix)}</p></details>` : ""}
  </li>`;
}

export function renderStigPlatform(options: StigPlatformOptions): string {
  const { db, platform, stigKey, cat, now, owner, open, look } = options;
  const label = platformLabel(platform);
  const stigs = stigsFor(db, platform);
  const chosen = stigs.find((s) => s.key === stigKey) ?? stigs[0] ?? null;
  const map = cciMap(db);
  const base = controlPageBase(db);
  const kev = kevForPlatform(db, platform);
  const directives = directivesForPlatform(db, platform);

  let main: Html;
  let aside: Html = html``;
  if (!chosen) {
    main = html`<div class="empty"><b>No ${label} STIG loaded.</b><p>${owner ? html`Follow one through the <a href="/watchlist">watchlist</a> (kind Baseline, the product's name) and fetch the DISA library from <a href="/sources">Sources</a>.` : "The owner can follow one through the watchlist."}</p></div>`;
  } else {
    const rules = loadRequirements(db, chosen.latest.id);
    const grouped = rulesByCat(rules);
    const changed = new Set(releaseChanges(db, chosen.latest.id).map((c) => c.ref));
    const link = (overrides: { stig?: string; cat?: Cat | undefined }) => {
      const p = new URLSearchParams();
      const key = overrides.stig ?? chosen.key;
      if (key !== stigs[0]?.key) p.set("stig", key);
      const c = "cat" in overrides ? overrides.cat : cat;
      if (c) p.set("cat", c === "CAT I" ? "1" : c === "CAT II" ? "2" : "3");
      const s = p.toString();
      return `/stigs/${platform}${s ? `?${s}` : ""}`;
    };
    const shownCats: Cat[] = cat ? [cat] : cats;
    const summary = chosen.previous ? changeSummaryFor(db, chosen.latest.id) : null;
    const changedRefs = summary ? [...summary.added, ...summary.substantive, ...summary.removed, ...summary.editorial] : [];
    const labels = new Map(rules.map((r) => [r.ref, r]));
    if (chosen.previous && summary) for (const r of loadRequirements(db, chosen.previous.id)) if (!labels.has(r.ref)) labels.set(r.ref, r);

    main = html`
      <form method="get" action="/stigs/${platform}" class="cat-pick">
        <label for="stig">STIG</label>
        <select id="stig" name="stig">${stigs.map((s) => html`<option value="${s.key}" ${s.key === chosen.key ? "selected" : ""}>${s.product} ${s.latest.version_label ?? ""}</option>`)}</select>
        ${cat ? html`<input type="hidden" name="cat" value="${cat === "CAT I" ? "1" : cat === "CAT II" ? "2" : "3"}">` : ""}
        <button type="submit">Show</button>
      </form>
      <div class="filters">
        <a class="${!cat ? "on" : ""}" href="${link({ cat: undefined })}">All <b>${rules.length}</b></a>
        ${cats.map((c) => html`<a class="${cat === c ? "on" : ""}" href="${link({ cat: c })}">${c} <b>${grouped[c].length}</b></a>`)}
        <a href="/standards/disa-stigs/${chosen.latest.id}/browse">Browse in the Register</a>
      </div>
      ${shownCats.map((c) =>
        grouped[c].length
          ? html`<section class="box cat">
              <h2>${c} <span class="count">${grouped[c].length}</span></h2>
              <p class="small">${catMeaning[c]}</p>
              <ol class="rules">${grouped[c].map((r) => ruleItem(r, chosen, map, base, changed))}</ol>
            </section>`
          : "",
      )}
      ${!cat && grouped.other.length ? html`<section class="box"><h2>Unrated <span class="count">${grouped.other.length}</span></h2><ol class="rules">${grouped.other.map((r) => ruleItem(r, chosen, map, base, changed))}</ol></section>` : ""}`;

    aside = html`
      <section class="box">
        <h2>${chosen.product}</h2>
        <dl class="kv">
          <dt>Version</dt><dd><a href="/standards/disa-stigs/${chosen.latest.id}">${chosen.latest.version_label ?? "unknown"}</a></dd>
          <dt>Published</dt><dd>${chosen.latest.published_at ? chosen.latest.published_at.slice(0, 10) : "unknown"} · loaded ${relativeTime(chosen.latest.parsed_at, now)}</dd>
          <dt>Rules</dt><dd>${rules.length}: ${chosen.counts["CAT I"]} CAT I, ${chosen.counts["CAT II"]} CAT II, ${chosen.counts["CAT III"]} CAT III</dd>
          <dt>Source</dt><dd><a href="${chosen.latest.source_url ?? "https://www.cyber.mil/stigs/downloads/"}" ${newTabIf(chosen.latest.source_url ?? "https://www.cyber.mil/")}>DISA zip</a></dd>
        </dl>
      </section>
      <section class="box">
        <h2>What changed in ${chosen.latest.version_label ?? "this version"}</h2>
        ${!chosen.previous
          ? html`<p class="small">First version loaded; the next release will be diffed against it rule by rule.</p>`
          : summary && changedRefs.length === 0
            ? html`<p class="small">No rule-level changes against ${chosen.previous.version_label ?? "the previous version"}.</p>`
            : html`<p class="small">Against ${chosen.previous.version_label ?? "the previous version"}: ${changeSummaryText(summary!)}. <a href="/standards/disa-stigs/${chosen.latest.id}">Every change with DISA's notes</a>.</p>
              <ul class="change-list">${[...new Set(changedRefs)].slice(0, 12).map((ref) => {
                const r = labels.get(ref);
                const kind = summary!.added.includes(ref) ? "ins" : summary!.removed.includes(ref) ? "del" : "mod";
                const note = notesFor(db, chosen.latest.id, ref)[0];
                return html`<li><a href="/standards/disa-stigs/${chosen.latest.id}/${ref}"><b>${r?.label ?? ref.toUpperCase()}</b></a> <span class="chip ${kind}">${kind === "ins" ? "added" : kind === "del" ? "removed" : "revised"}</span> ${r?.title ?? ""}${note ? html`<div class="note">DISA: ${note.text.length > 200 ? `${note.text.slice(0, 199)}…` : note.text}</div>` : ""}</li>`;
              })}</ul>`}
      </section>`;
  }

  const cisa = html`
    <section class="box">
      <h2>CISA on ${label}</h2>
      <h3 class="small">Known exploited <span class="count">${kev.total}</span></h3>
      ${kev.entries.length
        ? html`<ul class="kev-list">${kev.entries.map((k) => {
            const known = db.prepare("SELECT 1 FROM vulns WHERE cve_id = ?").get(k.cve) !== undefined;
            const href = known ? `/vulnerabilities/${k.cve}` : (k.url ?? `https://nvd.nist.gov/vuln/detail/${k.cve}`);
            return html`<li><a href="${href}" ${newTabIf(href)}>${k.title}</a><span class="when">${k.cve} · added ${k.publishedAt ? k.publishedAt.slice(0, 10) : "?"}${k.dueDate ? html` · due ${k.dueDate}` : ""}${k.ransomware ? html` · <span class="chip kev">ransomware</span>` : ""}</span></li>`;
          })}</ul>
          <p class="small"><a href="/wire?kind=kev">All KEV additions on the Wire</a></p>`
        : html`<p class="small">No KEV entry names ${label === "every platform" ? "it" : label}${kev.total === 0 && (db.prepare("SELECT COUNT(*) AS n FROM items WHERE kind = 'kev'").get() as { n: number }).n === 0 ? "; the catalog has not been fetched yet" : ""}.</p>`}
      <h3 class="small">Directives <span class="count">${directives.length}</span></h3>
      ${directives.length
        ? html`<ul class="kev-list">${directives.map(
            (d) => html`<li><a href="${d.url ?? "https://www.cisa.gov/news-events/directives"}" ${newTabIf(d.url)}>${d.title}</a><span class="when">${d.kind === "ed" ? "Emergency Directive" : d.kind === "bod" ? "Binding Operational Directive" : "Directive"}${d.publishedAt ? html` · ${d.publishedAt.slice(0, 10)}` : ""}${d.platforms.includes("all") ? " · every platform" : ""}</span></li>`,
          )}</ul>`
        : html`<p class="small">No directive names ${label}${(db.prepare("SELECT COUNT(*) AS n FROM items WHERE source_id = 'cisa-directives'").get() as { n: number }).n === 0 ? "; CISA's directives have not been fetched yet" : ""}.</p>`}
      <p class="small">KEV entries are matched by CISA's vendor and product; directives by what their titles name. Both are CISA's own words, linked.</p>
    </section>`;

  const content = html`
    <div class="rel">
      <h1>${label} <span class="arrow">STIGs</span></h1>
      <div class="when">${stigs.length} STIG${stigs.length === 1 ? "" : "s"} followed · <a href="/stigs">All platforms</a></div>
    </div>
    <div class="cols">
      <section class="main">${main}</section>
      <aside class="side">${aside}${cisa}</aside>
    </div>`;

  return page({ title: `${label} STIGs`, active: "stigs", content, meta: html`${stigs.length} STIGs`, owner, open, look });
}
