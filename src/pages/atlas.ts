import type { DatabaseSync } from "node:sqlite";
import { expectedNext, familyHeatmap, releaseTimeline, velocity } from "../atlas.ts";
import { html, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { page } from "./layout.ts";

const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function quarterLabel(d: Date): string {
  return `Q${Math.floor(d.getUTCMonth() / 3) + 1} ${d.getUTCFullYear()}`;
}

/**
 * The release timeline as inline SVG; positions are attributes, so the strict CSP is untouched.
 * Every mark is a link: a standard's name to its versions, a dot to that release. A dot sits on
 * a wider transparent circle so a four-pixel mark is not a four-pixel target.
 */
function timelineSvg(db: DatabaseSync, from: Date, to: Date): Html {
  const rows = releaseTimeline(db, from.toISOString(), to.toISOString());
  const W = 1000;
  const labelW = 230;
  const rowH = 34;
  const top = 28;
  const H = top + rows.length * rowH + 30;
  const span = to.getTime() - from.getTime();
  const x = (iso: string) => labelW + ((new Date(iso).getTime() - from.getTime()) / span) * (W - labelW - 20);
  const quarters: Date[] = [];
  for (let d = new Date(Date.UTC(from.getUTCFullYear(), Math.floor(from.getUTCMonth() / 3) * 3 + 3, 1)); d < to; d = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 3, 1))) quarters.push(d);
  return html`<svg class="atlas-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Release timeline per standard">
    ${quarters.map((q) => html`<line class="grid" x1="${x(q.toISOString()).toFixed(1)}" y1="${top - 8}" x2="${x(q.toISOString()).toFixed(1)}" y2="${H - 24}"></line><text class="axis" x="${x(q.toISOString()).toFixed(1)}" y="${H - 8}" text-anchor="middle">${quarterLabel(q)}</text>`)}
    ${rows.map((row, i) => {
      const y = top + i * rowH + rowH / 2;
      return html`<g>
        <a href="/standards/${row.sourceId}"><title>${row.name}: every version the Register holds</title><text class="label" x="0" y="${y + 4}">${row.name.length > 32 ? `${row.name.slice(0, 31)}…` : row.name}</text></a>
        <line class="track" x1="${labelW}" y1="${y}" x2="${W - 20}" y2="${y}"></line>
        ${row.releases.map((r) => {
          const radius = r.first ? 4 : 5 + Math.min(9, Math.sqrt(r.changes));
          const cx = x(r.publishedAt).toFixed(1);
          return html`<a href="/standards/${row.sourceId}/${r.documentId}"><title>${r.key} ${r.version ?? ""} · ${r.publishedAt.slice(0, 10)} · ${r.first ? "first version loaded" : `${r.changes} changed`}</title><circle class="hit" cx="${cx}" cy="${y}" r="12"></circle><circle class="dot ${r.first ? "first" : r.changes ? "changed" : "quiet"}" cx="${cx}" cy="${y}" r="${radius.toFixed(1)}"></circle></a>`;
        })}
      </g>`;
    })}
  </svg>`;
}

/**
 * The family map. A family's code leads to that family's controls in the latest version; a
 * release's label to the release; a cell to the release's changes in that family, or, for a
 * first version with nothing to compare, to the family's controls in it.
 */
function heatmapSvg(db: DatabaseSync): Html {
  const map = familyHeatmap(db);
  if (map.rows.length === 0) return html`<p class="small">No NIST SP 800-53 catalog loaded yet.</p>`;
  const latest = map.rows[map.rows.length - 1]!;
  const base = `/standards/${map.sourceId}`;
  const familyControls = (documentId: number, f: string) => `${base}/${documentId}/browse?family=${encodeURIComponent(f)}`;
  const cell = 34;
  const labelW = 150;
  const W = labelW + map.families.length * cell + 10;
  const H = 24 + map.rows.length * cell + 6;
  const level = (n: number) => (n === 0 ? 0 : map.max <= 1 ? 4 : Math.min(4, 1 + Math.floor((n / map.max) * 3.99)));
  return html`<svg class="atlas-svg heat" viewBox="0 0 ${W} ${H}" role="img" aria-label="Changed controls per family per release">
    ${map.families.map((f, i) => html`<a href="${familyControls(latest.documentId, f)}"><title>${f}: every control in the family, ${latest.version ?? "latest version"}</title><text class="axis" x="${labelW + i * cell + cell / 2}" y="16" text-anchor="middle">${f}</text></a>`)}
    ${map.rows.map((r, j) => {
      const y = 24 + j * cell;
      return html`<g>
        <a href="${base}/${r.documentId}"><title>${r.version ?? "?"}: ${r.first ? "first version loaded" : `${r.total} controls changed`}</title><text class="label" x="0" y="${y + cell / 2 + 4}">${r.version ?? "?"}${r.publishedAt ? ` · ${r.publishedAt.slice(0, 7)}` : ""}</text></a>
        ${map.families.map((f, i) => {
          const n = r.counts[f] ?? 0;
          const href = r.first ? familyControls(r.documentId, f) : `${base}/${r.documentId}?family=${encodeURIComponent(f)}`;
          return html`<a href="${href}"><title>${f} · ${r.version ?? ""}: ${r.first ? "first version" : `${n} changed`}</title><rect class="cell l${r.first ? 0 : level(n)}" x="${labelW + i * cell + 2}" y="${y + 2}" width="${cell - 4}" height="${cell - 4}" rx="3"></rect></a>`;
        })}
      </g>`;
    })}
  </svg>`;
}

export function renderAtlas(options: { db: DatabaseSync; owner: boolean; open: boolean; now: Date; look: LookState }): string {
  const { db, owner, open, now, look } = options;
  const to = now;
  const from = new Date(Date.UTC(now.getUTCFullYear() - 1, now.getUTCMonth() - 3, 1));
  const rows = releaseTimeline(db, from.toISOString(), to.toISOString());
  const v = velocity(db, new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000).toISOString());
  const due = expectedNext(db, now);

  const content = html`
    <div class="wire-top">
      <h1>Atlas</h1>
      <div class="small">${from.getUTCDate()} ${monthNames[from.getUTCMonth()]} ${from.getUTCFullYear()} → today · <a href="/register">${rows.length} standards with releases in view</a></div>
    </div>
    <p class="lede">Being in tune means knowing the rhythm, not just today's note. Each dot is a release <a href="/register">the Register</a> holds; its size is how many requirements changed. The map below is <a href="/standards/nist-sp-800-53">NIST SP 800-53</a>, release by release, family by family.</p>
    <div class="cols">
      <section class="main">
        <section class="box">
          <h2><a href="/register">Releases per standard</a> <span class="count">dot size = requirements changed</span></h2>
          ${rows.length ? timelineSvg(db, from, to) : html`<p class="small">No releases loaded in this window yet.</p>`}
          <p class="atlas-legend"><span class="key first">first version loaded</span><span class="key changed">release with changes</span><span class="key quiet">republished, no change</span></p>
        </section>
        <section class="box">
          <h2><a href="/standards/nist-sp-800-53">SP 800-53 change intensity by control family</a> <span class="count">rows = releases · cells = controls touched</span></h2>
          ${heatmapSvg(db)}
        </section>
      </section>
      <aside class="side">
        <section class="box">
          <h2>Change velocity <span class="count">trailing 12 months</span></h2>
          <div class="stat">
            <a href="/?kind=release"><small>Standard releases</small><b>${v.releases}</b></a>
            <a href="/register"><small>Requirements changed</small><b>${v.changedRequirements}</b></a>
            <a href="/?kind=kev"><small>KEV additions</small><b>${v.kevAdditions}</b></a>
            <a href="/?kind=vulnerability"><small>Notable CVEs</small><b>${v.notableCves}</b></a>
            <a href="/triage#affects"><small>Affects us (open)</small><b>${v.affectsUs}</b></a>
          </div>
        </section>
        <section class="box">
          <h2>Expected next <span class="count">from publisher cadence</span></h2>
          <ul class="due">${due.map((d) => html`<li><a href="${d.href}"><b>${d.what}</b><span class="d">${d.when}</span><span class="small">${d.basis}</span></a></li>`)}</ul>
        </section>
      </aside>
    </div>`;

  return page({ title: "Atlas", active: "atlas", content, meta: html`${v.releases} releases, 12 months`, owner, open, look });
}
