import type { DatabaseSync } from "node:sqlite";
import { expectedNext, familyHeatmap, releaseTimeline, velocity } from "../atlas.ts";
import { html, type Html } from "../html.ts";
import { page } from "./layout.ts";

const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function quarterLabel(d: Date): string {
  return `Q${Math.floor(d.getUTCMonth() / 3) + 1} ${d.getUTCFullYear()}`;
}

/** The release timeline as inline SVG; positions are attributes, so the strict CSP is untouched. */
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
        <text class="label" x="0" y="${y + 4}">${row.name.length > 32 ? `${row.name.slice(0, 31)}…` : row.name}</text>
        <line class="track" x1="${labelW}" y1="${y}" x2="${W - 20}" y2="${y}"></line>
        ${row.releases.map((r) => {
          const radius = r.first ? 4 : 5 + Math.min(9, Math.sqrt(r.changes));
          return html`<a href="/standards/${row.sourceId}/${r.documentId}"><circle class="dot ${r.first ? "first" : r.changes ? "changed" : "quiet"}" cx="${x(r.publishedAt).toFixed(1)}" cy="${y}" r="${radius.toFixed(1)}"><title>${r.key} ${r.version ?? ""} · ${r.publishedAt.slice(0, 10)} · ${r.first ? "first version loaded" : `${r.changes} changed`}</title></circle></a>`;
        })}
      </g>`;
    })}
  </svg>`;
}

function heatmapSvg(db: DatabaseSync): Html {
  const map = familyHeatmap(db);
  if (map.rows.length === 0) return html`<p class="small">No NIST SP 800-53 catalog loaded yet.</p>`;
  const cell = 34;
  const labelW = 150;
  const W = labelW + map.families.length * cell + 10;
  const H = 24 + map.rows.length * cell + 6;
  const level = (n: number) => (n === 0 ? 0 : map.max <= 1 ? 4 : Math.min(4, 1 + Math.floor((n / map.max) * 3.99)));
  return html`<svg class="atlas-svg heat" viewBox="0 0 ${W} ${H}" role="img" aria-label="Changed controls per family per release">
    ${map.families.map((f, i) => html`<text class="axis" x="${labelW + i * cell + cell / 2}" y="16" text-anchor="middle">${f}</text>`)}
    ${map.rows.map((r, j) => {
      const y = 24 + j * cell;
      return html`<g>
        <text class="label" x="0" y="${y + cell / 2 + 4}">${r.version ?? "?"}${r.publishedAt ? ` · ${r.publishedAt.slice(0, 7)}` : ""}</text>
        ${map.families.map((f, i) => {
          const n = r.counts[f] ?? 0;
          return html`<rect class="cell l${r.first ? 0 : level(n)}" x="${labelW + i * cell + 2}" y="${y + 2}" width="${cell - 4}" height="${cell - 4}" rx="3"><title>${f} · ${r.version ?? ""}: ${r.first ? "first version" : `${n} changed`}</title></rect>`;
        })}
      </g>`;
    })}
  </svg>`;
}

export function renderAtlas(options: { db: DatabaseSync; owner: boolean; open: boolean; now: Date }): string {
  const { db, owner, open, now } = options;
  const to = now;
  const from = new Date(Date.UTC(now.getUTCFullYear() - 1, now.getUTCMonth() - 3, 1));
  const rows = releaseTimeline(db, from.toISOString(), to.toISOString());
  const v = velocity(db, new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000).toISOString());
  const due = expectedNext(db, now);

  const content = html`
    <div class="wire-top">
      <h1>Atlas</h1>
      <div class="small">${from.getUTCDate()} ${monthNames[from.getUTCMonth()]} ${from.getUTCFullYear()} → today · ${rows.length} standards with releases in view</div>
    </div>
    <p class="lede">Being in tune means knowing the rhythm, not just today's note. Each dot is a release the Register holds; its size is how many requirements changed. The map below is NIST SP 800-53, release by release, family by family.</p>
    <div class="cols">
      <section class="main">
        <section class="box">
          <h2>Releases per standard <span class="count">dot size = requirements changed</span></h2>
          ${rows.length ? timelineSvg(db, from, to) : html`<p class="small">No releases loaded in this window yet.</p>`}
          <p class="legend"><span class="key first">first version loaded</span><span class="key changed">release with changes</span><span class="key quiet">republished, no change</span></p>
        </section>
        <section class="box">
          <h2>SP 800-53 change intensity by control family <span class="count">rows = releases · cells = controls touched</span></h2>
          ${heatmapSvg(db)}
        </section>
      </section>
      <aside class="side">
        <section class="box">
          <h2>Change velocity <span class="count">trailing 12 months</span></h2>
          <div class="stat">
            <div><small>Standard releases</small><b>${v.releases}</b></div>
            <div><small>Requirements changed</small><b>${v.changedRequirements}</b></div>
            <div><small>KEV additions</small><b>${v.kevAdditions}</b></div>
            <div><small>Notable CVEs</small><b>${v.notableCves}</b></div>
            <div><small>Affects us (open)</small><b>${v.affectsUs}</b></div>
          </div>
        </section>
        <section class="box">
          <h2>Expected next <span class="count">from publisher cadence</span></h2>
          <ul class="due">${due.map((d) => html`<li><b>${d.what}</b><span class="d">${d.when}</span><span class="small">${d.basis}</span></li>`)}</ul>
        </section>
      </aside>
    </div>`;

  return page({ title: "Atlas", active: "atlas", content, meta: html`${v.releases} releases, 12 months`, owner, open });
}
