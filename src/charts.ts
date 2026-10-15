import { html, type Html } from "./html.ts";

/**
 * Charts, drawn on the server as inline SVG. No script runs in the browser and the content
 * security policy allows no inline style, so every figure is geometry computed here and colour
 * from a class: `t-<tone>` sets the custom property --tone, which the stylesheet reads for a
 * stroke, a fill or a legend dot, in both looks and both schemes.
 *
 * Every chart says what it shows in words too (role="img" with the figures in its label, a
 * legend with the numbers), because a chart that only a sighted person can read is half a chart.
 * Labels come from the data (a vendor's name from a feed, a source's name) and go through the
 * html template, so nothing a feed says is ever markup here.
 */

export type Tone = "acc" | "cyan" | "amber" | "red" | "green" | "purple" | "mute";

export interface Slice {
  label: string;
  value: number;
  tone: Tone;
}

const count = (n: number): string => Math.round(n).toLocaleString("en-US");
const positive = (slices: Slice[]): Slice[] => slices.filter((s) => Number.isFinite(s.value) && s.value > 0);
const summary = (slices: Slice[]): string => (positive(slices).length ? positive(slices).map((s) => `${s.label} ${count(s.value)}`).join(", ") : "nothing yet");

/** The legend under a chart: one dot and figure per slice, zeros included so a person sees what is counted. */
function legend(slices: Slice[]): Html {
  return html`<ul class="legend">${slices.map((s) => html`<li><i class="t-${s.tone}"></i>${s.label} <b>${count(Math.max(0, s.value))}</b></li>`)}</ul>`;
}

/**
 * A donut: each slice an arc of one ring, the total (or a word) in the middle. Arcs are drawn
 * with a dash the length of the slice along the ring's circumference, each offset by what came
 * before. A zero total draws the empty track and says so.
 */
export function donut(slices: Slice[], options: { label: string; centre?: string; size?: number }): Html {
  const size = options.size ?? 168;
  const half = size / 2;
  const radius = Math.round(size * 0.37 * 100) / 100;
  const stroke = Math.round(size * 0.13 * 100) / 100;
  const circumference = 2 * Math.PI * radius;
  const shown = positive(slices);
  const total = shown.reduce((n, s) => n + s.value, 0);
  let offset = 0;
  const arcs = shown.map((s) => {
    const length = (s.value / total) * circumference;
    const arc = html`<circle class="arc t-${s.tone}" cx="${half}" cy="${half}" r="${radius}" stroke-width="${stroke}" stroke-dasharray="${length.toFixed(2)} ${Math.max(0, circumference - length).toFixed(2)}" stroke-dashoffset="${(offset === 0 ? 0 : -offset).toFixed(2)}"><title>${s.label}: ${count(s.value)}</title></circle>`;
    offset += length;
    return arc;
  });
  return html`<figure class="chart donut">
    <svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img" aria-label="${options.label}: ${summary(slices)}">
      <g transform="rotate(-90 ${half} ${half})">
        <circle class="track" cx="${half}" cy="${half}" r="${radius}" stroke-width="${stroke}"></circle>
        ${arcs}
      </g>
      <text class="centre" x="${half}" y="${half}" text-anchor="middle" dominant-baseline="central">${options.centre ?? count(total)}</text>
    </svg>
    <figcaption>${legend(slices)}</figcaption>
  </figure>`;
}

/**
 * Horizontal bars, one row each: the label, a bar as a share of the largest, the figure. The
 * row's words carry the meaning; the bar is decoration for the eye.
 */
export function bars(rows: Slice[], options: { label: string }): Html {
  const max = Math.max(1, ...rows.map((r) => (Number.isFinite(r.value) ? r.value : 0)));
  return html`<ul class="chart bars" aria-label="${options.label}">${rows.map((r) => {
    const value = Number.isFinite(r.value) ? Math.max(0, r.value) : 0;
    const width = Math.min(100, (value / max) * 100);
    return html`<li><span>${r.label}</span><svg viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true"><rect class="t-${r.tone}" x="0" y="0" width="${width.toFixed(1)}" height="8" rx="1"></rect></svg><b>${count(value)}</b></li>`;
  })}</ul>`;
}

export interface Series {
  label: string;
  tone: Tone;
  /** One value per tick, in order. */
  values: number[];
}

/** A round number at or above `n` for the top of an axis: 1, 2, 5 times a power of ten. */
export function niceCeiling(n: number): number {
  if (!Number.isFinite(n) || n <= 0) return 1;
  const power = 10 ** Math.floor(Math.log10(n));
  for (const step of [1, 2, 5, 10]) if (step * power >= n) return step * power;
  return 10 * power;
}

/**
 * Lines over time: one polyline per series on a shared axis, four grid lines with their values,
 * the first, middle and last ticks named. The label says each series' total and its last value.
 */
export function lines(series: Series[], options: { label: string; ticks: string[]; width?: number; height?: number }): Html {
  const width = options.width ?? 400;
  const height = options.height ?? 170;
  const left = 34;
  const right = 8;
  const top = 10;
  const bottom = 26;
  const ticks = options.ticks;
  const n = Math.max(1, ticks.length);
  const max = niceCeiling(Math.max(1, ...series.flatMap((s) => s.values.filter((v) => Number.isFinite(v)))));
  const x = (i: number): number => (n === 1 ? left : left + (i / (n - 1)) * (width - left - right));
  const y = (v: number): number => top + (1 - Math.max(0, Math.min(max, v)) / max) * (height - top - bottom);
  const rows = [0, 0.25, 0.5, 0.75, 1].map((f) => ({ v: max * f, y: y(max * f) }));
  const polylines = series.map((s) => {
    const points = ticks.map((_, i) => `${x(i).toFixed(1)},${y(s.values[i] ?? 0).toFixed(1)}`).join(" ");
    const last = s.values[n - 1] ?? 0;
    return html`<polyline class="t-${s.tone}" points="${points}"></polyline><circle class="t-${s.tone}" cx="${x(n - 1).toFixed(1)}" cy="${y(last).toFixed(1)}" r="3"></circle>`;
  });
  const words = series.map((s) => `${s.label} ${count(s.values.reduce((a, b) => a + (Number.isFinite(b) ? b : 0), 0))} in all, ${count(s.values[n - 1] ?? 0)} on ${ticks[n - 1] ?? "the last day"}`).join("; ");
  const named = [0, Math.floor((n - 1) / 2), n - 1].filter((i, k, all) => all.indexOf(i) === k);
  return html`<figure class="chart lines">
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${options.label}: ${words}">
      <g class="grid">${rows.map((r) => html`<line x1="${left}" x2="${width - right}" y1="${r.y.toFixed(1)}" y2="${r.y.toFixed(1)}"></line>`)}</g>
      <g class="axis">${rows.map((r) => html`<text x="${left - 6}" y="${(r.y + 3.5).toFixed(1)}" text-anchor="end">${count(r.v)}</text>`)}${named.map((i) => html`<text x="${x(i).toFixed(1)}" y="${height - 8}" text-anchor="${i === 0 ? "start" : i === n - 1 ? "end" : "middle"}">${ticks[i]}</text>`)}</g>
      ${polylines}
    </svg>
    <figcaption>${legend(series.map((s) => ({ label: s.label, tone: s.tone, value: s.values.reduce((a, b) => a + (Number.isFinite(b) ? b : 0), 0) })))}</figcaption>
  </figure>`;
}

/** One bar split into its parts, left to right, with the legend: a whole and how it divides. */
export function stacked(parts: Slice[], options: { label: string }): Html {
  const shown = positive(parts);
  const total = shown.reduce((n, s) => n + s.value, 0);
  let at = 0;
  const rects = shown.map((s) => {
    const width = (s.value / total) * 100;
    const rect = html`<rect class="t-${s.tone}" x="${at.toFixed(2)}" y="0" width="${width.toFixed(2)}" height="10"><title>${s.label}: ${count(s.value)}</title></rect>`;
    at += width;
    return rect;
  });
  return html`<figure class="chart stacked">
    <svg viewBox="0 0 100 10" preserveAspectRatio="none" role="img" aria-label="${options.label}: ${summary(parts)}">${total ? rects : html`<rect class="track" x="0" y="0" width="100" height="10"></rect>`}</svg>
    <figcaption>${legend(parts)}</figcaption>
  </figure>`;
}
