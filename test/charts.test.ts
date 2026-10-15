import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { bars, donut, lines, niceCeiling, stacked } from "../src/charts.ts";

describe("charts", () => {
  it("draw a donut whose arcs cover the ring once, skip zero slices, and say the figures in words", () => {
    const svg = donut([{ label: "Ahsay", value: 3, tone: "cyan" }, { label: "Other", value: 12, tone: "mute" }, { label: "None", value: 0, tone: "green" }], { label: "Known exploited by vendor" }).value;
    const arcs = [...svg.matchAll(/stroke-dasharray="([\d.]+) ([\d.]+)"/g)].map((m) => [Number(m[1]), Number(m[2])] as const);
    expect(arcs).toHaveLength(2);
    const circumference = 2 * Math.PI * 62.16;
    expect(arcs.reduce((n, [length]) => n + length, 0)).toBeCloseTo(circumference, 0);
    for (const [length, gap] of arcs) expect(length + gap).toBeCloseTo(circumference, 0);
    expect(svg).toContain('stroke-dashoffset="0.00"');
    expect(svg).toContain('aria-label="Known exploited by vendor: Ahsay 3, Other 12"');
    expect(svg).toContain(">15</text>");
    expect(svg).toContain("None <b>0</b>");
    expect(svg).toContain("<title>Ahsay: 3</title>");
  });

  it("draw an empty ring for nothing, and escape what the feeds say", () => {
    const svg = donut([{ label: "<b>Vendor</b> & co", value: 0, tone: "cyan" }], { label: "x", centre: "none" }).value;
    expect(svg).not.toContain('class="arc');
    expect(svg).toContain("x: nothing yet");
    expect(svg).toContain(">none</text>");
    expect(svg).toContain("&lt;b&gt;Vendor&lt;/b&gt; &amp; co");
    expect(svg).not.toContain("<b>Vendor");
  });

  it("scale bars to the largest, and clamp a value that is not a number", () => {
    const text = bars([{ label: "Critical", value: 6, tone: "red" }, { label: "High", value: 12, tone: "amber" }, { label: "Low", value: Number.NaN, tone: "green" }], { label: "By severity" }).value;
    expect(text).toContain('<rect class="t-red" x="0" y="0" width="50.0"');
    expect(text).toContain('<rect class="t-amber" x="0" y="0" width="100.0"');
    expect(text).toContain('<rect class="t-green" x="0" y="0" width="0.0"');
    expect(text).toContain('aria-label="By severity"');
    expect(text).toContain("<b>12</b>");
    expect(bars([], { label: "Nothing" }).value).toContain('<ul class="chart bars" aria-label="Nothing"></ul>');
  });

  it("round an axis up to 1, 2 or 5 times a power of ten", () => {
    expect([0, 1, 3, 7, 10, 11, 42, 99, 101, 450, 1200, Number.NaN].map(niceCeiling)).toEqual([1, 1, 5, 10, 10, 20, 50, 100, 200, 500, 2000, 1]);
  });

  it("draw one polyline per series with a point per tick, and the totals in words", () => {
    const text = lines([{ label: "News", tone: "cyan", values: [1, 2, 3] }, { label: "Standards", tone: "amber", values: [0, 0, 1] }], { label: "Items a day", ticks: ["10-01", "10-02", "10-03"] }).value;
    const polylines = [...text.matchAll(/<polyline class="t-(\w+)" points="([^"]+)"/g)];
    expect(polylines.map((m) => m[1])).toEqual(["cyan", "amber"]);
    expect(polylines[0]![2]!.split(" ")).toHaveLength(3);
    expect(text).toContain('aria-label="Items a day: News 6 in all, 3 on 10-03; Standards 1 in all, 1 on 10-03"');
    expect(text).toContain(">10-01</text>");
    expect(text).toContain(">10-02</text>");
    expect(text).toContain(">10-03</text>");
    expect(text).toContain(">5</text>");
    // A single tick still draws, and a value past the axis is held to it.
    expect(lines([{ label: "One", tone: "cyan", values: [7] }], { label: "x", ticks: ["10-01"] }).value).toContain("<polyline");
  });

  it("split a stacked bar by share, to a hundred, and draw the track when there is nothing", () => {
    const text = stacked([{ label: "New", value: 1, tone: "cyan" }, { label: "Done", value: 3, tone: "green" }], { label: "Triage" }).value;
    expect(text).toContain('<rect class="t-cyan" x="0.00" y="0" width="25.00"');
    expect(text).toContain('<rect class="t-green" x="25.00" y="0" width="75.00"');
    expect(text).toContain('aria-label="Triage: New 1, Done 3"');
    expect(stacked([{ label: "New", value: 0, tone: "cyan" }], { label: "Triage" }).value).toContain('class="track"');
  });
});

describe("the stylesheet's palettes", () => {
  const css = readFileSync(path.join(import.meta.dirname, "..", "public", "app.css"), "utf8");
  const blocks = [...css.matchAll(/(:root[^{]*)\{([^}]*)\}/g)].map((m) => ({ selector: m[1]!.trim(), names: new Set([...m[2]!.matchAll(/--([a-z0-9-]+)\s*:/g)].map((x) => x[1]!)) }));

  it("are the Register and the Console looks, each light and dark, every one defining the same names", () => {
    expect(blocks.map((b) => b.selector)).toEqual([
      ":root",
      ':root:not([data-scheme="light"])',
      ':root[data-scheme="dark"]',
      ':root[data-look="console"]',
      ':root[data-look="console"]:not([data-scheme="light"])',
      ':root[data-look="console"][data-scheme="dark"]',
    ]);
    const fonts = new Set(["serif", "sans", "mono"]);
    const colours = [...blocks[0]!.names].filter((n) => !fonts.has(n));
    expect(colours.length).toBeGreaterThan(20);
    for (const block of blocks.slice(1)) for (const name of colours) expect(block.names.has(name), `${block.selector} lacks --${name}`).toBe(true);
  });

  it("use no token they never define", () => {
    const used = new Set([...css.matchAll(/var\(--([a-z0-9-]+)\)/g)].map((m) => m[1]!));
    const defined = new Set([...blocks[0]!.names, "tone"]);
    for (const name of used) expect(defined.has(name), `--${name} is used but never defined`).toBe(true);
  });
});
