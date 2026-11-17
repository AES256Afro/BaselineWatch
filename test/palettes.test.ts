import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

/**
 * The stylesheet's four palettes: the Register and the Console looks, each light and dark. Every
 * one has to define the same names, because a page draws the same markup under all four and a
 * token missing from one of them is a colour that silently falls back to nothing.
 *
 * This lived in test/charts.test.ts, which was the only thing drawing those tones. The charts are
 * gone; the contract they relied on is not.
 */

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
    // --tone used to be the exception: the charts set it on a class rather than on :root. With the
    // charts gone the rule holds without an exception, which is the point of checking it.
    const used = new Set([...css.matchAll(/var\(--([a-z0-9-]+)\)/g)].map((m) => m[1]!));
    for (const name of used) expect(blocks[0]!.names.has(name), `--${name} is used but never defined`).toBe(true);
  });

  it("give every chip's text at least 4.5:1 against its ground, in all four palettes", () => {
    // Each pair is a chip's text and the colour under it, as the rules draw them: .chip.ok is
    // --ins-ink on --ins, the tinted chips their tone on its -bg, and so on. The dark .chip.ok was
    // white on a pale green, 1.7:1, before --ins-ink.
    const tokens = [...css.matchAll(/(:root[^{]*)\{([^}]*)\}/g)].map((m) => ({ selector: m[1]!.trim(), values: Object.fromEntries([...m[2]!.matchAll(/--([a-z0-9-]+)\s*:\s*(#[0-9a-f]{6})\s*;/gi)].map((x) => [x[1]!, x[2]!])) }));
    const luminance = (hex: string): number => {
      const [r, g, b] = hex.slice(1).match(/../g)!.map((x) => parseInt(x, 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
      return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
    };
    const ratio = (a: string, b: string): number => {
      const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
      return (hi! + 0.05) / (lo! + 0.05);
    };
    const pairs: [string, string][] = [
      ["ins-ink", "ins"], ["ins", "ins-bg"], ["del", "del-bg"], ["warn", "warn-bg"], ["paper", "del"],
      ["mute", "paper"], ["mute", "panel-2"], ["gen", "panel-2"], ["acc", "card"], ["acc", "paper"], ["acc-ink", "acc"],
    ];
    for (const block of tokens) {
      for (const [fg, bg] of pairs) {
        const a = block.values[fg], b = block.values[bg];
        expect(a && b, `${block.selector} lacks --${fg} or --${bg}`).toBeTruthy();
        expect(ratio(a!, b!), `${block.selector}: --${fg} on --${bg}`).toBeGreaterThanOrEqual(4.5);
      }
    }
  });
});
