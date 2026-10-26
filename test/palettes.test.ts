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
});
