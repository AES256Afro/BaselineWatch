import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { reportStyles, type ReportStyle } from "../src/report.ts";

// The printable checklist draws each report look with plain CSS (public/app.css, the
// .export[data-report=…] rules) while the Word, PDF and LaTeX exports draw it from reportStyles.
// Two copies of one palette drift unless something holds them together; this reads every rule of
// every look and compares its colours with the table's.

const css = readFileSync(path.join(import.meta.dirname, "..", "public", "app.css"), "utf8");

/** "#fff" and "#f2f2f2" as the table writes them: six upper-case hex digits. */
function hex(value: string): string {
  const digits = value.replace(/^#/, "");
  return (digits.length === 3 ? [...digits].map((d) => d + d).join("") : digits).toUpperCase();
}

/** Each colour the CSS gives one look, keyed by the ReportStyle colour it stands for. */
function cssColours(id: string): { key: keyof ReportStyle["colors"] | "page"; value: string; rule: string }[] {
  const prefix = `.export[data-report="${id}"]`;
  const out: { key: keyof ReportStyle["colors"] | "page"; value: string; rule: string }[] = [];
  for (const line of css.split("\n")) {
    if (!line.startsWith(prefix)) continue;
    const match = /^(.*?)\{(.*)\}\s*$/.exec(line);
    if (!match) continue;
    const selector = match[1]!.trim();
    const target = selector.split(",").at(-1)!.trim().slice(prefix.length).trim();
    for (const declaration of match[2]!.split(";")) {
      const [property, raw] = declaration.split(":").map((s) => s?.trim());
      if (!property || !raw) continue;
      const colour = /#[0-9a-f]{3,6}\b/i.exec(raw)?.[0];
      if (!colour) continue;
      const value = hex(colour);
      const at = (key: keyof ReportStyle["colors"] | "page") => out.push({ key, value, rule: `${selector} { ${property} }` });
      if (property === "border-color" || property === "border-bottom" || property === "border") at("rule");
      else if (target === "" && property === "color") at("ink");
      else if (target === "" && property === "background") at("page");
      else if (target === "h2" && property === "color") at("heading");
      else if (target === "th" && property === "background") at("headFill");
      else if (target === "th" && property === "color") at("headInk");
      else if (target === "pre" && property === "background") at("codeFill");
      else if (target === "pre" && property === "color") at("codeInk");
      else if (target === "a" && property === "color") at("accent");
      else throw new Error(`a colour this test does not map: ${selector} { ${property}: ${raw} }`);
    }
  }
  return out;
}

describe("report looks in the stylesheet", () => {
  it.each(reportStyles.map((s) => [s.id, s] as const))("draws %s in the colours reportStyles gives it", (id, style) => {
    const colours = cssColours(id);
    // Every look sets each of these at least once.
    expect(new Set(colours.map((c) => c.key))).toEqual(new Set(["ink", "page", "heading", "rule", "headFill", "headInk", "codeFill", "codeInk", "accent"]));
    for (const c of colours) {
      const expected = c.key === "page" ? (style.colors.page ?? "FFFFFF") : style.colors[c.key];
      expect(c.value, c.rule).toBe(expected?.toUpperCase());
    }
  });

  it("has a rule set for every look and none for a look the table does not have", () => {
    const inCss = new Set([...css.matchAll(/\.export\[data-report="([\w-]+)"\]/g)].map((m) => m[1]));
    expect([...inCss].sort()).toEqual(reportStyles.map((s) => s.id).sort());
  });
});
