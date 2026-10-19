import { unzipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { pdfText } from "../src/pdf.ts";
import { renderDocx, renderLatex, renderPdf, type Block } from "../src/report.ts";

const sample: Block[] = [
  { type: "title", text: "macOS test plan: Tahoe & friends" },
  { type: "subtitle", text: "Generated 2026-10-19" },
  { type: "h1", text: "Hardware root of trust (2)" },
  { type: "check", runs: [{ text: "hardware-root-macos 1", bold: true }, " Identify the chip"] },
  { type: "code", text: "system_profiler SPHardwareDataType\nsudo bputil -d" },
  { type: "p", runs: [{ text: "Success looks like: ", bold: true }, "Full Security, 100% of the time"] },
  { type: "bullet", runs: ["A note with <angle> brackets and a “quote”"] },
  { type: "table", header: ["Role", "Name"], rows: [["Prepared by", ""], ["Approved by", "Chris"]] },
];

describe("report renderers", () => {
  it("writes LaTeX with the special characters escaped and the lists and tables closed", () => {
    const tex = renderLatex(sample);
    expect(tex).toMatch(/^\\documentclass/);
    expect(tex).toContain("\\title{macOS test plan: Tahoe \\& friends}");
    expect(tex).toContain("\\section*{Hardware root of trust (2)}");
    expect(tex).toContain("\\begin{itemize}[label=$\\square$]");
    expect(tex).toContain("\\textbf{hardware-root-macos 1} Identify the chip");
    expect(tex).toContain("Full Security, 100\\% of the time");
    expect(tex).toContain("\\begin{Verbatim}");
    expect(tex).toContain("\\begin{longtable}");
    expect(tex).toContain("\\textbf{Role} & \\textbf{Name} \\\\ \\hline");
    expect(tex).toContain('"quote"');
    expect(tex.trim().endsWith("\\end{document}")).toBe(true);
    expect((tex.match(/\\begin\{itemize\}/g) ?? []).length).toBe((tex.match(/\\end\{itemize\}/g) ?? []).length);
  });

  it("writes a Word document Office can open: the parts, the styles and the text", () => {
    const bytes = renderDocx(sample);
    expect(bytes[0]).toBe(0x50); // P of PK
    const parts = unzipSync(bytes);
    expect(Object.keys(parts).sort()).toEqual(["[Content_Types].xml", "_rels/.rels", "word/_rels/document.xml.rels", "word/document.xml", "word/styles.xml"]);
    const doc = new TextDecoder().decode(parts["word/document.xml"]!);
    expect(doc).toContain('<w:pStyle w:val="Title"/>');
    expect(doc).toContain("macOS test plan: Tahoe &amp; friends");
    expect(doc).toContain('<w:pStyle w:val="Heading1"/>');
    expect(doc).toContain("☐ ");
    expect(doc).toContain("&lt;angle&gt; brackets");
    expect(doc).toContain("<w:tbl>");
    expect(doc).toContain('w:fill="E7E6E6"');
    expect(doc).toContain("<w:br/>"); // the second code line
    const styles = new TextDecoder().decode(parts["word/styles.xml"]!);
    expect(styles).toContain('w:styleId="Heading2"');
  });

  it("writes a PDF that reads back, wraps long lines and numbers its pages", async () => {
    const bytes = renderPdf(sample);
    expect(new TextDecoder("latin1").decode(bytes.subarray(0, 8))).toBe("%PDF-1.4");
    const text = await pdfText(bytes);
    expect(text).toContain("macOS test plan: Tahoe & friends");
    expect(text).toContain("[ ] hardware-root-macos 1 Identify the chip");
    expect(text).toContain("sudo bputil -d");
    expect(text).toContain('"quote"'); // typographic quotes folded for WinAnsi
    expect(text).toContain("Page 1 of 1");
    const long: Block[] = [{ type: "title", text: "Long" }];
    for (let i = 0; i < 120; i += 1) long.push({ type: "p", runs: [`Paragraph ${i} ${"word ".repeat(40)}`] });
    const pages = await pdfText(renderPdf(long));
    expect(pages).toContain("Page 1 of");
    expect(pages).toMatch(/Page \d+ of (\d+)/);
    const total = Number(/Page 1 of (\d+)/.exec(pages)![1]);
    expect(total).toBeGreaterThan(3);
    expect(pages).toContain(`Page ${total} of ${total}`);
  });
});
