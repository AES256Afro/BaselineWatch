import { strToU8, zipSync } from "fflate";

/**
 * One document, three typeset forms. A report is a list of blocks (title, headings, paragraphs,
 * bullets, checklist lines, code, tables); each renderer below writes it as LaTeX for the team's
 * own template, as a Word document a reviewer edits, or as a plain PDF that prints anywhere.
 * Nothing here needs a library beyond the zip the .docx format is: the PDF is written by hand in
 * the standard PDF fonts with the text wrapped by measure, and the Word parts are the minimum
 * Office opens.
 *
 * Every renderer takes a style: the plain look, or one of the ten looks drawn in
 * docs/mockups/exports (formal assessment, engineering runbook, executive, compact checklist,
 * modern, dark console, board, audit workpaper, Markdown-native, Word). A style is colours,
 * typefaces, a cover page and numbered headings; the content is the same in all of them.
 */

export type Inline = string | { text: string; bold?: boolean; mono?: boolean };

export type Block =
  | { type: "title"; text: string }
  | { type: "subtitle"; text: string }
  | { type: "h1" | "h2" | "h3"; text: string }
  | { type: "p"; runs: Inline[] }
  | { type: "bullet"; runs: Inline[] }
  | { type: "check"; runs: Inline[] }
  | { type: "code"; text: string }
  | { type: "table"; header: string[]; rows: string[][] };

export interface ReportStyle {
  id: string;
  label: string;
  /** What the look is for, in a line, for the picker. */
  blurb: string;
  /** The mockup it follows, under docs/mockups/exports; null for the plain look. */
  mockup: string | null;
  /** Colours as six hex digits, no #. */
  colors: { ink: string; muted: string; heading: string; accent: string; rule: string; headFill: string; headInk: string; codeFill: string; codeInk: string; page: string | null };
  /** Word and LaTeX typefaces; the PDF uses the nearest standard font. */
  fonts: { body: string; heading: string; mono: string; pdf: "helvetica" | "times" | "courier" };
  /** Body size in points. */
  size: number;
  /** A cover page: the title and summary alone on the first page. */
  cover: boolean;
  /** Numbered top-level headings (1., 2., 3.). */
  numbered: boolean;
  /** A rule under each top-level heading. */
  band: boolean;
}

const base = { ink: "1A1A1A", muted: "595959", rule: "999999", codeFill: "F2F2F2", codeInk: "1A1A1A", page: null };

export const reportStyles: ReportStyle[] = [
  {
    id: "plain",
    label: "Plain",
    blurb: "Calibri and grey tables, nothing else: the look before styles.",
    mockup: null,
    colors: { ...base, heading: "1A1A1A", accent: "1A1A1A", headFill: "E7E6E6", headInk: "1A1A1A" },
    fonts: { body: "Calibri", heading: "Calibri", mono: "Consolas", pdf: "helvetica" },
    size: 11,
    cover: false,
    numbered: false,
    band: false,
  },
  {
    id: "formal",
    label: "Formal assessment",
    blurb: "A government assessment report in the SP 800-53A manner: serif headings, numbered sections, cover page.",
    mockup: "01-formal-assessment.html",
    colors: { ...base, heading: "1F3A5F", accent: "1F3A5F", rule: "9A9A9A", headFill: "E9E9E4", headInk: "1A1A1A" },
    fonts: { body: "Cambria", heading: "Cambria", mono: "Consolas", pdf: "times" },
    size: 11,
    cover: true,
    numbered: true,
    band: true,
  },
  {
    id: "runbook",
    label: "Engineering runbook",
    blurb: "For the engineer at the keyboard: monospaced headings, dark command blocks.",
    mockup: "02-engineering-runbook.html",
    colors: { ink: "16181D", muted: "5F6672", heading: "2457C5", accent: "2457C5", rule: "D8DCE3", headFill: "0F1720", headInk: "D7E3F4", codeFill: "0F1720", codeInk: "D7E3F4", page: null },
    fonts: { body: "Segoe UI", heading: "Consolas", mono: "Consolas", pdf: "helvetica" },
    size: 10,
    cover: false,
    numbered: true,
    band: false,
  },
  {
    id: "executive",
    label: "Executive",
    blurb: "Navy and teal with a cover page: for the people who sign it off.",
    mockup: "03-executive-onepager.html",
    colors: { ink: "111827", muted: "6B7280", heading: "0B2545", accent: "13838F", rule: "E5E7EB", headFill: "0B2545", headInk: "FFFFFF", codeFill: "F3F4F6", codeInk: "111827", page: null },
    fonts: { body: "Calibri", heading: "Calibri Light", mono: "Consolas", pdf: "helvetica" },
    size: 11,
    cover: true,
    numbered: false,
    band: true,
  },
  {
    id: "checklist",
    label: "Compact checklist",
    blurb: "Black on white, small type, no cover: prints the most checks per page.",
    mockup: "04-compact-checklist.html",
    colors: { ink: "000000", muted: "555555", heading: "000000", accent: "000000", rule: "999999", headFill: "F0F0F0", headInk: "000000", codeFill: "F7F7F7", codeInk: "000000", page: null },
    fonts: { body: "Arial", heading: "Arial", mono: "Courier New", pdf: "helvetica" },
    size: 9,
    cover: false,
    numbered: false,
    band: false,
  },
  {
    id: "modern",
    label: "Modern",
    blurb: "A clean product look in indigo and slate.",
    mockup: "05-modern-saas.html",
    colors: { ink: "0F172A", muted: "64748B", heading: "5B5BD6", accent: "5B5BD6", rule: "E8EBF2", headFill: "EEF0FF", headInk: "0F172A", codeFill: "F6F7FB", codeInk: "0F172A", page: null },
    fonts: { body: "Segoe UI", heading: "Segoe UI Semibold", mono: "Consolas", pdf: "helvetica" },
    size: 10.5,
    cover: false,
    numbered: false,
    band: false,
  },
  {
    id: "console",
    label: "Dark console",
    blurb: "Light text on a dark page, terminal colours: for screens, not paper.",
    mockup: "06-dark-console.html",
    colors: { ink: "C9D4E0", muted: "6B7A8C", heading: "67E8F9", accent: "4ADE80", rule: "1F2A36", headFill: "111821", headInk: "4ADE80", codeFill: "111821", codeInk: "C9D4E0", page: "0B0F14" },
    fonts: { body: "Consolas", heading: "Consolas", mono: "Consolas", pdf: "courier" },
    size: 10,
    cover: false,
    numbered: false,
    band: true,
  },
  {
    id: "board",
    label: "Board",
    blurb: "Issue-tracker blues and lane greys, as the decisions board draws them.",
    mockup: "07-jira-kanban.html",
    colors: { ink: "172B4D", muted: "5E6C84", heading: "0C66E4", accent: "0C66E4", rule: "DFE1E6", headFill: "EBECF0", headInk: "172B4D", codeFill: "F4F5F7", codeInk: "172B4D", page: null },
    fonts: { body: "Segoe UI", heading: "Segoe UI Semibold", mono: "Consolas", pdf: "helvetica" },
    size: 10.5,
    cover: false,
    numbered: false,
    band: false,
  },
  {
    id: "workpaper",
    label: "Audit workpaper",
    blurb: "Ledger green and auditor blue, with room for initials and references.",
    mockup: "08-audit-workpaper.html",
    colors: { ink: "111111", muted: "4B4B4B", heading: "1A3FA0", accent: "B00020", rule: "9FB8A8", headFill: "E3EFE6", headInk: "111111", codeFill: "F3F8F1", codeInk: "111111", page: "FBFDF8" },
    fonts: { body: "Arial", heading: "Arial", mono: "Courier New", pdf: "helvetica" },
    size: 10,
    cover: true,
    numbered: true,
    band: true,
  },
  {
    id: "markdown",
    label: "Markdown-native",
    blurb: "How the report reads on GitHub: system fonts, ruled headings, grey code.",
    mockup: "09-markdown-native.html",
    colors: { ink: "1F2328", muted: "59636E", heading: "1F2328", accent: "0969DA", rule: "D1D9E0", headFill: "F6F8FA", headInk: "1F2328", codeFill: "F6F8FA", codeInk: "1F2328", page: null },
    fonts: { body: "Segoe UI", heading: "Segoe UI Semibold", mono: "Consolas", pdf: "helvetica" },
    size: 10.5,
    cover: false,
    numbered: false,
    band: true,
  },
  {
    id: "word",
    label: "Word",
    blurb: "Office's own blues: the house style of a document written in Word.",
    mockup: "10-docx-word.html",
    colors: { ink: "000000", muted: "595959", heading: "2F5496", accent: "4472C4", rule: "8EAADB", headFill: "D9E2F3", headInk: "000000", codeFill: "F2F2F2", codeInk: "000000", page: null },
    fonts: { body: "Calibri", heading: "Calibri Light", mono: "Consolas", pdf: "helvetica" },
    size: 11,
    cover: true,
    numbered: true,
    band: false,
  },
];

const plainStyle: ReportStyle = reportStyles[0]!;

export function reportStyle(id: unknown): ReportStyle {
  return reportStyles.find((s) => s.id === id) ?? plainStyle;
}

const plain = (runs: Inline[]): string => runs.map((r) => (typeof r === "string" ? r : r.text)).join("");

/** Top-level headings with their numbers when the style numbers them. */
function numberHeadings(blocks: Block[], style: ReportStyle): Block[] {
  if (!style.numbered) return blocks;
  let n = 0;
  return blocks.map((b) => (b.type === "h1" ? { ...b, text: `${++n}. ${b.text}` } : b));
}

// ---------------------------------------------------------------------------------------------
// LaTeX

const texEscape = (s: string): string =>
  s
    .replace(/\\/g, "\\textbackslash{}")
    .replace(/([&%$#_{}])/g, "\\$1")
    .replace(/~/g, "\\textasciitilde{}")
    .replace(/\^/g, "\\textasciicircum{}")
    .replace(/[“”„]/g, '"')
    .replace(/[‘’‚]/g, "'")
    .replace(/☐/g, "$\\square$")
    .replace(/→/g, "$\\rightarrow$")
    .replace(/←/g, "$\\leftarrow$")
    .replace(/≥/g, "$\\geq$")
    .replace(/≤/g, "$\\leq$")
    .replace(/≠/g, "$\\neq$")
    .replace(/…/g, "\\ldots{}")
    .replace(/–/g, "--")
    .replace(/—/g, "---")
    .replace(/[•·]/g, "\\textbullet{}")
    // inputenc with T1 carries Latin-1 and Latin Extended-A; anything beyond (CJK, emoji) would stop the compile, so it folds to ?.
    .replace(/[ƀ-￿]/g, "?");

const texRuns = (runs: Inline[]): string =>
  runs
    .map((r) => {
      if (typeof r === "string") return texEscape(r);
      let t = texEscape(r.text);
      if (r.mono) t = `\\texttt{${t}}`;
      if (r.bold) t = `\\textbf{${t}}`;
      return t;
    })
    .join("");

export function renderLatex(input: Block[], style: ReportStyle = plainStyle): string {
  const blocks = numberHeadings(input, style);
  const c = style.colors;
  // The plain look is the LaTeX it always was; the other looks add colour and a typeface.
  const styled = style.id !== plainStyle.id;
  const hue = (name: string): string => (styled ? `\\color{${name}}` : "");
  const out: string[] = [
    `\\documentclass[${style.size <= 9.5 ? 10 : style.size >= 11 ? 11 : 10}pt]{article}`,
    "\\usepackage[margin=1in]{geometry}",
    "\\usepackage[T1]{fontenc}",
    "\\usepackage[utf8]{inputenc}",
    "\\usepackage{amssymb}",
    "\\usepackage{longtable}",
    "\\usepackage{array}",
    "\\usepackage{enumitem}",
    "\\usepackage{hyperref}",
    "\\usepackage{fancyvrb}",
    "\\usepackage{fvextra}",
    "\\setlength{\\parskip}{4pt}",
    "\\setlength{\\parindent}{0pt}",
  ];
  if (styled) {
    out.push("\\usepackage[table]{xcolor}");
    for (const [name, hex] of [["ink", c.ink], ["heading", c.heading], ["rule", c.rule], ["headfill", c.headFill], ["headink", c.headInk]] as const) out.push(`\\definecolor{${name}}{HTML}{${hex}}`);
    out.push("\\arrayrulecolor{rule}");
    if (style.fonts.pdf === "times") out.push("\\usepackage{mathptmx}");
    else if (style.fonts.pdf === "courier") out.push("\\renewcommand{\\familydefault}{\\ttdefault}");
    else out.push("\\renewcommand{\\familydefault}{\\sfdefault}");
    if (c.page) out.push(`\\definecolor{page}{HTML}{${c.page}}`, "\\pagecolor{page}");
  }
  out.push("");
  const title = blocks.find((b) => b.type === "title");
  const subtitle = blocks.find((b) => b.type === "subtitle");
  if (title) out.push(`\\title{${hue("heading")}${texEscape(title.text)}}`, `\\date{${subtitle ? texEscape(subtitle.text) : ""}}`, "\\author{}");
  out.push("\\begin{document}");
  if (styled) out.push(hue("ink"));
  if (title) out.push("\\maketitle");
  if (title && style.cover) out.push("\\thispagestyle{empty}", "\\newpage");
  let list: "bullet" | "check" | null = null;
  const close = () => {
    if (list) out.push("\\end{itemize}");
    list = null;
  };
  for (const b of blocks) {
    if (b.type !== "bullet" && b.type !== "check") close();
    switch (b.type) {
      case "title":
      case "subtitle":
        break;
      case "h1":
        out.push(`\\section*{${hue("heading")}${texEscape(b.text)}}`);
        if (styled && style.band) out.push("{\\color{rule}\\hrule}");
        break;
      case "h2":
        out.push(`\\subsection*{${hue("heading")}${texEscape(b.text)}}`);
        break;
      case "h3":
        out.push(`\\subsubsection*{${texEscape(b.text)}}`);
        break;
      case "p":
        out.push(texRuns(b.runs), "");
        break;
      case "bullet":
      case "check":
        if (list !== b.type) {
          close();
          list = b.type;
          out.push(b.type === "check" ? "\\begin{itemize}[label=$\\square$]" : "\\begin{itemize}");
        }
        out.push(`  \\item ${texRuns(b.runs)}`);
        break;
      case "code":
        // A check procedure is quoted verbatim; an \end{Verbatim} inside it would close the block early
        // and hand the rest of the text to LaTeX, so that one token is kept from matching.
        out.push("\\begin{Verbatim}[fontsize=\\small,breaklines=true]", b.text.replace(/\r/g, "").replace(/\\end\s*\{\s*Verbatim\s*\}/g, "\\end {Verbatim}"), "\\end{Verbatim}");
        break;
      case "table": {
        const cols = b.header.length;
        out.push(`\\begin{longtable}{|${Array(cols).fill("p{\\dimexpr(\\linewidth-" + (cols + 1) * 2 + "\\tabcolsep)/" + cols + "\\relax}").join("|")}|}`, "\\hline");
        out.push(`${styled ? "\\rowcolor{headfill}" : ""}${b.header.map((h) => `\\textbf{${hue("headink")}${texEscape(h)}}`).join(" & ")} \\\\ \\hline`);
        out.push("\\endhead");
        for (const row of b.rows) out.push(`${row.map((cell) => texEscape(cell)).join(" & ")} \\\\ \\hline`);
        out.push("\\end{longtable}");
        break;
      }
    }
  }
  close();
  out.push("\\end{document}", "");
  return out.join("\n");
}

// ---------------------------------------------------------------------------------------------
// Word

/** Drops the characters XML 1.0 cannot carry: the C0 controls but tab, newline and return. */
// eslint-disable-next-line no-control-regex
const xmlSafe = (s: string): string => s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\ufffe\uffff]/g, "");
const xml = (s: string): string => xmlSafe(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function docxRun(r: Inline, options: { mono?: string | null; color?: string | null } = {}): string {
  const o = typeof r === "string" ? { text: r } : r;
  const props: string[] = [];
  if (o.bold) props.push("<w:b/>");
  const mono = options.mono ?? null;
  if (o.mono || mono) props.push(`<w:rFonts w:ascii="${xml(mono ?? "Consolas")}" w:hAnsi="${xml(mono ?? "Consolas")}" w:cs="${xml(mono ?? "Consolas")}"/><w:sz w:val="18"/>`);
  if (options.color) props.push(`<w:color w:val="${options.color}"/>`);
  const parts = xmlSafe(o.text).split(/\r?\n/);
  return parts.map((line, i) => `<w:r>${props.length ? `<w:rPr>${props.join("")}</w:rPr>` : ""}${i > 0 ? "<w:br/>" : ""}<w:t xml:space="preserve">${xml(line)}</w:t></w:r>`).join("");
}

function docxParagraph(runs: Inline[], options: { style?: string; mono?: string | null; indent?: boolean; prefix?: string; fill?: string; color?: string | null } = {}): string {
  const props: string[] = [];
  if (options.style) props.push(`<w:pStyle w:val="${options.style}"/>`);
  if (options.indent) props.push('<w:ind w:left="360" w:hanging="360"/>');
  if (options.fill) props.push(`<w:shd w:val="clear" w:color="auto" w:fill="${options.fill}"/>`);
  const run = { mono: options.mono ?? null, color: options.color ?? null };
  const body = (options.prefix ? docxRun(options.prefix, run) : "") + runs.map((r) => docxRun(r, run)).join("");
  return `<w:p>${props.length ? `<w:pPr>${props.join("")}</w:pPr>` : ""}${body}</w:p>`;
}

function docxTable(header: string[], rows: string[][], style: ReportStyle): string {
  const c = style.colors;
  const cell = (text: string, head: boolean) => `<w:tc><w:tcPr>${head ? `<w:shd w:val="clear" w:color="auto" w:fill="${c.headFill}"/>` : ""}</w:tcPr>${docxParagraph([{ text, bold: head }], head ? { color: c.headInk } : {})}</w:tc>`;
  const row = (cells: string[], head: boolean) => `<w:tr>${head ? "<w:trPr><w:tblHeader/></w:trPr>" : ""}${cells.map((cl) => cell(cl, head)).join("")}</w:tr>`;
  const border = (side: string) => `<w:${side} w:val="single" w:sz="4" w:color="${c.rule}"/>`;
  return `<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders>${["top", "left", "bottom", "right", "insideH", "insideV"].map(border).join("")}</w:tblBorders></w:tblPr>${row(header, true)}${rows.map((r) => row(r, false)).join("")}</w:tbl><w:p/>`;
}

export function renderDocx(input: Block[], style: ReportStyle = plainStyle): Uint8Array {
  const blocks = numberHeadings(input, style);
  const c = style.colors;
  const body: string[] = [];
  for (const b of blocks) {
    switch (b.type) {
      case "title":
        body.push(docxParagraph([b.text], { style: "Title" }));
        break;
      case "subtitle":
        body.push(docxParagraph([b.text], { style: "Subtitle" }));
        if (style.cover) body.push('<w:p><w:r><w:br w:type="page"/></w:r></w:p>');
        break;
      case "h1":
        body.push(docxParagraph([b.text], { style: "Heading1" }));
        break;
      case "h2":
        body.push(docxParagraph([b.text], { style: "Heading2" }));
        break;
      case "h3":
        body.push(docxParagraph([b.text], { style: "Heading3" }));
        break;
      case "p":
        body.push(docxParagraph(b.runs));
        break;
      case "bullet":
        body.push(docxParagraph(b.runs, { indent: true, prefix: "• " }));
        break;
      case "check":
        body.push(docxParagraph(b.runs, { indent: true, prefix: "☐ " }));
        break;
      case "code":
        body.push(docxParagraph([b.text], { mono: style.fonts.mono, fill: c.codeFill, color: c.codeInk }));
        break;
      case "table":
        body.push(docxTable(b.header, b.rows, style));
        break;
    }
  }
  const half = (pt: number) => Math.round(pt * 2);
  const font = (name: string) => `<w:rFonts w:ascii="${xml(name)}" w:hAnsi="${xml(name)}" w:cs="${xml(name)}"/>`;
  const band = style.band ? `<w:pBdr><w:bottom w:val="single" w:sz="8" w:space="2" w:color="${c.rule}"/></w:pBdr>` : "";
  const background = c.page ? `<w:background w:color="${c.page}"/>` : "";
  const document = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">${background}<w:body>${body.join("")}<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr></w:body></w:document>`;
  const styles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr>${font(style.fonts.body)}<w:color w:val="${c.ink}"/><w:sz w:val="${half(style.size)}"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="${style.cover ? 2400 : 0}" w:after="200"/></w:pPr><w:rPr>${font(style.fonts.heading)}<w:b/><w:color w:val="${c.heading}"/><w:sz w:val="${half(style.size * 2)}"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="${c.muted}"/><w:sz w:val="${half(style.size + 1)}"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/>${band}<w:spacing w:before="360" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr>${font(style.fonts.heading)}<w:b/><w:color w:val="${c.heading}"/><w:sz w:val="${half(style.size + 5)}"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr>${font(style.fonts.heading)}<w:b/><w:color w:val="${c.heading}"/><w:sz w:val="${half(style.size + 2)}"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="200" w:after="60"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr>${font(style.fonts.heading)}<w:b/><w:sz w:val="${half(style.size + 0.5)}"/></w:rPr></w:style>
</w:styles>`;
  // A page colour shows in Word only when the settings say to display it.
  const settings = c.page
    ? `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:displayBackgroundShape/></w:settings>`
    : null;
  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>${settings ? '<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>' : ""}</Types>`;
  const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`;
  const docRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>${settings ? '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>' : ""}</Relationships>`;
  const files: Record<string, Uint8Array> = {
    "[Content_Types].xml": strToU8(contentTypes),
    "_rels/.rels": strToU8(rels),
    "word/document.xml": strToU8(document),
    "word/_rels/document.xml.rels": strToU8(docRels),
    "word/styles.xml": strToU8(styles),
  };
  if (settings) files["word/settings.xml"] = strToU8(settings);
  return zipSync(files, { level: 6 });
}

// ---------------------------------------------------------------------------------------------
// PDF

/** Helvetica's advance widths per 1000 units for the printable Latin-1 range; anything else counts as 556 (a digit). */
const helvetica: Record<string, number> = {
  " ": 278, "!": 278, '"': 355, "#": 556, $: 556, "%": 889, "&": 667, "'": 191, "(": 333, ")": 333, "*": 389, "+": 584, ",": 278, "-": 333, ".": 278, "/": 278,
  "0": 556, "1": 556, "2": 556, "3": 556, "4": 556, "5": 556, "6": 556, "7": 556, "8": 556, "9": 556, ":": 278, ";": 278, "<": 584, "=": 584, ">": 584, "?": 556, "@": 1015,
  A: 667, B: 667, C: 722, D: 722, E: 667, F: 611, G: 778, H: 722, I: 278, J: 500, K: 667, L: 556, M: 833, N: 722, O: 778, P: 667, Q: 778, R: 722, S: 667, T: 611, U: 722, V: 667, W: 944, X: 667, Y: 667, Z: 611,
  "[": 278, "\\": 278, "]": 278, "^": 469, _: 556, "`": 333,
  a: 556, b: 556, c: 500, d: 556, e: 556, f: 278, g: 556, h: 556, i: 222, j: 222, k: 500, l: 222, m: 833, n: 556, o: 556, p: 556, q: 556, r: 333, s: 500, t: 278, u: 556, v: 500, w: 722, x: 500, y: 500, z: 500,
  "{": 334, "|": 260, "}": 334, "~": 584,
};

/** Text as WinAnsi can carry it: the typographic characters folded to their plain forms. */
function winAnsi(s: string): string {
  return s
    .replace(/\r\n?/g, "\n")
    .replace(/\t/g, "  ")
    .replace(/[“”„]/g, '"')
    .replace(/[‘’‚]/g, "'")
    .replace(/[–—]/g, "-")
    .replace(/…/g, "...")
    .replace(/☐/g, "[ ]")
    .replace(/[•·]/g, "-")
    .replace(/→/g, "->")
    .replace(/[^\x20-\x7e\xa0-\xff\n]/g, "?");
}

/**
 * The width of a line in points. Times is narrower than Helvetica and Courier is fixed at 600
 * units; Helvetica's widths over-measure Times a little, so a Times line wraps early, never late.
 */
function width(text: string, size: number, family: ReportStyle["fonts"]["pdf"] = "helvetica"): number {
  if (family === "courier") return [...text].length * 0.6 * size;
  let w = 0;
  for (const ch of text) w += helvetica[ch] ?? 556;
  return (w / 1000) * size;
}

function wrap(text: string, size: number, maxWidth: number, family: ReportStyle["fonts"]["pdf"]): string[] {
  const lines: string[] = [];
  for (const para of text.split("\n")) {
    const words = para.split(/\s+/).filter((w) => w !== "");
    if (words.length === 0) {
      lines.push("");
      continue;
    }
    let line = "";
    for (const word of words) {
      const candidate = line ? `${line} ${word}` : word;
      if (width(candidate, size, family) <= maxWidth || line === "") line = candidate;
      else {
        lines.push(line);
        line = word;
      }
    }
    lines.push(line);
  }
  return lines;
}

const pdfEscape = (s: string): string => s.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");

/** "1F3A5F" as a PDF fill colour operand: "0.122 0.227 0.373". */
const rgb = (hex: string): string =>
  [0, 2, 4]
    .map((i) => (parseInt(hex.slice(i, i + 2), 16) / 255).toFixed(3))
    .join(" ");

interface Line {
  text: string;
  size: number;
  bold: boolean;
  mono: boolean;
  indent: number;
  /** Space before the line, in points. */
  before: number;
  color: string;
  /** A filled band behind the line (a table header, a code block). */
  fill: string | null;
  /** A rule under the line (a heading with a band). */
  rule: boolean;
  /** Start a new page before this line (after a cover). */
  pageBreak: boolean;
}

const pdfFonts: Record<ReportStyle["fonts"]["pdf"], [string, string]> = {
  helvetica: ["Helvetica", "Helvetica-Bold"],
  times: ["Times-Roman", "Times-Bold"],
  courier: ["Courier", "Courier-Bold"],
};

/** The report as a PDF on US Letter: the style's standard font, wrapped by measure, numbered pages. */
export function renderPdf(input: Block[], style: ReportStyle = plainStyle): Uint8Array {
  const blocks = numberHeadings(input, style);
  const c = style.colors;
  const family = style.fonts.pdf;
  const pageWidth = 612;
  const pageHeight = 792;
  const margin = 54;
  const measure = pageWidth - margin * 2;
  const s = style.size - 1;
  const lines: Line[] = [];
  let breakNext = false;
  const push = (text: string, size: number, options: { bold?: boolean; mono?: boolean; indent?: number; before?: number; color?: string; fill?: string | null; rule?: boolean } = {}) => {
    const indent = options.indent ?? 0;
    const mono = options.mono ?? false;
    const wrapped = mono ? text.split("\n").flatMap((l) => (l === "" ? [""] : chunk(l, Math.max(10, Math.floor((measure - indent) / (0.6 * size)))))) : wrap(text, size, measure - indent, family);
    const pageBreak = breakNext;
    breakNext = false;
    wrapped.forEach((l, i) =>
      lines.push({
        text: l,
        size,
        bold: options.bold ?? false,
        mono,
        indent,
        before: i === 0 ? (options.before ?? 4) : 0,
        color: options.color ?? c.ink,
        fill: options.fill ?? null,
        rule: (options.rule ?? false) && i === wrapped.length - 1,
        pageBreak: i === 0 && pageBreak,
      }),
    );
  };
  for (const b of blocks) {
    switch (b.type) {
      case "title":
        push(winAnsi(b.text), s + 11, { bold: true, before: style.cover ? 200 : 0, color: c.heading });
        break;
      case "subtitle":
        push(winAnsi(b.text), s + 1, { before: 2, color: c.muted });
        if (style.cover) breakNext = true;
        break;
      case "h1":
        push(winAnsi(b.text), s + 6, { bold: true, before: 18, color: c.heading, rule: style.band });
        break;
      case "h2":
        push(winAnsi(b.text), s + 3.5, { bold: true, before: 12, color: c.heading });
        break;
      case "h3":
        push(winAnsi(b.text), s + 2, { bold: true, before: 8 });
        break;
      case "p":
        push(winAnsi(plain(b.runs)), s, { before: 6 });
        break;
      case "bullet":
        push(`- ${winAnsi(plain(b.runs))}`, s, { indent: 12, before: 2 });
        break;
      case "check":
        push(`[ ] ${winAnsi(plain(b.runs))}`, s, { indent: 12, before: 2, color: c.ink });
        break;
      case "code":
        push(winAnsi(b.text), s - 1.5, { mono: true, indent: 12, before: 4, color: c.codeInk, fill: c.codeFill });
        break;
      case "table":
        push(winAnsi(b.header.join(" | ")), s - 0.5, { bold: true, before: 6, color: c.headInk, fill: c.headFill });
        for (const row of b.rows) push(winAnsi(row.join(" | ")), s - 0.5, { before: 1, rule: true });
        break;
    }
  }
  // Lay the lines onto pages.
  const [regular, bold] = pdfFonts[family];
  const pages: string[][] = [];
  const background = c.page ? `${rgb(c.page)} rg 0 0 ${pageWidth} ${pageHeight} re f` : null;
  let content: string[] = background ? [background] : [];
  let y = pageHeight - margin;
  const newPage = () => {
    pages.push(content);
    content = background ? [background] : [];
    y = pageHeight - margin;
  };
  for (const line of lines) {
    const lead = line.size * 1.3;
    if (line.pageBreak || y - line.before - lead < margin + 20) newPage();
    y -= line.before + lead;
    if (line.fill) content.push(`${rgb(line.fill)} rg ${margin + line.indent - 3} ${(y - line.size * 0.3).toFixed(1)} ${measure - line.indent + 6} ${lead.toFixed(1)} re f`);
    if (line.text !== "") {
      const font = line.mono ? "/F3" : line.bold ? "/F2" : "/F1";
      content.push(`BT ${rgb(line.color)} rg ${font} ${line.size} Tf ${margin + line.indent} ${y.toFixed(1)} Td (${pdfEscape(line.text)}) Tj ET`);
    }
    if (line.rule) content.push(`${rgb(c.rule)} RG 0.6 w ${margin} ${(y - line.size * 0.35).toFixed(1)} m ${pageWidth - margin} ${(y - line.size * 0.35).toFixed(1)} l S`);
  }
  pages.push(content);
  pages.forEach((p, i) => p.push(`BT ${rgb(c.muted)} rg /F1 8 Tf ${margin} ${margin - 24} Td (${pdfEscape(`Page ${i + 1} of ${pages.length}`)}) Tj ET`));

  // Objects: 1 catalog, 2 pages, 3 to 5 fonts, then a page and a content stream per page.
  const objects: string[] = [];
  const add = (body: string): number => {
    objects.push(body);
    return objects.length;
  };
  add("<< /Type /Catalog /Pages 2 0 R >>");
  add("PAGES");
  add(`<< /Type /Font /Subtype /Type1 /BaseFont /${regular} /Encoding /WinAnsiEncoding >>`);
  add(`<< /Type /Font /Subtype /Type1 /BaseFont /${bold} /Encoding /WinAnsiEncoding >>`);
  add("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>");
  const pageIds: number[] = [];
  for (const p of pages) {
    const stream = p.join("\n");
    const bytes = Buffer.byteLength(stream, "latin1");
    const contentId = add(`<< /Length ${bytes} >>\nstream\n${stream}\nendstream`);
    pageIds.push(add(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents ${contentId} 0 R >>`));
  }
  objects[1] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pageIds.length} >>`;
  let out = "%PDF-1.4\n%\xe2\xe3\xcf\xd3\n";
  const offsets: number[] = [];
  objects.forEach((body, i) => {
    offsets.push(Buffer.byteLength(out, "latin1"));
    out += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = Buffer.byteLength(out, "latin1");
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const o of offsets) out += `${String(o).padStart(10, "0")} 00000 n \n`;
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return new Uint8Array(Buffer.from(out, "latin1"));
}

function chunk(text: string, size: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < text.length; i += size) out.push(text.slice(i, i + size));
  return out;
}
