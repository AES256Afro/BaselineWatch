import { strToU8, zipSync } from "fflate";

/**
 * One document, three typeset forms. A report is a list of blocks (title, headings, paragraphs,
 * bullets, checklist lines, code, tables); each renderer below writes it as LaTeX for the team's
 * own template, as a Word document a reviewer edits, or as a plain PDF that prints anywhere.
 * Nothing here needs a library beyond the zip the .docx format is: the PDF is written by hand in
 * Helvetica with the text wrapped by measure, and the Word parts are the minimum Office opens.
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

const plain = (runs: Inline[]): string => runs.map((r) => (typeof r === "string" ? r : r.text)).join("");

// ---------------------------------------------------------------------------------------------
// LaTeX

const texEscape = (s: string): string =>
  s
    .replace(/\\/g, "\\textbackslash{}")
    .replace(/([&%$#_{}])/g, "\\$1")
    .replace(/~/g, "\\textasciitilde{}")
    .replace(/\^/g, "\\textasciicircum{}")
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/☐/g, "$\\square$");

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

export function renderLatex(blocks: Block[]): string {
  const out: string[] = [
    "\\documentclass[11pt]{article}",
    "\\usepackage[margin=1in]{geometry}",
    "\\usepackage[T1]{fontenc}",
    "\\usepackage[utf8]{inputenc}",
    "\\usepackage{amssymb}",
    "\\usepackage{longtable}",
    "\\usepackage{array}",
    "\\usepackage{enumitem}",
    "\\usepackage{hyperref}",
    "\\usepackage{fancyvrb}",
    "\\setlength{\\parskip}{4pt}",
    "\\setlength{\\parindent}{0pt}",
    "",
  ];
  const title = blocks.find((b) => b.type === "title");
  const subtitle = blocks.find((b) => b.type === "subtitle");
  if (title) out.push(`\\title{${texEscape(title.text)}}`, `\\date{${subtitle ? texEscape(subtitle.text) : ""}}`, "\\author{}");
  out.push("\\begin{document}");
  if (title) out.push("\\maketitle");
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
        out.push(`\\section*{${texEscape(b.text)}}`);
        break;
      case "h2":
        out.push(`\\subsection*{${texEscape(b.text)}}`);
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
        out.push("\\begin{Verbatim}[fontsize=\\small,breaklines=true]", b.text.replace(/\r/g, ""), "\\end{Verbatim}");
        break;
      case "table": {
        const cols = b.header.length;
        out.push(`\\begin{longtable}{|${Array(cols).fill("p{\\dimexpr(\\linewidth-" + (cols + 1) * 2 + "\\tabcolsep)/" + cols + "\\relax}").join("|")}|}`, "\\hline");
        out.push(`${b.header.map((h) => `\\textbf{${texEscape(h)}}`).join(" & ")} \\\\ \\hline`);
        out.push("\\endhead");
        for (const row of b.rows) out.push(`${row.map((c) => texEscape(c)).join(" & ")} \\\\ \\hline`);
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

function docxRun(r: Inline, mono = false): string {
  const o = typeof r === "string" ? { text: r } : r;
  const props: string[] = [];
  if (o.bold) props.push("<w:b/>");
  if (o.mono || mono) props.push('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="18"/>');
  const parts = xmlSafe(o.text).split(/\r?\n/);
  return parts.map((line, i) => `<w:r>${props.length ? `<w:rPr>${props.join("")}</w:rPr>` : ""}${i > 0 ? "<w:br/>" : ""}<w:t xml:space="preserve">${xml(line)}</w:t></w:r>`).join("");
}

function docxParagraph(runs: Inline[], options: { style?: string; mono?: boolean; indent?: boolean; prefix?: string } = {}): string {
  const props: string[] = [];
  if (options.style) props.push(`<w:pStyle w:val="${options.style}"/>`);
  if (options.indent) props.push('<w:ind w:left="360" w:hanging="360"/>');
  if (options.mono) props.push('<w:shd w:val="clear" w:color="auto" w:fill="F2F2F2"/>');
  const body = (options.prefix ? docxRun(options.prefix) : "") + runs.map((r) => docxRun(r, options.mono)).join("");
  return `<w:p>${props.length ? `<w:pPr>${props.join("")}</w:pPr>` : ""}${body}</w:p>`;
}

function docxTable(header: string[], rows: string[][]): string {
  const cell = (text: string, head: boolean) => `<w:tc><w:tcPr>${head ? '<w:shd w:val="clear" w:color="auto" w:fill="E7E6E6"/>' : ""}</w:tcPr>${docxParagraph([{ text, bold: head }])}</w:tc>`;
  const row = (cells: string[], head: boolean) => `<w:tr>${cells.map((c) => cell(c, head)).join("")}</w:tr>`;
  return `<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders><w:top w:val="single" w:sz="4" w:color="999999"/><w:left w:val="single" w:sz="4" w:color="999999"/><w:bottom w:val="single" w:sz="4" w:color="999999"/><w:right w:val="single" w:sz="4" w:color="999999"/><w:insideH w:val="single" w:sz="4" w:color="999999"/><w:insideV w:val="single" w:sz="4" w:color="999999"/></w:tblBorders></w:tblPr>${row(header, true)}${rows.map((r) => row(r, false)).join("")}</w:tbl><w:p/>`;
}

export function renderDocx(blocks: Block[]): Uint8Array {
  const body: string[] = [];
  for (const b of blocks) {
    switch (b.type) {
      case "title":
        body.push(docxParagraph([b.text], { style: "Title" }));
        break;
      case "subtitle":
        body.push(docxParagraph([b.text], { style: "Subtitle" }));
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
        body.push(docxParagraph([b.text], { mono: true }));
        break;
      case "table":
        body.push(docxTable(b.header, b.rows));
        break;
    }
  }
  const document = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${body.join("")}<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr></w:body></w:document>`;
  const styles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="22"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="200"/></w:pPr><w:rPr><w:b/><w:sz w:val="44"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="595959"/><w:sz w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="360" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="32"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="200" w:after="60"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:sz w:val="23"/></w:rPr></w:style>
</w:styles>`;
  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>`;
  const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`;
  const docRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`;
  return zipSync(
    {
      "[Content_Types].xml": strToU8(contentTypes),
      "_rels/.rels": strToU8(rels),
      "word/document.xml": strToU8(document),
      "word/_rels/document.xml.rels": strToU8(docRels),
      "word/styles.xml": strToU8(styles),
    },
    { level: 6 },
  );
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
    .replace(/[“”„]/g, '"')
    .replace(/[‘’‚]/g, "'")
    .replace(/[–—]/g, "-")
    .replace(/…/g, "...")
    .replace(/☐/g, "[ ]")
    .replace(/[•·]/g, "-")
    .replace(/→/g, "->")
    .replace(/[^\x20-\x7e\xa0-\xff]/g, "?");
}

function width(text: string, size: number): number {
  let w = 0;
  for (const ch of text) w += helvetica[ch] ?? 556;
  return (w / 1000) * size;
}

function wrap(text: string, size: number, maxWidth: number): string[] {
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
      if (width(candidate, size) <= maxWidth || line === "") line = candidate;
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

interface Line {
  text: string;
  size: number;
  bold: boolean;
  mono: boolean;
  indent: number;
  /** Space before the line, in points. */
  before: number;
}

/** The report as a plain PDF on US Letter: Helvetica, wrapped by measure, numbered pages. */
export function renderPdf(blocks: Block[]): Uint8Array {
  const pageWidth = 612;
  const pageHeight = 792;
  const margin = 54;
  const measure = pageWidth - margin * 2;
  const lines: Line[] = [];
  const push = (text: string, size: number, options: { bold?: boolean; mono?: boolean; indent?: number; before?: number } = {}) => {
    const indent = options.indent ?? 0;
    const monoWidth = options.mono ? 0.6 * size : 0;
    const wrapped = options.mono ? text.split("\n").flatMap((l) => (l === "" ? [""] : chunk(l, Math.max(10, Math.floor((measure - indent) / monoWidth))))) : wrap(text, size, measure - indent);
    wrapped.forEach((l, i) => lines.push({ text: l, size, bold: options.bold ?? false, mono: options.mono ?? false, indent, before: i === 0 ? (options.before ?? 4) : 0 }));
  };
  for (const b of blocks) {
    switch (b.type) {
      case "title":
        push(winAnsi(b.text), 20, { bold: true, before: 0 });
        break;
      case "subtitle":
        push(winAnsi(b.text), 11, { before: 2 });
        break;
      case "h1":
        push(winAnsi(b.text), 15, { bold: true, before: 18 });
        break;
      case "h2":
        push(winAnsi(b.text), 12.5, { bold: true, before: 12 });
        break;
      case "h3":
        push(winAnsi(b.text), 11, { bold: true, before: 8 });
        break;
      case "p":
        push(winAnsi(plain(b.runs)), 10, { before: 6 });
        break;
      case "bullet":
        push(`- ${winAnsi(plain(b.runs))}`, 10, { indent: 12, before: 2 });
        break;
      case "check":
        push(`[ ] ${winAnsi(plain(b.runs))}`, 10, { indent: 12, before: 2 });
        break;
      case "code":
        push(winAnsi(b.text), 8.5, { mono: true, indent: 12, before: 4 });
        break;
      case "table":
        push(winAnsi(b.header.join(" | ")), 9.5, { bold: true, before: 6 });
        for (const row of b.rows) push(winAnsi(row.join(" | ")), 9.5, { before: 1 });
        break;
    }
  }
  // Lay the lines onto pages.
  const pages: string[][] = [];
  let content: string[] = [];
  let y = pageHeight - margin;
  const newPage = () => {
    if (content.length) pages.push(content);
    content = [];
    y = pageHeight - margin;
  };
  for (const line of lines) {
    const lead = line.size * 1.3;
    if (y - line.before - lead < margin + 20) newPage();
    y -= line.before + lead;
    if (line.text !== "") {
      const font = line.mono ? "/F3" : line.bold ? "/F2" : "/F1";
      content.push(`BT ${font} ${line.size} Tf ${margin + line.indent} ${y.toFixed(1)} Td (${pdfEscape(line.text)}) Tj ET`);
    }
  }
  if (content.length || pages.length === 0) pages.push(content);
  pages.forEach((p, i) => p.push(`BT /F1 8 Tf ${margin} ${margin - 24} Td (${pdfEscape(`Page ${i + 1} of ${pages.length}`)}) Tj ET`));

  // Objects: 1 catalog, 2 pages, 3 to 5 fonts, then a page and a content stream per page.
  const objects: string[] = [];
  const add = (body: string): number => {
    objects.push(body);
    return objects.length;
  };
  add("<< /Type /Catalog /Pages 2 0 R >>");
  add("PAGES");
  add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
  add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>");
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
