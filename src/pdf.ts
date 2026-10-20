/**
 * Text out of a PDF, page by page, with lines rebuilt from the glyph positions. Used for the
 * documents publishers ship only as PDF: DISA's revision histories, Microsoft's baseline
 * announcements, and later CIS benchmarks. Loaded lazily; pdfjs is a large module.
 */
import type * as PdfJs from "pdfjs-dist/legacy/build/pdf.mjs";

type TextItem = { str: string; transform: number[]; hasEOL?: boolean };

let loader: Promise<typeof PdfJs> | null = null;

function pdfjs(): Promise<typeof PdfJs> {
  loader ??= import("pdfjs-dist/legacy/build/pdf.mjs");
  return loader;
}

/** Enough for any benchmark or revision history; a hostile file with a million pages or a deflate bomb stops here. */
const maxPages = 3000;
const maxChars = 16 * 1024 * 1024;
const deadlineMs = 120_000;

export async function pdfPages(bytes: Uint8Array): Promise<string[]> {
  const lib = await pdfjs();
  // pdfjs transfers the array's buffer to its worker, which detaches it: it gets its own copy, so the caller's bytes stay whole.
  const task = lib.getDocument({ data: new Uint8Array(bytes), useSystemFonts: false, disableFontFace: true, verbosity: 0 });
  // Parsing runs on this thread (no worker in Node): past the deadline the document is torn down and the next page read fails.
  const timer = setTimeout(() => void task.destroy().catch(() => {}), deadlineMs);
  timer.unref();
  const pages: string[] = [];
  let chars = 0;
  try {
    const doc = await task.promise;
    const count = Math.min(doc.numPages, maxPages);
    for (let i = 1; i <= count && chars <= maxChars; i += 1) {
      const page = await doc.getPage(i);
      const content = await page.getTextContent();
      const lines: string[] = [];
      let line = "";
      let lastY: number | null = null;
      const flush = () => {
        if (line.trim() !== "") lines.push(line.trimEnd());
        line = "";
      };
      for (const item of content.items as TextItem[]) {
        if (typeof item.str !== "string") continue;
        const y = item.transform[5] ?? 0;
        if (lastY !== null && Math.abs(y - lastY) > 2) {
          flush();
          // A vertical gap well beyond one line of text is a paragraph break.
          if (lastY - y > 20 && lines.length && lines[lines.length - 1] !== "") lines.push("");
        }
        if (item.str.trim() === "") {
          if (line && !line.endsWith(" ")) line += " ";
        } else {
          if (line && !line.endsWith(" ") && !item.str.startsWith(" ")) line += " ";
          line += item.str;
        }
        lastY = y;
        if (item.hasEOL) flush();
      }
      flush();
      const text = lines.join("\n");
      chars += text.length;
      pages.push(text);
    }
  } finally {
    clearTimeout(timer);
    await task.destroy().catch(() => {});
  }
  return pages;
}

export async function pdfText(bytes: Uint8Array): Promise<string> {
  return (await pdfPages(bytes)).join("\n\f\n");
}

/** Collapses the line breaks a PDF's layout introduces mid-sentence, keeping real paragraph breaks and list items. */
export function unwrap(text: string): string {
  return text
    .replace(/\r/g, "")
    .split(/\n{2,}|\f/)
    .map((block) =>
      block
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l !== "")
        .reduce((acc, l) => (acc === "" ? l : /^[-•*]\s/.test(l) ? `${acc}\n${l}` : `${acc} ${l}`), ""),
    )
    .filter((b) => b !== "")
    .join("\n\n");
}
