import type { NormalizedRequirement } from "../oscal.ts";
import { pdfText, unwrap } from "../pdf.ts";
import type { Adapter, ParsedDocument } from "./types.ts";

/**
 * CIS Benchmarks arrive as PDFs the owner uploads (they sit behind registration and may not be
 * redistributed). A benchmark is a numbered list of recommendations, each with the same
 * labelled sections; this reads that shape out of the PDF's text. Nothing CIS leaves the box.
 */

const headingLine = /^(\d+(?:\.\d+)+)\s+\((L[12]|BL|NG|Level \d)\)\s+(.+?)\s*(\((?:Automated|Manual|Scored|Not Scored)\))?\s*$/;
const sectionNames = ["Profile Applicability", "Description", "Rationale", "Impact", "Audit", "Remediation", "Default Value", "References", "CIS Controls", "Additional Information", "MITRE ATT&CK Mappings"];
const sectionLine = new RegExp(`^(${sectionNames.map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")}):\\s*(.*)$`);

export interface CisRecommendation {
  number: string;
  level: string;
  title: string;
  assessment: string | null;
  sections: Record<string, string>;
}

export interface CisParsed {
  title: string | null;
  version: string | null;
  /** The cover's date beside the version ("v4.0.0 - 03-31-2025"), as YYYY-MM-DD. */
  publishedAt: string | null;
  recommendations: CisRecommendation[];
}

/** "v4.0.0 - 03-31-2025": CIS prints the version and its date, month first, on the cover. */
const versionDate = /\bv(\d+\.\d+\.\d+)\s*-\s*(\d{2})-(\d{2})-(\d{4})\b/;

/** The cover date of `version`, or null when the text has none or it is not a calendar date. */
function coverDate(lines: string[], version: string | null): string | null {
  for (const line of lines) {
    const m = versionDate.exec(line);
    if (!m || m[1] !== version) continue;
    const [month, day, year] = [Number(m[2]), Number(m[3]), Number(m[4])];
    const date = new Date(Date.UTC(year, month - 1, day));
    if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return null;
    return `${m[4]}-${m[2]}-${m[3]}`;
  }
  return null;
}

/** The recommendations in a benchmark's text. Page furniture (page numbers, "Page N") is dropped. */
export function parseCisText(text: string): CisParsed {
  const lines = text
    .replace(/\r/g, "")
    .split(/\n|\f/)
    .map((l) => l.trim())
    .filter((l) => l !== "" && !/^Page \d+$/i.test(l) && !/^\d+ \| P a g e$/i.test(l) && !/^\d+$/.test(l));
  const titleLine = lines.find((l) => /^CIS .+ Benchmark$/i.test(l)) ?? lines.find((l) => /Benchmark/i.test(l) && l.length < 120) ?? null;
  const version = lines.map((l) => /^v(\d+\.\d+\.\d+)\b/.exec(l)?.[1] ?? /\bv(\d+\.\d+\.\d+)\s*-\s*\d{2}-\d{2}-\d{4}/.exec(l)?.[1]).find((v): v is string => !!v) ?? null;

  const recs: CisRecommendation[] = [];
  let current: CisRecommendation | null = null;
  let section: string | null = null;
  const seen = new Set<string>();
  for (const line of lines) {
    const heading = headingLine.exec(line);
    if (heading && !seen.has(heading[1]!)) {
      // A table-of-contents line repeats the heading with a trailing page number; the body heading comes later and wins.
      current = { number: heading[1]!, level: heading[2]!, title: heading[3]!.replace(/\s*\.{3,}\s*\d*$/, "").trim(), assessment: heading[4]?.replace(/[()]/g, "") ?? null, sections: {} };
      section = null;
      recs.push(current);
      continue;
    }
    if (!current) continue;
    const sec = sectionLine.exec(line);
    if (sec) {
      section = sec[1]!;
      if (sec[2]) current.sections[section] = sec[2];
      continue;
    }
    if (section) current.sections[section] = current.sections[section] ? `${current.sections[section]}\n${line}` : line;
  }
  // Keep recommendations that gathered a body; headings from the table of contents have none.
  const withBody = recs.filter((r) => Object.keys(r.sections).length > 0);
  for (const r of withBody) {
    for (const key of Object.keys(r.sections)) r.sections[key] = unwrap(r.sections[key]!);
    seen.add(r.number);
  }
  return { title: titleLine, version, publishedAt: coverDate(lines, version), recommendations: withBody };
}

export function cisRequirements(parsed: CisParsed): NormalizedRequirement[] {
  return parsed.recommendations.map((r) => ({
    ref: r.number,
    parentRef: r.number.includes(".") ? r.number.slice(0, r.number.lastIndexOf(".")) : null,
    family: r.number.split(".")[0] ?? null,
    label: r.number,
    title: r.title,
    statement: r.sections.Remediation ?? null,
    guidance: [r.sections.Description, r.sections.Rationale].filter(Boolean).join("\n\n") || null,
    params: [],
    related: (r.sections["CIS Controls"] ?? "").match(/\bv\d+\s+\d+(?:\.\d+)*/g) ?? [],
    sortKey: r.number
      .split(".")
      .map((n) => n.padStart(3, "0"))
      .join("."),
    status: "active",
    extra: {
      level: r.level,
      ...(r.assessment ? { assessment: r.assessment } : {}),
      ...(r.sections.Audit ? { audit: r.sections.Audit } : {}),
      ...(r.sections["Default Value"] ? { defaultValue: r.sections["Default Value"] } : {}),
      ...(r.sections.Impact ? { impact: r.sections.Impact } : {}),
      ...(r.sections["Profile Applicability"] ? { profiles: r.sections["Profile Applicability"] } : {}),
    },
  }));
}

/** The manual-upload adapter: no documents() or history(), only parseDocument for what the owner brings. */
export const cisAdapter: Adapter = {
  id: "cis",
  async parseDocument(bytes, target): Promise<ParsedDocument> {
    const text = await pdfText(bytes);
    const parsed = parseCisText(text);
    if (parsed.recommendations.length === 0) throw new Error("no CIS recommendations found in this PDF; is it a CIS Benchmark?");
    // Left blank, "Published" falls back to the cover's date, not the upload time: a benchmark
    // uploaded after a newer one would otherwise read as the newest.
    return {
      title: parsed.title ?? target.key,
      versionLabel: target.versionLabel ?? parsed.version,
      publishedAt: target.publishedAt ?? (parsed.publishedAt ? `${parsed.publishedAt}T00:00:00.000Z` : null),
      requirements: cisRequirements(parsed),
    };
  },
};

/** "CIS Ubuntu Linux 24.04 LTS Benchmark" → cis:ubuntu-linux-24-04-lts */
export function cisKey(title: string | null, filename: string): string {
  // A WorkBench filename joins words with underscores and carries the version
  // ("CIS_Microsoft_Windows_11_Enterprise_Benchmark_v4.0.0.pdf"); left in, each version would key
  // a series of its own and nothing would ever be compared.
  const base = (title ?? filename.replace(/\.pdf$/i, "").replace(/_/g, " "))
    .replace(/^CIS\s+/i, "")
    .replace(/\s+Benchmark.*$/i, "")
    .replace(/\s+v\d[\d.]*\s*$/i, "");
  return `cis:${base.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "benchmark"}`;
}
