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
  recommendations: CisRecommendation[];
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
  return { title: titleLine, version, recommendations: withBody };
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
    return {
      title: parsed.title ?? target.key,
      versionLabel: target.versionLabel ?? parsed.version,
      publishedAt: target.publishedAt ?? null,
      requirements: cisRequirements(parsed),
    };
  },
};

/** "CIS Ubuntu Linux 24.04 LTS Benchmark" → cis:ubuntu-linux-24-04-lts */
export function cisKey(title: string | null, filename: string): string {
  const base = (title ?? filename.replace(/\.pdf$/i, "")).replace(/^CIS\s+/i, "").replace(/\s+Benchmark.*$/i, "");
  return `cis:${base.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "benchmark"}`;
}
