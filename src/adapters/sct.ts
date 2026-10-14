import type { NormalizedRequirement } from "../oscal.ts";
import { entryText, findEntry, unzipAll } from "../zip.ts";
import type { Adapter, DocumentTarget, ParsedDocument, SourceRow } from "./types.ts";

/**
 * Microsoft Security Compliance Toolkit. The download page embeds its file list; each
 * "<product> Security Baseline" zip carries a `.PolicyRules` file (Policy Analyzer's format)
 * listing every registry, security-template and audit setting the baseline sets. That file,
 * not the spreadsheet, is what BaselineWatch diffs.
 */

export interface SctFile {
  name: string;
  url: string;
  size: number;
  datePublished: string | null;
}

/** The file list from the download page's `__DLCDetails__` JSON. */
export function parseSctListing(html: string): SctFile[] {
  const start = html.indexOf("__DLCDetails__=");
  if (start < 0) throw new Error("download page has no __DLCDetails__ block");
  const from = html.indexOf("{", start);
  // The block ends at the script close; find the matching brace by depth.
  let depth = 0;
  let end = -1;
  let inString = false;
  for (let i = from; i < html.length; i += 1) {
    const ch = html[i];
    if (inString) {
      if (ch === "\\") i += 1;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  if (end < 0) throw new Error("download page JSON did not close");
  const details = JSON.parse(html.slice(from, end)) as { dlcDetailsView?: { downloadFile?: { name: string; url: string; size?: string; datePublished?: string }[] } };
  const files = details.dlcDetailsView?.downloadFile ?? [];
  return files.map((f) => ({ name: f.name, url: f.url, size: Number(f.size ?? 0), datePublished: usDate(f.datePublished) }));
}

/** "10/8/2026 6:35:40 PM" (Microsoft's listing) to ISO. */
export function usDate(value: string | undefined): string | null {
  if (!value) return null;
  const m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?)?$/i.exec(value.trim());
  if (!m) return null;
  let hour = Number(m[4] ?? 0);
  const ampm = m[7]?.toUpperCase();
  if (ampm === "PM" && hour < 12) hour += 12;
  if (ampm === "AM" && hour === 12) hour = 0;
  const date = new Date(Date.UTC(Number(m[3]), Number(m[1]) - 1, Number(m[2]), hour, Number(m[5] ?? 0), Number(m[6] ?? 0)));
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/** "Windows Server 2025 Security Baseline - 2602.zip" → key windows-server-2025, version 2602. */
export function baselineTarget(file: SctFile): DocumentTarget | null {
  if (!/security baseline/i.test(file.name) || !/\.zip$/i.test(file.name)) return null;
  const base = file.name.replace(/\.zip$/i, "");
  const product = base.replace(/\s*security baseline.*$/i, "").trim();
  const tail = base.replace(/^.*security baseline/i, "").replace(/^[\s-]+/, "").trim();
  const versionLabel = tail || (file.datePublished ? file.datePublished.slice(0, 10) : null);
  const key = `baseline:${product.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}`;
  return { key, url: file.url, versionLabel, publishedAt: file.datePublished };
}

const auditSetting: Record<string, string> = { "0": "No auditing", "1": "Success", "2": "Failure", "3": "Success and Failure" };

function element(xml: string, tag: string): string | null {
  const m = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`).exec(xml);
  return m?.[1]?.trim() ?? null;
}

function decodeXml(text: string): string {
  return text.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
}

/** Strips the version token from a GPO name so refs stay stable across releases: "MSFT Windows Server 2025 v2602 - Member Server" → "Windows Server 2025 - Member Server". */
export function policyScope(policyName: string): string {
  return policyName
    .replace(/^MSFT\s+/i, "")
    .replace(/\s+v\d{2,}[A-Za-z0-9]*\b/i, "")
    .replace(/\s+/g, " ")
    .trim();
}

/** Every setting in a PolicyRules file as a requirement: the ref is scope + setting, the statement is the value. */
export function parsePolicyRules(xml: string): NormalizedRequirement[] {
  const out: NormalizedRequirement[] = [];
  const seen = new Set<string>();
  const push = (r: NormalizedRequirement) => {
    if (seen.has(r.ref)) return;
    seen.add(r.ref);
    out.push(r);
  };
  for (const m of xml.matchAll(/<(ComputerConfig|UserConfig)>([\s\S]*?)<\/\1>/g)) {
    const hive = m[1] === "UserConfig" ? "User" : "Computer";
    const body = m[2]!;
    const key = decodeXml(element(body, "Key") ?? "");
    const value = decodeXml(element(body, "Value") ?? "");
    const regType = element(body, "RegType") ?? "";
    const regData = decodeXml(element(body, "RegData") ?? "");
    const scope = policyScope(element(body, "PolicyName") ?? "");
    const ref = `${scope}|${hive}|${key}\\${value}`.toLowerCase();
    push({
      ref,
      parentRef: null,
      family: scope,
      label: value || key,
      title: `${hive === "User" ? "HKCU" : "HKLM"}\\${key}\\${value}`,
      statement: `${regType} = ${regData}`,
      guidance: null,
      params: [],
      related: [],
      sortKey: ref,
      status: "active",
      extra: { kind: "registry", hive, regType, regData, policy: scope },
    });
  }
  for (const m of xml.matchAll(/<SecurityTemplate(?:\s+Section="([^"]*)")?>([\s\S]*?)<\/SecurityTemplate>/g)) {
    const section = decodeXml(m[1] ?? "");
    const body = m[2]!;
    const line = decodeXml(element(body, "LineItem") ?? "");
    const eq = line.indexOf("=");
    const name = eq >= 0 ? line.slice(0, eq).trim() : line.trim();
    const setting = eq >= 0 ? line.slice(eq + 1).trim() : "";
    const scope = policyScope(element(body, "PolicyName") ?? "");
    const ref = `${scope}|template|${section}|${name}`.toLowerCase();
    push({
      ref,
      parentRef: null,
      family: scope,
      label: name,
      title: `${section}: ${name}`,
      statement: setting,
      guidance: null,
      params: [],
      related: [],
      sortKey: ref,
      status: "active",
      extra: { kind: "security-template", section, policy: scope },
    });
  }
  for (const m of xml.matchAll(/<AuditSubcategory>([\s\S]*?)<\/AuditSubcategory>/g)) {
    const body = m[1]!;
    const guid = (element(body, "GUID") ?? "").toLowerCase();
    const name = decodeXml(element(body, "Name") ?? "");
    const setting = element(body, "Setting") ?? "";
    const scope = policyScope(element(body, "PolicyName") ?? "");
    const ref = `${scope}|audit|${guid}`.toLowerCase();
    push({
      ref,
      parentRef: null,
      family: scope,
      label: name,
      title: `Audit policy: ${name}`,
      statement: auditSetting[setting] ?? setting,
      guidance: null,
      params: [],
      related: [],
      sortKey: ref,
      status: "active",
      extra: { kind: "audit", guid, policy: scope },
    });
  }
  return out;
}

export const sctAdapter: Adapter = {
  id: "sct",
  headers: { accept: "text/html,application/xhtml+xml" },
  async documents(source: SourceRow, ctx) {
    const page = await ctx.http(source.url, { headers: { accept: "text/html" }, timeoutMs: 60_000 });
    const files = parseSctListing(new TextDecoder("utf-8").decode(page.bytes));
    return files.map(baselineTarget).filter((t): t is DocumentTarget => t !== null);
  },
  parseDocument(bytes, target): ParsedDocument {
    const entries = unzipAll(bytes);
    const rules = entries.filter((e) => /\.PolicyRules$/i.test(e.name));
    if (rules.length === 0) throw new Error("baseline zip has no .PolicyRules file");
    // Older toolkits ship one PolicyRules per GPO set; newer ones a single file. Read them all.
    const requirements: NormalizedRequirement[] = [];
    const seen = new Set<string>();
    for (const file of rules) {
      for (const r of parsePolicyRules(entryText(file))) {
        if (seen.has(r.ref)) continue;
        seen.add(r.ref);
        requirements.push(r);
      }
    }
    if (requirements.length === 0) throw new Error(`${rules.map((r) => r.name).join(", ")} hold no settings BaselineWatch can read`);
    const first = findEntry(entries, /\.PolicyRules$/i)!;
    const folder = first.name.includes("/") ? first.name.split("/")[0]! : target.key;
    return { title: folder, versionLabel: target.versionLabel ?? null, publishedAt: target.publishedAt ?? null, requirements };
  },
};
