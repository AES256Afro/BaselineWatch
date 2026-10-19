import { XMLParser } from "fast-xml-parser";
import { parseStigRevisionHistory } from "../explain.ts";
import type { NormalizedRequirement } from "../oscal.ts";
import { pdfText } from "../pdf.ts";
import { entryText, findEntry, unzipAll } from "../zip.ts";
import { plainText, type Adapter, type DocumentTarget, type ListingContext, type ParsedDocument, type SourceRow } from "./types.ts";

/**
 * DISA STIGs. The STIG document library at cyber.mil is a Salesforce app whose table is filled
 * by one Apex call that answers without a login; the adapter makes that call, picks the STIGs the
 * owner follows, downloads each zip and reads the XCCDF inside. Rules are keyed by their Group id
 * (V-nnnnnn), which DISA keeps stable across releases, so a release diffs rule by rule.
 */

export interface DisaListingItem {
  FileName: string;
  DownloadLink: string;
  UploadDate: string;
  RawDownloadType?: string;
  DownloadType?: string;
  Name?: string;
}

/** The body of the Apex call the library page itself makes. */
export const listingRequest = JSON.stringify({
  namespace: "",
  classname: "@udd/01pRw0000002mOj",
  method: "getCyberDocumentCatalogByDocumentLibrary",
  isContinuation: false,
  params: { documentLibrary: "STIGs" },
  cacheable: false,
});

/** STIGs followed when the watchlist names none. */
export const defaultStigs = [
  "Microsoft Windows 11",
  "Microsoft Windows Server 2025",
  "Microsoft Windows Server 2022",
  "Red Hat Enterprise Linux 9",
  "Red Hat Enterprise Linux 10",
  "Canonical Ubuntu 24.04",
  "Canonical Ubuntu 22.04",
  "Apple macOS 26",
  "Apple macOS 15",
  "Apple iOS/iPadOS 27",
  "Apple iOS/iPadOS 26",
  "Google Android 17",
  "Google Android 16",
  "Samsung Android 17",
  "Samsung Android 16",
  "Microsoft Edge",
  "Google Chrome",
  "Mozilla Firefox",
  "Cisco IOS XE Router",
  "Application Security and Development",
];

const excludedTypes = /Sunset|SCAP|Supplemental Automation|Compilation|Tools/i;

function slug(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

/** "Microsoft Windows Server 2025 STIG - Ver 1, Rel 4" → product and V1R4; continuous STIGs take the Y26M04 token from the file name. */
export function stigTarget(item: DisaListingItem): DocumentTarget | null {
  const link = item.DownloadLink ?? "";
  if (!/\.zip$/i.test(link)) return null;
  if (excludedTypes.test(item.RawDownloadType ?? item.DownloadType ?? "")) return null;
  const name = (item.FileName ?? "").split(String.fromCharCode(0x200b)).join("").trim();
  if (!/\b(STIG|SRG)\b/.test(name)) return null;
  const versionMatch = /Ver\s*(\d+),?\s*Rel\s*([\d.]+)/i.exec(name);
  const fileToken = /_(Y\d{2}M\d{2})_/i.exec(link)?.[1];
  const versionLabel = versionMatch ? `V${versionMatch[1]}R${versionMatch[2]}` : (fileToken ?? null);
  const product = name.replace(/\s*-\s*Ver\s*\d+.*$/i, "").replace(/\s+(STIG|SRG)\s*$/i, "").trim();
  return {
    key: `stig:${slug(product)}`,
    url: link,
    versionLabel,
    publishedAt: item.UploadDate ? `${item.UploadDate}T00:00:00.000Z` : null,
  };
}

const clean = (name: string | undefined): string => (name ?? "").split(String.fromCharCode(0x200b)).join("").trim();

/** The library listing, through the Apex call the page itself makes; the URL is the DISA source's. */
export async function fetchListing(ctx: Pick<ListingContext, "db" | "http">, listingUrl?: string): Promise<DisaListingItem[]> {
  const url = listingUrl ?? (ctx.db.prepare("SELECT url FROM sources WHERE id = 'disa-stigs'").get() as { url: string } | undefined)?.url;
  if (!url) throw new Error("the DISA STIG library source is missing");
  const response = await ctx.http(url, {
    body: listingRequest,
    headers: { "content-type": "application/json", accept: "application/json", referer: "https://www.cyber.mil/stigs/downloads/", origin: "https://www.cyber.mil" },
    timeoutMs: 90_000,
  });
  const listing = JSON.parse(new TextDecoder("utf-8").decode(response.bytes)) as { returnValue?: DisaListingItem[] };
  if (!Array.isArray(listing.returnValue)) throw new Error("STIG library listing has no returnValue array");
  return listing.returnValue;
}

/**
 * The listing entry for one of DISA's dated packages ("Intune Policy - October 2026", "Group
 * Policy Objects (GPOs) - October 2026"): the month is the version, the upload date the publication date.
 */
export function packageTarget(items: DisaListingItem[], key: string, namePattern: RegExp): DocumentTarget | null {
  const item = items.find((i) => namePattern.test(clean(i.FileName)) && /\.zip$/i.test(i.DownloadLink ?? ""));
  if (!item) return null;
  const month = namePattern.exec(clean(item.FileName))?.[1]?.trim() ?? null;
  return { key, url: item.DownloadLink, versionLabel: month, publishedAt: item.UploadDate ? `${item.UploadDate}T00:00:00.000Z` : null };
}

/** The STIGs to follow: the watchlist's baseline entries, or the defaults. */
export function followedPatterns(ctx: Pick<ListingContext, "db">): string[] {
  const rows = ctx.db.prepare("SELECT value FROM watchlist WHERE kind = 'baseline'").all() as { value: string }[];
  const values = rows.map((r) => r.value.replace(/^stig:\s*/i, "").trim()).filter((v) => v.length > 0);
  return values.length ? values : defaultStigs;
}

export function selectStigs(items: DisaListingItem[], patterns: string[]): DocumentTarget[] {
  const lowered = patterns.map((p) => p.toLowerCase());
  const targets: DocumentTarget[] = [];
  const seen = new Set<string>();
  for (const item of items) {
    const name = (item.FileName ?? "").toLowerCase();
    if (!lowered.some((p) => name.includes(p))) continue;
    const target = stigTarget(item);
    if (!target || seen.has(target.key)) continue;
    seen.add(target.key);
    targets.push(target);
  }
  return targets;
}

type Node = Record<string, unknown>;

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  textNodeName: "#text",
  trimValues: true,
  processEntities: true,
  isArray: (name) => name === "Group" || name === "Rule" || name === "ident" || name === "reference",
});

function text(value: unknown): string | null {
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  if (Array.isArray(value)) return text(value[0]);
  if (value && typeof value === "object") {
    const t = (value as Node)["#text"];
    if (typeof t === "string" || typeof t === "number") return String(t);
  }
  return null;
}

/** The `<VulnDiscussion>` inside a rule's description, which DISA stores as escaped XML. */
function discussion(description: string | null): string | null {
  if (!description) return null;
  const m = /<VulnDiscussion>([\s\S]*?)<\/VulnDiscussion>/i.exec(description);
  return plainText(m?.[1] ?? description, 4000);
}

const severityFamily: Record<string, string> = { high: "CAT I", medium: "CAT II", low: "CAT III" };

export interface ParsedStig extends ParsedDocument {
  benchmarkId: string | null;
  releaseInfo: string | null;
}

export function parseXccdf(xml: string): ParsedStig {
  const doc = parser.parse(xml) as Node;
  const benchmark = doc.Benchmark as Node | undefined;
  if (!benchmark) throw new Error("not an XCCDF benchmark");
  const title = text(benchmark.title) ?? "STIG";
  const plain = benchmark["plain-text"];
  const plainList = Array.isArray(plain) ? (plain as Node[]) : plain ? [plain as Node] : [];
  const releaseInfo = text(plainList.find((p) => p["@_id"] === "release-info")) ?? null;
  const status = benchmark.status as Node | string | undefined;
  const statusDate = typeof status === "object" && status ? (status["@_date"] as string | undefined) : undefined;
  const requirements: NormalizedRequirement[] = [];
  for (const group of (benchmark.Group as Node[] | undefined) ?? []) {
    const groupId = String(group["@_id"] ?? "");
    const srg = text(group.title);
    for (const rule of (group.Rule as Node[] | undefined) ?? []) {
      const ruleId = String(rule["@_id"] ?? "");
      const severity = String(rule["@_severity"] ?? "").toLowerCase();
      const stigId = text(rule.version) ?? groupId;
      const check = rule.check as Node | Node[] | undefined;
      const checkNode = Array.isArray(check) ? check[0] : check;
      const checkContent = checkNode ? text(checkNode["check-content"]) : null;
      const ccis = ((rule.ident as Node[] | undefined) ?? []).map((i) => text(i)).filter((v): v is string => v !== null && v.startsWith("CCI-"));
      requirements.push({
        ref: groupId.toLowerCase(),
        parentRef: null,
        family: severityFamily[severity] ?? (severity ? severity.toUpperCase() : null),
        label: stigId,
        title: plainText(text(rule.title), 500) ?? stigId,
        statement: plainText(checkContent, 6000),
        guidance: discussion(text(rule.description)),
        params: [],
        related: ccis,
        sortKey: stigId,
        status: "active",
        extra: {
          ruleId,
          severity,
          srg,
          fix: plainText(text(rule.fixtext), 6000),
          ...(ccis.length ? { ccis } : {}),
        },
      });
    }
  }
  return {
    title,
    versionLabel: releaseInfo ? (/Release:\s*([\d.]+)/i.exec(releaseInfo)?.[1] ?? null) : null,
    publishedAt: statusDate ? `${statusDate}T00:00:00.000Z` : null,
    requirements,
    benchmarkId: typeof benchmark["@_id"] === "string" ? benchmark["@_id"] : null,
    releaseInfo,
  };
}

export const disaAdapter: Adapter = {
  id: "disa-stig",
  headers: { accept: "application/json, application/zip, */*" },
  async documents(source: SourceRow, ctx) {
    return selectStigs(await fetchListing(ctx, source.url), followedPatterns(ctx));
  },
  async parseDocument(bytes, target): Promise<ParsedDocument> {
    const entries = unzipAll(bytes);
    const xccdf = findEntry(entries, /xccdf\.xml$/i);
    if (!xccdf) throw new Error("STIG zip has no XCCDF file");
    const parsed = parseXccdf(entryText(xccdf));
    const versionLabel = target.versionLabel ?? parsed.versionLabel;
    let rationale: ParsedDocument["rationale"] = null;
    let notes: ParsedDocument["notes"] = [];
    const history = findEntry(entries, /Revision_History\.pdf$/i);
    if (history) {
      try {
        const text = await pdfText(history.bytes);
        const parsedHistory = parseStigRevisionHistory(text, versionLabel);
        notes = parsedHistory.notes;
        const summary = [...parsedHistory.notes.map((n) => `${n.label}: ${n.text}`), ...parsedHistory.general];
        if (summary.length) rationale = { text: `Revision History, ${versionLabel ?? "this release"}:\n${summary.map((s) => `- ${s}`).join("\n")}`, url: target.url };
      } catch {
        // A revision history that will not parse costs nothing but the rationale.
      }
    }
    return {
      title: parsed.title,
      versionLabel,
      publishedAt: target.publishedAt ?? parsed.publishedAt,
      requirements: parsed.requirements,
      rationale,
      notes,
    };
  },
};
