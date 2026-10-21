import type { NormalizedRequirement } from "../oscal.ts";
import { entryText, unzipAll, type ZipEntry } from "../zip.ts";
import { fetchListing, packageTarget } from "./disa.ts";
import { slugOf, policyFamily } from "./disa-intune.ts";
import { plainText, type Adapter, type DocumentTarget, type ParsedDocument, type SourceRow } from "./types.ts";

/**
 * DISA's GPO package, read for its checklists: under `Support Files/Checklist Files` DISA ships
 * one STIG Viewer checklist (.ckl) per STIG it provides policies for, with every rule marked
 * NotAFinding ("GPO - ... / Intune - ...": its policies set it), Not_Applicable ("Outside scope
 * of GPO configurations": a manual step), Open or Not_Reviewed. That is DISA's own statement of
 * what its GPO and Intune policies cover, rule by rule; the baseline builder quotes it. The GPO
 * backups themselves are not parsed. The zip is about 7 MB and moves quarterly; the listing's
 * date gates the download.
 */

export const gpoPackageKey = "gpo:checklists";
const packageName = /^Group Policy Objects \(GPOs\) - (.+)$/i;

const statusLabels: Record<string, string> = {
  NotAFinding: "Covered by DISA's policy",
  Not_Applicable: "Not applicable to the policy",
  Open: "Open",
  Not_Reviewed: "Not reviewed",
};

interface Vuln {
  vulnNum: string;
  ruleVer: string | null;
  ruleTitle: string | null;
  severity: string | null;
  status: string;
  comments: string | null;
  findingDetails: string | null;
}

function attr(vuln: string, name: string): string | null {
  const m = new RegExp(`<VULN_ATTRIBUTE>${name}</VULN_ATTRIBUTE>\\s*<ATTRIBUTE_DATA>([\\s\\S]*?)</ATTRIBUTE_DATA>`).exec(vuln);
  return m ? plainText(m[1], 2000) : null;
}

/** The rules of one checklist with DISA's verdict on each. */
export function parseChecklist(xml: string): { stigId: string | null; vulns: Vuln[] } {
  const text = xml.replace(/^\uFEFF/, "");
  const stigId = /<SID_NAME>stigid<\/SID_NAME>\s*<SID_DATA>([^<]*)<\/SID_DATA>/.exec(text)?.[1]?.trim() ?? null;
  const vulns: Vuln[] = [];
  for (const m of text.matchAll(/<VULN>([\s\S]*?)<\/VULN>/g)) {
    const v = m[1] ?? "";
    const vulnNum = attr(v, "Vuln_Num");
    if (!vulnNum) continue;
    vulns.push({
      vulnNum,
      ruleVer: attr(v, "Rule_Ver"),
      ruleTitle: attr(v, "Rule_Title"),
      severity: attr(v, "Severity"),
      status: /<STATUS>([^<]*)<\/STATUS>/.exec(v)?.[1]?.trim() ?? "Not_Reviewed",
      comments: plainText(/<COMMENTS>([\s\S]*?)<\/COMMENTS>/.exec(v)?.[1], 2000),
      findingDetails: plainText(/<FINDING_DETAILS>([\s\S]*?)<\/FINDING_DETAILS>/.exec(v)?.[1], 2000),
    });
  }
  return { stigId, vulns };
}

/** Every checklist in the package as requirements keyed by checklist and V-id. */
export function parseGpoPackage(entries: ZipEntry[]): { checklists: string[]; requirements: NormalizedRequirement[] } {
  const checklists: string[] = [];
  const requirements: NormalizedRequirement[] = [];
  for (const e of entries.filter((e) => /Checklist Files\/[^/]+\.ckl$/i.test(e.name)).sort((a, b) => a.name.localeCompare(b.name))) {
    const name = e.name.split("/").pop()!.replace(/\.ckl$/i, "").trim();
    const { family, version } = policyFamily(name);
    const slug = slugOf(family);
    const parsed = parseChecklist(entryText(e));
    if (parsed.vulns.length === 0) continue;
    checklists.push(name);
    for (const v of parsed.vulns) {
      const status = statusLabels[v.status] ?? v.status;
      requirements.push({
        ref: `${slug}|${v.vulnNum.toLowerCase()}`,
        parentRef: null,
        family,
        label: v.ruleVer ?? v.vulnNum,
        title: v.ruleTitle ?? v.vulnNum,
        statement: `${status}${v.comments ? `. ${v.comments}` : ""}${v.findingDetails ? ` ${v.findingDetails}` : ""}`,
        guidance: null,
        params: [],
        related: [],
        sortKey: `${slug}|${v.ruleVer ?? v.vulnNum}`,
        status: "active",
        extra: {
          checklist: name,
          ...(version ? { checklistVersion: version } : {}),
          ...(parsed.stigId ? { stigId: parsed.stigId } : {}),
          vulnNum: v.vulnNum,
          status: v.status,
          ...(v.severity ? { severity: v.severity } : {}),
          ...(v.comments ? { comments: v.comments } : {}),
          ...(v.findingDetails ? { findingDetails: v.findingDetails } : {}),
        },
      });
    }
  }
  if (requirements.length === 0) throw new Error("the package holds no checklist BaselineWatch can read");
  return { checklists, requirements };
}

export const disaGpoAdapter: Adapter = {
  id: "disa-gpo",
  headers: { accept: "application/zip, application/octet-stream, */*" },
  async documents(_source: SourceRow, ctx): Promise<DocumentTarget[]> {
    const target = packageTarget(await fetchListing(ctx), gpoPackageKey, packageName);
    return target ? [target] : [];
  },
  parseDocument(bytes, target): ParsedDocument {
    const { checklists, requirements } = parseGpoPackage(unzipAll(bytes));
    return {
      title: `DISA STIG GPO Package checklists${target.versionLabel ? `, ${target.versionLabel}` : ""}`,
      versionLabel: target.versionLabel ?? null,
      publishedAt: target.publishedAt ?? null,
      requirements,
      rationale: { text: `Checklists in this package: ${checklists.join("; ")}.`, url: target.url },
    };
  },
};
