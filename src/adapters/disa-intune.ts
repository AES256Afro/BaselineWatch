import type { NormalizedRequirement } from "../oscal.ts";
import { entryText, unzipAll, type ZipEntry } from "../zip.ts";
import { fetchListing, packageTarget } from "./disa.ts";
import type { Adapter, DocumentTarget, ParsedDocument, SourceRow } from "./types.ts";

/**
 * DISA's Intune policy package: the settings-catalog policies DISA itself ships for its STIGs
 * (Windows 11, Windows 10, Edge, Chrome, Defender, the firewall, Microsoft 365 Apps), exported
 * from Microsoft Graph as `configurationPolicies` JSON. Each setting becomes a requirement keyed
 * by policy and settings-catalog definition id, so a quarterly package diffs setting by setting
 * and the baseline builder can name the definition DISA uses for a STIG rule.
 */

export const intunePackageKey = "intune:package";
const packageName = /^Intune Policy - (.+)$/i;

interface SettingInstance {
  "@odata.type"?: string;
  settingDefinitionId?: string;
  choiceSettingValue?: { value?: string; children?: SettingInstance[] };
  simpleSettingValue?: { "@odata.type"?: string; value?: unknown };
  simpleSettingCollectionValue?: { value?: unknown }[];
  groupSettingCollectionValue?: { children?: SettingInstance[] }[];
}

interface CatalogPolicy {
  name?: string;
  description?: string;
  platforms?: string;
  technologies?: string;
  lastModifiedDateTime?: string;
  settings?: { settingInstance?: SettingInstance }[];
}

/** The value a setting instance carries, readable: "1", "X_Admin", "a; b", "child = 6". */
export function valueText(inst: SettingInstance): string {
  const id = inst.settingDefinitionId ?? "";
  const choice = inst.choiceSettingValue;
  if (choice) {
    const own = choice.value && choice.value.startsWith(`${id}_`) ? choice.value.slice(id.length + 1) : (choice.value ?? "");
    const children = (choice.children ?? []).map((c) => `${shortId(c.settingDefinitionId ?? "", id)} = ${valueText(c)}`);
    return [own, ...children].filter((s) => s !== "").join("; ");
  }
  if (inst.simpleSettingValue) return String(inst.simpleSettingValue.value ?? "");
  if (inst.simpleSettingCollectionValue) return inst.simpleSettingCollectionValue.map((v) => String(v.value ?? "")).join("; ");
  if (inst.groupSettingCollectionValue) {
    return inst.groupSettingCollectionValue.map((g, i) => `[${i + 1}] ${(g.children ?? []).map((c) => `${shortId(c.settingDefinitionId ?? "", id)} = ${valueText(c)}`).join("; ")}`).join(" | ");
  }
  return "";
}

/** A child's id without the parent's prefix: `..._minpinlength` of `device_vendor_msft_bitlocker_systemdrivesminimumpinlength`. */
function shortId(childId: string, parentId: string): string {
  return childId.startsWith(`${parentId}_`) ? childId.slice(parentId.length + 1) : childId.replace(/^(device|user)_vendor_msft_(policy_config_)?/, "");
}

/** "DoD Windows 11 STIG v2r11 Settings Catalog" → "DoD Windows 11 STIG Settings Catalog" and "v2r11". */
export function policyFamily(name: string): { family: string; version: string | null } {
  const m = /\s+(v\d+r\d+)\b/i.exec(name);
  return { family: name.replace(/\s+v\d+r\d+\b/i, "").replace(/\s+/g, " ").trim(), version: m?.[1]?.toLowerCase() ?? null };
}

export function slugOf(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

/** The policy's settings as requirements, one per top-level setting instance. */
export function normalizePolicy(json: string): { name: string; requirements: NormalizedRequirement[] } {
  const policy = JSON.parse(json.replace(/^\uFEFF/, "")) as CatalogPolicy;
  const name = (policy.name ?? "").trim();
  if (!name || !Array.isArray(policy.settings)) throw new Error("not a settings-catalog policy export");
  const { family, version } = policyFamily(name);
  const slug = slugOf(family);
  const requirements: NormalizedRequirement[] = [];
  for (const s of policy.settings) {
    const inst = s.settingInstance;
    const id = inst?.settingDefinitionId;
    if (!inst || !id) continue;
    requirements.push({
      ref: `${slug}|${id.toLowerCase()}`,
      parentRef: null,
      family,
      label: id,
      title: `${family}: ${id.replace(/^(device|user)_vendor_msft_(policy_config_)?/, "")}`,
      statement: valueText(inst),
      guidance: null,
      params: [],
      related: [],
      sortKey: `${slug}|${id.toLowerCase()}`,
      status: "active",
      extra: {
        policy: name,
        ...(version ? { policyVersion: version } : {}),
        ...(policy.platforms ? { platforms: policy.platforms } : {}),
        ...(policy.technologies ? { technologies: policy.technologies } : {}),
        ...(inst["@odata.type"] ? { instance: inst["@odata.type"].replace("#microsoft.graph.deviceManagementConfiguration", "") } : {}),
        scope: id.startsWith("user_") ? "user" : "device",
      },
    });
  }
  return { name, requirements };
}

/** Every settings-catalog export in the package; the other profile kinds (custom OMA-URI, macOS plists, scripts) are not settings. */
export function parseIntunePackage(entries: ZipEntry[]): { policies: string[]; requirements: NormalizedRequirement[] } {
  const policies: string[] = [];
  const requirements: NormalizedRequirement[] = [];
  const seen = new Set<string>();
  for (const e of entries.filter((e) => /Settings Catalog\/[^/]+\.json$/i.test(e.name) && !/\/Assignments\//i.test(e.name)).sort((a, b) => a.name.localeCompare(b.name))) {
    let parsed: { name: string; requirements: NormalizedRequirement[] };
    try {
      parsed = normalizePolicy(entryText(e));
    } catch {
      continue; // a file that is not a policy export (a sample, a note) is skipped, not fatal
    }
    policies.push(parsed.name);
    for (const r of parsed.requirements) {
      if (seen.has(r.ref)) continue;
      seen.add(r.ref);
      requirements.push(r);
    }
  }
  if (requirements.length === 0) throw new Error("the package holds no settings-catalog policy BaselineWatch can read");
  return { policies, requirements };
}

export const disaIntuneAdapter: Adapter = {
  id: "disa-intune",
  headers: { accept: "application/zip, application/octet-stream, */*" },
  async documents(_source: SourceRow, ctx): Promise<DocumentTarget[]> {
    const target = packageTarget(await fetchListing(ctx), intunePackageKey, packageName);
    return target ? [target] : [];
  },
  parseDocument(bytes, target): ParsedDocument {
    const { policies, requirements } = parseIntunePackage(unzipAll(bytes));
    return {
      title: `DISA STIG Intune Policy Package${target.versionLabel ? `, ${target.versionLabel}` : ""}`,
      versionLabel: target.versionLabel ?? null,
      publishedAt: target.publishedAt ?? null,
      requirements,
      rationale: { text: `Settings-catalog policies in this package: ${policies.join("; ")}.`, url: target.url },
    };
  },
};
