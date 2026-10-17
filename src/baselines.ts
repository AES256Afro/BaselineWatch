import type { DatabaseSync } from "node:sqlite";
import type { NormalizedRequirement } from "./oscal.ts";
import { latestDocument, listDocuments, loadRequirements, type DocumentRow } from "./register.ts";
import { cciMap, compareControlRefs, controlLabel, controlsFor, followedStigs, type CciMap, type StigSummary } from "./stigs.ts";

/**
 * The baseline builder: per platform, the strictest published profile, built from rows the
 * adapters stored and nothing else. A STIG's CAT I and CAT II rules (CAT III on request); for
 * Windows the Microsoft baseline settings for the same product, joined to rules by registry
 * path; for macOS the mSCP rules in the 800-53 High and DISA STIG baselines, joined by STIG id;
 * and the NIST SP 800-53 High baseline controls with the rules that implement each. Where DISA
 * ships an Intune settings-catalog policy and a checklist for the STIG, each rule carries the
 * definition DISA uses and DISA's verdict on whether its policies set the rule at all.
 */

export type BuilderPlatform = "windows" | "macos" | "linux";

export const builderPlatforms: { id: BuilderPlatform; label: string; blurb: string }[] = [
  { id: "windows", label: "Windows", blurb: "A Windows STIG, Microsoft's Security Compliance Toolkit baseline for the same product, DISA's Intune policy and checklist, and the SP 800-53 High controls." },
  { id: "macos", label: "macOS", blurb: "A macOS STIG joined to NIST's macOS Security Compliance Project rules (payload keys for Jamf), and the SP 800-53 High controls." },
  { id: "linux", label: "Linux", blurb: "A Linux STIG with its fix procedures, and the SP 800-53 High controls." },
];

export function isBuilderPlatform(value: unknown): value is BuilderPlatform {
  return value === "windows" || value === "macos" || value === "linux";
}

export interface DocChoice {
  /** The document key, such as stig:microsoft-windows-11 or baseline:windows-11-v25h2. */
  key: string;
  documentId: number;
  /** "Microsoft Windows 11 V2R11". */
  label: string;
  version: string | null;
  publishedAt: string | null;
  url: string | null;
  /** The source id, for links into the Register. */
  source: string;
}

export interface RegistryValue {
  hive: string;
  key: string;
  value: string;
  type: string | null;
  data: string | null;
}

export interface IntuneSetting {
  definitionId: string;
  value: string;
  policy: string;
}

export interface ProfileItem {
  id: string;
  kind: "stig" | "sct" | "mscp" | "control";
  label: string;
  title: string;
  severity: string | null;
  section: string;
  check: string | null;
  fix: string | null;
  controls: string[];
  /** STIG ids this item stands for or joins to (an mSCP rule's STIG ids, a setting's rule). */
  stigIds: string[];
  mscp: { id: string; payloads: { domain: string; keys: Record<string, unknown> }[]; ddm: unknown; odv: unknown; baselines: string[] } | null;
  registry: RegistryValue[];
  gpoPath: { path: string; setting: string } | null;
  intune: IntuneSetting[];
  checklist: { status: string; label: string; comment: string | null } | null;
  /** The Microsoft baseline's value for the same registry path, on a STIG item. */
  sctValue: string | null;
  url: string;
  /** On a control item: the labels of the included rules that implement it. */
  implementedBy: string[];
  /** Whether the person kept it. */
  included: boolean;
}

export interface ProfileOptions {
  platform: BuilderPlatform;
  stig?: string | undefined;
  sct?: string | undefined;
  mscp?: string | undefined;
  cat3?: boolean;
  /** Item ids the person unticked. */
  drop?: string[];
}

export interface Components {
  stig: DocChoice | null;
  sct: DocChoice | null;
  mscp: DocChoice | null;
  controls: DocChoice | null;
  catalog: DocChoice | null;
  intune: DocChoice | null;
  checklist: DocChoice | null;
  cciVersion: string | null;
}

export interface NextComparison {
  component: "stig" | "sct" | "mscp";
  current: DocChoice;
  next: DocChoice;
  added: { label: string; title: string }[];
  removed: { label: string; title: string }[];
  /** Severity moved into or out of the strict set, or a value or text changed. */
  changed: { label: string; title: string; what: string }[];
}

export interface Profile {
  platform: BuilderPlatform;
  options: ProfileOptions;
  components: Components;
  choices: { stigs: DocChoice[]; scts: DocChoice[]; mscps: DocChoice[] };
  items: ProfileItem[];
  next: NextComparison[];
  counts: { included: number; dropped: number; byKind: Record<ProfileItem["kind"], number> };
}

const stigPlatform: Record<BuilderPlatform, string> = { windows: "windows", macos: "macos", linux: "linux" };

function choiceOf(doc: DocumentRow, label: string): DocChoice {
  return { key: doc.document_key, documentId: doc.id, label: `${label} ${doc.version_label ?? ""}`.trim(), version: doc.version_label, publishedAt: doc.published_at, url: doc.source_url, source: doc.source_id };
}

/**
 * Every loaded version of every STIG on the platform, newest first within a STIG. The newest OS
 * leads on macOS and Linux (macOS 26 before 15, RHEL 10 before 9); on Windows the client STIG
 * leads, since Windows 11 is what most people build first.
 */
export function stigChoices(db: DatabaseSync, platform: BuilderPlatform): DocChoice[] {
  const out: DocChoice[] = [];
  const stigs = followedStigs(db).filter((s) => s.platform === stigPlatform[platform]);
  stigs.sort((a, b) => (platform === "windows" ? a.product.localeCompare(b.product, "en", { numeric: true }) : b.product.localeCompare(a.product, "en", { numeric: true })));
  for (const stig of stigs) {
    for (const doc of listDocuments(db, "disa-stigs").filter((d) => d.document_key === stig.key)) out.push(choiceOf(doc, stig.product));
  }
  return out;
}

const sctLabel = (key: string): string =>
  key
    .replace(/^baseline:/, "")
    .split("-")
    .map((w) => (/^v\d/.test(w) ? w : w.charAt(0).toUpperCase() + w.slice(1)))
    .join(" ");

/** The latest version of each Windows baseline in the Security Compliance Toolkit. */
export function sctChoices(db: DatabaseSync): DocChoice[] {
  const keys = (db.prepare("SELECT DISTINCT document_key FROM documents WHERE source_id = 'microsoft-sct' AND document_key LIKE 'baseline:windows%' ORDER BY document_key").all() as { document_key: string }[]).map((r) => r.document_key);
  return keys.map((k) => latestDocument(db, "microsoft-sct", k)).filter((d): d is DocumentRow => d !== null).map((d) => choiceOf(d, sctLabel(d.document_key)));
}

/** The latest version of each mSCP branch. */
export function mscpChoices(db: DatabaseSync): DocChoice[] {
  const keys = (db.prepare("SELECT DISTINCT document_key FROM documents WHERE source_id = 'nist-mscp' ORDER BY document_key").all() as { document_key: string }[]).map((r) => r.document_key);
  return keys
    .map((k) => latestDocument(db, "nist-mscp", k))
    .filter((d): d is DocumentRow => d !== null)
    .map((d) => ({ ...choiceOf(d, d.document_key), label: `${(d.title ?? "macOS").split(":")[0]}: ${d.version_label ?? d.document_key.replace("mscp:", "")}` }));
}

/** The SCT baseline that belongs to a STIG's product: Windows 11 to the newest Windows 11 baseline, Server 2025 to its own. */
export function defaultSct(stigKey: string, scts: DocChoice[]): DocChoice | null {
  const product = stigKey.replace(/^stig:microsoft-/, "");
  const candidates = scts.filter((s) => s.key.startsWith(`baseline:${product}`));
  if (!candidates.length) return null;
  return [...candidates].sort((a, b) => versionToken(b.key).localeCompare(versionToken(a.key)) || (b.publishedAt ?? "").localeCompare(a.publishedAt ?? ""))[0] ?? null;
}

/** "v25h2" of baseline:windows-11-v25h2, padded so v26h2 sorts after v25h2 and after v2. */
function versionToken(key: string): string {
  const m = /-v(\d+)(?:h(\d))?$/.exec(key);
  return m ? `${m[1]!.padStart(4, "0")}${m[2] ?? "0"}` : "0000";
}

const mscpBranchFor: Record<string, string> = { "26": "tahoe", "15": "sequoia", "14": "sonoma", "13": "ventura" };

/** The mSCP branch for a macOS STIG: macOS 26 is tahoe, macOS 15 is sequoia. */
export function defaultMscp(stigKey: string, mscps: DocChoice[]): DocChoice | null {
  const major = /macos-(\d+)/.exec(stigKey)?.[1];
  const branch = major ? mscpBranchFor[major] : undefined;
  return (branch ? mscps.find((m) => m.key === `mscp:${branch}`) : undefined) ?? null;
}

/** Which of DISA's Intune policies and checklists speak for a STIG. */
export const disaPolicyFamilies: Record<string, { intune: string | null; checklist: string | null }> = {
  "stig:microsoft-windows-11": { intune: "DoD Windows 11 STIG Settings Catalog", checklist: "DoD Windows 11 STIG" },
  "stig:microsoft-windows-10": { intune: "DoD Windows 10 STIG Settings Catalog", checklist: "DoD Windows 10 STIG" },
  "stig:microsoft-windows-server-2025": { intune: null, checklist: "DoD WinSvr 2025 MS STIG" },
  "stig:microsoft-windows-server-2022": { intune: null, checklist: "DoD WinSvr 2022 MS STIG" },
  "stig:microsoft-windows-server-2019": { intune: null, checklist: "DoD WinSvr 2019 DC and MS STIG" },
  "stig:microsoft-edge": { intune: "DoD Microsoft Edge STIG Settings Catalog", checklist: "DoD Microsoft Edge STIG" },
  "stig:google-chrome": { intune: "DoD Google Chrome STIG Settings Catalog", checklist: "DoD Google Chrome STIG" },
  "stig:mozilla-firefox": { intune: null, checklist: "DoD Mozilla Firefox STIG" },
  "stig:microsoft-windows-defender-firewall-with-advanced-security": { intune: "DoD Windows Defender Firewall STIG Settings Catalog", checklist: "DoD Windows Defender Firewall STIG" },
};

/**
 * The registry values a Windows STIG check names: blocks of "Registry Hive: HKEY_LOCAL_MACHINE",
 * "Registry Path: \SOFTWARE\...\", "Value Name: X", "Type: REG_DWORD", "Value: 0x1 (1)". The
 * check text is stored with whitespace collapsed, so the labels are the anchors.
 */
export function registryFromCheck(check: string | null): RegistryValue[] {
  if (!check) return [];
  const out: RegistryValue[] = [];
  let hive = "";
  let key = "";
  const re = /Registry Hive:\s*(HKEY_[A-Z_]+)|Registry Path:\s*(\\?[^\n]*?\\)(?=\s*(?:Value Name:|Registry|$))|Value Name:\s*([^\n]+?)(?=\s*(?:Value Type:|Type:|Value:|Registry|Value Name:|$))|(?:Value )?Type:\s*(REG_[A-Z_]+)|Value:\s*([^\n]+?)(?=\s*(?:Registry|Value Name:|Note:|If |For |When |$))/g;
  for (const m of check.matchAll(re)) {
    if (m[1]) hive = m[1];
    else if (m[2]) key = m[2].replace(/^\\+|\\+$/g, "");
    else if (m[3]) {
      if (hive && key) out.push({ hive, key, value: m[3].trim(), type: null, data: null });
    } else if (m[4]) {
      const last = out[out.length - 1];
      if (last && last.type === null) last.type = m[4];
    } else if (m[5]) {
      const last = out[out.length - 1];
      if (last && last.data === null) last.data = m[5].trim();
    }
  }
  return out;
}

/** The Group Policy path a Windows STIG fix names: "Computer Configuration >> ... >> "Setting"". */
export function gpoPathFromFix(fix: string | null): { path: string; setting: string } | null {
  if (!fix) return null;
  const m = /((?:Computer|User) Configuration(?:\s*>>\s*[^>"\n]+?)+)\s*>>\s*"([^"]+)"/.exec(fix);
  return m ? { path: m[1]!.replace(/\s*>>\s*/g, " >> ").trim(), setting: m[2]!.trim() } : null;
}

const hiveShort: Record<string, string> = { HKEY_LOCAL_MACHINE: "hklm", HKEY_CURRENT_USER: "hkcu", HKLM: "hklm", HKCU: "hkcu" };

/** One normalised form for a registry path from either side: hklm\software\policies\...\valuename. */
export function registryKey(hive: string, key: string, value: string): string {
  return `${hiveShort[hive.toUpperCase()] ?? hive.toLowerCase()}\\${key.replace(/^\\+|\\+$/g, "").toLowerCase()}\\${value.toLowerCase()}`;
}

/** The SCT setting's registry path, from its title "HKLM\Key\Value". */
function sctRegistryKey(r: NormalizedRequirement): string | null {
  if (r.extra.kind !== "registry") return null;
  const m = /^(HKLM|HKCU)\\(.+)\\([^\\]+)$/i.exec(r.title);
  return m ? registryKey(m[1]!, m[2]!, m[3]!) : null;
}

const normalise = (s: string): string => s.replace(/\([^)]*\)/g, "").toLowerCase().replace(/[^a-z0-9]/g, "");

/**
 * The settings-catalog definitions DISA uses for a rule, by name: the policy's display name in
 * the STIG fix text ("Configure SMBv1 Server") against the tail of the definition id
 * (mssecurityguide_configuresmbv1server). A parenthetical such as "(SEHOP)" is ignored.
 */
export function matchIntune(rule: { gpoPath: { setting: string } | null; registry: RegistryValue[] }, settings: NormalizedRequirement[]): IntuneSetting[] {
  const names = new Set<string>();
  if (rule.gpoPath) names.add(normalise(rule.gpoPath.setting));
  for (const r of rule.registry) if (r.value.length >= 8) names.add(normalise(r.value));
  const out: IntuneSetting[] = [];
  for (const s of settings) {
    // A definition revised in place carries a _v2 suffix (machineinactivitylimit_v2); the name does not.
    const tail = s.label.replace(/^(device|user)_vendor_msft_(policy_config_)?/, "").replace(/_v\d+$/, "").replace(/_/g, "");
    for (const n of names) {
      if (n.length < 8) continue;
      if (tail.endsWith(n) || (n.length >= 14 && tail.includes(n))) {
        out.push({ definitionId: s.label, value: s.statement ?? "", policy: String(s.extra.policy ?? s.family ?? "") });
        break;
      }
    }
  }
  return out;
}

function parseChoice(value: string | undefined, choices: DocChoice[], fallback: DocChoice | null): DocChoice | null {
  if (!value) return fallback;
  const byDoc = /^(.+)@(\d+)$/.exec(value);
  if (byDoc) return choices.find((c) => c.key === byDoc[1] && c.documentId === Number(byDoc[2])) ?? fallback;
  return choices.find((c) => c.key === value) ?? fallback;
}

const mscpSettingSections = new Set(["macOS", "Auditing", "Authentication", "iCloud", "Password policy", "System Settings"]);

function payloadsOf(r: NormalizedRequirement): { domain: string; keys: Record<string, unknown> }[] {
  const info = r.extra.mobileconfigInfo;
  if (!info || typeof info !== "object") return [];
  return Object.entries(info as Record<string, unknown>).map(([domain, keys]) => ({ domain, keys: keys && typeof keys === "object" ? (keys as Record<string, unknown>) : { value: keys } }));
}

/** Builds the profile for a platform from the Register's rows and the person's choices. */
export function buildProfile(db: DatabaseSync, options: ProfileOptions): Profile {
  const stigs = stigChoices(db, options.platform);
  const scts = options.platform === "windows" ? sctChoices(db) : [];
  const mscps = options.platform === "macos" ? mscpChoices(db) : [];
  const stig = parseChoice(options.stig, stigs, stigs[0] ?? null);
  const sct = options.platform === "windows" ? parseChoice(options.sct, scts, stig ? defaultSct(stig.key, scts) : null) : null;
  const mscp = options.platform === "macos" ? parseChoice(options.mscp, mscps, stig ? defaultMscp(stig.key, mscps) : null) : null;
  const map = cciMap(db);
  const highDoc = latestDocument(db, "nist-sp-800-53b", "profile:high");
  const catalogDoc = latestDocument(db, "nist-sp-800-53", "catalog");
  const intuneDoc = latestDocument(db, "disa-intune", "intune:package");
  const checklistDoc = latestDocument(db, "disa-gpo", "gpo:checklists");
  const families = stig ? (disaPolicyFamilies[stig.key] ?? { intune: null, checklist: null }) : { intune: null, checklist: null };
  const dropped = new Set(options.drop ?? []);
  const items: ProfileItem[] = [];

  // DISA's Intune settings and checklist verdicts for this STIG, when it ships them.
  const intuneSettings = intuneDoc && families.intune ? loadRequirements(db, intuneDoc.id).filter((r) => r.family === families.intune) : [];
  const verdicts = new Map<string, { status: string; label: string; comment: string | null }>();
  if (checklistDoc && families.checklist) {
    for (const r of loadRequirements(db, checklistDoc.id).filter((r) => r.family === families.checklist)) {
      verdicts.set(String(r.extra.vulnNum ?? "").toLowerCase(), { status: String(r.extra.status ?? ""), label: (r.statement ?? "").split(". ")[0] ?? "", comment: typeof r.extra.comments === "string" ? r.extra.comments : null });
    }
  }

  // The STIG's rules, CAT I and II (and III on request).
  const stigRules = stig ? loadRequirements(db, stig.documentId) : [];
  const cats = new Set(options.cat3 ? ["CAT I", "CAT II", "CAT III"] : ["CAT I", "CAT II"]);
  const stigItems = new Map<string, ProfileItem>();
  for (const r of stigRules.filter((r) => cats.has(r.family ?? "") && r.status === "active")) {
    const fix = typeof r.extra.fix === "string" ? r.extra.fix : null;
    const registry = options.platform === "windows" ? registryFromCheck(r.statement) : [];
    const gpoPath = options.platform === "windows" ? gpoPathFromFix(fix) : null;
    const item: ProfileItem = {
      id: `stig:${r.ref}`,
      kind: "stig",
      label: r.label,
      title: r.title,
      severity: r.family,
      section: r.family ?? "unrated",
      check: r.statement,
      fix,
      controls: controlsFor(r, map),
      stigIds: [r.label],
      mscp: null,
      registry,
      gpoPath,
      intune: intuneSettings.length ? matchIntune({ gpoPath, registry }, intuneSettings) : [],
      checklist: verdicts.get(r.ref) ?? null,
      sctValue: null,
      url: `/standards/disa-stigs/${stig!.documentId}/${r.ref}`,
      implementedBy: [],
      included: !dropped.has(`stig:${r.ref}`),
    };
    stigItems.set(r.label, item);
    items.push(item);
  }

  // Microsoft's baseline: settings joined to rules by registry path; the rest as additions.
  if (sct) {
    const byRegistry = new Map<string, ProfileItem>();
    for (const item of stigItems.values()) for (const reg of item.registry) byRegistry.set(registryKey(reg.hive, reg.key, reg.value), item);
    for (const r of loadRequirements(db, sct.documentId)) {
      const key = sctRegistryKey(r);
      const joined = key ? byRegistry.get(key) : undefined;
      if (joined) {
        joined.sctValue = r.statement;
        continue;
      }
      items.push({
        id: `sct:${r.ref}`,
        kind: "sct",
        label: r.label,
        title: r.title,
        severity: null,
        section: `Microsoft baseline: ${r.family ?? sct.label}`,
        check: null,
        fix: null,
        controls: [],
        stigIds: [],
        mscp: null,
        registry: r.extra.kind === "registry" && key ? [{ hive: r.title.startsWith("HKCU") ? "HKEY_CURRENT_USER" : "HKEY_LOCAL_MACHINE", key: r.title.replace(/^HK(LM|CU)\\/, "").replace(/\\[^\\]+$/, ""), value: r.label, type: typeof r.extra.regType === "string" ? r.extra.regType : null, data: typeof r.extra.regData === "string" ? r.extra.regData : null }] : [],
        gpoPath: null,
        intune: [],
        checklist: null,
        sctValue: r.statement,
        url: `/standards/microsoft-sct/${sct.documentId}/${encodeURIComponent(r.ref)}`,
        implementedBy: [],
        included: !dropped.has(`sct:${r.ref}`),
      });
    }
  }

  // mSCP: rules in the High or DISA STIG baselines joined to the STIG's rules by STIG id; the rest as additions.
  if (mscp) {
    for (const r of loadRequirements(db, mscp.documentId)) {
      if (!mscpSettingSections.has(r.family ?? "")) continue;
      const baselines = Array.isArray(r.extra.baselines) ? (r.extra.baselines as string[]) : [];
      if (!baselines.includes("800-53r5_high") && !baselines.includes("DISA-STIG")) continue;
      const stigIds = Array.isArray(r.extra.stig) ? (r.extra.stig as string[]) : [];
      const info = { id: r.label, payloads: payloadsOf(r), ddm: r.extra.ddmInfo ?? null, odv: r.extra.odv ?? null, baselines };
      const joined = stigIds.map((id) => stigItems.get(id)).find((i) => i !== undefined);
      if (joined) {
        joined.mscp = info;
        joined.stigIds = [...new Set([...joined.stigIds, ...stigIds])];
        for (const c of r.related) if (!joined.controls.includes(c)) joined.controls.push(c);
        joined.controls.sort(compareControlRefs);
        if (!joined.fix || /Configuration Profile/i.test(joined.fix)) joined.fix = joined.fix ?? (typeof r.extra.fix === "string" ? r.extra.fix : null);
        continue;
      }
      items.push({
        id: `mscp:${r.ref}`,
        kind: "mscp",
        label: r.label,
        title: r.title,
        severity: typeof r.extra.severity === "string" ? r.extra.severity : null,
        section: `mSCP adds: ${r.family ?? "rule"}`,
        check: r.statement,
        fix: typeof r.extra.fix === "string" ? r.extra.fix : null,
        controls: [...r.related].sort(compareControlRefs),
        stigIds,
        mscp: info,
        registry: [],
        gpoPath: null,
        intune: [],
        checklist: null,
        sctValue: null,
        url: `/standards/nist-mscp/${mscp.documentId}/${r.ref}`,
        implementedBy: [],
        included: !dropped.has(`mscp:${r.ref}`),
      });
    }
  }

  // The SP 800-53 High baseline: each control with the included rules that implement it.
  if (highDoc) {
    const titles = new Map<string, { title: string; family: string | null }>();
    if (catalogDoc) for (const c of loadRequirements(db, catalogDoc.id)) titles.set(c.ref, { title: c.title, family: c.family });
    const implementers = new Map<string, string[]>();
    for (const item of items) if (item.included && item.kind !== "control") for (const c of item.controls) implementers.set(c, [...(implementers.get(c) ?? []), item.label]);
    for (const c of loadRequirements(db, highDoc.id).map((r) => r.ref).sort(compareControlRefs)) {
      const meta = titles.get(c);
      items.push({
        id: `control:${c}`,
        kind: "control",
        label: controlLabel(c),
        title: meta?.title ?? c.toUpperCase(),
        severity: null,
        section: `SP 800-53 High: ${meta?.family ?? c.slice(0, 2).toUpperCase()}`,
        check: null,
        fix: null,
        controls: [c],
        stigIds: [],
        mscp: null,
        registry: [],
        gpoPath: null,
        intune: [],
        checklist: null,
        sctValue: null,
        url: catalogDoc ? `/standards/nist-sp-800-53/${catalogDoc.id}/${c}` : `/standards/nist-sp-800-53b`,
        implementedBy: implementers.get(c) ?? [],
        included: !dropped.has(`control:${c}`),
      });
    }
  }

  const byKind: Record<ProfileItem["kind"], number> = { stig: 0, sct: 0, mscp: 0, control: 0 };
  for (const i of items) if (i.included) byKind[i.kind] += 1;
  const components: Components = {
    stig,
    sct,
    mscp,
    controls: highDoc ? choiceOf(highDoc, "SP 800-53 High baseline") : null,
    catalog: catalogDoc ? choiceOf(catalogDoc, "SP 800-53") : null,
    intune: intuneDoc && families.intune ? { ...choiceOf(intuneDoc, families.intune), label: families.intune } : null,
    checklist: checklistDoc && families.checklist ? { ...choiceOf(checklistDoc, families.checklist), label: families.checklist } : null,
    cciVersion: map.version,
  };
  return {
    platform: options.platform,
    options,
    components,
    choices: { stigs, scts, mscps },
    items,
    next: compareNext(db, { stig, sct, mscp }, { stigs, scts, mscps }, cats, map),
    counts: { included: items.filter((i) => i.included).length, dropped: items.filter((i) => !i.included).length, byKind },
  };
}

/** "Current versus next": what the strict set gains or loses in a newer version of each component. */
export function compareNext(
  db: DatabaseSync,
  chosen: { stig: DocChoice | null; sct: DocChoice | null; mscp: DocChoice | null },
  choices: { stigs: DocChoice[]; scts: DocChoice[]; mscps: DocChoice[] },
  cats: Set<string>,
  map: CciMap,
): NextComparison[] {
  const out: NextComparison[] = [];
  if (chosen.stig) {
    const newer = choices.stigs.filter((c) => c.key === chosen.stig!.key && (c.publishedAt ?? "") > (chosen.stig!.publishedAt ?? "")).sort((a, b) => (a.publishedAt ?? "").localeCompare(b.publishedAt ?? ""));
    const next = newer[0];
    if (next) out.push(compareStigs(db, chosen.stig, next, cats, map));
  }
  if (chosen.sct) {
    const product = /^(baseline:[a-z0-9-]+?)(?:-v\d+h?\d?)?$/.exec(chosen.sct.key)?.[1] ?? chosen.sct.key;
    const next = choices.scts.filter((c) => c.key.startsWith(product) && c.key !== chosen.sct!.key && versionToken(c.key) > versionToken(chosen.sct!.key)).sort((a, b) => versionToken(a.key).localeCompare(versionToken(b.key)))[0];
    if (next) out.push(compareSettings(db, chosen.sct, next));
  }
  if (chosen.mscp) {
    const order = ["ventura", "sonoma", "sequoia", "tahoe"];
    const at = order.indexOf(chosen.mscp.key.replace("mscp:", ""));
    const next = at >= 0 ? choices.mscps.find((c) => c.key === `mscp:${order[at + 1]}`) : undefined;
    if (next) out.push(compareMscp(db, chosen.mscp, next));
  }
  return out;
}

function compareStigs(db: DatabaseSync, current: DocChoice, next: DocChoice, cats: Set<string>, map: CciMap): NextComparison {
  const strict = (id: number) => new Map(loadRequirements(db, id).filter((r) => cats.has(r.family ?? "") && r.status === "active").map((r) => [r.ref, r]));
  const a = strict(current.documentId);
  const b = strict(next.documentId);
  const all = new Map(loadRequirements(db, next.documentId).map((r) => [r.ref, r]));
  const added = [...b.values()].filter((r) => !a.has(r.ref)).map((r) => ({ label: r.label, title: r.title }));
  const removed = [...a.values()].filter((r) => !b.has(r.ref)).map((r) => ({ label: r.label, title: `${r.title}${all.get(r.ref) ? ` (now ${all.get(r.ref)!.family ?? "unrated"})` : " (rule removed)"}` }));
  const changed: NextComparison["changed"] = [];
  for (const [ref, r] of a) {
    const n = b.get(ref);
    if (!n) continue;
    const what: string[] = [];
    if (r.family !== n.family) what.push(`${r.family} → ${n.family}`);
    if ((r.statement ?? "") !== (n.statement ?? "")) what.push("check text");
    if ((r.extra.fix ?? "") !== (n.extra.fix ?? "")) what.push("fix text");
    const before = controlsFor(r, map).join(",");
    const after = controlsFor(n, map).join(",");
    if (before !== after) what.push("controls");
    if (what.length) changed.push({ label: n.label, title: n.title, what: what.join(", ") });
  }
  return { component: "stig", current, next, added, removed, changed };
}

function compareSettings(db: DatabaseSync, current: DocChoice, next: DocChoice): NextComparison {
  const a = new Map(loadRequirements(db, current.documentId).map((r) => [r.ref, r]));
  const b = new Map(loadRequirements(db, next.documentId).map((r) => [r.ref, r]));
  const added = [...b.values()].filter((r) => !a.has(r.ref)).map((r) => ({ label: r.label, title: `${r.title} = ${r.statement ?? ""}` }));
  const removed = [...a.values()].filter((r) => !b.has(r.ref)).map((r) => ({ label: r.label, title: r.title }));
  const changed: NextComparison["changed"] = [];
  for (const [ref, r] of a) {
    const n = b.get(ref);
    if (n && (r.statement ?? "") !== (n.statement ?? "")) changed.push({ label: n.label, title: n.title, what: `${r.statement ?? ""} → ${n.statement ?? ""}` });
  }
  return { component: "sct", current, next, added, removed, changed };
}

function compareMscp(db: DatabaseSync, current: DocChoice, next: DocChoice): NextComparison {
  const strict = (id: number) =>
    new Map(
      loadRequirements(db, id)
        .filter((r) => mscpSettingSections.has(r.family ?? "") && Array.isArray(r.extra.baselines) && ((r.extra.baselines as string[]).includes("800-53r5_high") || (r.extra.baselines as string[]).includes("DISA-STIG")))
        .map((r) => [r.ref, r]),
    );
  const a = strict(current.documentId);
  const b = strict(next.documentId);
  const added = [...b.values()].filter((r) => !a.has(r.ref)).map((r) => ({ label: r.label, title: r.title }));
  const removed = [...a.values()].filter((r) => !b.has(r.ref)).map((r) => ({ label: r.label, title: r.title }));
  const changed: NextComparison["changed"] = [];
  for (const [ref, r] of a) {
    const n = b.get(ref);
    if (!n) continue;
    const what: string[] = [];
    if ((r.statement ?? "") !== (n.statement ?? "")) what.push("check");
    if (JSON.stringify(r.extra.mobileconfigInfo ?? null) !== JSON.stringify(n.extra.mobileconfigInfo ?? null)) what.push("payload keys");
    if (JSON.stringify(r.extra.odv ?? null) !== JSON.stringify(n.extra.odv ?? null)) what.push("values");
    if (what.length) changed.push({ label: n.label, title: n.title, what: what.join(", ") });
  }
  return { component: "mscp", current, next, added, removed, changed };
}

/** The STIGs a platform's builder can start from, for the index page. */
export function builderSummary(db: DatabaseSync, platform: BuilderPlatform): { stigs: StigSummary[]; scts: number; mscps: number; high: boolean } {
  return {
    stigs: followedStigs(db).filter((s) => s.platform === stigPlatform[platform]),
    scts: platform === "windows" ? sctChoices(db).length : 0,
    mscps: platform === "macos" ? mscpChoices(db).length : 0,
    high: latestDocument(db, "nist-sp-800-53b", "profile:high") !== null,
  };
}
