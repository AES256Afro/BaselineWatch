import { parse as parseYaml } from "yaml";
import type { NormalizedRequirement } from "../oscal.ts";
import { compareControlRefs } from "../stigs.ts";
import { entryText, unzipAll, type ZipEntry } from "../zip.ts";
import { isoDate, plainText, type Adapter, type DocumentTarget, type ListingContext, type ParsedDocument, type SourceRow } from "./types.ts";

/**
 * NIST's macOS Security Compliance Project (github.com/usnistgov/macos_security): one branch per
 * macOS release, `rules/<section>/<id>.yaml` with a check, a fix, the configuration-profile
 * payload keys and references to SP 800-53 r5, 800-171 r3, the CCIs, the DISA STIG ids and CIS,
 * and `baselines/*.yaml` naming which rules make up each baseline (800-53 High, DISA STIG, CIS
 * Level 1 and 2, CMMC...). One zip per branch (about 1 MB) read whole; the GitHub commits API
 * gives the branch's current commit so an unchanged branch costs one small request a day.
 */

export const mscpRepository = "https://github.com/usnistgov/macos_security";
/** Branches followed: the current macOS and the one before it, and the current iOS/iPadOS. */
export const mscpBranches = ["tahoe", "sequoia", "ios_26"] as const;

export function branchZipUrl(ref: string): string {
  return `https://codeload.github.com/usnistgov/macos_security/zip/${/^[0-9a-f]{40}$/.test(ref) ? ref : `refs/heads/${ref}`}`;
}

export function branchCommitUrl(branch: string): string {
  return `https://api.github.com/repos/usnistgov/macos_security/commits/${branch}`;
}

const sectionLabels: Record<string, string> = {
  os: "macOS",
  audit: "Auditing",
  auth: "Authentication",
  icloud: "iCloud",
  pwpolicy: "Password policy",
  system_settings: "System Settings",
  supplemental: "Supplemental",
  inherent: "Inherent",
  permanent: "Permanent",
  not_applicable: "Not applicable",
  srg: "SRG",
};

type Json = Record<string, unknown>;
const obj = (v: unknown): Json => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Json) : {});
const str = (v: unknown): string | null => (typeof v === "string" && v.trim() !== "" ? v.trim() : typeof v === "number" || typeof v === "boolean" ? String(v) : null);
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => str(x)).filter((x): x is string => x !== null) : []);

/** "AC-2(1)" as the Register writes it: ac-2.1. Entries that are not control ids ("N/A") are dropped. */
export function controlRefOf(label: string): string | null {
  const m = /^([A-Za-z]{2})-(\d+)(?:\s*\((\d+)\))?$/.exec(label.trim());
  if (!m) return null;
  return `${m[1]!.toLowerCase()}-${Number(m[2])}${m[3] ? `.${Number(m[3])}` : ""}`;
}

export interface MscpVersion {
  os: string | null;
  platform: string | null;
  version: string | null;
  cpe: string | null;
  date: string | null;
}

export function parseVersion(text: string): MscpVersion {
  const v = obj(parseYaml(text));
  return { os: str(v.os), platform: str(v.platform), version: str(v.version), cpe: str(v.cpe), date: str(v.date) };
}

/** A rule file as a requirement; `baselines` are the baseline files that list it. */
export function normalizeRule(section: string, text: string, baselines: string[]): NormalizedRequirement | null {
  const r = obj(parseYaml(text));
  const id = str(r.id);
  if (!id) return null;
  const refs = obj(r.references);
  const controls = [...new Set(strings(refs["800-53r5"]).map(controlRefOf).filter((c): c is string => c !== null))].sort(compareControlRefs);
  const cis = obj(refs.cis);
  const mobileconfigInfo = r.mobileconfig_info !== null && typeof r.mobileconfig_info === "object" ? r.mobileconfig_info : null;
  const ddmInfo = r.ddm_info !== null && typeof r.ddm_info === "object" ? r.ddm_info : null;
  const title = plainText(str(r.title), 300) ?? id;
  const extra: Record<string, unknown> = {};
  const put = (k: string, v: unknown) => {
    if (v === null || v === undefined || v === "" || (Array.isArray(v) && v.length === 0) || (typeof v === "object" && !Array.isArray(v) && Object.keys(v as object).length === 0)) return;
    extra[k] = v;
  };
  put("fix", str(r.fix));
  put("result", r.result !== undefined ? r.result : null);
  put("severity", str(r.severity));
  put("mobileconfig", r.mobileconfig === true ? true : null);
  put("mobileconfigInfo", mobileconfigInfo);
  put("ddmInfo", ddmInfo);
  put("odv", r.odv !== null && typeof r.odv === "object" ? r.odv : null);
  put("tags", strings(r.tags));
  put("macOS", strings(r.macOS));
  put("stig", strings(refs.disa_stig));
  put("srg", strings(refs.srg));
  put("cci", strings(refs.cci));
  put("cce", strings(refs.cce));
  put("nist171", strings(refs["800-171r3"]));
  put("cmmc", strings(refs.cmmc));
  put("cisBenchmark", strings(cis.benchmark));
  put("cisControls", strings(cis["controls v8"]));
  put("baselines", [...baselines].sort());
  put("section", section);
  return {
    ref: id.toLowerCase(),
    parentRef: null,
    family: sectionLabels[section] ?? section,
    label: id,
    title,
    statement: str(r.check),
    guidance: str(r.discussion),
    params: [],
    related: controls,
    sortKey: `${section}/${id}`,
    status: "active",
    extra,
  };
}

export interface ParsedMscp extends ParsedDocument {
  version: MscpVersion;
  /** Baseline file stem to the rules it lists. */
  baselines: Map<string, string[]>;
}

/** The whole branch zip: VERSION.yaml, every rule, every baseline's membership. */
export function parseMscpZip(entries: ZipEntry[]): ParsedMscp {
  const versionEntry = entries.find((e) => /(^|\/)VERSION\.yaml$/i.test(e.name));
  if (!versionEntry) throw new Error("mSCP zip has no VERSION.yaml");
  const version = parseVersion(entryText(versionEntry));
  const baselines = new Map<string, string[]>();
  for (const e of entries) {
    const m = /(^|\/)baselines\/([^/]+)\.ya?ml$/i.exec(e.name);
    if (!m) continue;
    const doc = obj(parseYaml(entryText(e)));
    const rules = (Array.isArray(doc.profile) ? doc.profile : []).flatMap((section) => strings(obj(section).rules));
    baselines.set(m[2]!, rules);
  }
  const membership = new Map<string, string[]>();
  for (const [baseline, rules] of baselines) for (const r of rules) membership.set(r, [...(membership.get(r) ?? []), baseline]);
  const requirements: NormalizedRequirement[] = [];
  for (const e of entries) {
    const m = /(^|\/)rules\/([^/]+)\/([^/]+)\.ya?ml$/i.exec(e.name);
    if (!m) continue;
    try {
      const rule = normalizeRule(m[2]!, entryText(e), membership.get(m[3]!) ?? []);
      if (rule) requirements.push(rule);
    } catch (error) {
      throw new Error(`${e.name}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  if (requirements.length === 0) throw new Error("mSCP zip holds no rules");
  requirements.sort((a, b) => a.sortKey.localeCompare(b.sortKey));
  // The iOS/iPadOS branches use the same section ids as macOS; the "os" section is the platform's.
  const platform = version.platform ?? "macOS";
  if (/ios/i.test(platform)) for (const r of requirements) if (r.family === "macOS") r.family = "iOS/iPadOS";
  const os = version.os ? `${platform} ${version.os}` : platform;
  return {
    title: `${os}: ${version.version ?? "macOS Security Compliance Project"}`,
    versionLabel: version.version,
    publishedAt: version.date ? (isoDate(version.date) ?? `${version.date}T00:00:00.000Z`) : null,
    requirements,
    rationale: null,
    version,
    baselines,
  };
}

/** The branches to follow: watchlist baseline entries written "mscp: <branch>", or the defaults. */
export function followedBranches(ctx: Pick<ListingContext, "db">): string[] {
  const rows = ctx.db.prepare("SELECT value FROM watchlist WHERE kind = 'baseline' AND value LIKE 'mscp:%'").all() as { value: string }[];
  const named = rows.map((r) => r.value.replace(/^mscp:\s*/i, "").trim().toLowerCase()).filter((v) => /^[a-z0-9_.-]+$/.test(v));
  return named.length ? [...new Set(named)] : [...mscpBranches];
}

interface CommitInfo {
  sha: string;
  date: string | null;
  message: string | null;
  url: string | null;
}

async function latestCommit(ctx: Pick<ListingContext, "http">, branch: string): Promise<CommitInfo | null> {
  try {
    const response = await ctx.http(branchCommitUrl(branch), { headers: { accept: "application/vnd.github+json" }, timeoutMs: 30_000 });
    const json = obj(JSON.parse(new TextDecoder("utf-8").decode(response.bytes)));
    const sha = str(json.sha);
    if (!sha || !/^[0-9a-f]{40}$/.test(sha)) return null;
    const commit = obj(json.commit);
    const committer = obj(commit.committer);
    return { sha, date: isoDate(committer.date), message: str(commit.message)?.split("\n")[0] ?? null, url: str(json.html_url) };
  } catch {
    return null;
  }
}

export const mscpAdapter: Adapter = {
  id: "nist-mscp",
  headers: { accept: "application/zip, application/octet-stream, */*" },
  async documents(_source: SourceRow, ctx): Promise<DocumentTarget[]> {
    const targets: DocumentTarget[] = [];
    for (const branch of followedBranches(ctx)) {
      const commit = await latestCommit(ctx, branch);
      if (commit) {
        // The exact commit's zip: a URL that changes with the branch, so an unchanged branch is skipped on the listing alone.
        targets.push({
          key: `mscp:${branch}`,
          url: branchZipUrl(commit.sha),
          versionLabel: null,
          publishedAt: commit.date,
          rationale: commit.message ? { text: `Latest commit on ${branch}: ${commit.message}`, url: commit.url } : null,
        });
      } else {
        targets.push({ key: `mscp:${branch}`, url: branchZipUrl(branch), versionLabel: null, publishedAt: null });
      }
    }
    return targets;
  },
  parseDocument(bytes, target): ParsedDocument {
    const parsed = parseMscpZip(unzipAll(bytes));
    const sha = /\/zip\/([0-9a-f]{40})$/.exec(target.url)?.[1];
    const versionLabel = parsed.versionLabel ? `${parsed.versionLabel}${sha ? ` (${sha.slice(0, 7)})` : ""}` : (sha?.slice(0, 7) ?? null);
    return { title: parsed.title, versionLabel, publishedAt: target.publishedAt ?? parsed.publishedAt, requirements: parsed.requirements, rationale: target.rationale ?? null };
  },
};
