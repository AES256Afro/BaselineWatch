/**
 * Blocklists and canary sets as Register sources (M12.2). Each list is one document whose
 * entries are its requirements, matched by name across versions, so the list's next release
 * shows in the Register as a diff with a date, like any standard. Nothing here is ever fetched
 * from a name on a list: the lists are documents read from their publishers, and the canary
 * names they yield are only ever resolved (M12.3), never loaded, and never linked.
 *
 * Three Zero Breach lists (github.com/interplains/zero-breach): the AdFection / Candiru
 * indicator list (`iocs/adfection_iocs.txt`, one indicator per line with its tier, confidence
 * and source tag) and its DNS and ad blocklist exports (`dist/adfection.domains.txt`,
 * `dist/adfection.adblock.txt`). The list's current commit comes from the GitHub commits API,
 * so an unchanged list costs one small request a day, and the commit's first line is the
 * publisher's reason for the release.
 *
 * Four canary sets, twelve names each, derived from a public list: ad domains from EasyList,
 * tracker domains from EasyPrivacy, malware hosts from URLhaus and phishing hosts from OpenPhish.
 * The twelve are the candidates whose names hash lowest under SHA-256, so the pick is
 * deterministic, nobody chose them, and the set moves only when the list drops one of them or
 * gains a name that hashes lower.
 */
import { createHash } from "node:crypto";
import type { HttpGet } from "../http.ts";
import type { NormalizedRequirement } from "../oscal.ts";
import type { Adapter, DocumentTarget, ParsedDocument, SourceRow } from "./types.ts";
import { isoDate } from "./types.ts";

const zeroBreachRepository = "https://github.com/interplains/zero-breach";
const zeroBreachRaw = "https://raw.githubusercontent.com/interplains/zero-breach";
const zeroBreachApi = "https://api.github.com/repos/interplains/zero-breach";

/** Names in each canary set: twelve, in four sets, the plan's forty-eight. */
export const canaryCount = 12;

const decode = (bytes: Uint8Array): string => new TextDecoder("utf-8").decode(bytes);
const sha256 = (text: string): string => createHash("sha256").update(text).digest("hex");
const base = { parentRef: null, params: [] as NormalizedRequirement["params"], related: [] as string[], status: "active" as const };

/** One line of a list as a requirement: the name is its identity across versions, the line as published is its text. */
function lineRequirement(name: string, line: string, title: string, family: string): NormalizedRequirement {
  return { ...base, ref: name, family, label: name, title, statement: line, guidance: null, sortKey: name, extra: {} };
}

/** Keeps the first requirement for each ref; a list that repeats a name is still one entry. */
function unique(requirements: NormalizedRequirement[]): NormalizedRequirement[] {
  const seen = new Set<string>();
  return requirements.filter((r) => (seen.has(r.ref) ? false : (seen.add(r.ref), true)));
}

// ---------------------------------------------------------------------------------------------
// Zero Breach: the AdFection / Candiru indicator list and its exports.

const tierNames: Record<string, string> = {
  cc: "Command-and-control",
  validator: "Validator server",
  delivery: "Ad delivery",
  historical: "Historical Candiru infrastructure",
  sample: "Spyware sample",
  "vuln-driver": "Abused signed driver",
  candiru: "Candiru infrastructure",
  "candiru-ip": "Candiru infrastructure address",
};

export type IndicatorType = "sha256" | "ip" | "domain";

/** The list infers the type from the shape: 64 hex characters a SHA-256, a dotted quad an address, anything else a domain. */
export function indicatorType(value: string): IndicatorType {
  if (/^[0-9a-f]{64}$/i.test(value)) return "sha256";
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return "ip";
  return "domain";
}

/**
 * `iocs/adfection_iocs.txt`: `indicator <TAB> tier <TAB> confidence <TAB> source-tag` lines
 * under `#` comments. A `# Source:` comment opens a group and names the report (with its URL on
 * the next lines); every indicator that follows carries that report as its guidance. The header's
 * `# as-of:` date is the publisher's own version.
 */
export function parseIndicators(text: string): ParsedDocument {
  const requirements: NormalizedRequirement[] = [];
  let title = "AdFection / Candiru indicators";
  let asOf: string | null = null;
  let source: { text: string[]; url: string | null; open: boolean } | null = null;
  text.split(/\r?\n/).forEach((raw, index) => {
    const line = raw.trim();
    if (line === "") return;
    if (line.startsWith("#")) {
      const comment = line.replace(/^#\s?/, "").trim();
      if (index === 0 && comment) title = comment.replace(/\s+-\s+indicators of compromise$/i, " indicators");
      const dated = /^as-of:\s*(\d{4}-\d{2}-\d{2})/.exec(comment);
      if (dated) asOf = dated[1] ?? null;
      const opens = /^Source:\s*(.+)$/.exec(comment);
      if (opens) {
        source = { text: [opens[1] ?? ""], url: null, open: true };
        return;
      }
      if (source?.open) {
        if (comment === "") source.open = false;
        else if (/^https?:\/\/\S+$/.test(comment)) {
          source.url = source.url ?? comment;
          source.open = false;
        } else if (source.text.length < 3) source.text.push(comment);
      }
      return;
    }
    const [value, tier, confidence, tag] = line.split(/\t+/).map((f) => f.trim());
    if (!value || !tier) return;
    const type = indicatorType(value);
    const tierName = tierNames[tier] ?? tier;
    const name = value.toLowerCase();
    const extra: Record<string, unknown> = { type, tier };
    if (confidence) extra.confidence = confidence;
    if (tag) extra.source = tag;
    requirements.push({
      ...base,
      ref: name,
      family: tierName,
      label: name,
      title: `${tierName} (${type === "sha256" ? "SHA-256" : type === "ip" ? "address" : "domain"}, ${confidence ?? "unstated"} source)`,
      statement: `Tier: ${tier} (${tierName}). Confidence: ${confidence ?? "unstated"}. Source: ${tag ?? "unstated"}.`,
      guidance: source ? `Source: ${source.text.join(" ")}${source.url ? `\n${source.url}` : ""}` : null,
      sortKey: `${tier}/${name}`,
      extra,
    });
  });
  if (requirements.length === 0) throw new Error("not the Zero Breach indicator list: no indicator lines");
  return { title, versionLabel: asOf, publishedAt: isoDate(asOf), requirements: unique(requirements) };
}

/** The `generated YYYY-MM-DD` date in a dist export's first comment line. */
function generatedOn(header: string): string | null {
  return /generated\s+(\d{4}-\d{2}-\d{2})/.exec(header)?.[1] ?? null;
}

/** `dist/adfection.domains.txt`: one domain per line under `#` comments, the form a Pi-hole or AdGuard Home takes. */
export function parseDomainList(text: string): ParsedDocument {
  const lines = text.split(/\r?\n/).map((l) => l.trim());
  const header = lines[0]?.startsWith("#") ? lines[0].replace(/^#\s*/, "") : "";
  const requirements = lines
    .filter((l) => l !== "" && !l.startsWith("#"))
    .map((l) => lineRequirement(l.toLowerCase(), l, "Listed domain", "Domains"));
  if (requirements.length === 0) throw new Error("not a domain list: no domain lines");
  const generated = generatedOn(header);
  return {
    title: header.replace(/\s+-\s+generated.*$/, "") || "Domain blocklist",
    versionLabel: generated,
    publishedAt: isoDate(generated),
    requirements: unique(requirements),
  };
}

/** The name a `||name^...` network rule blocks; other rules keep the whole rule as their identity. */
export function ruleName(rule: string): string {
  return (/^\|\|([^^/$*|]+)\^/.exec(rule)?.[1] ?? rule).toLowerCase();
}

/** `dist/adfection.adblock.txt`: an Adblock Plus list, `!` comments and `[Adblock Plus x]` headers around `||domain^` rules. */
export function parseAdblockList(text: string): ParsedDocument {
  const lines = text.split(/\r?\n/).map((l) => l.trim());
  const comments = lines.filter((l) => l.startsWith("!")).map((l) => l.replace(/^!\s*/, ""));
  const title = comments.map((c) => /^Title:\s*(.+)$/.exec(c)?.[1]).find((t): t is string => t !== undefined) ?? "Ad blocklist";
  const generated = comments.map(generatedOn).find((g): g is string => g !== null) ?? null;
  const requirements = lines
    .filter((l) => l !== "" && !l.startsWith("!") && !/^\[.*\]$/.test(l))
    .map((l) => lineRequirement(ruleName(l), l, "Network rule", "Rules"));
  if (requirements.length === 0) throw new Error("not an Adblock Plus list: no rules");
  return { title: title.trim(), versionLabel: generated, publishedAt: isoDate(generated), requirements: unique(requirements) };
}

interface ZeroBreachCommit {
  sha: string;
  date: string | null;
  message: string | null;
}

/** The commit the lists' history starts from: the one that added the dist/ exports, so the first diff is real. */
const zeroBreachHistory: readonly ZeroBreachCommit[] = [
  { sha: "e36dc961b8c60060c3b164d1a1c78d401e231a5e", date: "2026-10-18T14:01:41.000Z", message: "Add historical indicators, HW.sys path check, blocklists, and an updater" },
];

/** The newest commit that touched a file, from the GitHub commits API. */
async function zeroBreachHead(http: HttpGet, path: string): Promise<ZeroBreachCommit> {
  const response = await http(`${zeroBreachApi}/commits?path=${path}&per_page=1`, { headers: { accept: "application/vnd.github+json" } });
  const commits = JSON.parse(decode(response.bytes)) as unknown;
  const head = Array.isArray(commits) ? (commits[0] as Record<string, unknown> | undefined) : undefined;
  const sha = typeof head?.sha === "string" ? head.sha : "";
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new Error(`GitHub lists no commit for ${path}`);
  const commit = (head?.commit ?? {}) as { committer?: { date?: unknown }; author?: { date?: unknown }; message?: unknown };
  const message = typeof commit.message === "string" ? (commit.message.split("\n")[0]?.trim() ?? "") : "";
  return { sha, date: isoDate(commit.committer?.date) ?? isoDate(commit.author?.date), message: message === "" ? null : message };
}

interface ZeroBreachList {
  id: string;
  key: string;
  path: string;
  parse(text: string): ParsedDocument;
}

function zeroBreachTarget(list: ZeroBreachList, commit: ZeroBreachCommit): DocumentTarget {
  const short = commit.sha.slice(0, 7);
  return {
    key: list.key,
    url: `${zeroBreachRaw}/${commit.sha}/${list.path}`,
    versionLabel: commit.date ? `${commit.date.slice(0, 10)} (${short})` : short,
    publishedAt: commit.date,
    rationale: commit.message ? { text: `Commit ${short}: ${commit.message}`, url: `${zeroBreachRepository}/commit/${commit.sha}` } : null,
  };
}

function zeroBreachAdapter(list: ZeroBreachList): Adapter {
  return {
    id: list.id,
    documents: async (_source: SourceRow, ctx) => [zeroBreachTarget(list, await zeroBreachHead(ctx.http, list.path))],
    history: () => zeroBreachHistory.map((commit) => zeroBreachTarget(list, commit)),
    parseDocument: (bytes) => list.parse(decode(bytes)),
  };
}

export const adfectionIndicatorsAdapter = zeroBreachAdapter({ id: "adfection-indicators", key: "indicators", path: "iocs/adfection_iocs.txt", parse: parseIndicators });
export const adfectionDnsAdapter = zeroBreachAdapter({ id: "adfection-dns", key: "domains", path: "dist/adfection.domains.txt", parse: parseDomainList });
export const adfectionAdblockAdapter = zeroBreachAdapter({ id: "adfection-adblock", key: "adblock", path: "dist/adfection.adblock.txt", parse: parseAdblockList });

// ---------------------------------------------------------------------------------------------
// Canary sets derived from public lists.

export interface Candidate {
  /** The name a resolver would be asked for. */
  name: string;
  /** The line of the list that puts it there, as published. */
  line: string;
}

/** A rule that blocks a domain outright, with or without `$third-party`: `||example.com^`. */
const outrightDomainRule = /^\|\|([a-z0-9-]+(?:\.[a-z0-9-]+)+)\^(?:\$third-party)?$/;

/** The domains an Adblock Plus list (EasyList, EasyPrivacy) blocks outright. */
export function filterListDomains(text: string): Candidate[] {
  const out: Candidate[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const m = outrightDomainRule.exec(line);
    if (m?.[1]) out.push({ name: m[1], line });
  }
  return out;
}

/** The hosts of a hosts-format list (`127.0.0.1<TAB>host`, as URLhaus publishes it). */
export function hostfileHosts(text: string): Candidate[] {
  const out: Candidate[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const m = /^(?:127\.0\.0\.1|0\.0\.0\.0)\s+(\S+)$/.exec(line);
    if (m?.[1]) out.push({ name: m[1].toLowerCase(), line });
  }
  return out;
}

/** The hosts of a list of URLs (OpenPhish); the line kept is the origin alone, never the path. */
export function urlHosts(text: string): Candidate[] {
  const out: Candidate[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!/^https?:\/\//i.test(line)) continue;
    try {
      const url = new URL(line);
      out.push({ name: url.hostname.toLowerCase(), line: `${url.protocol}//${url.host}/` });
    } catch {
      // not a URL: skipped
    }
  }
  return out;
}

/**
 * Hosts a resolver could sinkhole without collateral: the registrable name itself (two labels
 * once a leading `www.` is dropped), never an address, never a subdomain of a shared platform
 * (github.io, r2.dev, blogspot.com and the like carry many sites under one name).
 */
export function apexHosts(candidates: Candidate[]): Candidate[] {
  return candidates.flatMap((c) => {
    const name = c.name.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
    if (/^[\d.]+$/.test(name) || name.includes(":") || name.startsWith("[")) return [];
    const labels = name.split(".");
    if (labels.length !== 2) return [];
    if (!labels.every((l) => /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(l)) || !/^[a-z]{2,}$/.test(labels[1] ?? "")) return [];
    return [{ name, line: c.line }];
  });
}

/** The `count` candidates whose names hash lowest, deduplicated by name and returned in name order. */
export function pickCanaries(candidates: Candidate[], count = canaryCount): Candidate[] {
  const byName = new Map<string, Candidate>();
  for (const c of candidates) if (!byName.has(c.name)) byName.set(c.name, c);
  return [...byName.values()]
    .map((c) => ({ c, hash: sha256(c.name) }))
    .sort((a, b) => (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0))
    .slice(0, count)
    .map((x) => x.c)
    .sort((a, b) => a.name.localeCompare(b.name));
}

interface ListVersion {
  label: string | null;
  publishedAt: string | null;
}

const months: Record<string, string> = { jan: "01", feb: "02", mar: "03", apr: "04", may: "05", jun: "06", jul: "07", aug: "08", sep: "09", oct: "10", nov: "11", dec: "12" };

/** `! Version: 202610200112` and `! Last modified: 20 Oct 2026 01:12 UTC` from an EasyList header. */
function filterListVersion(text: string): ListVersion {
  const head = text.slice(0, 4000);
  const label = /^! Version:\s*(\S+)/m.exec(head)?.[1] ?? null;
  const m = /^! Last modified:\s*(\d{1,2}) ([A-Za-z]{3}) (\d{4}) (\d{2}):(\d{2}) UTC/m.exec(head);
  const month = m ? months[m[2]!.toLowerCase()] : undefined;
  const publishedAt = m && month ? `${m[3]}-${month}-${m[1]!.padStart(2, "0")}T${m[4]}:${m[5]}:00.000Z` : null;
  return { label, publishedAt };
}

/** `# Last updated: 2026-10-20 01:17:09 (UTC)` from the URLhaus host file. */
function hostfileVersion(text: string): ListVersion {
  const m = /^#\s*Last updated:\s*(\d{4}-\d{2}-\d{2}) (\d{2}):(\d{2}):(\d{2}) \(UTC\)/m.exec(text.slice(0, 2000));
  if (!m) return { label: null, publishedAt: null };
  return { label: `${m[1]} ${m[2]}:${m[3]} UTC`, publishedAt: `${m[1]}T${m[2]}:${m[3]}:${m[4]}.000Z` };
}

/** A feed with no version line is labelled by the hash of its bytes; the fetch time dates it. */
function contentVersion(text: string): ListVersion {
  return { label: `feed ${sha256(text).slice(0, 7)}`, publishedAt: null };
}

export interface CanaryList {
  id: string;
  /** "Ad", "Tracker", "Malware", "Phishing": the word before "canary". */
  category: string;
  listName: string;
  candidates(text: string): Candidate[];
  version(text: string): ListVersion;
}

export const canaryLists: readonly CanaryList[] = [
  { id: "canary-ads", category: "Ad", listName: "EasyList", candidates: filterListDomains, version: filterListVersion },
  { id: "canary-trackers", category: "Tracker", listName: "EasyPrivacy", candidates: filterListDomains, version: filterListVersion },
  { id: "canary-malware", category: "Malware", listName: "URLhaus", candidates: (text) => apexHosts(hostfileHosts(text)), version: hostfileVersion },
  { id: "canary-phishing", category: "Phishing", listName: "OpenPhish", candidates: (text) => apexHosts(urlHosts(text)), version: contentVersion },
];

/** The canary set a list yields: its twelve names as requirements, the list's own version and date. */
export function canaryDocument(list: CanaryList, text: string): ParsedDocument {
  const picked = pickCanaries(list.candidates(text));
  if (picked.length === 0) throw new Error(`${list.listName} yielded no canary candidates: not the list this adapter expects`);
  const version = list.version(text);
  return {
    title: `${list.category} canaries from ${list.listName}`,
    versionLabel: version.label,
    publishedAt: version.publishedAt,
    requirements: picked.map((c) => lineRequirement(c.name, c.line, `${list.category} canary`, `${list.category} canaries (${list.listName})`)),
  };
}

function canaryAdapter(list: CanaryList): Adapter {
  return {
    id: list.id,
    headers: { accept: "text/plain, */*;q=0.5" },
    documents: (source: SourceRow) => [{ key: "canaries", url: source.url }],
    parseDocument: (bytes) => canaryDocument(list, decode(bytes)),
  };
}

const canaryAdapters = Object.fromEntries(canaryLists.map((list) => [list.id, canaryAdapter(list)])) as Record<string, Adapter>;

export const canaryAdsAdapter = canaryAdapters["canary-ads"]!;
export const canaryTrackersAdapter = canaryAdapters["canary-trackers"]!;
export const canaryMalwareAdapter = canaryAdapters["canary-malware"]!;
export const canaryPhishingAdapter = canaryAdapters["canary-phishing"]!;
