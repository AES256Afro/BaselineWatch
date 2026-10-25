import { safeUrl, upsertItems } from "../items.ts";
import { parseJson } from "../json.ts";
import { kbUrl, releaseNoteUrl, upsertMsrcVulns, type MsrcFix, type MsrcVulnDraft } from "../msrc.ts";
import { plainText, type Adapter, type ParsedItem, type PullOutcome } from "./types.ts";

/**
 * Microsoft's Security Update Guide through its CVRF API, which needs no key. The index at
 * /updates lists every monthly release ("October 2026 Security Updates") with the date it was
 * last revised; each release is one JSON document of every CVE Microsoft published that month —
 * its title, severity, exploit status, CVSS, and the KB that fixes it on each product — about
 * 25 MB and revised through the month as CVEs are added or re-released. A daily pull reads the
 * index, fetches the documents in the last forty days whose revision date moved, and keeps one
 * row per CVE in msrc_vulns; the Wire gets one item per release, not one per CVE. The
 * documents are a stream, not a standard: they are not kept as snapshots.
 */

export const msrcApi = "https://api.msrc.microsoft.com/cvrf/v3.0";

export interface MsrcRelease {
  /** "2026-Oct": the id the API and the release-note pages share. */
  id: string;
  title: string;
  initialReleaseDate: string;
  currentReleaseDate: string;
  cvrfUrl: string;
}

/** This month's release and the one before it: two Patch Tuesdays are at most 35 days apart. */
export const releaseWindowDays = 40;

/** Microsoft's stamps come with a zone in the index and without one in the documents; both are UTC. */
function stamp(value: unknown): string | null {
  if (typeof value !== "string" || value === "") return null;
  const date = new Date(/[Zz]$|[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/** The monthly security releases inside the window, oldest first; the Azure Linux release notes the same index lists are not. */
export function parseMsrcIndex(text: string, now: Date, windowDays = releaseWindowDays): MsrcRelease[] {
  const data = parseJson<{ value?: unknown }>(text, {});
  if (!Array.isArray(data.value)) throw new Error("the Security Update Guide index was not the JSON list expected");
  const since = now.getTime() - windowDays * 86_400_000;
  const out: MsrcRelease[] = [];
  for (const raw of data.value) {
    const e = (raw ?? {}) as Record<string, unknown>;
    const id = typeof e.ID === "string" ? e.ID : null;
    const title = typeof e.DocumentTitle === "string" ? e.DocumentTitle : "";
    const initial = stamp(e.InitialReleaseDate);
    const url = typeof e.CvrfUrl === "string" ? e.CvrfUrl : null;
    if (!id || !url || !initial || !/Security Updates$/.test(title) || new Date(initial).getTime() < since) continue;
    out.push({ id, title, initialReleaseDate: initial, currentReleaseDate: stamp(e.CurrentReleaseDate) ?? initial, cvrfUrl: url });
  }
  return out.sort((a, b) => a.initialReleaseDate.localeCompare(b.initialReleaseDate));
}

interface Note {
  Type?: number;
  Title?: string;
  Value?: string;
}
interface Threat {
  Type?: number;
  Description?: { Value?: string };
}
interface Remediation {
  Type?: number;
  Description?: { Value?: string };
  URL?: string;
  ProductID?: string[];
  FixedBuild?: string;
  RestartRequired?: { Value?: string };
}
interface Vulnerability {
  CVE?: string;
  Title?: { Value?: string };
  Notes?: Note[];
  Threats?: Threat[];
  CVSSScoreSets?: { BaseScore?: number; Vector?: string }[];
  Remediations?: Remediation[];
}
interface Document {
  ProductTree?: { FullProductName?: { ProductID?: string; Value?: string }[] };
  Vulnerability?: Vulnerability[];
}

const severityRank: Record<string, number> = { critical: 4, important: 3, moderate: 2, low: 1 };
const maxFixes = 24;
const maxProducts = 24;

/**
 * Vendor fixes (type 2) grouped by KB and the build it produces, with each product's
 * per-architecture names folded into one. One KB serves several Windows versions with different
 * builds (KB5127648 is 10.0.26100.x on 24H2 and 10.0.26200.x on 25H2), so the build is part of
 * the key: a device's build is only ever compared with the build for its own version.
 */
function fixesOf(remediations: Remediation[], names: Map<string, string>): MsrcFix[] {
  const byKey = new Map<string, MsrcFix>();
  for (const r of remediations) {
    if (r.Type !== 2) continue;
    const label = r.Description?.Value?.trim() || null;
    const kb = label && /^\d{5,8}$/.test(label) ? label : null;
    const key = `${kb ?? r.URL ?? label ?? ""}|${r.FixedBuild?.trim() ?? ""}`;
    if (key === "|") continue;
    const fix = byKey.get(key) ?? {
      kb,
      // Microsoft's own JSON, but a remote value all the same: it ends up in an href.
      url: kb ? kbUrl(kb) : safeUrl(r.URL),
      label: kb ? null : label,
      products: [],
      fixedBuild: r.FixedBuild?.trim() || null,
      restart: r.RestartRequired?.Value ? /^yes$/i.test(r.RestartRequired.Value.trim()) : null,
    };
    for (const id of r.ProductID ?? []) {
      const name = (names.get(id) ?? "").replace(/ for (x64|ARM64|32-bit|Itanium)-based Systems$/i, "").trim();
      if (name && !fix.products.includes(name) && fix.products.length < maxProducts) fix.products.push(name);
    }
    byKey.set(key, fix);
  }
  return [...byKey.values()].slice(0, maxFixes);
}

/** One monthly document's CVEs; the ADV advisories in it are not CVEs and are left. */
export function parseMsrcRelease(text: string, release: MsrcRelease): { vulns: MsrcVulnDraft[]; products: number } {
  const doc = parseJson<Document>(text, {});
  if (!Array.isArray(doc.Vulnerability)) throw new Error(`${release.id} was not the CVRF document expected`);
  const names = new Map<string, string>();
  for (const p of doc.ProductTree?.FullProductName ?? []) if (p.ProductID && p.Value) names.set(p.ProductID, p.Value);
  const vulns: MsrcVulnDraft[] = [];
  for (const v of doc.Vulnerability) {
    const cveId = (v.CVE ?? "").trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,7}$/.test(cveId)) continue;
    const notes = v.Notes ?? [];
    const tag = (type: number): string | null => notes.find((n) => n.Type === type)?.Title?.trim() || null;
    let severity: string | null = null;
    let status: string | null = null;
    for (const t of v.Threats ?? []) {
      const value = t.Description?.Value?.trim();
      if (!value) continue;
      if (t.Type === 3 && (severityRank[value.toLowerCase()] ?? 0) > (severityRank[severity?.toLowerCase() ?? ""] ?? 0)) severity = value;
      if (t.Type === 1) status = value;
    }
    let cvss: { BaseScore?: number; Vector?: string } | null = null;
    for (const s of v.CVSSScoreSets ?? []) if (typeof s.BaseScore === "number" && (cvss === null || s.BaseScore > (cvss.BaseScore ?? 0))) cvss = s;
    vulns.push({
      cveId,
      releaseId: release.id,
      title: plainText(v.Title?.Value, 300) ?? cveId,
      family: tag(7),
      vendor: tag(8),
      severity,
      exploited: /Exploited:Yes/i.test(status ?? ""),
      disclosed: /Publicly Disclosed:Yes/i.test(status ?? ""),
      exploitability: /Latest Software Release:([^;]+)/i.exec(status ?? "")?.[1]?.trim() ?? null,
      cvssScore: cvss?.BaseScore ?? null,
      cvssVector: cvss?.Vector ?? null,
      description: plainText(notes.find((n) => n.Type === 2)?.Value, 600),
      fixes: fixesOf(v.Remediations ?? [], names),
      releasedAt: release.initialReleaseDate,
      revisedAt: release.currentReleaseDate,
    });
  }
  if (vulns.length === 0) throw new Error(`${release.id} carried no CVE BaselineWatch could read`);
  return { vulns, products: names.size };
}

const edgeFamily = "Microsoft Edge (Chromium-based)";
const azureLinuxFamily = "Mariner";

/** The release as one Wire item: Microsoft's own CVEs counted apart from the Chromium and Azure Linux ones it republishes. */
export function releaseItem(release: MsrcRelease, vulns: MsrcVulnDraft[]): ParsedItem {
  const chromium = vulns.filter((v) => v.family === edgeFamily && v.vendor !== "Microsoft");
  const azureLinux = vulns.filter((v) => v.family === azureLinuxFamily);
  const own = vulns.filter((v) => !chromium.includes(v) && !azureLinux.includes(v));
  const critical = own.filter((v) => v.severity === "Critical");
  const exploited = own.filter((v) => v.exploited);
  const disclosed = own.filter((v) => v.disclosed);
  const ids = (list: MsrcVulnDraft[]): string => list.map((v) => v.cveId).join(", ");
  const inner = [`${critical.length} critical`];
  if (exploited.length) inner.push(`${exploited.length} under active exploitation: ${ids(exploited)}`);
  if (disclosed.length) inner.push(`${disclosed.length} publicly disclosed: ${ids(disclosed)}`);
  const republished = [chromium.length ? `${chromium.length} Chromium CVEs republished for Edge` : null, azureLinux.length ? `${azureLinux.length} for Azure Linux` : null].filter((s) => s !== null);
  const cves = [...new Set([...exploited, ...disclosed, ...critical].map((v) => v.cveId))].slice(0, 60);
  return {
    kind: "article",
    externalId: release.id,
    title: `Microsoft ${release.title}: ${own.length} CVEs${exploited.length ? `, ${exploited.length} exploited` : ""}${critical.length ? `, ${critical.length} critical` : ""}`,
    url: releaseNoteUrl(release.id),
    summary: `${own.length} CVEs in Microsoft products (${inner.join("; ")})${republished.length ? `, with ${republished.join(" and ")}` : ""}. Revised ${release.currentReleaseDate.slice(0, 10)}.`,
    publishedAt: release.initialReleaseDate,
    signals: {
      release: release.id,
      ...(cves.length ? { cves } : {}),
      counts: { total: vulns.length, microsoft: own.length, critical: critical.length, exploited: exploited.length, disclosed: disclosed.length, chromium: chromium.length, azureLinux: azureLinux.length },
    },
  };
}

const revisedKey = (releaseId: string): string => `msrc.${releaseId}.revised`;

export const msrcAdapter: Adapter = {
  id: "msrc",
  headers: { accept: "application/json" },
  async pull(ctx): Promise<PullOutcome> {
    const at = ctx.now().toISOString();
    const index = await ctx.http(ctx.source.url, { headers: { accept: "application/json" }, timeoutMs: 60_000, maxBytes: 8 * 1024 * 1024 });
    const releases = parseMsrcIndex(new TextDecoder("utf-8").decode(index.bytes), ctx.now());
    if (releases.length === 0) throw new Error(`the Security Update Guide index listed no monthly release in the last ${releaseWindowDays} days`);
    const known = ctx.db.prepare("SELECT value FROM app_settings WHERE key = ?");
    const remember = ctx.db.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at");
    const items: ParsedItem[] = [];
    let read = 0;
    let inserted = 0;
    let updated = 0;
    let cves = 0;
    for (const release of releases) {
      if ((known.get(revisedKey(release.id)) as { value: string } | undefined)?.value === release.currentReleaseDate) continue;
      const doc = await ctx.http(release.cvrfUrl, { headers: { accept: "application/json" }, timeoutMs: 300_000, maxBytes: 96 * 1024 * 1024, publicOnly: true });
      const { vulns } = parseMsrcRelease(new TextDecoder("utf-8").decode(doc.bytes), release);
      const counts = upsertMsrcVulns(ctx.db, vulns, at);
      inserted += counts.inserted;
      updated += counts.updated;
      cves += vulns.length;
      items.push(releaseItem(release, vulns));
      remember.run(revisedKey(release.id), release.currentReleaseDate, at);
      read += 1;
      ctx.log(`[msrc] ${release.id}: ${vulns.length} CVEs, revised ${release.currentReleaseDate}`);
    }
    upsertItems(ctx.db, ctx.source.id, items, at);
    const named = releases.map((r) => r.id).join(", ");
    return { items: cves, inserted, updated, detail: read ? `${read} of ${releases.length} monthly release(s) read (${named})` : `${named} unchanged since the last read` };
  },
};
