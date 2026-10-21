/**
 * OSV.dev, queried for each package on the watchlist. OSV aggregates the GitHub Advisory
 * Database, the PyPI, Go, Rust and other ecosystem databases and the Linux distributions'
 * trackers, so one query per package covers the GHSA ids too. An advisory lands on its CVE's row
 * when it has one and on a row of its own otherwise; the Wire shows what is fresh or changed,
 * never a package's back catalogue.
 */
import { scoreCvss3 } from "../cvss.ts";
import { advisoryKey, applyAdvisory, isNotable, loadWatchlist, parsePackageValue, recordVulnItem, type AffectedPackage, type NormalizedAdvisory, type WatchEntry } from "../vulns.ts";
import type { Adapter, AlertDraft, PullContext, PullOutcome } from "./types.ts";
import { isoDate } from "./types.ts";

/** The parts of an OSV record BaselineWatch reads. */
export interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  severity?: { type?: string; score?: string }[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
  references?: { type?: string; url?: string }[];
  affected?: { package?: { ecosystem?: string; name?: string }; ranges?: { type?: string; events?: Record<string, string>[] }[] }[];
}

export interface OsvQueryResponse {
  vulns?: OsvVuln[];
  next_page_token?: string;
}

/** OSV's ecosystem names, from the way people type them. */
const ecosystemNames: Record<string, string> = {
  npm: "npm", pypi: "PyPI", go: "Go", maven: "Maven", "crates.io": "crates.io", crates: "crates.io", cargo: "crates.io", rubygems: "RubyGems", gem: "RubyGems",
  nuget: "NuGet", packagist: "Packagist", composer: "Packagist", pub: "Pub", hex: "Hex", hackage: "Hackage", cran: "CRAN", conancenter: "ConanCenter",
  "github actions": "GitHub Actions", swifturl: "SwiftURL", bitnami: "Bitnami", linux: "Linux", "oss-fuzz": "OSS-Fuzz", debian: "Debian", ubuntu: "Ubuntu",
  alpine: "Alpine", "rocky linux": "Rocky Linux", almalinux: "AlmaLinux", mageia: "Mageia", opensuse: "openSUSE", suse: "SUSE", "red hat": "Red Hat",
  chainguard: "Chainguard", wolfi: "Wolfi",
};

/** `pypi` → `PyPI`, `debian:12` → `Debian:12`; anything unknown passes through as typed. */
export function osvEcosystem(name: string): string {
  const [head = "", ...rest] = name.split(":");
  const canonical = ecosystemNames[head.trim().toLowerCase()] ?? head.trim();
  return [canonical, ...rest].join(":");
}

export function normalizeOsv(v: OsvVuln, fallbackModified: string): NormalizedAdvisory {
  const vector = (v.severity ?? []).map((s) => s.score ?? "").find((s) => /^CVSS:3\.[01]\//.test(s)) ?? null;
  const scored = scoreCvss3(vector);
  const fromGithub = /^GHSA-/i.test(v.id);
  const packages: AffectedPackage[] = [];
  for (const affected of v.affected ?? []) {
    const ecosystem = affected.package?.ecosystem;
    const name = affected.package?.name;
    if (!ecosystem || !name) continue;
    const introduced: string[] = [];
    const fixed: string[] = [];
    const lastAffected: string[] = [];
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.introduced !== undefined) introduced.push(event.introduced);
        if (event.fixed !== undefined) fixed.push(event.fixed);
        if (event.last_affected !== undefined) lastAffected.push(event.last_affected);
      }
    }
    packages.push({ ecosystem, name, introduced: [...new Set(introduced)], fixed: [...new Set(fixed)], lastAffected: [...new Set(lastAffected)], advisory: v.id });
  }
  return {
    id: v.id,
    aliases: v.aliases ?? [],
    summary: v.summary?.trim() || null,
    details: v.details?.trim() || null,
    publishedAt: isoDate(v.published),
    modifiedAt: isoDate(v.modified) ?? fallbackModified,
    cvss: scored ? { version: scored.version, score: scored.score, severity: scored.severity, vector: scored.vector, source: fromGithub ? "github-advisories" : "osv.dev" } : null,
    cwes: (v.database_specific?.cwe_ids ?? []).filter((c) => /^CWE-\d+$/.test(c)),
    references: (v.references ?? [])
      .filter((r): r is { type?: string; url: string } => typeof r.url === "string" && r.url !== "")
      .slice(0, 60)
      .map((r) => ({ url: r.url, tags: r.type ? [r.type.toLowerCase()] : [] })),
    packages,
  };
}

const freshDays = 30;
const pauseMs = 300;
const lastPullKey = "osv.last_pull";
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Stores a page of OSV records. Records that are aliases of one another (a GHSA and the PYSEC
 * that mirrors it) are one advisory here: the GitHub-reviewed record speaks for the group and
 * the others lend their ids and packages, so a pull never flips a row between two wordings.
 */
function storeOsvRecords(
  ctx: Pick<PullContext, "db">,
  records: OsvVuln[],
  options: { observedAt: string; watch: WatchEntry[]; announce: boolean },
): { items: number; inserted: number; updated: number; alerts: AlertDraft[] } {
  const { observedAt, watch, announce } = options;
  const groups = new Map<string, OsvVuln[]>();
  for (const record of records) {
    const key = advisoryKey({ id: record.id, aliases: record.aliases ?? [] });
    groups.set(key, [...(groups.get(key) ?? []), record]);
  }
  let inserted = 0;
  let updated = 0;
  const alerts: AlertDraft[] = [];
  ctx.db.exec("BEGIN IMMEDIATE");
  try {
    for (const group of groups.values()) {
      const primary = group.find((r) => /^GHSA-/i.test(r.id)) ?? group[0]!;
      const advisory = normalizeOsv(primary, observedAt);
      const others = group.filter((r) => r !== primary).map((r) => normalizeOsv(r, observedAt));
      advisory.aliases = [...new Set([...advisory.aliases, ...others.flatMap((o) => [o.id, ...o.aliases])])];
      advisory.packages = [...advisory.packages, ...others.flatMap((o) => o.packages)];
      const result = applyAdvisory(ctx.db, advisory, observedAt, watch);
      if (result.isNew) inserted += 1;
      else if (result.changes.length) updated += 1;
      const publishedRecently = advisory.publishedAt !== null && new Date(observedAt).getTime() - new Date(advisory.publishedAt).getTime() <= freshDays * 24 * 60 * 60 * 1000;
      const fresh = result.isNew ? publishedRecently : result.changes.length > 0;
      if (fresh && isNotable(result.row, result.isNew, observedAt)) {
        recordVulnItem(ctx.db, result.row, result.changes, observedAt);
        if (announce && result.row.watch_hit === 1) {
          const what = result.isNew ? "new advisory" : result.changes.map((c) => (c.field === "cvss" ? `CVSS ${c.before ?? "unscored"} → ${c.after ?? "unscored"}` : c.field)).join(", ");
          alerts.push({
            kind: "watch",
            title: `${result.row.cve_id}: ${result.watchLabels.join(", ")}`,
            body: `${what}. ${result.row.cvss_score !== null ? `CVSS ${result.row.cvss_score.toFixed(1)}. ` : ""}${(result.row.description ?? "").slice(0, 240)}`,
            url: `/vulnerabilities/${result.row.cve_id}`,
          });
        }
      }
    }
    ctx.db.exec("COMMIT");
  } catch (error) {
    ctx.db.exec("ROLLBACK");
    throw error;
  }
  return { items: groups.size, inserted, updated, alerts };
}

function readSetting(ctx: PullContext, key: string): string | null {
  return (ctx.db.prepare("SELECT value FROM app_settings WHERE key = ?").get(key) as { value: string } | undefined)?.value ?? null;
}

function writeSetting(ctx: PullContext, key: string, value: string): void {
  ctx.db.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").run(
    key,
    value,
    ctx.now().toISOString(),
  );
}

/** One POST per watched package (and per page of its results), a short pause between requests. */
export const osvAdapter: Adapter = {
  id: "osv",
  async pull(ctx): Promise<PullOutcome> {
    const watch = loadWatchlist(ctx.db);
    const packages = watch
      .filter((e) => e.kind === "package")
      .map((e) => parsePackageValue(e.value))
      .filter((p): p is { ecosystem: string; name: string } => p !== null);
    if (packages.length === 0) {
      return { items: 0, inserted: 0, updated: 0, detail: "no package on the watchlist yet (kind package, value ecosystem:name)" };
    }
    const announce = readSetting(ctx, lastPullKey) !== null; // a first pull is a back catalogue, not news
    const observedAt = ctx.now().toISOString();
    let items = 0;
    let inserted = 0;
    let updated = 0;
    let requests = 0;
    const alerts: AlertDraft[] = [];
    for (const pkg of packages) {
      const ecosystem = osvEcosystem(pkg.ecosystem);
      let token: string | undefined;
      let found = 0;
      do {
        if (requests > 0) await sleep(pauseMs);
        const body = JSON.stringify({ package: { name: pkg.name, ecosystem }, ...(token ? { page_token: token } : {}) });
        const response = await ctx.http(ctx.source.url, { method: "POST", body, headers: { accept: "application/json", "content-type": "application/json" }, timeoutMs: 60_000, maxBytes: 50 * 1024 * 1024 });
        requests += 1;
        const page = JSON.parse(new TextDecoder("utf-8").decode(response.bytes)) as OsvQueryResponse;
        const stored = storeOsvRecords(ctx, page.vulns ?? [], { observedAt, watch, announce });
        items += stored.items;
        inserted += stored.inserted;
        updated += stored.updated;
        found += stored.items;
        alerts.push(...stored.alerts);
        token = page.next_page_token;
      } while (token);
      ctx.log(`[osv] ${ecosystem}:${pkg.name}: ${found} advisor${found === 1 ? "y" : "ies"}`);
    }
    writeSetting(ctx, lastPullKey, observedAt);
    return { items, inserted, updated, detail: `${packages.length} package(s), ${requests} request(s)`, alerts };
  },
};
