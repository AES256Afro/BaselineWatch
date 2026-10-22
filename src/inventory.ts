import type { DatabaseSync } from "node:sqlite";
import { eolFor, eolWord } from "./eol.ts";
import type { HttpGet } from "./http.ts";
import { parseJson } from "./json.ts";
import { compareDotted, newestVersion } from "./versions.ts";

/**
 * Is this device affected? (Scan 2.0, S7.) A report the inventory script printed — the OS and
 * its build, the browsers and their versions, the distribution's packages — pasted back by the
 * owner and read against what this instance knows: Windows builds against the Security Update
 * Guide's fixed builds per KB, browsers against the newest release the vendor feeds carry, the
 * OS against Apple's releases and endoflife.date, and Linux packages against OSV, which is asked
 * in one batch to say which advisories cover each installed version. The report is read and
 * answered; nothing from it is stored.
 */

export interface InventoryReport {
  bw: number;
  os: { family: "windows" | "macos" | "linux"; name: string | null; version: string | null; build: string | null; display: string | null; id: string | null; versionId: string | null };
  browsers: { name: string; version: string }[];
  packages: { name: string; version: string }[];
  /** Which package manager the list came from: dpkg, rpm, apk. */
  packageSource: "dpkg" | "rpm" | "apk" | null;
}

export type FindingState = "ok" | "warn" | "bad" | "na";

export interface DeviceFinding {
  id: string;
  title: string;
  state: FindingState;
  text: string;
  /** CVEs or advisories, each linking somewhere: a CVE page here, or OSV. */
  refs: { id: string; href: string; note: string | null }[];
  quoted: string[];
  /** Where to go next: the KB on the Patch Tuesday page, the vendor's note. */
  links?: { label: string; href: string }[];
}

const markerStart = "BW-REPORT-BEGIN";
const markerEnd = "BW-REPORT-END";

/** The report as the script printed it, between its markers or as the whole text; refused when it is not one. */
export function readReport(text: string): InventoryReport {
  const a = text.indexOf(markerStart);
  const b = text.indexOf(markerEnd);
  const body = a >= 0 && b > a ? text.slice(a + markerStart.length, b) : text;
  const raw = parseJson<Record<string, unknown>>(body.trim(), {});
  if (raw.bw !== 1 || typeof raw.os !== "object" || raw.os === null) throw new Error("That is not a report from bw-inventory: no bw: 1 and os block.");
  const os = raw.os as Record<string, unknown>;
  const family = os.family === "windows" || os.family === "macos" || os.family === "linux" ? os.family : null;
  if (!family) throw new Error("The report's os.family is not windows, macos or linux.");
  const str = (v: unknown, max = 120): string | null => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : null);
  const list = <T>(v: unknown, read: (x: Record<string, unknown>) => T | null, max: number): T[] =>
    Array.isArray(v) ? v.slice(0, max).map((x) => read((x ?? {}) as Record<string, unknown>)).filter((x): x is T => x !== null) : [];
  return {
    bw: 1,
    os: { family, name: str(os.name), version: str(os.version), build: str(os.build), display: str(os.display), id: str(os.id), versionId: str(os.version_id ?? os.versionId) },
    browsers: list(raw.browsers, (x) => (str(x.name) && str(x.version) ? { name: str(x.name)!, version: str(x.version)! } : null), 20),
    packages: list(raw.packages, (x) => (str(x.name) && str(x.version) ? { name: str(x.name)!, version: str(x.version)! } : null), 5000),
    packageSource: raw.package_source === "dpkg" || raw.package_source === "rpm" || raw.package_source === "apk" ? raw.package_source : null,
  };
}

// ------------------------------------------------------------------ Windows, from the guide

/** "24H2" and a build "10.0.26100.9711" to the guide's product name: Windows 11 Version 24H2 (or Windows 10, by build). */
export function windowsProduct(display: string | null, build: string | null): string | null {
  const v = display?.toUpperCase().match(/\d{2}H\d/)?.[0];
  if (!v) return null;
  const major = Number(build?.split(".")[2] ?? 0);
  return `${major >= 22000 ? "Windows 11" : "Windows 10"} Version ${v}`;
}

/** The CVEs whose fix for this product has a build newer than the device's: the updates not yet installed. */
export function matchWindows(db: DatabaseSync, report: InventoryReport): DeviceFinding {
  const product = windowsProduct(report.os.display, report.os.build);
  const build = report.os.build;
  if (!product || !build) return { id: "windows", title: "Windows updates", state: "na", text: "The report carries no Windows version and build to read (the script reads them from the registry).", refs: [], quoted: [] };
  const rows = db.prepare("SELECT cve_id, severity, exploited, fixes_json, release_id FROM msrc_vulns WHERE fixes_json LIKE ?").all(`%"${product}"%`) as { cve_id: string; severity: string | null; exploited: number; fixes_json: string; release_id: string }[];
  const missing = new Map<string, { cve_id: string; severity: string | null; exploited: number; kb: string | null; fixedBuild: string; release_id: string }>();
  for (const r of rows) {
    for (const f of parseJson<{ kb: string | null; products: string[]; fixedBuild: string | null }[]>(r.fixes_json, [])) {
      if (!f.products.includes(product) || !f.fixedBuild) continue;
      if (compareDotted(build, f.fixedBuild) < 0) missing.set(r.cve_id, { cve_id: r.cve_id, severity: r.severity, exploited: r.exploited, kb: f.kb, fixedBuild: f.fixedBuild, release_id: r.release_id });
    }
  }
  const quoted = [`${product}, build ${build}`];
  if (rows.length === 0) return { id: "windows", title: "Windows updates", state: "na", text: `No row in the Security Update Guide names ${product} yet; the source pulls daily.`, refs: [], quoted };
  if (missing.size === 0) return { id: "windows", title: "Windows updates", state: "ok", text: `Build ${build} carries every security update the guide lists for ${product} (${rows.length} CVEs).`, refs: [], quoted };
  const list = [...missing.values()].sort((a, b) => b.exploited - a.exploited || (a.severity === "Critical" ? -1 : 0) - (b.severity === "Critical" ? -1 : 0));
  const exploited = list.filter((m) => m.exploited === 1).length;
  const kbs = [...new Set(list.map((m) => (m.kb ? `KB${m.kb}` : m.fixedBuild)))];
  return {
    id: "windows",
    title: "Windows updates",
    state: exploited ? "bad" : "warn",
    text: `${list.length} CVE(s) fixed in ${kbs.slice(0, 3).join(", ")}${kbs.length > 3 ? ` and ${kbs.length - 3} more` : ""} are not on this build${exploited ? `; ${exploited} of them Microsoft says are exploited` : ""}. Install the update and restart.`,
    refs: list.slice(0, 60).map((m) => ({ id: m.cve_id, href: `/vulnerabilities/${m.cve_id}`, note: `${m.severity ?? ""}${m.exploited ? " · exploited" : ""} · ${m.kb ? `KB${m.kb}` : m.fixedBuild} (${m.release_id})` })),
    quoted: [...quoted, `Newest fixed build the guide names: ${newestVersion(list.map((m) => m.fixedBuild)) ?? "?"}`],
    links: kbs.filter((k) => k.startsWith("KB")).slice(0, 6).map((k) => ({ label: `${k} on Patch Tuesday`, href: `/vulnerabilities/microsoft?q=${k.slice(2)}` })),
  };
}

// ------------------------------------------------------------------ browsers, from the vendors

export type ReleaseLine = "chrome" | "firefox" | "safari" | "edge" | "ios" | "ipados";

export interface LatestRelease {
  browser: ReleaseLine;
  version: string;
  /** Items carrying a newer version than the one asked about, newest first; for iOS and iPadOS, within the device's own major line. */
  newer: { title: string; url: string | null; version: string; published_at: string | null }[];
  /** For iOS and iPadOS: a newer major line exists (27 beside 26.x), which a device that supports it should move to. */
  newerLine: string | null;
}

export function isReleaseLine(value: unknown): value is ReleaseLine {
  return value === "chrome" || value === "firefox" || value === "safari" || value === "edge" || value === "ios" || value === "ipados";
}

const chromeVersion = (text: string): string | null => /\b(\d{2,3}\.\d+\.\d{3,5}\.\d+)\b/.exec(text)?.[1] ?? /\bChrome (?:Stable )?(\d{2,3})\b/.exec(text)?.[1] ?? null;

/** What the vendor feeds say is the newest release of a browser, and which releases are newer than `version`. */
export function latestBrowser(db: DatabaseSync, browser: ReleaseLine, version: string | null): LatestRelease | null {
  const rows = (() => {
    if (browser === "ios" || browser === "ipados") {
      const re = browser === "ios" ? /\biOS (\d+(?:\.\d+)*)/ : /\biPadOS (\d+(?:\.\d+)*)/;
      return (db.prepare("SELECT title, url, published_at FROM items WHERE source_id = 'apple-security' AND (title LIKE 'iOS %' OR title LIKE 'iPadOS %') ORDER BY published_at DESC LIMIT 60").all() as { title: string; url: string | null; published_at: string | null }[]).map((r) => ({ ...r, version: re.exec(r.title)?.[1] ?? null }));
    }
    if (browser === "chrome" || browser === "edge") {
      return (db.prepare("SELECT title, url, summary, published_at FROM items WHERE source_id = 'chrome-releases' AND title LIKE '%Stable Channel Update for Desktop%' ORDER BY published_at DESC LIMIT 40").all() as { title: string; url: string | null; summary: string | null; published_at: string | null }[]).map((r) => ({ ...r, version: chromeVersion(`${r.summary ?? ""}`) }));
    }
    if (browser === "firefox") {
      return (db.prepare("SELECT title, url, signals_json, published_at FROM items WHERE source_id = 'mozilla-mfsa' ORDER BY published_at DESC LIMIT 80").all() as { title: string; url: string | null; signals_json: string | null; published_at: string | null }[])
        .map((r) => ({ ...r, version: /^Firefox (\d+(?:\.\d+)*)$/.exec(parseJson<{ product?: string }>(r.signals_json, {}).product ?? "")?.[1] ?? null }));
    }
    return (db.prepare("SELECT title, url, published_at FROM items WHERE source_id = 'apple-security' AND title LIKE 'Safari %' ORDER BY published_at DESC LIMIT 40").all() as { title: string; url: string | null; published_at: string | null }[]).map((r) => ({ ...r, version: /^Safari (\d+(?:\.\d+)*)/.exec(r.title)?.[1] ?? null }));
  })().filter((r): r is typeof r & { version: string } => r.version !== null);
  if (rows.length === 0) return null;
  const latest = newestVersion(rows.map((r) => r.version))!;
  // A phone stays on its own line (26.7.x) when it cannot run the next (27); it is judged within that line, and told the next exists.
  const lineOf = (v: string): string => v.split(".")[0]!;
  const sameLine = (browser === "ios" || browser === "ipados") && version ? rows.filter((r) => lineOf(r.version) === lineOf(version)) : rows;
  const newer = version ? sameLine.filter((r) => compareDotted(r.version, version) > 0).map((r) => ({ title: r.title, url: r.url, version: r.version, published_at: r.published_at })) : [];
  const newerLine = (browser === "ios" || browser === "ipados") && version && lineOf(latest) !== lineOf(version) && compareDotted(latest, version) > 0 ? latest : null;
  return { browser, version: newerVersionWithin(sameLine, latest, version), newer, newerLine };
}

/** The newest version of the device's own line when it has one, else the newest overall. */
function newerVersionWithin(rows: { version: string }[], latest: string, version: string | null): string {
  if (!version || rows.length === 0) return latest;
  return newestVersion(rows.map((r) => r.version)) ?? latest;
}

export function judgeBrowser(name: string, version: string, latest: LatestRelease | null): DeviceFinding {
  const id = `browser-${name.toLowerCase().replace(/[^a-z]+/g, "-")}`;
  if (!latest) return { id, title: name, state: "na", text: `No release of ${name} is in the sources yet, so ${version} cannot be judged.`, refs: [], quoted: [`${name} ${version}`] };
  const behind = compareDotted(version, latest.version) < 0;
  const line = latest.newerLine ? ` ${name} ${latest.newerLine} exists for devices that support it.` : "";
  if (!behind) return { id, title: name, state: "ok", text: `Nothing newer than ${version} is announced for ${name}${latest.newerLine ? ` ${version.split(".")[0]}` : ""} (newest: ${latest.version}).${line}`, refs: [], quoted: [`${name} ${version}`] };
  const n = latest.newer.length;
  const what = latest.browser === "firefox" ? (n === 1 ? "advisory" : "advisories") : n === 1 ? "release" : "releases";
  return {
    id,
    title: name,
    state: n >= 2 ? "bad" : "warn",
    text: `${version} is behind ${latest.version}: ${n} newer ${what} with security fixes since. Update, then relaunch.${line}`,
    refs: latest.newer.slice(0, 8).map((r) => ({ id: r.version, href: r.url ?? "#", note: `${r.title}${r.published_at ? ` · ${r.published_at.slice(0, 10)}` : ""}` })),
    quoted: [`${name} ${version}`, `Newest announced: ${latest.version}`],
  };
}

function browserKey(name: string): LatestRelease["browser"] | null {
  const n = name.toLowerCase();
  if (n.includes("firefox")) return "firefox";
  if (n.includes("edge")) return "edge";
  if (n.includes("chrome") || n.includes("chromium")) return "chrome";
  if (n.includes("safari")) return "safari";
  return null;
}

export function matchBrowsers(db: DatabaseSync, report: InventoryReport): DeviceFinding[] {
  return report.browsers.map((b) => {
    const key = browserKey(b.name);
    return key ? judgeBrowser(b.name, b.version, latestBrowser(db, key, b.version)) : { id: `browser-${b.name.toLowerCase().replace(/[^a-z]+/g, "-")}`, title: b.name, state: "na" as const, text: `${b.name} ${b.version}: no vendor feed for it here.`, refs: [], quoted: [] };
  });
}

// ------------------------------------------------------------------ the OS, from Apple and endoflife.date

export function matchOs(db: DatabaseSync, report: InventoryReport): DeviceFinding {
  const { os } = report;
  if (os.family === "macos" && os.version) {
    const major = os.version.split(".")[0]!;
    const rows = (db.prepare("SELECT title, url, published_at FROM items WHERE source_id = 'apple-security' AND title LIKE 'macOS %' ORDER BY published_at DESC LIMIT 60").all() as { title: string; url: string | null; published_at: string | null }[])
      .map((r) => ({ ...r, version: /\b(\d{2}(?:\.\d+)+)\s*$/.exec(r.title)?.[1] ?? null }))
      .filter((r): r is typeof r & { version: string } => r.version !== null && r.version.split(".")[0] === major);
    const eol = eolFor(db, "macos", major);
    const quoted = [`macOS ${os.version}${os.build ? ` (${os.build})` : ""}`, ...eol.map((c) => `endoflife.date: ${eolWord(c.eol)}${c.latest ? ` · latest ${c.latest}` : ""}`)];
    const latest = newestVersion(rows.map((r) => r.version));
    if (!latest) return { id: "os", title: "macOS", state: "na", text: `No macOS ${major} release is in the sources yet.`, refs: [], quoted };
    const newer = rows.filter((r) => compareDotted(r.version, os.version!) > 0);
    if (newer.length === 0) return { id: "os", title: "macOS", state: "ok", text: `${os.version} is the newest macOS ${major} with security content Apple has published.`, refs: [], quoted };
    return { id: "os", title: "macOS", state: newer.length >= 2 ? "bad" : "warn", text: `${os.version} is behind ${latest}: ${newer.length} newer release(s) with security content. Software Update, then restart.`, refs: newer.slice(0, 8).map((n) => ({ id: n.version, href: n.url ?? "#", note: `${n.title}${n.published_at ? ` · ${n.published_at.slice(0, 10)}` : ""}` })), quoted };
  }
  if (os.family === "windows") {
    const product = windowsProduct(os.display, os.build);
    const v = os.display?.toUpperCase().match(/\d{2}H\d/)?.[0];
    const eol = v ? eolFor(db, "windows", product?.startsWith("Windows 10") ? `10-${v}` : v) : [];
    const ended = eol.filter((c) => /^\d{4}-/.test(c.eol) && c.eol < new Date().toISOString().slice(0, 10));
    const quoted = [`${product ?? "Windows"}, build ${os.build ?? "?"}`, ...eol.map((c) => `endoflife.date: ${c.edition ?? ""} ${eolWord(c.eol)}`.trim())];
    if (eol.length === 0) return { id: "os", title: "Windows support", state: "na", text: "endoflife.date has no row for this version yet.", refs: [], quoted };
    if (ended.length === eol.length) return { id: "os", title: "Windows support", state: "bad", text: `Support for ${product} ended on every edition (${ended.map((c) => c.eol).join(", ")}): no more security updates. Move to a supported version.`, refs: [], quoted };
    if (ended.length) return { id: "os", title: "Windows support", state: "warn", text: `Support for ${product} has ended on ${ended.map((c) => c.edition ?? "one edition").join(" and ")}; the other edition(s) continue.`, refs: [], quoted };
    return { id: "os", title: "Windows support", state: "ok", text: `${product} is in support: ${eol.map((c) => `${c.edition} until ${c.eol}`).join("; ")}.`, refs: [], quoted };
  }
  if (os.family === "linux" && os.id && os.versionId) {
    const key = os.id === "ubuntu" ? `ubuntu-${os.versionId}` : /^(rhel|redhat)$/.test(os.id) ? `rhel-${os.versionId.split(".")[0]}` : null;
    const eol = key ? eolFor(db, "linux", key) : [];
    const quoted = [`${os.name ?? os.id} ${os.versionId}`, ...eol.map((c) => `endoflife.date: ${eolWord(c.eol)}${c.support ? ` (support ${eolWord(c.support)})` : ""}`)];
    if (eol.length === 0) return { id: "os", title: "Distribution support", state: "na", text: "endoflife.date has no row for this distribution and release here (Ubuntu and RHEL are read).", refs: [], quoted };
    const c = eol[0]!;
    const today = new Date().toISOString().slice(0, 10);
    if (/^\d{4}-/.test(c.eol) && c.eol < today) return { id: "os", title: "Distribution support", state: "bad", text: `Support ended ${c.eol}: no more security updates for this release.`, refs: [], quoted };
    return { id: "os", title: "Distribution support", state: "ok", text: `In support${/^\d{4}-/.test(c.eol) ? ` until ${c.eol}` : ""}.`, refs: [], quoted };
  }
  return { id: "os", title: "Operating system", state: "na", text: "The report carries no OS version to read.", refs: [], quoted: [] };
}

// ------------------------------------------------------------------ packages, from OSV

export const osvBatchUrl = "https://api.osv.dev/v1/querybatch";

/** The OSV ecosystem for a distribution as /etc/os-release names it; null for one OSV does not carry. */
export function osvEcosystem(id: string | null, versionId: string | null, source: InventoryReport["packageSource"]): string | null {
  if (!id || !versionId) return null;
  const major = versionId.split(".")[0]!;
  switch (id.toLowerCase()) {
    case "debian":
      return `Debian:${major}`;
    case "ubuntu": {
      const [y, m] = versionId.split(".");
      return `Ubuntu:${versionId}${Number(y) % 2 === 0 && m === "04" ? ":LTS" : ""}`;
    }
    case "alpine":
      return `Alpine:v${versionId.split(".").slice(0, 2).join(".")}`;
    case "almalinux":
      return `AlmaLinux:${major}`;
    case "rocky":
      return `Rocky Linux:${major}`;
    case "rhel":
    case "redhat":
      return "Red Hat";
    default:
      return source === "apk" ? `Alpine:v${versionId.split(".").slice(0, 2).join(".")}` : null;
  }
}

export interface PackageHit {
  name: string;
  version: string;
  ids: string[];
}

/** Asks OSV, a thousand packages a request, which advisories cover each installed version; a hit's CVE id is read from the advisory's own id. */
export async function queryOsv(http: HttpGet, ecosystem: string, packages: InventoryReport["packages"]): Promise<PackageHit[]> {
  const hits: PackageHit[] = [];
  for (let i = 0; i < packages.length; i += 1000) {
    const chunk = packages.slice(i, i + 1000);
    const body = JSON.stringify({ queries: chunk.map((p) => ({ package: { name: p.name, ecosystem }, version: p.version })) });
    const response = await http(osvBatchUrl, { method: "POST", body, headers: { accept: "application/json", "content-type": "application/json" }, timeoutMs: 60_000, maxBytes: 50 * 1024 * 1024 });
    const data = parseJson<{ results?: { vulns?: { id?: string }[] }[] }>(new TextDecoder().decode(response.bytes), {});
    if (!Array.isArray(data.results)) throw new Error("OSV did not answer with the results list expected");
    data.results.forEach((r, j) => {
      const ids = (r.vulns ?? []).map((v) => v.id).filter((id): id is string => typeof id === "string");
      if (ids.length) hits.push({ name: chunk[j]!.name, version: chunk[j]!.version, ids });
    });
  }
  return hits;
}

/** A hit's reference: the CVE page here when the advisory id carries a CVE id this instance knows, else OSV's page. */
function refFor(db: DatabaseSync, id: string): { id: string; href: string; note: string | null } {
  const cve = /CVE-\d{4}-\d{4,7}/.exec(id)?.[0] ?? null;
  const row = cve ? (db.prepare("SELECT cvss_score, kev FROM vulns WHERE cve_id = ?").get(cve) as { cvss_score: number | null; kev: number } | undefined) : undefined;
  if (cve && row) return { id: cve, href: `/vulnerabilities/${cve}`, note: `${row.cvss_score !== null ? `CVSS ${row.cvss_score.toFixed(1)}` : "unscored"}${row.kev ? " · KEV" : ""}` };
  return { id, href: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`, note: null };
}

export async function matchPackages(db: DatabaseSync, http: HttpGet, report: InventoryReport): Promise<DeviceFinding> {
  const ecosystem = osvEcosystem(report.os.id, report.os.versionId, report.packageSource);
  if (report.packages.length === 0) return { id: "packages", title: "Installed packages", state: "na", text: "The report lists no packages (the script reads dpkg, rpm or apk on Linux).", refs: [], quoted: [] };
  if (!ecosystem) return { id: "packages", title: "Installed packages", state: "na", text: `OSV carries no advisories for ${report.os.name ?? report.os.id ?? "this distribution"} ${report.os.versionId ?? ""}, so ${report.packages.length} packages cannot be judged here.`, refs: [], quoted: [] };
  let hits: PackageHit[];
  try {
    hits = await queryOsv(http, ecosystem, report.packages);
  } catch (error) {
    return { id: "packages", title: "Installed packages", state: "na", text: `OSV did not answer (${error instanceof Error ? error.message : String(error)}); ${report.packages.length} packages were not judged.`, refs: [], quoted: [] };
  }
  const quoted = [`${report.packages.length} packages as ${ecosystem}, asked of OSV`];
  if (hits.length === 0) return { id: "packages", title: "Installed packages", state: "ok", text: `OSV lists no open advisory for any of the ${report.packages.length} installed versions.`, refs: [], quoted };
  const refs = hits.flatMap((h) => h.ids.slice(0, 12).map((id) => ({ ...refFor(db, id), note: `${h.name} ${h.version}${refFor(db, id).note ? ` · ${refFor(db, id).note}` : ""}` })));
  const seen = new Set<string>();
  const unique = refs.filter((r) => (seen.has(`${r.id}|${r.note}`) ? false : (seen.add(`${r.id}|${r.note}`), true)));
  const kev = unique.filter((r) => r.note?.includes("KEV")).length;
  return {
    id: "packages",
    title: "Installed packages",
    state: kev ? "bad" : "warn",
    text: `${hits.length} package(s) have open advisories for the installed version: ${hits.slice(0, 6).map((h) => h.name).join(", ")}${hits.length > 6 ? ` and ${hits.length - 6} more` : ""}${kev ? `; ${kev} of the CVEs are on the KEV` : ""}. Update the distribution's packages.`,
    refs: unique.slice(0, 200),
    quoted,
  };
}

/** The whole reading of a report. */
export async function readDevice(db: DatabaseSync, http: HttpGet, report: InventoryReport): Promise<DeviceFinding[]> {
  const findings: DeviceFinding[] = [];
  if (report.os.family === "windows") findings.push(matchWindows(db, report));
  findings.push(matchOs(db, report));
  findings.push(...matchBrowsers(db, report));
  if (report.os.family === "linux") findings.push(await matchPackages(db, http, report));
  return findings;
}
