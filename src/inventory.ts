import type { DatabaseSync } from "node:sqlite";
import { distroEcosystem, ecosystemCovers } from "./ecosystems.ts";
import { eolFor, eolWord, windowsEdition } from "./eol.ts";
import type { HttpGet } from "./http.ts";
import { parseJson } from "./json.ts";
import { compareDebian, compareDotted, newestVersion } from "./versions.ts";
import { agree, counted } from "./words.ts";

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
  os: {
    family: "windows" | "macos" | "linux";
    name: string | null;
    version: string | null;
    build: string | null;
    display: string | null;
    id: string | null;
    versionId: string | null;
    /** Windows: the registry's EditionID (Professional, EnterpriseS, IoTEnterpriseS, ServerStandard). */
    edition?: string | null;
    /** Linux: /etc/os-release's ID_LIKE, when the report carries it (the shell script of 2026-11 does not). */
    idLike?: string | null;
  };
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
    os: { family, name: str(os.name), version: str(os.version), build: str(os.build), display: str(os.display), id: str(os.id), versionId: str(os.version_id ?? os.versionId), edition: str(os.edition, 60), idLike: str(os.id_like ?? os.idLike) },
    browsers: list(raw.browsers, (x) => (str(x.name) && str(x.version) ? { name: str(x.name)!, version: str(x.version)! } : null), 20),
    packages: list(raw.packages, (x) => (str(x.name) && str(x.version) ? { name: str(x.name)!, version: str(x.version)! } : null), 5000),
    packageSource: raw.package_source === "dpkg" || raw.package_source === "rpm" || raw.package_source === "apk" ? raw.package_source : null,
  };
}

// ------------------------------------------------------------------ Windows, from the guide

/**
 * The Windows version a report states: DisplayVersion's "24H2", or, where the script fell back to
 * ReleaseId because the release predates DisplayVersion (Windows 10 LTSC 2019 is 1809, LTSB 2016
 * is 1607), the four digits alone.
 */
function windowsVersion(display: string | null | undefined): string | null {
  const d = (display ?? "").trim().toUpperCase();
  return /\d{2}H\d/.exec(d)?.[0] ?? /^\d{4}$/.exec(d)?.[0] ?? null;
}

/** "24H2" (or "1809") and a build "10.0.26100.9711" to the guide's product name: Windows 11 Version 24H2 (or Windows 10, by build). */
export function windowsProduct(display: string | null, build: string | null): string | null {
  const v = windowsVersion(display);
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
    text: `${counted(list.length, "CVE")} fixed in ${kbs.slice(0, 3).join(", ")}${kbs.length > 3 ? ` and ${kbs.length - 3} more` : ""} ${agree(list.length, "is", "are")} not on this build${exploited ? `; Microsoft says ${exploited} of them ${agree(exploited, "is", "are")} exploited` : ""}. Install the update and restart.`,
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

function matchBrowsers(db: DatabaseSync, report: InventoryReport): DeviceFinding[] {
  return report.browsers.map((b) => {
    const key = browserKey(b.name);
    return key ? judgeBrowser(b.name, b.version, latestBrowser(db, key, b.version)) : { id: `browser-${b.name.toLowerCase().replace(/[^a-z]+/g, "-")}`, title: b.name, state: "na" as const, text: `${b.name} ${b.version}: no vendor feed for it here.`, refs: [], quoted: [] };
  });
}

// ------------------------------------------------------------------ the OS, from Apple and endoflife.date

const isoDay = (now: Date): string => now.toISOString().slice(0, 10);
const isDate = (v: string): boolean => /^\d{4}-\d{2}-\d{2}$/.test(v);

function matchWindowsSupport(db: DatabaseSync, report: InventoryReport, today: string): DeviceFinding {
  const { os } = report;
  const product = windowsProduct(os.display, os.build);
  const v = windowsVersion(os.display);
  const edition = windowsEdition(os.edition);
  const named = os.edition ? ` (${os.edition})` : "";
  if (edition === "server") return { id: "os", title: "Windows support", state: "na", text: `This is a Windows Server edition${named}; its support dates are not read here (endoflife.date's Windows Server product is not one this instance follows).`, refs: [], quoted: [`${os.name ?? "Windows Server"}, build ${os.build ?? "?"}`] };
  // An EditionID the mapping does not know (a new SKU, a Cloud or Team edition) is named, not
  // guessed at: reading every edition's dates for it would say "the report does not say which".
  if (os.edition && edition === null) return { id: "os", title: "Windows support", state: "na", text: `This is the ${os.edition} edition, which this check does not map to an endoflife.date cycle; its support dates are not read here.`, refs: [], quoted: [`${product ?? os.name ?? "Windows"}, build ${os.build ?? "?"}, edition ${os.edition}`] };
  if (edition && v && product) {
    // The edition picks one cycle (src/eol.ts keeps the mapping); the first that endoflife.date holds is the one.
    const row = eolFor(db, "windows", product.startsWith("Windows 10") ? `10-${v}` : v, edition)[0];
    const quoted = [`${product}, build ${os.build ?? "?"}, edition ${os.edition}`, ...(row ? [`endoflife.date ${row.cycle}: ${eolWord(row.eol)}`] : [])];
    if (!row) return { id: "os", title: "Windows support", state: "na", text: `endoflife.date has no row for ${product} ${edition.word} yet.`, refs: [], quoted };
    if (isDate(row.eol) && row.eol < today) return { id: "os", title: "Windows support", state: "bad", text: `Support for ${product} ${edition.word}, the edition here${named}, ended on ${row.eol}: no more security updates. Move to a supported version.`, refs: [], quoted };
    return { id: "os", title: "Windows support", state: "ok", text: `${product} ${edition.word}, the edition here${named}, is in support${isDate(row.eol) ? ` until ${row.eol}` : ""}.`, refs: [], quoted };
  }
  const eol = v ? eolFor(db, "windows", product?.startsWith("Windows 10") ? `10-${v}` : v) : [];
  const ended = eol.filter((c) => isDate(c.eol) && c.eol < today);
  const quoted = [`${product ?? "Windows"}, build ${os.build ?? "?"}`, ...eol.map((c) => ["endoflife.date:", c.edition, eolWord(c.eol)].filter(Boolean).join(" "))];
  if (eol.length === 0) return { id: "os", title: "Windows support", state: "na", text: "endoflife.date has no row for this version yet.", refs: [], quoted };
  if (ended.length === eol.length) return { id: "os", title: "Windows support", state: "bad", text: `Support for ${product} ended on every edition (${ended.map((c) => c.eol).join(", ")}): no more security updates. Move to a supported version.`, refs: [], quoted };
  if (ended.length) return { id: "os", title: "Windows support", state: "warn", text: `Support for ${product} has ended on ${ended.map((c) => c.edition ?? "one edition").join(" and ")}; the others continue. The report does not say which edition this is.`, refs: [], quoted };
  return { id: "os", title: "Windows support", state: "ok", text: `${product} is in support: ${eol.map((c) => `${c.edition ?? "every edition"} until ${c.eol}`).join("; ")}.`, refs: [], quoted };
}

export function matchOs(db: DatabaseSync, report: InventoryReport, now: Date = new Date()): DeviceFinding {
  const { os } = report;
  const today = isoDay(now);
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
    return { id: "os", title: "macOS", state: newer.length >= 2 ? "bad" : "warn", text: `${os.version} is behind ${latest}: ${counted(newer.length, "newer release")} with security content. Software Update, then restart.`, refs: newer.slice(0, 8).map((n) => ({ id: n.version, href: n.url ?? "#", note: `${n.title}${n.published_at ? ` · ${n.published_at.slice(0, 10)}` : ""}` })), quoted };
  }
  if (os.family === "windows") return matchWindowsSupport(db, report, today);
  if (os.family === "linux" && os.id && os.versionId) {
    const key = os.id === "ubuntu" ? `ubuntu-${os.versionId}` : /^(rhel|redhat)$/.test(os.id) ? `rhel-${os.versionId.split(".")[0]}` : null;
    const eol = key ? eolFor(db, "linux", key) : [];
    const quoted = [`${os.name ?? os.id} ${os.versionId}`, ...eol.map((c) => `endoflife.date: ${eolWord(c.eol)}${c.support ? ` (support ${eolWord(c.support)})` : ""}`)];
    if (eol.length === 0) return { id: "os", title: "Distribution support", state: "na", text: "endoflife.date has no row for this distribution and release here (Ubuntu and RHEL are read).", refs: [], quoted };
    const c = eol[0]!;
    if (isDate(c.eol) && c.eol < today) {
      // An Ubuntu LTS goes on under Ubuntu Pro's Expanded Security Maintenance; the table holds no ESM end to name.
      const esm = key?.startsWith("ubuntu-") && c.lts === 1;
      const after = esm ? "security updates continue only under Ubuntu Pro (ESM), for a machine attached to it; the ESM end date is not read here" : "no more security updates for this release";
      return { id: "os", title: "Distribution support", state: "bad", text: `Standard support ended ${c.eol}: ${after}.`, refs: [], quoted };
    }
    return { id: "os", title: "Distribution support", state: "ok", text: `In support${/^\d{4}-/.test(c.eol) ? ` until ${c.eol}` : ""}.`, refs: [], quoted };
  }
  return { id: "os", title: "Operating system", state: "na", text: "The report carries no OS version to read.", refs: [], quoted: [] };
}

// ------------------------------------------------------------------ packages, from OSV

export const osvBatchUrl = "https://api.osv.dev/v1/querybatch";

/**
 * The distribution whose packages a derivative installs, for asking OSV: Pop!_OS and Linux Mint
 * are built on an Ubuntu release, Raspbian and LMDE on a Debian one. The inventory script of
 * 2026-11 sends ID and VERSION_ID only, so the derivatives seen in practice are mapped here by
 * hand (Mint's own release numbers to Ubuntu's); a report that carries ID_LIKE is read through it
 * when its VERSION_ID is already the parent's.
 */
export function packageBase(id: string | null, versionId: string | null, idLike?: string | null): { id: string; versionId: string; via: string | null } | null {
  if (!id || !versionId) return null;
  const lower = id.toLowerCase();
  const major = Number(versionId.split(".")[0]);
  if (lower === "pop") return { id: "ubuntu", versionId, via: "Pop!_OS" };
  if (lower === "raspbian") return { id: "debian", versionId: String(major), via: "Raspbian" };
  if (lower === "linuxmint") {
    const ubuntu: Record<number, string> = { 19: "18.04", 20: "20.04", 21: "22.04", 22: "24.04" };
    const lmde: Record<number, string> = { 4: "10", 5: "11", 6: "12", 7: "13" };
    if (ubuntu[major]) return { id: "ubuntu", versionId: ubuntu[major], via: `Linux Mint ${major}` };
    if (lmde[major]) return { id: "debian", versionId: lmde[major], via: `LMDE ${major}` };
    return null;
  }
  if (distroEcosystem(lower, versionId)) return { id: lower, versionId, via: null };
  const like = (idLike ?? "").toLowerCase().split(/\s+/);
  if (like.includes("ubuntu") && /^\d{2}\.\d{2}$/.test(versionId)) return { id: "ubuntu", versionId, via: id };
  if (like.includes("debian") && /^\d+$/.test(versionId)) return { id: "debian", versionId, via: id };
  return null;
}

/** The OSV ecosystem for a device's distribution, through the parent a derivative's packages come from; an apk report from an unnamed distribution is Alpine's. */
export function osvEcosystem(id: string | null, versionId: string | null, source: InventoryReport["packageSource"], idLike?: string | null): string | null {
  if (!id || !versionId) return null;
  const base = packageBase(id, versionId, idLike);
  return (base ? distroEcosystem(base.id, base.versionId) : null) ?? (source === "apk" ? distroEcosystem("alpine", versionId) : null);
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
  const cve = /CVE-\d{4}-\d{4,}/.exec(id)?.[0] ?? null;
  const row = cve ? (db.prepare("SELECT cvss_score, kev FROM vulns WHERE cve_id = ?").get(cve) as { cvss_score: number | null; kev: number } | undefined) : undefined;
  if (cve && row) return { id: cve, href: `/vulnerabilities/${cve}`, note: `${row.cvss_score !== null ? `CVSS ${row.cvss_score.toFixed(1)}` : "unscored"}${row.kev ? " · KEV" : ""}` };
  return { id, href: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`, note: null };
}

export const osvQueryUrl = "https://api.osv.dev/v1/query";

/** At most this many packages are asked of OSV one by one for their advisories' fixed versions, six at a time. */
const fixLookupLimit = 150;
const fixLookupConcurrency = 6;

interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: { type?: string; events?: Record<string, string>[] }[];
}

/**
 * Whether an advisory publishes a fixed version above the installed one for this package. OSV has
 * already said the installed version is affected; the question is whether a range carries a
 * `fixed` event. For Debian and Ubuntu that event is compared with the installed version by
 * Debian's rules; for the others, whose version rules this does not implement, a fixed event in a
 * range that covers the installed version is taken as the fix.
 */
export function hasFixAbove(affected: OsvAffected[], name: string, ecosystem: string, installed: string): boolean {
  const family = ecosystem.split(":")[0]!.toLowerCase();
  const same = (eco: string | undefined): boolean => !!eco && eco.split(":")[0]!.toLowerCase() === family && (ecosystemCovers(eco, ecosystem) || ecosystemCovers(ecosystem, eco));
  const ours = affected.filter((a) => same(a.package?.ecosystem));
  const named = ours.filter((a) => a.package?.name === name);
  const fixed = (named.length ? named : ours).flatMap((a) => (a.ranges ?? []).flatMap((r) => (r.events ?? []).map((e) => e.fixed).filter((f): f is string => typeof f === "string" && f !== "")));
  if (family === "debian" || family === "ubuntu") return fixed.some((f) => compareDebian(f, installed) > 0);
  return fixed.length > 0;
}

/** Runs `work` over `items`, `limit` at a time, in order of the results. */
async function pooled<T, R>(items: T[], limit: number, work: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array<R>(items.length);
  let next = 0;
  const run = async (): Promise<void> => {
    while (next < items.length) {
      const k = next;
      next += 1;
      out[k] = await work(items[k]!, k);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run));
  return out;
}

interface SplitHit extends PackageHit {
  /** Advisories with a fixed version above the installed one: the update that ends them is published. */
  fixable: string[];
  /** Advisories OSV lists for the installed version with no fix published. */
  unfixed: string[];
  /** Whether the advisories were read for their fixes; false past the lookup limit or when OSV did not answer. */
  checked: boolean;
}

/**
 * Splits each hit's advisories into those with a published fix and those without, by asking OSV
 * for the package's full records (one /v1/query per package with hits, bounded in count and
 * concurrency). A hit past the limit, or whose query fails, is left whole as fixable: unread is
 * not the same as no fix.
 */
async function splitByFix(http: HttpGet, ecosystem: string, hits: PackageHit[], limit = fixLookupLimit): Promise<SplitHit[]> {
  return pooled(hits, fixLookupConcurrency, async (hit, k) => {
    const whole: SplitHit = { ...hit, fixable: hit.ids, unfixed: [], checked: false };
    if (k >= limit) return whole;
    try {
      const body = JSON.stringify({ package: { name: hit.name, ecosystem }, version: hit.version });
      const response = await http(osvQueryUrl, { method: "POST", body, headers: { accept: "application/json", "content-type": "application/json" }, timeoutMs: 30_000, maxBytes: 20 * 1024 * 1024 });
      const data = parseJson<{ vulns?: { id?: string; affected?: OsvAffected[] }[] }>(new TextDecoder().decode(response.bytes), {});
      if (!Array.isArray(data.vulns)) return whole;
      const records = new Map(data.vulns.filter((v) => typeof v.id === "string").map((v) => [v.id!, v.affected ?? []]));
      const fixable: string[] = [];
      const unfixed: string[] = [];
      for (const id of hit.ids) {
        const affected = records.get(id);
        // An id the batch named but the query did not return is left with the fixable: unread.
        if (!affected || hasFixAbove(affected, hit.name, ecosystem, hit.version)) fixable.push(id);
        else unfixed.push(id);
      }
      return { ...hit, fixable, unfixed, checked: true };
    } catch {
      return whole;
    }
  });
}

export async function matchPackages(db: DatabaseSync, http: HttpGet, report: InventoryReport): Promise<DeviceFinding> {
  const ecosystem = osvEcosystem(report.os.id, report.os.versionId, report.packageSource, report.os.idLike);
  const n = report.packages.length;
  const packagesWord = counted(n, "package");
  if (n === 0) return { id: "packages", title: "Installed packages", state: "na", text: "The report lists no packages (the script reads dpkg, rpm or apk on Linux).", refs: [], quoted: [] };
  if (!ecosystem) return { id: "packages", title: "Installed packages", state: "na", text: `OSV carries no advisories for ${[report.os.name ?? report.os.id ?? "this distribution", report.os.versionId].filter(Boolean).join(" ")}, so ${packagesWord} cannot be judged here.`, refs: [], quoted: [] };
  let hits: PackageHit[];
  try {
    hits = await queryOsv(http, ecosystem, report.packages);
  } catch (error) {
    return { id: "packages", title: "Installed packages", state: "na", text: `OSV did not answer (${error instanceof Error ? error.message : String(error)}); ${packagesWord} ${agree(n, "was", "were")} not judged.`, refs: [], quoted: [] };
  }
  const base = packageBase(report.os.id, report.os.versionId, report.os.idLike);
  const quoted = [`${packagesWord} as ${ecosystem}, asked of OSV${base?.via ? ` (${base.via} installs that release's packages)` : ""}`];
  if (hits.length === 0) return { id: "packages", title: "Installed packages", state: "ok", text: `OSV lists no open advisory for any of the ${n === 1 ? "1 installed version" : `${n} installed versions`}.`, refs: [], quoted };
  const split = await splitByFix(http, ecosystem, hits);
  const unchecked = split.filter((h) => !h.checked).length;
  if (unchecked) quoted.push(`${counted(unchecked, "package")} with advisories ${agree(unchecked, "was", "were")} not read for a fix (OSV's records are read for the first ${fixLookupLimit}); ${agree(unchecked, "it is", "they are")} counted as open`);
  // One lookup per advisory id, not three: a report can carry five thousand packages, and the
  // same row was being read again inside the note it had just been read for.
  const refsOf = (h: SplitHit, ids: string[], extra: string | null) =>
    ids.slice(0, 12).map((id) => {
      const ref = refFor(db, id);
      return { ...ref, note: [`${h.name} ${h.version}`, ref.note, extra].filter(Boolean).join(" · ") };
    });
  const seen = new Set<string>();
  const dedupe = <R extends { id: string; note: string | null }>(list: R[]): R[] => list.filter((r) => (seen.has(`${r.id}|${r.note}`) ? false : (seen.add(`${r.id}|${r.note}`), true)));
  const open = split.filter((h) => h.fixable.length > 0);
  const openRefs = dedupe(open.flatMap((h) => refsOf(h, h.fixable, null)));
  const waiting = split.filter((h) => h.unfixed.length > 0);
  const unfixedCount = waiting.reduce((sum, h) => sum + h.unfixed.length, 0);
  const waitingRefs = dedupe(waiting.flatMap((h) => refsOf(h, h.unfixed, "no fix published")));
  const noFix = unfixedCount ? `${counted(unfixedCount, "advisory", "advisories")} on ${counted(waiting.length, "package")} ${agree(unfixedCount, "has", "have")} no fix published yet; the distribution has nothing to install for ${agree(unfixedCount, "it", "them")}.` : "";
  const refs = [...openRefs, ...waitingRefs].slice(0, 200);
  if (open.length === 0) return { id: "packages", title: "Installed packages", state: "ok", text: `No installed version has an advisory with a fix published. ${noFix}`.trim(), refs, quoted };
  const kev = openRefs.filter((r) => r.note?.includes("KEV")).length;
  return {
    id: "packages",
    title: "Installed packages",
    state: kev ? "bad" : "warn",
    text: `${counted(open.length, "package")} ${agree(open.length, "has", "have")} advisories with a fixed version published above the one installed: ${open.slice(0, 6).map((h) => h.name).join(", ")}${open.length > 6 ? ` and ${open.length - 6} more` : ""}${kev ? `; ${counted(kev, "of the CVEs is", "of the CVEs are")} on the KEV` : ""}. Update the distribution's packages.${noFix ? ` ${noFix}` : ""}`,
    refs,
    quoted,
  };
}

/** The whole reading of a report. */
export async function readDevice(db: DatabaseSync, http: HttpGet, report: InventoryReport, now: Date = new Date()): Promise<DeviceFinding[]> {
  const findings: DeviceFinding[] = [];
  if (report.os.family === "windows") findings.push(matchWindows(db, report));
  findings.push(matchOs(db, report, now));
  findings.push(...matchBrowsers(db, report));
  if (report.os.family === "linux") findings.push(await matchPackages(db, http, report));
  return findings;
}
