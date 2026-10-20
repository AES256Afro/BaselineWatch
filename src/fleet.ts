import { readFileSync } from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";

/**
 * The fleet: the operating systems a team runs, each release of them, and the hardware each
 * release supports, kept as YAML under data/platforms.yaml so a new release or a new device
 * family is a few lines, not code. The test plan reads it to offer a version and a hardware
 * select, to grey out hardware a version cannot run on (macOS 27 on an Intel Mac), and to leave
 * out a template or a step that needs hardware the chosen device lacks (a Secure Enclave check on
 * an Intel Mac without a T2 chip). The Platforms page lists it with the support dates.
 *
 * Every date and model list is the vendor's, with the page it came from; the file says "verify"
 * where a date is inferred from the vendor's practice rather than published.
 */

export type FleetPlatform = "windows" | "macos" | "linux" | "ios" | "ipados" | "android" | "collaboration";

export const fleetPlatforms: { id: FleetPlatform; label: string; blurb: string }[] = [
  { id: "windows", label: "Windows", blurb: "Windows 11 by feature update, with Microsoft's servicing dates per edition." },
  { id: "macos", label: "macOS", blurb: "Each macOS release and the Macs it runs on: Apple silicon, Intel with the T2 chip, Intel without." },
  { id: "linux", label: "Linux", blurb: "Red Hat Enterprise Linux and Ubuntu LTS, with their support phases." },
  { id: "ios", label: "iOS", blurb: "Each iOS release and the iPhones it supports." },
  { id: "ipados", label: "iPadOS", blurb: "Each iPadOS release and the iPads it supports." },
  { id: "android", label: "Android", blurb: "Android by platform release, with Pixel and Samsung Galaxy (Knox) update commitments." },
  { id: "collaboration", label: "Collaboration", blurb: "Meeting-room and collaboration devices: Samsung displays first, then Teams Rooms, Zoom Rooms and Webex devices." },
];

export function isFleetPlatform(value: unknown): value is FleetPlatform {
  return fleetPlatforms.some((p) => p.id === value);
}

export function fleetPlatformName(id: FleetPlatform): string {
  return fleetPlatforms.find((p) => p.id === id)?.label ?? id;
}

export interface Hardware {
  id: string;
  label: string;
  platforms: FleetPlatform[];
  /** Whether the device has a hardware key store and root of trust (Secure Enclave, T2, TPM 2.0, StrongBox). */
  secureElement: boolean;
  note: string | null;
}

export interface Release {
  platform: FleetPlatform;
  id: string;
  label: string;
  status: "current" | "supported" | "ended" | "upcoming";
  released: string | null;
  /** Free text per edition or phase ("Home and Pro 2027-10-12; Enterprise 2028-10-10"). */
  supportEnds: string | null;
  /** Hardware ids this release runs on; empty means every family of the platform. */
  hardware: string[];
  /** The models in the vendor's words, when a family does not say it all ("Intel: MacBook Pro 16-inch 2019 …"). */
  models: string | null;
  /** The published baselines that name this release, in the publishers' words. */
  baselines: string[];
  /** Register document keys the builder should default to for this release: stig:…, mscp:…, baseline:… */
  documents: { stig?: string; mscp?: string; sct?: string };
  /** What changed in this release that a test plan should know (features arriving or leaving). */
  notes: string[];
  sources: { title: string; url: string }[];
}

export interface Fleet {
  hardware: Hardware[];
  releases: Release[];
  errors: string[];
}

export const fleetFile = path.join(import.meta.dirname, "..", "data", "platforms.yaml");

type Json = Record<string, unknown>;
const obj = (v: unknown): Json => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Json) : {});
const str = (v: unknown): string | null => (typeof v === "string" && v.trim() !== "" ? v.trim() : typeof v === "number" ? String(v) : null);
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => str(x)).filter((x): x is string => x !== null) : []);
const dateOrNull = (v: unknown): string | null => {
  const s = str(v);
  if (!s) return null;
  // YAML reads an unquoted 2026-09-15 as a Date; a string stays a string.
  return s;
};

/** The fleet file, read on every request so an edit shows at once; a broken file is reported, not fatal. */
export function loadFleet(file: string = fleetFile): Fleet {
  let doc: Json;
  try {
    doc = obj(parseYaml(readFileSync(file, "utf8")));
  } catch (error) {
    return { hardware: [], releases: [], errors: [`${path.basename(file)}: ${error instanceof Error ? error.message : String(error)}`] };
  }
  const errors: string[] = [];
  const hardware: Hardware[] = [];
  for (const raw of Array.isArray(doc.hardware) ? doc.hardware : []) {
    const h = obj(raw);
    const id = str(h.id);
    const label = str(h.label);
    if (!id || !label) {
      errors.push(`hardware entry without id or label`);
      continue;
    }
    hardware.push({ id, label, platforms: strings(h.platforms).filter(isFleetPlatform), secureElement: h.secure_element === true, note: str(h.note) });
  }
  const releases: Release[] = [];
  for (const [platform, raw] of Object.entries(obj(doc.platforms))) {
    if (!isFleetPlatform(platform)) {
      errors.push(`unknown platform ${platform}`);
      continue;
    }
    for (const entry of Array.isArray(obj(raw).releases) ? (obj(raw).releases as unknown[]) : []) {
      const r = obj(entry);
      const id = str(r.id);
      const label = str(r.label);
      if (!id || !label) {
        errors.push(`${platform}: release without id or label`);
        continue;
      }
      const status = r.status === "current" || r.status === "supported" || r.status === "ended" || r.status === "upcoming" ? r.status : "supported";
      const hw = strings(r.hardware);
      for (const h of hw) if (!hardware.some((x) => x.id === h)) errors.push(`${platform} ${id}: unknown hardware ${h}`);
      const documents = obj(r.documents);
      releases.push({
        platform,
        id,
        label,
        status,
        released: dateOrNull(r.released instanceof Date ? r.released.toISOString().slice(0, 10) : r.released),
        supportEnds: str(r.support_ends instanceof Date ? r.support_ends.toISOString().slice(0, 10) : r.support_ends),
        hardware: hw,
        models: str(r.models),
        baselines: strings(r.baselines),
        documents: {
          ...(str(documents.stig) ? { stig: str(documents.stig)! } : {}),
          ...(str(documents.mscp) ? { mscp: str(documents.mscp)! } : {}),
          ...(str(documents.sct) ? { sct: str(documents.sct)! } : {}),
        },
        notes: strings(r.notes),
        sources: (Array.isArray(r.sources) ? r.sources : []).map((s) => obj(s)).map((s) => ({ title: str(s.title) ?? "", url: str(s.url) ?? "" })).filter((s) => s.title && /^https:\/\//.test(s.url)),
      });
    }
  }
  return { hardware, releases, errors };
}

/** The dates a release's support text names, oldest first ("Home and Pro 2027-10-12; Enterprise 2028-10-10" → both). */
export function supportDates(release: Release): string[] {
  return [...new Set((release.supportEnds ?? "").match(/\b20\d\d-\d\d-\d\d\b/g) ?? [])].sort();
}

export interface SupportEnding {
  release: Release;
  /** The support date that falls inside the window. */
  date: string;
  /** Days from now to that date, zero on the day. */
  days: number;
  /** The clause of the support text that carries the date ("Enterprise and Education 2026-11-10"). */
  clause: string;
}

/**
 * Releases with a support date inside the next `days` days (today included), nearest first: the
 * Today tile and the Platforms page say which editions are about to stop getting fixes. A date
 * already past is not "ending"; the release's status says it ended.
 */
export function endingSupport(fleet: Fleet, now: Date, days = 90): SupportEnding[] {
  const start = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const out: SupportEnding[] = [];
  for (const release of fleet.releases) {
    for (const date of supportDates(release)) {
      const at = Date.parse(`${date}T00:00:00Z`);
      const ahead = Math.round((at - start) / 86_400_000);
      if (ahead < 0 || ahead > days) continue;
      const clause = (release.supportEnds ?? "").split(/;|\(/).map((c) => c.trim()).find((c) => c.includes(date)) ?? date;
      out.push({ release, date, days: ahead, clause: clause.replace(/\)$/, "") });
    }
  }
  return out.sort((a, b) => a.days - b.days || a.release.label.localeCompare(b.release.label));
}

/** The releases of one platform, in the file's order (newest first by convention). */
export function releasesOf(fleet: Fleet, platform: FleetPlatform): Release[] {
  return fleet.releases.filter((r) => r.platform === platform);
}

/** The hardware families of one platform. */
export function hardwareOf(fleet: Fleet, platform: FleetPlatform): Hardware[] {
  return fleet.hardware.filter((h) => h.platforms.includes(platform));
}

export function findRelease(fleet: Fleet, platform: FleetPlatform, id: string | undefined): Release | null {
  return id ? (releasesOf(fleet, platform).find((r) => r.id === id) ?? null) : null;
}

export function findHardware(fleet: Fleet, id: string | undefined): Hardware | null {
  return id ? (fleet.hardware.find((h) => h.id === id) ?? null) : null;
}

/** Whether a release runs on a hardware family; a release that names no hardware runs on all of the platform's. */
export function runsOn(release: Release, hardware: Hardware): boolean {
  if (!hardware.platforms.includes(release.platform)) return false;
  return release.hardware.length === 0 || release.hardware.includes(hardware.id);
}

/**
 * A version constraint as a template writes it: "26", ">=14", "<=15", "24H2", ">=24H2". Versions
 * are compared by the order of the platform's releases in the file (newest first), so "22H2" and
 * "26" need no numeric parsing and Windows feature updates sort right.
 */
export interface VersionRule {
  op: ">=" | "<=" | "=";
  id: string;
}

export function parseVersionRule(text: string): VersionRule | null {
  const m = /^(>=|<=|=)?\s*([A-Za-z0-9.-]+)$/.exec(text.trim());
  if (!m) return null;
  return { op: (m[1] as VersionRule["op"] | undefined) ?? "=", id: m[2]! };
}

/** Whether the chosen release satisfies the rule, by the platform's release order; an unknown id in the rule matches nothing. */
export function versionMatches(fleet: Fleet, release: Release, rule: VersionRule): boolean {
  const order = releasesOf(fleet, release.platform).map((r) => r.id);
  const at = order.indexOf(release.id);
  const want = order.indexOf(rule.id);
  if (at < 0 || want < 0) return rule.op === "=" && release.id === rule.id;
  // Newest first: a smaller index is a newer release.
  if (rule.op === "=") return at === want;
  if (rule.op === ">=") return at <= want;
  return at >= want;
}

export interface Applies {
  /** Per platform, the version rules; the template or step applies when any rule matches. */
  versions: Partial<Record<FleetPlatform, VersionRule[]>>;
  /** Hardware ids; applies when the chosen hardware is one of them. */
  hardware: string[];
}

export const appliesToAll: Applies = { versions: {}, hardware: [] };

/** Reads an `applies:` block: { versions: { macos: [">=14"] }, hardware: [apple-silicon, intel-t2] }. */
export function parseApplies(raw: unknown): Applies {
  const a = obj(raw);
  const versions: Applies["versions"] = {};
  for (const [platform, rules] of Object.entries(obj(a.versions))) {
    if (!isFleetPlatform(platform)) continue;
    const list = (Array.isArray(rules) ? rules : [rules]).map((r) => parseVersionRule(String(r))).filter((r): r is VersionRule => r !== null);
    if (list.length) versions[platform] = list;
  }
  return { versions, hardware: strings(a.hardware) };
}

export interface Applicability {
  ok: boolean;
  /** Why not, in a phrase the page and the report show: "needs Apple silicon or an Intel Mac with the T2 chip". */
  reason: string | null;
}

/**
 * Whether something applies to the chosen release and hardware. With no release chosen a version
 * rule cannot be judged and is taken as applying; with no hardware chosen, likewise. A rule on
 * another platform is ignored.
 */
export function applicability(fleet: Fleet, applies: Applies, release: Release | null, hardware: Hardware | null): Applicability {
  if (release) {
    const rules = applies.versions[release.platform];
    if (rules && rules.length && !rules.some((r) => versionMatches(fleet, release, r))) {
      return { ok: false, reason: `applies to ${fleetPlatformName(release.platform)} ${rules.map((r) => `${r.op === "=" ? "" : r.op}${r.id}`).join(" or ")}, not ${release.label}` };
    }
  }
  if (hardware && applies.hardware.length && !applies.hardware.includes(hardware.id)) {
    const names = applies.hardware.map((id) => findHardware(fleet, id)?.label ?? id);
    return { ok: false, reason: `needs ${names.length > 1 ? `${names.slice(0, -1).join(", ")} or ${names[names.length - 1]}` : names[0]}, not ${hardware.label}` };
  }
  return { ok: true, reason: null };
}
