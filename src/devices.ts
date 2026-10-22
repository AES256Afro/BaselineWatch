import type { DatabaseSync } from "node:sqlite";
import type { DeviceFinding, InventoryReport } from "./inventory.ts";
import { parseJson } from "./json.ts";

/**
 * The owner's devices over time (Scan 2.0, S7): each reading of a device kept as its verdicts
 * and CVE ids — never the report — so the device page can say what changed since the last
 * reading and Today can count the devices with something open. The owner names the device when
 * pasting; a name seen before continues that device's history.
 */

export interface DeviceReading {
  id: number;
  device: string;
  os: string;
  os_label: string | null;
  read_at: string;
  worst: "ok" | "warn" | "bad" | "na";
  findings: StoredFinding[];
}

export interface StoredFinding {
  id: string;
  title: string;
  state: DeviceFinding["state"];
  text: string;
  refs: { id: string; href: string }[];
}

const rank: Record<DeviceFinding["state"], number> = { bad: 3, warn: 2, na: 1, ok: 0 };

/** The reading's verdict: the worst row that was read; "na" only when nothing could be read at all. */
export function worstOf(findings: { state: DeviceFinding["state"] }[]): DeviceReading["worst"] {
  const read = findings.filter((f) => f.state !== "na");
  if (read.length === 0) return "na";
  return read.reduce<DeviceReading["worst"]>((w, f) => (rank[f.state] > rank[w] ? f.state : w), "ok");
}

/** The device as the reading describes it: "Windows 11 Pro 24H2, build 10.0.26100.9445". */
export function osLabel(report: InventoryReport): string {
  const { os } = report;
  const parts = [os.name ?? os.family, os.display ?? os.version ?? os.versionId].filter((p): p is string => typeof p === "string" && p !== "");
  return `${parts.join(" ")}${os.build ? `, build ${os.build}` : ""}`;
}

/** A device name as typed: letters, digits, spaces and a little punctuation, sixty characters. */
export function deviceName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const name = value.trim().replace(/\s+/g, " ").slice(0, 60);
  return /^[\p{L}\p{N} ._'-]+$/u.test(name) ? name : null;
}

export function recordReading(db: DatabaseSync, device: string, report: InventoryReport, findings: DeviceFinding[], at: string): DeviceReading {
  const stored: StoredFinding[] = findings.map((f) => ({ id: f.id, title: f.title, state: f.state, text: f.text, refs: f.refs.slice(0, 100).map((r) => ({ id: r.id, href: r.href })) }));
  const worst = worstOf(findings);
  const result = db.prepare("INSERT INTO device_readings (device, os, os_label, read_at, worst, findings_json) VALUES (?, ?, ?, ?, ?, ?)").run(device, report.os.family, osLabel(report), at, worst, JSON.stringify(stored));
  return { id: Number(result.lastInsertRowid), device, os: report.os.family, os_label: osLabel(report), read_at: at, worst, findings: stored };
}

function rowOf(r: Record<string, unknown>): DeviceReading {
  return { id: r.id as number, device: r.device as string, os: r.os as string, os_label: (r.os_label as string | null) ?? null, read_at: r.read_at as string, worst: r.worst as DeviceReading["worst"], findings: parseJson<StoredFinding[]>(r.findings_json as string, []) };
}

/** The newest reading of each device, newest first. */
export function latestReadings(db: DatabaseSync): DeviceReading[] {
  return (db.prepare("SELECT * FROM device_readings WHERE id IN (SELECT MAX(id) FROM device_readings GROUP BY device) ORDER BY read_at DESC").all() as Record<string, unknown>[]).map(rowOf);
}

/** One device's readings, newest first. */
export function readingsOf(db: DatabaseSync, device: string, limit = 20): DeviceReading[] {
  return (db.prepare("SELECT * FROM device_readings WHERE device = ? ORDER BY id DESC LIMIT ?").all(device, limit) as Record<string, unknown>[]).map(rowOf);
}

/** What moved between a device's last reading and this one: refs that appeared, refs that went. */
export function readingChanges(previous: DeviceReading | null, current: { findings: StoredFinding[] }): { appeared: string[]; cleared: string[] } {
  if (!previous) return { appeared: [], cleared: [] };
  const before = new Set(previous.findings.flatMap((f) => f.refs.map((r) => r.id)));
  const after = new Set(current.findings.flatMap((f) => f.refs.map((r) => r.id)));
  return { appeared: [...after].filter((id) => !before.has(id)), cleared: [...before].filter((id) => !after.has(id)) };
}

export function deleteDevice(db: DatabaseSync, device: string): number {
  return Number(db.prepare("DELETE FROM device_readings WHERE device = ?").run(device).changes);
}

/** Today's figure: devices read, and how many have something open. */
export function devicesTile(db: DatabaseSync): { read: number; exposed: number; behind: number } {
  const latest = latestReadings(db);
  return { read: latest.length, exposed: latest.filter((r) => r.worst === "bad").length, behind: latest.filter((r) => r.worst === "warn").length };
}
