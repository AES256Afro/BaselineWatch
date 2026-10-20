import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { applicability, endingSupport, findHardware, findRelease, fleetFile, hardwareOf, loadFleet, parseApplies, parseVersionRule, releasesOf, runsOn, supportDates, versionMatches } from "../src/fleet.ts";
import { loadTemplates, templatesDir } from "../src/testplans.ts";

describe("the fleet file", () => {
  const fleet = loadFleet(fleetFile);

  it("reads every platform's releases and hardware without errors", () => {
    expect(fleet.errors).toEqual([]);
    expect(fleet.hardware.length).toBeGreaterThanOrEqual(15);
    for (const p of ["windows", "macos", "linux", "ios", "ipados", "android", "collaboration"] as const) {
      expect(releasesOf(fleet, p).length, p).toBeGreaterThanOrEqual(1);
      expect(hardwareOf(fleet, p).length, p).toBeGreaterThanOrEqual(1);
    }
    const ids = fleet.releases.map((r) => `${r.platform}:${r.id}`);
    expect(new Set(ids).size).toBe(ids.length);
    for (const r of fleet.releases) {
      expect(r.sources.length, `${r.platform} ${r.id} has a vendor source`).toBeGreaterThanOrEqual(1);
      for (const h of r.hardware) expect(findHardware(fleet, h), `${r.platform} ${r.id} hardware ${h}`).not.toBeNull();
    }
  });

  it("knows what shipped this autumn and what each release runs on", () => {
    const goldenGate = findRelease(fleet, "macos", "27")!;
    expect(goldenGate.label).toBe("macOS 27 Golden Gate");
    expect(goldenGate.status).toBe("current");
    expect(goldenGate.released).toBe("2026-09-14");
    expect(goldenGate.hardware).toEqual(["apple-silicon"]);
    expect(runsOn(goldenGate, findHardware(fleet, "intel-t2")!)).toBe(false);
    expect(runsOn(goldenGate, findHardware(fleet, "apple-silicon")!)).toBe(true);
    const tahoe = findRelease(fleet, "macos", "26")!;
    expect(runsOn(tahoe, findHardware(fleet, "intel-t2")!)).toBe(true);
    expect(runsOn(tahoe, findHardware(fleet, "intel")!)).toBe(false);
    expect(tahoe.models).toMatch(/MacBook Pro 16-inch 2019/);
    const w = findRelease(fleet, "windows", "26H2")!;
    expect(w.released).toBe("2026-09-29");
    expect(w.supportEnds).toMatch(/2029-10-09/);
    expect(findRelease(fleet, "windows", "22H2")!.status).toBe("ended");
    expect(findRelease(fleet, "ios", "27")!.hardware).toEqual(["iphone-a13"]);
    expect(findRelease(fleet, "android", "17")!.released).toBe("2026-06-16");
    expect(findRelease(fleet, "linux", "rhel-10")!.notes.join(" ")).toMatch(/FIPS/);
    // Windows 11 runs on any TPM 2.0 PC; a release that names no hardware runs on every family of its platform.
    expect(runsOn(findRelease(fleet, "windows", "10-22H2")!, findHardware(fleet, "tpm-2")!)).toBe(true);
    expect(runsOn(findRelease(fleet, "windows", "10-22H2")!, findHardware(fleet, "apple-silicon")!)).toBe(false);
  });

  it("says which releases stop getting fixes within ninety days, nearest first", () => {
    const w25 = findRelease(fleet, "windows", "25H2")!;
    expect(supportDates(w25)).toEqual(["2027-10-12", "2028-10-10"]);
    expect(supportDates(findRelease(fleet, "macos", "27")!)).toEqual([]);
    const soon = endingSupport(fleet, new Date("2026-10-19T12:00:00Z"), 90);
    // Windows 11 23H2's Enterprise and Education servicing ends 2026-11-10; 24H2's Home and Pro ended 2026-10-13 and is not "ending".
    expect(soon.map((e) => `${e.release.id} ${e.date} ${e.days}`)).toEqual(["23H2 2026-11-10 22"]);
    expect(soon[0]!.clause).toBe("Enterprise and Education 2026-11-10");
    expect(endingSupport(fleet, new Date("2026-11-10T23:00:00Z"), 90)[0]!.days).toBe(0);
    expect(endingSupport(fleet, new Date("2026-11-11T00:00:00Z"), 90).some((e) => e.release.id === "23H2")).toBe(false);
    // A wider window reaches the next ones; a narrow one reaches none.
    expect(endingSupport(fleet, new Date("2026-10-19T12:00:00Z"), 400).length).toBeGreaterThan(1);
    expect(endingSupport(fleet, new Date("2026-10-19T12:00:00Z"), 7)).toEqual([]);
  });

  it("judges version rules by the platform's release order, newest first", () => {
    expect(parseVersionRule(">=24H2")).toEqual({ op: ">=", id: "24H2" });
    expect(parseVersionRule("26")).toEqual({ op: "=", id: "26" });
    expect(parseVersionRule("<= rhel-9")).toEqual({ op: "<=", id: "rhel-9" });
    expect(parseVersionRule("")).toBeNull();
    const w25 = findRelease(fleet, "windows", "25H2")!;
    expect(versionMatches(fleet, w25, { op: ">=", id: "24H2" })).toBe(true);
    expect(versionMatches(fleet, w25, { op: ">=", id: "26H2" })).toBe(false);
    expect(versionMatches(fleet, w25, { op: "<=", id: "25H2" })).toBe(true);
    expect(versionMatches(fleet, w25, { op: "=", id: "25H2" })).toBe(true);
    expect(versionMatches(fleet, w25, { op: ">=", id: "nope" })).toBe(false);
    const ventura = findRelease(fleet, "macos", "13")!;
    expect(versionMatches(fleet, ventura, { op: ">=", id: "14" })).toBe(false);
    expect(versionMatches(fleet, findRelease(fleet, "macos", "27")!, { op: ">=", id: "14" })).toBe(true);
  });

  it("says whether a template applies, and why not, in words", () => {
    const applies = parseApplies({ versions: { macos: [">=14"], windows: ["25H2", ">=26H2"] }, hardware: ["apple-silicon", "intel-t2"] });
    expect(applies.versions.macos).toEqual([{ op: ">=", id: "14" }]);
    expect(applies.versions.windows).toHaveLength(2);
    expect(applies.hardware).toEqual(["apple-silicon", "intel-t2"]);
    const ventura = findRelease(fleet, "macos", "13")!;
    const golden = findRelease(fleet, "macos", "27")!;
    expect(applicability(fleet, applies, ventura, null)).toEqual({ ok: false, reason: "applies to macOS >=14, not macOS 13 Ventura" });
    expect(applicability(fleet, applies, golden, findHardware(fleet, "intel"))).toEqual({ ok: false, reason: "needs Apple silicon Mac (M1 and later) or Intel Mac with the Apple T2 Security Chip (2018 to 2020), not Intel Mac without a T2 chip (2017 and earlier)" });
    expect(applicability(fleet, applies, golden, findHardware(fleet, "apple-silicon"))).toEqual({ ok: true, reason: null });
    // Nothing chosen: a rule cannot be judged and is taken as applying; a rule on another platform is ignored.
    expect(applicability(fleet, applies, null, null).ok).toBe(true);
    expect(applicability(fleet, applies, findRelease(fleet, "linux", "rhel-9"), null).ok).toBe(true);
    expect(applicability(fleet, parseApplies(undefined), ventura, findHardware(fleet, "intel")).ok).toBe(true);
  });

  it("reports a broken file rather than failing", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "bw-fleet-"));
    const bad = path.join(dir, "platforms.yaml");
    writeFileSync(bad, "hardware:\n  - id: x\n    label: X\n    platforms: [macos]\nplatforms:\n  amiga:\n    releases: []\n  macos:\n    releases:\n      - id: '99'\n        label: macOS 99\n        hardware: [y]\n");
    const f = loadFleet(bad);
    expect(f.errors).toEqual(["unknown platform amiga", "macos 99: unknown hardware y"]);
    expect(f.releases).toHaveLength(1);
    expect(f.releases[0]!.status).toBe("supported");
    expect(loadFleet(path.join(dir, "missing.yaml")).errors[0]).toMatch(/missing\.yaml/);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("the templates against the fleet", () => {
  it("name only hardware and releases the fleet knows, and every step cites a document", () => {
    const fleet = loadFleet(fleetFile);
    const { templates, errors } = loadTemplates(templatesDir);
    expect(errors).toEqual([]);
    for (const t of templates) {
      const rules = [t.applies, ...t.steps.map((s) => s.applies)];
      for (const a of rules) {
        for (const h of a.hardware) expect(findHardware(fleet, h), `${t.id}: hardware ${h}`).not.toBeNull();
        for (const [platform, list] of Object.entries(a.versions)) {
          for (const r of list ?? []) expect(findRelease(fleet, platform as "macos", r.id), `${t.id}: ${platform} ${r.id}`).not.toBeNull();
        }
      }
      for (const s of t.steps) expect(s.source?.url, `${t.id}: ${s.do.slice(0, 40)}`).toMatch(/^https:\/\//);
    }
    const mac = templates.find((t) => t.id === "hardware-root-macos")!;
    expect(mac.applies.hardware).toEqual(["apple-silicon", "intel-t2"]);
    expect(mac.steps[1]!.applies.hardware).toEqual(["apple-silicon"]);
    expect(mac.steps[1]!.fail).toMatch(/Startup Security Utility/);
    const win = templates.find((t) => t.id === "windows-feature-update")!;
    expect(win.steps[4]!.applies.versions.windows).toEqual([{ op: ">=", id: "25H2" }]);
  });
});
