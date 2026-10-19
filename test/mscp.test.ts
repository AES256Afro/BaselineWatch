import { zipSync } from "fflate";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { branchCommitUrl, branchZipUrl, controlRefOf, followedBranches, mscpAdapter, parseMscpZip, parseVersion } from "../src/adapters/mscp.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { listDocuments, loadRequirements } from "../src/register.ts";
import { unzipAll } from "../src/zip.ts";
import { fakeHttp, fixturesDir } from "./helpers.ts";

/** The fixture folder as the zip GitHub serves: one top-level folder named after the ref. */
export function mscpZip(top = "macos_security-tahoe"): Uint8Array {
  const root = path.join(fixturesDir, "mscp");
  const files: Record<string, Uint8Array> = {};
  const walk = (dir: string, rel: string) => {
    for (const name of readdirSync(dir)) {
      const full = path.join(dir, name);
      const key = rel ? `${rel}/${name}` : name;
      if (statSync(full).isDirectory()) walk(full, key);
      else files[`${top}/${key}`] = new Uint8Array(readFileSync(full));
    }
  };
  walk(root, "");
  return new Uint8Array(zipSync(files));
}

describe("mSCP rules", () => {
  it("reads the version, every rule with its references and payload, and baseline membership", () => {
    const parsed = parseMscpZip(unzipAll(mscpZip()));
    expect(parsed.version).toEqual({ os: "26.0", platform: "macOS", version: "Tahoe Guidance, Revision 3.0", cpe: "o:apple:macos:26.0", date: "2026-06-22" });
    expect(parsed.title).toBe("macOS 26.0: Tahoe Guidance, Revision 3.0");
    expect(parsed.publishedAt).toBe("2026-06-22T00:00:00.000Z");
    expect(parsed.requirements).toHaveLength(7);
    const fv = parsed.requirements.find((r) => r.ref === "system_settings_filevault_enforce")!;
    expect(fv.family).toBe("System Settings");
    expect(fv.title).toBe("Enforce FileVault");
    expect(fv.statement).toContain("fdesetup status");
    expect(fv.guidance).toMatch(/^FileVault _MUST_ be enforced/);
    expect(fv.related).toEqual(["sc-28", "sc-28.1"]);
    expect(fv.extra).toMatchObject({
      severity: "high",
      mobileconfig: true,
      mobileconfigInfo: { "com.apple.MCX": { dontAllowFDEDisable: true } },
      stig: ["APPL-26-005020"],
      cci: ["CCI-001199", "CCI-002475", "CCI-002476"],
      nist171: ["03.13.08"],
      cisBenchmark: ["2.6.6 (level 1)"],
      section: "system_settings",
    });
    expect(fv.extra.baselines).toEqual(expect.arrayContaining(["800-53r5_high", "DISA-STIG", "all_rules"]));
    const sc = parsed.requirements.find((r) => r.ref === "auth_smartcard_enforce")!;
    expect(sc.related).toEqual(["ia-2", "ia-2.1", "ia-2.2", "ia-2.6", "ia-2.8", "ia-2.12", "ia-5.2"]);
    const timeout = parsed.requirements.find((r) => r.ref === "system_settings_screensaver_timeout_enforce")!;
    expect(timeout.extra.odv).toMatchObject({ recommended: 1200, stig: 900 });
    expect(parsed.baselines.get("DISA-STIG")).toContain("auth_smartcard_enforce");
    expect(parsed.baselines.get("800-53r5_high")!.length).toBeGreaterThan(50);
    expect(controlRefOf("AC-2(1)")).toBe("ac-2.1");
    expect(controlRefOf("N/A")).toBeNull();
    expect(parseVersion("os: '15.0'\nversion: Sequoia")).toMatchObject({ os: "15.0", version: "Sequoia" });
    expect(() => parseMscpZip(unzipAll(new Uint8Array(zipSync({ "x/README.md": new Uint8Array([1]) }))))).toThrow(/VERSION\.yaml/);
  });
});

describe("mSCP adapter end to end", () => {
  let db: ReturnType<typeof openDatabase>;
  let dataDir = "";
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-mscp-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("follows the branches through the commits API, loads the exact commit's zip, and skips an unchanged branch", async () => {
    const source = getSource(db, "nist-mscp")!;
    expect(followedBranches({ db })).toEqual(["tahoe", "sequoia", "ios_26"]);
    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('baseline', 'mscp: tahoe', NULL, ?)").run(new Date().toISOString());
    expect(followedBranches({ db })).toEqual(["tahoe"]);
    const sha = "cf656e844a4091868b2eeb8e6405f8f83952d08f";
    const http = fakeHttp({
      [branchCommitUrl("tahoe")]: { text: JSON.stringify({ sha, html_url: `https://github.com/usnistgov/macos_security/commit/${sha}`, commit: { message: "Merge pull request #1234 from usnistgov/tahoe_rule_fixes\n\nTahoe rule fixes", committer: { date: "2026-06-25T13:21:01Z" } } }) },
      [branchZipUrl(sha)]: { bytes: mscpZip(`macos_security-${sha}`) },
    });
    const at = new Date("2026-10-17T10:00:00Z");
    const first = await ingestSource(db, dataDir, source, { http, now: () => at });
    expect(first.status).toBe("ok");
    expect(first.detail).toContain("mscp:tahoe Tahoe Guidance, Revision 3.0 (cf656e8): first version, 7 requirements");
    const docs = listDocuments(db, "nist-mscp");
    expect(docs).toHaveLength(1);
    expect(docs[0]).toMatchObject({ document_key: "mscp:tahoe", version_label: "Tahoe Guidance, Revision 3.0 (cf656e8)", published_at: "2026-06-25T13:21:01.000Z", requirement_count: 7 });
    expect((db.prepare("SELECT text FROM explanations WHERE to_document_id = ?").get(docs[0]!.id) as { text: string }).text).toBe("Latest commit on tahoe: Merge pull request #1234 from usnistgov/tahoe_rule_fixes");
    expect(loadRequirements(db, docs[0]!.id).find((r) => r.ref === "os_sip_enable")?.extra.fix).toContain("csrutil enable");

    const calls = http.calls.length;
    const second = await ingestSource(db, dataDir, source, { http, now: () => new Date("2026-10-18T10:00:00Z") });
    expect(second.status).toBe("unchanged");
    expect(http.calls.length).toBe(calls + 1); // the commits API only
  });

  it("falls back to the branch zip when the commits API is unavailable", async () => {
    const source = getSource(db, "nist-mscp")!;
    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('baseline', 'mscp: tahoe', NULL, ?)").run(new Date().toISOString());
    const http = fakeHttp({ [branchCommitUrl("tahoe")]: { status: 403 }, [branchZipUrl("tahoe")]: { bytes: mscpZip() } });
    const result = await ingestSource(db, dataDir, source, { http, now: () => new Date("2026-10-17T10:00:00Z") });
    expect(result.status).toBe("ok");
    expect(listDocuments(db, "nist-mscp")[0]).toMatchObject({ version_label: "Tahoe Guidance, Revision 3.0", published_at: "2026-06-22T00:00:00.000Z" });
    expect(mscpAdapter.id).toBe("nist-mscp");
  });
});
