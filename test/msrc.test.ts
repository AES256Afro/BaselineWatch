import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { msrcApi, parseMsrcIndex, parseMsrcRelease, releaseItem, type MsrcRelease } from "../src/adapters/msrc.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { msrcFlags, msrcFor } from "../src/msrc.ts";
import { fakeHttp, fixture, startTestApp } from "./helpers.ts";

/**
 * Microsoft's Security Update Guide (N5): the index and the October 2026 document as served on
 * 2026-10-21, the document cut to twenty entries that keep every shape the parser reads.
 */

const text = (name: string) => new TextDecoder().decode(fixture(`msrc/${name}`));
const now = new Date("2026-10-21T22:00:00Z");
const october: MsrcRelease = { id: "2026-Oct", title: "October 2026 Security Updates", initialReleaseDate: "2026-10-13T07:00:00.000Z", currentReleaseDate: "2026-10-21T18:43:11.000Z", cvrfUrl: `${msrcApi}/cvrf/2026-Oct` };

describe("the updates index", () => {
  it("keeps the monthly security releases of the last forty days, oldest first, and not the Azure Linux notes", () => {
    const releases = parseMsrcIndex(text("updates.json"), now);
    expect(releases.map((r) => r.id)).toEqual(["2026-Oct"]);
    expect(releases[0]).toEqual(october);
    // Wider: September too, and still none of the "Mariner Release Notes" entries.
    expect(parseMsrcIndex(text("updates.json"), now, 60).map((r) => r.id)).toEqual(["2026-Sep", "2026-Oct"]);
  });

  it("refuses an index that is not the list expected", () => {
    expect(() => parseMsrcIndex('{"nope": 1}', now)).toThrow(/not the JSON list/);
  });
});

describe("a monthly document", () => {
  const { vulns } = parseMsrcRelease(text("2026-Oct.json"), october);
  const byId = new Map(vulns.map((v) => [v.cveId, v]));

  it("yields one row per CVE, leaving the ADV advisories", () => {
    expect(vulns.length).toBe(19);
    expect(vulns.every((v) => /^CVE-/.test(v.cveId))).toBe(true);
  });

  it("reads the title, tags, severity, CVSS and the KB per product, folding the architectures", () => {
    const v = byId.get("CVE-2026-100200")!;
    expect(v.title).toBe("Windows Update Service Elevation of Privilege Vulnerability");
    expect(v.family).toBe("Windows Update Service");
    expect(v.vendor).toBe("Microsoft");
    expect(v.severity).toBe("Important");
    expect(v.cvssScore).toBe(7);
    expect(v.cvssVector).toMatch(/^CVSS:3\.1\//);
    expect(v.description).toBe("Use after free in Windows Update Service allows an authorized attacker to elevate privileges locally.");
    expect(v.exploited).toBe(false);
    expect(v.exploitability).toBe("Exploitation Less Likely");
    const kb = v.fixes.find((f) => f.kb === "5127648")!;
    expect(kb.url).toBe("https://support.microsoft.com/help/5127648");
    expect(kb.products).toContain("Windows 11 Version 24H2");
    expect(kb.products.some((p) => /x64-based/.test(p))).toBe(false);
    expect(kb.fixedBuild).toBe("10.0.26100.9711");
    expect(kb.restart).toBe(true);
  });

  it("reads Microsoft's exploit status words", () => {
    expect(byId.get("CVE-2026-96951")?.exploited).toBe(true);
    expect(byId.get("CVE-2026-96951")?.exploitability).toBe("Exploitation Detected");
    expect(byId.get("CVE-2026-108398")?.disclosed).toBe(true);
    expect(byId.get("CVE-2026-92707")?.disclosed).toBe(true);
  });

  it("tells a republished Chromium or Azure Linux CVE from Microsoft's own", () => {
    const chromium = vulns.filter((v) => v.family === "Microsoft Edge (Chromium-based)" && v.vendor !== "Microsoft");
    const azure = vulns.filter((v) => v.family === "Mariner");
    expect(chromium.length).toBe(2);
    expect(azure.length).toBe(2);
    const item = releaseItem(october, vulns);
    expect(item.externalId).toBe("2026-Oct");
    expect(item.url).toBe("https://msrc.microsoft.com/update-guide/releaseNote/2026-Oct");
    expect(item.title).toBe("Microsoft October 2026 Security Updates: 15 CVEs, 1 exploited, 5 critical");
    expect(item.summary).toContain("1 under active exploitation: CVE-2026-96951");
    expect(item.summary).toContain("2 publicly disclosed");
    expect(item.summary).toContain("2 Chromium CVEs republished for Edge and 2 for Azure Linux");
    expect(item.summary).toContain("Revised 2026-10-21");
    expect((item.signals as { cves: string[] }).cves).toContain("CVE-2026-96951");
  });

  it("refuses a document with no CVE in it rather than storing an empty month", () => {
    expect(() => parseMsrcRelease('{"Vulnerability": []}', october)).toThrow(/no CVE/);
    expect(() => parseMsrcRelease("<html>", october)).toThrow(/not the CVRF document/);
  });
});

describe("the pull", () => {
  let db: DatabaseSync;
  let dataDir: string;
  const routes = {
    [`${msrcApi}/updates`]: { bytes: fixture("msrc/updates.json") },
    [`${msrcApi}/cvrf/2026-Oct`]: { bytes: fixture("msrc/2026-Oct.json") },
  };

  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-msrc-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("reads a changed month once, stores its CVEs and one Wire item, and skips it next time", async () => {
    const http = fakeHttp(routes);
    const source = getSource(db, "msrc")!;
    expect(source.enabled).toBe(1);
    const first = await ingestSource(db, dataDir, source, { http, now: () => now });
    expect(first.status).toBe("ok");
    expect(first.inserted).toBe(19);
    expect(first.detail).toBe("1 of 1 monthly release(s) read (2026-Oct)");
    expect(http.calls.map((c) => c.url)).toEqual([`${msrcApi}/updates`, `${msrcApi}/cvrf/2026-Oct`]);

    const again = await ingestSource(db, dataDir, source, { http, now: () => now });
    expect(again.detail).toBe("2026-Oct unchanged since the last read");
    // The index was read again; the 25 MB document was not.
    expect(http.calls.filter((c) => c.url.endsWith("/cvrf/2026-Oct")).length).toBe(1);

    const row = msrcFor(db, "cve-2026-100200")!;
    expect(row.release_id).toBe("2026-Oct");
    expect(row.fixes.map((f) => f.kb)).toContain("5127648");
    expect(msrcFlags(db, ["CVE-2026-96951", "CVE-2026-100200"]).get("CVE-2026-96951")).toEqual({ exploited: true, disclosed: false });
    expect(msrcFlags(db, ["CVE-2026-96951", "CVE-2026-100200"]).has("CVE-2026-100200")).toBe(false);
    const item = db.prepare("SELECT title, kind FROM items WHERE source_id = 'msrc'").all() as { title: string; kind: string }[];
    expect(item).toEqual([{ title: "Microsoft October 2026 Security Updates: 15 CVEs, 1 exploited, 5 critical", kind: "article" }]);
    // No snapshot of the stream.
    expect((db.prepare("SELECT COUNT(*) AS n FROM snapshots WHERE source_id = 'msrc'").get() as { n: number }).n).toBe(0);
  });

  it("reads the document again when Microsoft revises it", async () => {
    const http = fakeHttp(routes);
    const source = getSource(db, "msrc")!;
    await ingestSource(db, dataDir, source, { http, now: () => now });
    db.prepare("UPDATE app_settings SET value = '2026-10-14T00:00:00.000Z' WHERE key = 'msrc.2026-Oct.revised'").run();
    const again = await ingestSource(db, dataDir, source, { http, now: () => now });
    expect(again.detail).toBe("1 of 1 monthly release(s) read (2026-Oct)");
    expect(again.inserted).toBe(0);
    expect(again.updated).toBe(19);
  });
});

describe("on the pages", () => {
  it("puts the KB per product under Fix and marks what Microsoft says is exploited", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      const db = app.db;
      const insert = db.prepare("INSERT INTO vulns (cve_id, last_modified_at, cvss_score, cvss_severity, description, first_seen_at, last_seen_at) VALUES (?, ?, 7.0, 'HIGH', ?, ?, ?)");
      insert.run("CVE-2026-100200", now.toISOString(), "Windows Update Service EoP", now.toISOString(), now.toISOString());
      insert.run("CVE-2026-96951", now.toISOString(), "exploited one", now.toISOString(), now.toISOString());
      await ingestSource(db, app.dataDir, getSource(db, "msrc")!, { http: fakeHttp({ [`${msrcApi}/updates`]: { bytes: fixture("msrc/updates.json") }, [`${msrcApi}/cvrf/2026-Oct`]: { bytes: fixture("msrc/2026-Oct.json") } }), now: () => now });
      const page = await (await fetch(`${app.base}/vulnerabilities/CVE-2026-100200`)).text();
      expect(page).toContain("Microsoft's update · Important");
      expect(page).toContain('href="https://support.microsoft.com/help/5127648"');
      expect(page).toContain("KB5127648</a> — Windows 11 Version 24H2");
      expect(page).toContain("build 10.0.26100.9711");
      expect(page).toContain("restart required");
      expect(page).toContain('href="https://msrc.microsoft.com/update-guide/releaseNote/2026-Oct"');
      expect(page).not.toContain("Nothing published yet");

      const exploited = await (await fetch(`${app.base}/vulnerabilities/CVE-2026-96951`)).text();
      expect(exploited).toContain('<span class="chip kev">Microsoft: exploited</span>');
      const list = await (await fetch(`${app.base}/vulnerabilities`)).text();
      expect(list).toContain('title="Microsoft reports this CVE exploited">exploited</span>');
      // The release is on the Wire under vendor advisories, once.
      const wire = await (await fetch(`${app.base}/?group=vulnerabilities`)).text();
      expect(wire).toContain("Microsoft October 2026 Security Updates");
    } finally {
      await app.close();
    }
  });
});
