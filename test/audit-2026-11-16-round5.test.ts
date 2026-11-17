import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { nistCatalogAdapter } from "../src/adapters/oscal-nist.ts";
import { digestTextFor, type DigestRow } from "../src/digest.ts";
import { wireFeed, vulnFeed } from "../src/feeds.ts";
import { untaggedReferences, userContentHost } from "../src/fix.ts";
import { endingSupport, type Fleet, type Release } from "../src/fleet.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestDocumentTarget } from "../src/ingest.ts";
import { vulnFilters } from "../src/routes/query.ts";
import { cookieFrom, formPost, nistFixtureHttp, nistOneDiff, startTestApp } from "./helpers.ts";

/**
 * The fifth round of the 16 November audit: the MCP release tool's unknown id, the triage form's
 * due date and control, the feeds' titles, the vendor reference on a user-content host, the fleet's
 * notes for a visitor, and the digest's restore line on every route a visitor reads it by.
 */

const at = "2026-11-16T12:00:00.000Z";
const now = new Date(at);

function freshDb() {
  const db = openDatabase(":memory:");
  migrate(db);
  return db;
}

describe("B8-1: the release tool refuses an id it does not hold", () => {
  it("fails for an unknown or another source's id and falls back only when none is given", async () => {
    const app = await startTestApp({ now: () => now });
    const client = new Client({ name: "test", version: "0" });
    const dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-r5-"));
    try {
      const catalog = getSource(app.db, "nist-sp-800-53")!;
      for (const target of nistCatalogAdapter.history!(catalog).filter(nistOneDiff)) {
        await ingestDocumentTarget(app.db, dataDir, catalog, nistCatalogAdapter, target, { http: nistFixtureHttp(), now: () => now });
      }
      await client.connect(new StreamableHTTPClientTransport(new URL(`${app.base}/mcp`)) as unknown as Parameters<Client["connect"]>[0]);
      const latest = await client.callTool({ name: "release", arguments: { source: "nist-sp-800-53" } });
      expect(latest.isError).toBeFalsy();
      for (const id of [99999, -1]) {
        const result = await client.callTool({ name: "release", arguments: { source: "nist-sp-800-53", document_id: id } });
        expect(result.isError).toBe(true);
        expect((result.content as { text: string }[])[0]!.text).toContain(`No loaded version for nist-sp-800-53 with id ${id}.`);
      }
      const docId = (app.db.prepare("SELECT id FROM documents WHERE source_id = 'nist-sp-800-53' LIMIT 1").get() as { id: number }).id;
      expect((await client.callTool({ name: "release", arguments: { source: "disa-stigs", document_id: docId } })).isError).toBe(true);
      expect((await client.callTool({ name: "vulnerability", arguments: { id: "C" } })).isError).toBe(true);
    } finally {
      await client.close();
      rmSync(dataDir, { recursive: true, force: true });
      await app.close();
    }
  });
});

describe("B8-2: the triage form takes a real day and a control the release holds", () => {
  it("refuses 2026-02-31 and a control ref that is not there", async () => {
    const app = await startTestApp({ now: () => now, env: { BW_ADMIN_PASSWORD: "hunter2hunter2" } });
    try {
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
      const vuln = Number(
        app.db
          .prepare("INSERT INTO vulns (cve_id, last_modified_at, vuln_status, description, cwes_json, cpes_json, vendors_json, products_json, kev, watch_hit, first_seen_at, last_seen_at) VALUES ('CVE-2026-0001', ?, 'Analyzed', 'x', '[]', '[]', '[]', '[]', 0, 0, ?, ?)")
          .run(at, at, at).lastInsertRowid,
      );
      expect((await formPost(app.base, "/triage", { kind: "vuln", id: String(vuln), state: "reviewing", due: "2026-02-31" }, cookie)).status).toBe(400);
      expect((await formPost(app.base, "/triage", { kind: "vuln", id: String(vuln), state: "reviewing", due: "2026-02-28" }, cookie)).status).toBe(303);
      expect((await formPost(app.base, "/triage", { kind: "control", id: "424242", key: "ac-2", state: "reviewing" }, cookie)).status).toBe(400);
      expect(app.db.prepare("SELECT COUNT(*) AS n FROM triage WHERE subject_kind = 'control'").get()).toEqual({ n: 0 });
    } finally {
      await app.close();
    }
  });
});

describe("B8-3: a feed's title names the filters the list applied", () => {
  it("names platform, most dangerous and AI, leaves out a q that searched nothing, and clamps CVSS", () => {
    const db = freshDb();
    const wire = wireFeed(db, "https://example.test", { platform: "windows", danger: true, topic: "ai", q: '""' }, "https://example.test/feed.xml");
    const title = /<title>([^<]*)<\/title>/.exec(wire)![1]!;
    expect(title).toContain("Windows");
    expect(title).toContain("most dangerous");
    expect(title).toContain("AI");
    expect(title).not.toContain("“");
    expect(wireFeed(db, "https://example.test", { hideAi: true }, "x")).toContain("AI hidden");
    expect(vulnFilters({ min_cvss: "99" }, now).minCvss).toBe(10);
    expect(vulnFilters({ min_cvss: "-3" }, now).minCvss).toBe(0);
    expect(vulnFeed(db, "https://example.test", { ...vulnFilters({ min_cvss: "99", q: "\u0001" }, now) }, "x")).toMatch(/<title>[^<]*CVSS 10\+<\/title>/);
  });
});

describe("B8-4: a user-content host is nobody's vendor reference", () => {
  it("matches the vendor's registrable name exactly and skips user-content hosts", () => {
    expect(userContentHost("raw.githubusercontent.com")).toBe(true);
    expect(userContentHost("lh3.googleusercontent.com")).toBe(true);
    expect(userContentHost("someone.github.io")).toBe(true);
    expect(userContentHost("sites.google.com")).toBe(true);
    expect(userContentHost("github.com")).toBe(false);
    const refs = [
      { url: "https://attacker.github.io/advisory", tags: [] },
      { url: "https://sites.google.com/view/x", tags: [] },
      { url: "https://lh3.googleusercontent.com/x", tags: [] },
      { url: "https://googleish.com/x", tags: [] },
    ];
    expect(untaggedReferences(refs, ["github", "google"], null).lead?.whose).toBeNull();
    expect(untaggedReferences([...refs, { url: "https://support.google.com/x", tags: [] }], ["google"], null).lead).toMatchObject({ host: "support.google.com", whose: "vendor" });
  });
});

describe("B8-5 and B8-6: the fleet's file errors and verify notes are the owner's", () => {
  it("drops the verify note from the support-ending clause for a visitor", () => {
    const release = { platform: "windows", id: "x", label: "Windows X", status: "supported", supportEnds: "Enterprise 2026-12-01, verify)", models: null, baselines: [], notes: [] } as unknown as Release;
    const fleet = { releases: [release], hardware: [], errors: [] } as unknown as Fleet;
    expect(endingSupport(fleet, now, 90, true)[0]!.clause).toContain("verify");
    expect(endingSupport(fleet, now, 90, false)[0]!.clause).toBe("Enterprise 2026-12-01");
  });
});

describe("S8-1: a visitor's digest has no restore line on any route", () => {
  it("filters it in digestTextFor and so in /api/v1/digest", async () => {
    const row = { id: 1, period: "daily", covers_from: at, covers_to: at, generated_at: at, text: "Hello\nRestore: last rehearsed never", public_text: "Hello\nRestore: last rehearsed never" } as DigestRow;
    expect(digestTextFor(row, false)).toBe("Hello");
    expect(digestTextFor(row, true)).toContain("Restore:");
    const app = await startTestApp({ now: () => now, env: { BW_ADMIN_PASSWORD: "hunter2hunter2" } });
    try {
      app.db.prepare("INSERT INTO digests (period, covers_from, covers_to, generated_at, text, public_text) VALUES ('daily', ?, ?, ?, ?, ?)").run(at, at, at, row.text, row.public_text);
      const body = await (await fetch(`${app.base}/api/v1/digest`)).text();
      expect(body).toContain("Hello");
      expect(body).not.toContain("Restore:");
    } finally {
      await app.close();
    }
  });
});
