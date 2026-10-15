import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { nist171Adapter } from "../src/adapters/oscal-nist.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { diffRequirements, summarizeChanges } from "../src/differ.ts";
import type { HttpGet } from "../src/http.ts";
import { getSource, ingestDocumentTarget } from "../src/ingest.ts";
import { latestDocument, loadRequirements, releaseChanges } from "../src/register.ts";
import { listWire } from "../src/wire.ts";
import { fixture } from "./helpers.ts";

const at = new Date("2026-10-15T12:00:00Z");
const ctx = { db: null as unknown as DatabaseSync, source: null as never, http: (async () => { throw new Error("no network"); }) as HttpGet };

describe("NIST SP 800-171 Revision 3", () => {
  it("names requirements the way the publication does", async () => {
    const doc = await nist171Adapter.parseDocument!(fixture("oscal-171-catalog-1.1.0.json"), { key: "catalog", url: "x" }, ctx);
    expect(doc.title).toBe("NIST SP 800-171 Revision 3");
    expect(doc.versionLabel).toBe("OSCAL 1.1.0");
    expect(doc.publishedAt).toBe("2026-05-12T01:01:09.000Z");
    expect(doc.requirements).toHaveLength(22 + 12);
    const byRef = new Map(doc.requirements.map((r) => [r.ref, r]));
    const accounts = byRef.get("03.01.01")!;
    expect(accounts.label).toBe("03.01.01");
    expect(accounts.title).toBe("Account Management");
    expect(accounts.family).toBe("03.01 Access Control");
    expect(accounts.statement?.split("\n")[0]).toBe("a. Define the types of system accounts allowed and prohibited.");
    expect(accounts.statement).not.toContain("SR-03.01.01");
    expect(accounts.params.length).toBeGreaterThan(0);
    expect(accounts.extra.assessmentObjective).toBeTruthy();
    expect(byRef.get("03.01.13")?.status).toBe("withdrawn");
    expect(byRef.get("03.05.01")?.family).toBe("03.05 Identification and Authentication");
    expect(doc.rationale).toBeNull();
  });

  it("would read NIST's OSCAL 1.0.0 to 1.1.0 as statements appearing, which is why there is no backfill", async () => {
    const before = await nist171Adapter.parseDocument!(fixture("oscal-171-catalog-1.0.0.json"), { key: "catalog", url: "x" }, ctx);
    const after = await nist171Adapter.parseDocument!(fixture("oscal-171-catalog-1.1.0.json"), { key: "catalog", url: "x" }, ctx);
    expect(before.versionLabel).toBe("OSCAL 1.0.0");
    const changes = diffRequirements(before.requirements, after.requirements);
    const summary = summarizeChanges(changes);
    expect(summary.added).toEqual([]);
    expect(summary.removed).toEqual([]);
    const filled = changes.filter((c) => c.field === "statement" && c.before === null && c.after !== null).map((c) => c.ref);
    expect(filled).toContain("03.01.02");
    expect(filled.length).toBeGreaterThanOrEqual(8);
    expect(nist171Adapter.history).toBeUndefined();
  });

  describe("ingestion", () => {
    let db: DatabaseSync;
    let dataDir = "";
    beforeEach(() => {
      db = openDatabase(":memory:");
      migrate(db);
      dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-171-"));
    });
    afterEach(() => {
      db.close();
      rmSync(dataDir, { recursive: true, force: true });
    });

    it("loads the current catalog as the first version and posts it to the Wire", async () => {
      const http: HttpGet = async (url) => ({ url, status: 200, notModified: false, bytes: fixture("oscal-171-catalog-1.1.0.json"), etag: null, lastModified: null, contentType: "application/json" });
      const source = getSource(db, "nist-sp-800-171")!;
      expect(source.group_name).toBe("standards");
      const [target] = await nist171Adapter.documents!(source, { db, http, now: () => at });
      const outcome = await ingestDocumentTarget(db, dataDir, source, nist171Adapter, target!, { http, now: () => at });
      expect(outcome.status).toBe("ok");
      expect(outcome.summary).toBe("first version, 34 requirements");
      const doc = latestDocument(db, "nist-sp-800-171", "catalog")!;
      expect(doc.version_label).toBe("OSCAL 1.1.0");
      expect(releaseChanges(db, doc.id)).toHaveLength(0);
      expect(loadRequirements(db, doc.id).find((r) => r.ref === "03.01.01")?.label).toBe("03.01.01");
      const release = listWire(db, { kind: "release" }).find((i) => i.source_id === "nist-sp-800-171");
      expect(release?.title).toBe(`${source.name} OSCAL 1.1.0: loaded as the first version (34 requirements)`);
      expect(source.enabled).toBe(1);
      expect(source.url).toContain("SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json");
    });
  });
});
