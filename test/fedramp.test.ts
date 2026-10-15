import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fedrampRulesAdapter, normalizeRules } from "../src/adapters/fedramp-rules.ts";
import { migrate, openDatabase } from "../src/db.ts";
import type { HttpGet } from "../src/http.ts";
import { getSource, ingestDocumentTarget } from "../src/ingest.ts";
import { explanationsFor, latestDocument, listDocuments, notesFor, releaseChanges } from "../src/register.ts";
import { listWire } from "../src/wire.ts";
import { fixture } from "./helpers.ts";

const at = new Date("2026-10-15T12:00:00Z");
const load = (name: string): unknown => JSON.parse(new TextDecoder().decode(fixture(name)));

/** Serves the October 8 commit and, for anything else (main included), the October 13 file. */
function fedrampHttp(): HttpGet {
  return async (url) => ({
    url,
    status: 200,
    notModified: false,
    bytes: fixture(url.includes("6eb376782a") ? "fedramp/rules-2026.10.08.json" : "fedramp/rules-2026.10.13.json"),
    etag: null,
    lastModified: null,
    contentType: "application/json",
  });
}

describe("FedRAMP Consolidated Rules", () => {
  it("normalises rules, indicators, definitions and control parameters into requirements", () => {
    const doc = normalizeRules(load("fedramp/rules-2026.10.13.json"));
    expect(doc.title).toBe("FedRAMP Consolidated Rules for 2026");
    expect(doc.versionLabel).toBe("2026.10.13.01");
    expect(doc.publishedAt).toBe("2026-10-13T00:00:00.000Z");
    const byRef = new Map(doc.requirements.map((r) => [r.ref, r]));

    const vre = byRef.get("afc-frp-vre")!;
    expect(vre.label).toBe("AFC-FRP-VRE");
    expect(vre.family).toBe("AFC: Addressing FedRAMP Communication");
    expect(vre.title).toBe("Verified Emails");
    expect(vre.statement).toContain("FedRAMP MUST send messages");
    expect(vre.guidance).toContain("Anyone at GSA can send email");
    expect(vre.extra).toMatchObject({ force: "MUST", subset: "FedRAMP Responsibilities", affects: ["FedRAMP"] });
    expect(byRef.get("afc-frp-cds")!.statement).toContain("- **Emergency:**");

    const rat = byRef.get("ksi-ced-rat")!;
    expect(rat.family).toBe("KSI-CED: Cybersecurity Education");
    expect(rat.title).toBe("Reviewing All Training");
    expect(rat.related).toEqual(expect.arrayContaining(["at-2", "cm-11", "ir-9.4"]));

    const acv = byRef.get("frd-acv")!;
    expect(acv.family).toBe("FRD: Definitions");
    expect(acv.title).toBe("Accepted Vulnerability");
    expect(acv.statement).toContain("does not intend to fully mitigate");

    const ac = byRef.get("ctl-ac-06-01")!;
    expect(ac.label).toBe("AC-06-01");
    expect(ac.params).toEqual([
      { id: "ac-06.01_odp.02", label: "all functions not publicly accessible" },
      { id: "ac-06.01_odp.05", label: "all security-relevant information not publicly available" },
    ]);
    expect(byRef.get("ctl-ac-20")!.guidance).toContain("AC-20 describes system access");

    expect(doc.requirements.filter((r) => r.family?.startsWith("AFC") || r.family?.startsWith("CCM"))).toHaveLength(35);
    expect(new Set(doc.requirements.map((r) => r.ref)).size).toBe(doc.requirements.length);
    expect(doc.notes?.find((n) => n.ref === "ksi-ced-rat")?.text).toMatch(/^2026-10-13: Updated control mappings/);
    expect(doc.rationale?.text).toContain("dated 2026-10-13");
    expect(doc.rationale?.url).toBe("https://github.com/FedRAMP/rules/commits/main/fedramp-consolidated-rules.json");
  });

  describe("ingestion", () => {
    let db: DatabaseSync;
    let dataDir = "";
    beforeEach(() => {
      db = openDatabase(":memory:");
      migrate(db);
      dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-fedramp-"));
    });
    afterEach(() => {
      db.close();
      rmSync(dataDir, { recursive: true, force: true });
    });

    it("diffs October 13 against October 8 and keeps FedRAMP's notes beside the changes", async () => {
      const http = fedrampHttp();
      const source = getSource(db, "fedramp-rules")!;
      expect(source.group_name).toBe("standards");
      const octoberEighth = fedrampRulesAdapter.history!(source).find((t) => t.url.includes("6eb376782a"))!;
      const first = await ingestDocumentTarget(db, dataDir, source, fedrampRulesAdapter, octoberEighth, { http, now: () => at });
      expect(first.status).toBe("ok");
      expect(first.versionLabel).toBe("2026.10.08.01");
      const second = await ingestDocumentTarget(db, dataDir, source, fedrampRulesAdapter, { key: "rules", url: source.url }, { http, now: () => at });
      expect(second.status).toBe("ok");
      expect(second.versionLabel).toBe("2026.10.13.01");

      expect(listDocuments(db, "fedramp-rules")).toHaveLength(2);
      const latest = latestDocument(db, "fedramp-rules", "rules")!;
      expect(latest.previous_document_id).toBe(first.documentId);
      const changes = releaseChanges(db, latest.id);
      expect(changes.length).toBeGreaterThan(0);
      expect(changes.some((c) => c.kind === "added" || c.kind === "removed")).toBe(false);
      const mapping = changes.find((c) => c.ref === "ksi-ced-rat" && c.field === "related")!;
      expect(mapping.after_text).toContain("cm-11");
      expect(mapping.before_text).not.toContain("cm-11");
      expect(notesFor(db, latest.id, "ksi-ced-rat").map((n) => n.text)).toEqual([expect.stringMatching(/^2026-10-13: Updated control mappings/)]);
      expect(explanationsFor(db, latest.id).map((e) => e.kind)).toEqual(["publisher"]);
      const release = listWire(db, { kind: "release" }).find((i) => i.source_id === "fedramp-rules" && i.external_id === `rules#${latest.id}`);
      expect(release?.title).toMatch(/FedRAMP Consolidated Rules \(2026\) 2026\.10\.13\.01: /);
      expect(release?.url).toBe(`/standards/fedramp-rules/${latest.id}`);
    });
  });
});
