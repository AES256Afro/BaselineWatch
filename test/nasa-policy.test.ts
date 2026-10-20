import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adapterFor, nasaPolicyAdapter } from "../src/adapters/index.ts";
import { parseReference, referenceRequirements, sectionKey, stableId } from "../src/adapters/nasa-policy.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestDocumentTarget } from "../src/ingest.ts";
import { latestDocument, listDocuments } from "../src/register.ts";
import { fakeHttp, fixture } from "./helpers.ts";

const listingUrl = "https://www.nasa.gov/cybersecurity-policies/";
const docxUrl = "https://www.nasa.gov/wp-content/uploads/2026/09/cybersecurity-policy-reference-changes-for2026-q3-update-1.docx?emrc=f94093";
const at = new Date("2026-10-20T12:00:00Z");

describe("stableId", () => {
  it("keeps what survives a revision and drops what does not", () => {
    expect(stableId("NPR 2810.1F")).toBe("npr-2810.1");
    expect(stableId("NPD 1382.17K")).toBe("npd-1382.17");
    expect(stableId("NASA-SPEC-2600 Version 6.0")).toBe("nasa-spec-2600");
    expect(stableId("NASA-STD-8739.8B")).toBe("nasa-std-8739.8");
    expect(stableId("SP 800-53 Rev. 5")).toBe("sp-800-53");
    expect(stableId("SP 800-53A Rev. 5")).toBe("sp-800-53a");
    expect(stableId("SP 800-57 Part 1 Rev. 5")).toBe("sp-800-57-part-1");
    expect(stableId("SP 800-55 Vol. 1")).toBe("sp-800-55-vol-1");
    // A FIPS number's dash digit is the publication itself: 140-2 and 140-3 are both listed.
    expect(stableId("FIPS 140-3")).toBe("fips-140-3");
    expect(stableId("FIPS 140-2")).toBe("fips-140-2");
    expect(stableId("SP 800-73-4 (02/12/2016)")).toBe("sp-800-73-4");
  });
});

describe("parseReference on the real 2026 Q3 document", () => {
  const reference = parseReference(fixture("nasa/cybersecurity-policy-reference-2026-q3.docx"));

  it("reads the as-of date and the eight sections", () => {
    expect(reference.asOf?.slice(0, 10)).toBe("2026-09-15");
    expect(reference.sections.map((s) => sectionKey(s.heading))).toEqual([
      "directive", "naii", "handbook", "standard", "memo", "other", "fips", "nist",
    ]);
  });

  it("reads the directives with their dates and expiry", () => {
    const directives = reference.sections[0]!;
    expect(directives.heading).toMatch(/NASA Policy Directives \(NPD\) and NASA Procedural Requirements \(NPR\)/);
    const npr2810 = directives.entries.find((e) => e.id === "NPR 2810.1F")!;
    expect(npr2810.title).toBe("Security of Information and Information Systems");
    expect(npr2810.date).toBe("January 3, 2022");
    expect(npr2810.expiry).toBe("January 3, 2027");
  });

  it("reads the NASA standards, NASA-SPEC-2600 among them", () => {
    const standards = reference.sections[3]!;
    const spec = standards.entries.find((e) => e.id.startsWith("NASA-SPEC-2600"))!;
    expect(spec.title).toBe("Enumeration of ASCS Cybersecurity Requirements");
    expect(spec.date).toBe("January 12, 2026");
    expect(standards.entries.some((e) => e.id === "NASA-STD-2607" && e.title === "Network Security")).toBe(true);
  });

  it("splits a NIST row's status note from its title", () => {
    const nist = reference.sections[7]!;
    const mscp = nist.entries.find((e) => e.id === "SP 800-219 Rev. 2")!;
    expect(mscp.title).toBe("Automated Secure Configuration Guidance from the macOS Security Compliance Project (mSCP)");
    expect(mscp.note).toBe("Comment period closed as of 8/14/26");
    const fips = reference.sections[6]!;
    expect(fips.entries.find((e) => e.id === "FIPS 197")!.note).toBeNull();
  });

  it("reads a memorandum's sender", () => {
    const memos = reference.sections[4]!;
    const ipv6 = memos.entries.find((e) => e.id === "IPv6 Implementation")!;
    expect(ipv6.from).toBe("NASA CIO");
    expect(ipv6.date).toBe("May 11, 2021");
  });

  it("turns the tables into requirement rows with stable, unique refs", () => {
    const rows = referenceRequirements(reference);
    expect(rows.length).toBeGreaterThan(200);
    expect(new Set(rows.map((r) => r.ref)).size).toBe(rows.length);
    const npr = rows.find((r) => r.ref === "directive:npr-2810.1")!;
    expect(npr.label).toBe("NPR 2810.1F");
    expect(npr.statement).toBe("Listed as NPR 2810.1F. Dated January 3, 2022. Expires January 3, 2027.");
    // SP 800-224 is listed under both the FIPS and (eventually) SP sections; the section key keeps them apart.
    expect(rows.some((r) => r.ref === "fips:sp-800-224")).toBe(true);
    const handbook = rows.find((r) => r.ref.startsWith("handbook:its-hbk-1382.03-"));
    expect(handbook).toBeDefined();
  });
});

describe("the nasa-cyber-ref source", () => {
  let db: DatabaseSync;
  let dataDir: string;

  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-nasa-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("is seeded and read by the adapter", () => {
    const source = getSource(db, "nasa-cyber-ref")!;
    expect(source).toMatchObject({ kind: "requirement-set", group_name: "standards", format: "docx", schedule: "weekly", enabled: 1 });
    expect(adapterFor(source)).toBe(nasaPolicyAdapter);
  });

  it("follows the page's .docx link, loads the reference once, and fetches nothing new until it moves", async () => {
    const http = fakeHttp({
      [listingUrl]: { text: new TextDecoder().decode(fixture("nasa/cybersecurity-policies.html")) },
      [docxUrl]: { bytes: fixture("nasa/cybersecurity-policy-reference-2026-q3.docx"), contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
    });
    const source = getSource(db, "nasa-cyber-ref")!;
    const ctx = { db, http, now: () => at };

    const targets = await nasaPolicyAdapter.documents!(source, ctx);
    expect(targets).toEqual([{ key: "reference", url: docxUrl, title: "NASA Cybersecurity Policy Reference" }]);

    const outcome = await ingestDocumentTarget(db, dataDir, source, nasaPolicyAdapter, targets[0]!, { http, now: () => at });
    expect(outcome.status).toBe("ok");
    expect(outcome.versionLabel).toBe("as of 2026-09-15");
    expect(outcome.summary).toMatch(/^first version, \d{3} requirements$/);

    const latest = latestDocument(db, "nasa-cyber-ref", "reference")!;
    expect(latest.title).toBe("NASA Cybersecurity Policy Reference");
    expect(latest.published_at?.slice(0, 10)).toBe("2026-09-15");

    // The same bytes again: unchanged, no second document.
    const again = await ingestDocumentTarget(db, dataDir, source, nasaPolicyAdapter, targets[0]!, { http, now: () => at });
    expect(again.status).toBe("unchanged");
    expect(listDocuments(db, "nasa-cyber-ref")).toHaveLength(1);
  });

  it("says so when the page no longer links the reference", async () => {
    const http = fakeHttp({ [listingUrl]: { text: "<html><body><p>Nothing here.</p></body></html>" } });
    const source = getSource(db, "nasa-cyber-ref")!;
    await expect(nasaPolicyAdapter.documents!(source, { db, http, now: () => at })).rejects.toThrow(/no longer links/);
  });
});
