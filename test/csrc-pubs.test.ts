import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { baseNumber, changeLog, cleanLines, csrcPublicationsAdapter, currentPage, headingOf, parseNistSections, parsePublicationPage, publications, sectionRequirements, shortNumber, successor } from "../src/adapters/csrc-pubs.ts";
import { adapterFor, csrcPubsAdapter } from "../src/adapters/index.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestDocumentTarget } from "../src/ingest.ts";
import { explanationsFor, latestDocument, listDocuments, releaseChanges } from "../src/register.ts";
import { fakeHttp, fixture } from "./helpers.ts";
import { simplePdf } from "./pdf-helper.ts";

const text = (name: string): string => new TextDecoder().decode(fixture(name));
const page3 = "https://csrc.nist.gov/pubs/fips/201-3/final";
const page2 = "https://csrc.nist.gov/pubs/fips/201-2/final";
const at = new Date("2026-10-19T12:00:00Z");

describe("CSRC publication pages", () => {
  it("reads the current revision's page: number, date, PDF, what it supersedes, its history and the Planning Note", () => {
    const page = parsePublicationPage(text("csrc/fips-201-3.html"), page3);
    expect(page.title).toBe("Personal Identity Verification (PIV) of Federal Employees and Contractors");
    expect(page.number).toBe("FIPS 201-3");
    expect(page.publishedAt).toBe("2022-01-24T00:00:00.000Z");
    expect(page.pdfUrl).toBe("https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.201-3.pdf");
    expect(page.supersedes).toEqual([{ url: page2, text: "FIPS 201-2 (09/05/2013)" }]);
    expect(page.supersededBy).toEqual([]);
    expect(page.history).toEqual([
      { url: "https://csrc.nist.gov/pubs/fips/201-3/ipd", text: "FIPS 201-3 (Draft)", current: false },
      { url: page3, text: "FIPS 201-3 (Final)", current: true },
    ]);
    expect(page.withdrawn).toBe(false);
    expect(page.planningNote?.date).toBe("03/23/2022");
    expect(page.planningNote?.text).toMatch(/^Some potential updates have been identified/);
  });

  it("reads a superseded revision's page: withdrawn, with its successor", () => {
    const page = parsePublicationPage(text("csrc/fips-201-2.html"), page2);
    expect(page.number).toBe("FIPS 201-2");
    expect(page.withdrawn).toBe(true);
    expect(page.supersededBy).toEqual([{ url: page3, text: "FIPS 201-3" }]);
    expect(page.supersedes.map((s) => s.text)).toEqual(["SP 800-104 (06/29/2007)", "FIPS 201-1 (06/23/2006)"]);
    expect(page.pdfUrl).toBe("https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.201-2.pdf");
  });

  it("shortens numbers the way CSRC cites them and finds the part that stays across revisions", () => {
    expect(shortNumber("NIST Internal or Interagency Report (NISTIR) 8320D (Draft)")).toBe("IR 8320D (Draft)");
    expect(shortNumber("NIST Special Publication (SP) 800-57 Part 1 Rev. 5")).toBe("SP 800-57 Part 1 Rev. 5");
    expect(shortNumber("Federal Information Processing Standard (FIPS) 201-2 (Withdrawn)")).toBe("FIPS 201-2");
    expect(baseNumber("SP 800-73-4 (02/12/2016)")).toBe("sp 800-73");
    expect(baseNumber("SP 800-73-5")).toBe("sp 800-73");
    expect(baseNumber("SP 800-57 Part 1 Rev. 4 (01/28/2016)")).toBe("sp 800-57 part 1");
    expect(baseNumber("FIPS 201-2")).toBe("fips 201");
    expect(baseNumber("SP 800-63B-4")).toBe("sp 800-63b");
    expect(baseNumber("SP 800-63B (03/02/2020)")).toBe("sp 800-63b");
    expect(baseNumber("SP 800-157 Rev. 1 (Draft)")).toBe("sp 800-157");
  });

  it("follows a superseded page, or a draft whose history moved on, to the newest revision", async () => {
    const draft = `<html><body><h1 id="pub-title">Thing</h1><span id="pub-history-link-0" data-current-document='true'>SP 800-9 (Draft)</span><a href="/pubs/fips/201-3/final" id="pub-history-link-1" data-current-document='false'>SP 800-9</a></body></html>`;
    const http = fakeHttp({
      [page2]: { text: text("csrc/fips-201-2.html") },
      [page3]: { text: text("csrc/fips-201-3.html") },
      "https://csrc.nist.gov/pubs/sp/800/9/ipd": { text: draft },
    });
    expect((await currentPage(http, page2)).number).toBe("FIPS 201-3");
    expect((await currentPage(http, "https://csrc.nist.gov/pubs/sp/800/9/ipd")).number).toBe("FIPS 201-3");
    expect((await currentPage(http, page3)).url).toBe(page3);
  });

  it("lists the tracked publications with unique keys and CSRC pages", () => {
    for (const [sourceId, list] of Object.entries(publications)) {
      expect(list.length).toBeGreaterThanOrEqual(10);
      expect(new Set(list.map((p) => p.key)).size).toBe(list.length);
      for (const p of list) expect(p.page, `${sourceId} ${p.key}`).toMatch(/^https:\/\/csrc\.nist\.gov\/pubs\//);
    }
    expect(publications["nist-piv"]!.map((p) => p.key)).toEqual(expect.arrayContaining(["fips-201", "sp-800-73-pt1", "sp-800-78", "sp-800-157", "sp-800-63b"]));
    expect(publications["nist-platform"]!.map((p) => p.key)).toEqual(expect.arrayContaining(["fips-140", "sp-800-193", "sp-800-147b", "ir-8320d"]));
  });
});

describe("NIST publication text", () => {
  it("takes outline headings and leaves list items, prose and the table of contents alone", () => {
    expect(headingOf("1. Introduction")).toEqual({ parts: [1], label: "1", title: "Introduction" });
    expect(headingOf("1.1. Purpose")).toEqual({ parts: [1, 1], label: "1.1", title: "Purpose" });
    expect(headingOf("2.10.1 Derived PIV Credential Issuance Requirements")).toEqual({ parts: [2, 10, 1], label: "2.10.1", title: "Derived PIV Credential Issuance Requirements" });
    expect(headingOf("Appendix E. Revision History")).toEqual({ parts: ["E"], label: "Appendix E", title: "Revision History" });
    expect(headingOf("E.1 Something Else")).toEqual({ parts: ["E", 1], label: "E.1", title: "Something Else" });
    expect(headingOf("1. Name of Standard. Personal Identity Verification (PIV) of Federal Employees and")).toBeNull();
    expect(headingOf("2. OCSP status response messages.")).toBeNull();
    expect(headingOf("1.1 Purpose . . . . . . . . . . . . . . . 1")).toBeNull();
    expect(headingOf("1.1 Purpose ..................................1-1")).toBeNull();
    expect(headingOf("100 Bureau Drive (Mail Stop 8930) Gaithersburg, MD 20899-8930")).toBeNull();
    expect(headingOf("6.1 Special-Risk Security Provision. The U.S. Government has personnel, facilities,")).toBeNull();
    expect(headingOf("2024 was the year")).toBeNull();
  });

  it("knows which heading can follow which", () => {
    expect(successor([1], [1, 1])).toBe(true);
    expect(successor([1, 1], [1, 2])).toBe(true);
    expect(successor([1, 2], [2])).toBe(true);
    expect(successor([3, 2, 3], [4])).toBe(true);
    expect(successor([2, 1], [2, 1, 1])).toBe(true);
    expect(successor([7], ["A"])).toBe(true);
    expect(successor(["A"], ["A", 1])).toBe(true);
    expect(successor(["A", 2], ["B"])).toBe(true);
    expect(successor([2, 1], [7])).toBe(false);
    expect(successor([1], [3])).toBe(false);
    expect(successor([2, 1], [2, 3])).toBe(false);
    expect(successor([7], ["C"])).toBe(false);
  });

  it("drops running headers, footers and page numbers before reading the outline", () => {
    const pages = ["", "NIST SP 800-0 TITLE", "", "1", "1 Introduction", "First page text.", "", "i"].join("\n") + "\f" + ["", "NIST SP 800-0 TITLE", "", "2", "continues here.", "1.1 Purpose", "Body.", "ii"].join("\n") + "\f" + ["", "NIST SP 800-0 TITLE", "", "3", "2 Next", "More.", "iii"].join("\n");
    const lines = cleanLines(pages);
    expect(lines).not.toContain("NIST SP 800-0 TITLE");
    expect(lines).not.toContain("1");
    expect(lines).not.toContain("ii");
    expect(lines).toEqual(["1 Introduction", "First page text.", "continues here.", "1.1 Purpose", "Body.", "2 Next", "More."]);
    const sections = parseNistSections(pages);
    expect(sections.map((s) => [s.ref, s.body])).toEqual([
      ["1", "First page text. continues here."],
      ["1.1", "Body."],
      ["2", "More."],
    ]);
  });

  it("reads SP 800-78-5's sections from its real text, with the change log as the publisher's reason", () => {
    const sections = parseNistSections(text("csrc/sp-800-78-5.txt"));
    const refs = sections.map((s) => s.ref);
    expect(new Set(refs).size).toBe(refs.length);
    expect(refs).toEqual(expect.arrayContaining(["1", "1.1", "1.4", "2", "3", "3.1", "3.2", "3.2.1", "3.2.2", "3.2.3", "4", "5", "6", "6.1", "6.2", "6.3", "7", "a", "b"]));
    const byRef = new Map(sections.map((s) => [s.ref, s]));
    expect(byRef.get("2")!.title).toBe("Application of Cryptography in FIPS 201-3");
    expect(byRef.get("3.2.1")!.title).toBe("Specification of Digital Signatures on Authentication Information");
    expect(byRef.get("3.1")!.body).toContain("PIV Authentication key");
    expect(byRef.get("b")!.title).toBe("Change Log");
    // Numbered list items and cross-references are not sections, and the table of contents is not read twice.
    expect(sections.some((s) => /^OCSP status|^The mandatory|^An optional/.test(s.title))).toBe(false);
    expect(sections.filter((s) => s.ref === "6")).toHaveLength(1);
    // Page furniture is gone.
    expect(sections.some((s) => (s.body ?? "").includes("July 2024 and Key Sizes for PIV"))).toBe(false);

    const requirements = sectionRequirements(sections);
    const r = requirements.find((x) => x.ref === "3.2.1")!;
    expect(r).toMatchObject({ label: "3.2.1", parentRef: "3.2", family: "3 On-Card Cryptographic Requirements", sortKey: "003.002.001", status: "active" });
    const b = requirements.find((x) => x.ref === "b")!;
    expect(b).toMatchObject({ label: "Appendix B", parentRef: null, family: "Appendix B Change Log", sortKey: "b" });

    const log = changeLog(sections)!;
    expect(log).toMatch(/^Appendix B Change Log:\n/);
    expect(log).toContain("In 2024, Revision 5");
  });
});

describe("the NIST publication sources", () => {
  let db: DatabaseSync;
  let dataDir: string;

  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-csrc-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("are seeded and read by the adapter", () => {
    for (const id of ["nist-piv", "nist-platform"]) {
      const source = getSource(db, id)!;
      expect(source).toMatchObject({ kind: "requirement-set", group_name: "standards", format: "csrc-pdf", schedule: "daily", enabled: 1 });
      expect(adapterFor(source)).toBe(csrcPubsAdapter);
      expect(publications[id]).toBeDefined();
    }
  });

  it("loads the superseded revision first, diffs the current one section by section, and then fetches nothing until the page moves", async () => {
    const v2 = simplePdf([
      "1. Introduction",
      "This Standard describes the PIV system.",
      "1.1 Purpose",
      "To specify the PIV Card and its issuers.",
      "2. Common Identification Requirements",
      "2.1 Control Objectives",
      "Agencies must issue cards to employees.",
      "Appendix A. Revision History",
      "FIPS 201-1 March 2006 Added the NACI indicator.",
    ]);
    const v3 = simplePdf([
      "1. Introduction",
      "This Standard describes the PIV system.",
      "1.1 Purpose",
      "To specify the PIV Card and its issuers.",
      "2. Common Identification Requirements",
      "2.1 Control Objectives",
      "Agencies must issue cards to employees and contractors.",
      "2.2 Credentialing Requirements",
      "Issuers follow the credentialing standards.",
      "Appendix A. Revision History",
      "FIPS 201-1 March 2006 Added the NACI indicator.",
      "FIPS 201-3 January 2022 Added derived PIV credentials and federation.",
    ]);
    const http = fakeHttp({
      [page3]: { text: text("csrc/fips-201-3.html") },
      [page2]: { text: text("csrc/fips-201-2.html") },
      "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.201-3.pdf": { bytes: v3, contentType: "application/pdf" },
      "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.201-2.pdf": { bytes: v2, contentType: "application/pdf" },
    });
    const source = getSource(db, "nist-piv")!;
    const adapter = csrcPublicationsAdapter({ "nist-piv": [{ key: "fips-201", page: page3 }] });
    const ctx = { db, http, now: () => at };

    const targets = await adapter.documents!(source, ctx);
    expect(targets.map((t) => [t.key, t.versionLabel, t.publishedAt?.slice(0, 10)])).toEqual([
      ["fips-201", "FIPS 201-2", "2013-09-05"],
      ["fips-201", "FIPS 201-3", "2022-01-24"],
    ]);
    expect(targets[1]!.title).toBe("Personal Identity Verification (PIV) of Federal Employees and Contractors");
    expect(targets[1]!.rationale?.text).toMatch(/^Planning Note \(03\/23\/2022\): Some potential updates/);

    const outcomes = [];
    for (const t of targets) outcomes.push(await ingestDocumentTarget(db, dataDir, source, adapter, t, { http, now: () => at }));
    expect(outcomes.map((o) => [o.status, o.summary])).toEqual([
      ["ok", "first version, 5 requirements"],
      ["ok", expect.stringContaining("1 added")],
    ]);

    const docs = listDocuments(db, "nist-piv");
    expect(docs).toHaveLength(2);
    const latest = latestDocument(db, "nist-piv", "fips-201")!;
    expect(latest.version_label).toBe("FIPS 201-3");
    expect(latest.title).toBe("Personal Identity Verification (PIV) of Federal Employees and Contractors");
    expect(latest.previous_document_id).toBe(docs.find((d) => d.version_label === "FIPS 201-2")!.id);
    const changes = releaseChanges(db, latest.id);
    expect(changes.map((c) => [c.ref, c.kind, c.field])).toEqual(expect.arrayContaining([
      ["2.1", "modified", "statement"],
      ["2.2", "added", null],
      ["a", "modified", "statement"],
    ]));
    // The PDF's own revision history is the publisher's reason, ahead of the page's Planning Note.
    const explanations = explanationsFor(db, latest.id);
    expect(explanations.some((e) => e.kind === "publisher" && e.text.startsWith("Appendix A Revision History:") && e.text.includes("Added derived PIV credentials"))).toBe(true);

    // A later day: the page still names the same file and date, so nothing is downloaded.
    const pdfCalls = () => http.calls.filter((c) => c.url.endsWith(".pdf")).length;
    const before = pdfCalls();
    const again = await adapter.documents!(source, ctx);
    expect(again.map((t) => t.versionLabel)).toEqual(["FIPS 201-3"]);
    const outcome = await ingestDocumentTarget(db, dataDir, source, adapter, again[0]!, { http, now: () => at });
    expect(outcome.status).toBe("unchanged");
    expect(pdfCalls()).toBe(before);
    expect(listDocuments(db, "nist-piv")).toHaveLength(2);
  });

  it("reports a publication whose page cannot be read, and a page that leads to no PDF, beside their keys", async () => {
    const noPdf = `<html><body><h1 id="pub-title">Nothing</h1><meta name="citation_technical_report_number" content="NIST Special Publication (SP) 800-0"></body></html>`;
    const http = fakeHttp({ "https://csrc.nist.gov/pubs/sp/800/0/final": { text: noPdf } });
    const source = getSource(db, "nist-platform")!;
    const adapter = csrcPublicationsAdapter({
      "nist-platform": [
        { key: "sp-800-0", page: "https://csrc.nist.gov/pubs/sp/800/0/final" },
        { key: "sp-800-404", page: "https://csrc.nist.gov/pubs/sp/800/404/final" },
      ],
    });
    const targets = await adapter.documents!(source, { db, http, now: () => at });
    expect(targets.map((t) => t.key)).toEqual(["sp-800-0", "sp-800-404"]);
    const outcomes = [];
    for (const t of targets) outcomes.push(await ingestDocumentTarget(db, dataDir, source, adapter, t, { http, now: () => at }));
    expect(outcomes[0]).toMatchObject({ status: "error", error: expect.stringContaining("no PDF") });
    expect(outcomes[1]).toMatchObject({ status: "error", error: expect.stringContaining("no route") });
  });
});
