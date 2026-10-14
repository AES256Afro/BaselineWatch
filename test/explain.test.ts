import { zipSync } from "fflate";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { disaAdapter } from "../src/adapters/disa.ts";
import { nistCatalogAdapter } from "../src/adapters/oscal-nist.ts";
import { sctAdapter } from "../src/adapters/sct.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { announcementText, extractPlanningNote, parseStigRevisionHistory } from "../src/explain.ts";
import type { HttpGet } from "../src/http.ts";
import { getSource, ingestDocumentTarget, ingestSource } from "../src/ingest.ts";
import { releasePrompt, summarizeRelease } from "../src/llm.ts";
import { pdfPages, unwrap } from "../src/pdf.ts";
import { explanationsFor, latestDocument, notesFor, releaseChanges } from "../src/register.ts";
import { fakeHttp, fixture } from "./helpers.ts";
import { simplePdf } from "./pdf-helper.ts";

const text = (name: string) => new TextDecoder().decode(fixture(name));
const at = new Date("2026-10-15T04:00:00Z");

describe("publisher rationale extraction", () => {
  it("reads DISA's revision history into per-rule notes for one version", () => {
    const history = parseStigRevisionHistory(text("stig-revision-history.txt"), "V1R4");
    expect(history.notes.length).toBeGreaterThanOrEqual(10);
    const pw = history.notes.filter((n) => n.text.startsWith("Updated max password age value to 180 days"));
    expect(pw.map((n) => n.label).sort()).toEqual(["WN25-00-000020", "WN25-AC-000050"]);
    expect(history.notes.find((n) => n.label === "WN25-SO-000140")?.text).toBe("Removed rule due to overlap with WN25-SO-000130.");
    expect(history.general.some((g) => g.startsWith("Requirements were updated throughout"))).toBe(true);
    // Only V1R4's block, not V1R3's.
    expect(history.notes.some((n) => n.label === "WN25-00-000332")).toBe(false);
    const older = parseStigRevisionHistory(text("stig-revision-history.txt"), "V1R3");
    expect(older.notes.some((n) => n.label === "WN25-00-000332")).toBe(true);
  });

  it("turns Microsoft's announcement into prose and NIST's page into its Planning Note", () => {
    const prose = announcementText(text("sct-announcement.txt"));
    expect(prose).toMatch(/^Microsoft is pleased to announce the February 2026 Revision \(v2602\)/);
    expect(prose).toContain("Configure the behavior of the sudo command");
    expect(prose.split("\n\n").length).toBeGreaterThan(3);

    const note = extractPlanningNote(text("csrc-80053.html"))!;
    expect(note.date).toBe("08/27/2025");
    expect(note.text).toMatch(/^On August 27, 2025, NIST issued a minor release of SP 800-53 \(Release 5\.2\.0\)/);
    expect(note.text).toContain("New Control/Control Enhancements: SA-15(13), SA-24, SI-02(07)");
    expect(note.text).not.toContain("Date Published");
    expect(extractPlanningNote("<html><p>nothing here</p></html>")).toBeNull();
  });

  it("reads text out of a PDF and unwraps layout line breaks", async () => {
    const pages = await pdfPages(simplePdf(["REVISION HISTORY", "- WN25-00-000020 - Updated max password", "age value to 180 days.", "- WN25-00-000140 - Revised Check text."]));
    expect(pages).toHaveLength(1);
    expect(pages[0]).toContain("REVISION HISTORY");
    expect(pages[0]).toContain("WN25-00-000020");
    expect(unwrap("a line\nwrapped here\n\n- an item\ncontinued\n- another")).toBe("a line wrapped here\n\n- an item continued\n- another");
  });
});

describe("generated summaries", () => {
  it("builds a grounded prompt and stores what the model answers, or nothing when it is off", async () => {
    const release = {
      standard: "NIST SP 800-53",
      version: "5.2.0",
      previousVersion: "5.1.1",
      rationale: "On August 27, 2025, NIST issued a minor release.",
      changes: [{ label: "SA-24", title: "Design For Cyber Resiliency", kind: "added", field: null, before: null, after: "SA-24 Design For Cyber Resiliency" }],
    };
    const prompt = releasePrompt(release);
    expect(prompt).toContain("Do not invent reasons");
    expect(prompt).toContain("- SA-24 Design For Cyber Resiliency: added");
    const calls: string[] = [];
    const http: HttpGet = async (url, options) => {
      calls.push(`${url} ${options?.body ?? ""}`);
      return { url, status: 200, notModified: false, bytes: new TextEncoder().encode(JSON.stringify({ response: "  Release 5.2.0 adds SA-24. " })), etag: null, lastModified: null, contentType: "application/json" };
    };
    expect(await summarizeRelease({ url: "http://ollama:11434/", model: "m" }, http, release)).toBe("Release 5.2.0 adds SA-24.");
    expect(calls[0]).toMatch(/^http:\/\/ollama:11434\/api\/generate /);
    expect(calls[0]).toContain('"model":"m"');
    expect(await summarizeRelease({ url: null, model: "m" }, http, release)).toBeNull();
    const broken: HttpGet = async () => {
      throw new Error("down");
    };
    expect(await summarizeRelease({ url: "http://ollama:11434", model: "m" }, broken, release)).toBeNull();
  });
});

describe("explanations through the pipeline", () => {
  let db: ReturnType<typeof openDatabase>;
  let dataDir = "";
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-explain-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("attaches DISA's per-rule notes to the changes they explain and a generated summary to the release", async () => {
    const source = getSource(db, "disa-stigs")!;
    const v1 = zipSync({ "STIG/U_MS_Windows_Server_2025_STIG_V1R3_Manual-xccdf.xml": fixture("stig.xccdf.xml") });
    const changedXml = text("stig.xccdf.xml").replace("within 30 days", "within 14 days").replace("</Benchmark>", "</Benchmark>");
    const historyPdf = simplePdf(["REVISION HISTORY", "V1R4 Microsoft Windows Server 2025 STIG, V1R3", "- WN25-00-000001 - Shortened the update window to 14 days.", "- Requirements were updated throughout.", "30 September 2026", "V1R3 Microsoft Windows Server 2025 STIG, V1R2", "- WN25-00-000332 - Corrected syntax."]);
    const v2 = zipSync({ "STIG/U_MS_Windows_Server_2025_STIG_V1R4_Manual-xccdf.xml": new TextEncoder().encode(changedXml), "STIG/U_MS_Windows_Server_2025_V1R4_Revision_History.pdf": historyPdf });

    const llmCalls: string[] = [];
    const http: HttpGet = async (url, options) => {
      if (url === "https://zips/v1.zip") return { url, status: 200, notModified: false, bytes: new Uint8Array(v1), etag: null, lastModified: null, contentType: "application/zip" };
      if (url === "https://zips/v2.zip") return { url, status: 200, notModified: false, bytes: new Uint8Array(v2), etag: null, lastModified: null, contentType: "application/zip" };
      if (url.endsWith("/api/generate")) {
        llmCalls.push(options?.body ?? "");
        return { url, status: 200, notModified: false, bytes: new TextEncoder().encode(JSON.stringify({ response: "V1R4 shortens the patch window to 14 days." })), etag: null, lastModified: null, contentType: "application/json" };
      }
      throw new Error(`unexpected ${url}`);
    };
    const settings = { nvdApiKey: null, nvdBackfillDays: 1, llmUrl: "http://ollama:11434", llmModel: "test-model" };
    const first = await ingestDocumentTarget(db, dataDir, source, disaAdapter, { key: "stig:ws2025", url: "https://zips/v1.zip", versionLabel: "V1R3" }, { http, now: () => at, settings });
    expect(first.status).toBe("ok");
    expect(llmCalls).toHaveLength(0); // nothing to summarise on a first load
    const second = await ingestDocumentTarget(db, dataDir, source, disaAdapter, { key: "stig:ws2025", url: "https://zips/v2.zip", versionLabel: "V1R4" }, { http, now: () => at, settings });
    expect(second.status).toBe("ok");
    expect(second.summary).toContain("1 revised");

    const latest = latestDocument(db, "disa-stigs", "stig:ws2025")!;
    const changes = releaseChanges(db, latest.id);
    expect(changes.map((c) => c.ref)).toEqual(["v-277982"]);
    const notes = notesFor(db, latest.id, "v-277982");
    expect(notes).toHaveLength(1);
    expect(notes[0]?.text).toBe("Shortened the update window to 14 days.");
    const release = explanationsFor(db, latest.id);
    expect(release.map((e) => e.kind).sort()).toEqual(["generated", "publisher"]);
    expect(release.find((e) => e.kind === "publisher")?.text).toContain("WN25-00-000001: Shortened the update window to 14 days.");
    expect(release.find((e) => e.kind === "publisher")?.text).toContain("Requirements were updated throughout.");
    expect(release.find((e) => e.kind === "generated")?.text).toBe("V1R4 shortens the patch window to 14 days.");
    expect(llmCalls).toHaveLength(1);
    expect(llmCalls[0]).toContain("Shortened the update window");
  });

  it("stores Microsoft's announcement and NIST's Planning Note as the publisher's words", async () => {
    const sct = getSource(db, "microsoft-sct")!;
    const zip = zipSync({ "WS2025/Documentation/MSFT-WS2025-v2602.PolicyRules": fixture("sct.PolicyRules"), "WS2025/Documentation/Announcement.pdf": simplePdf(["Microsoft is pleased to announce the February 2026 Revision (v2602).", "Summary of Changes in This Release", "The sudo command is now disabled on MS and DC."]) });
    const outcome = await ingestDocumentTarget(db, dataDir, sct, sctAdapter, { key: "baseline:ws2025", url: "https://zips/ws.zip", versionLabel: "2602" }, { http: fakeHttp({ "https://zips/ws.zip": { bytes: new Uint8Array(zip) } }), now: () => at });
    expect(outcome.status).toBe("ok");
    const doc = latestDocument(db, "microsoft-sct", "baseline:ws2025")!;
    const why = explanationsFor(db, doc.id);
    expect(why).toHaveLength(1);
    expect(why[0]?.kind).toBe("publisher");
    expect(why[0]?.text).toContain("sudo command is now disabled");

    const nist = getSource(db, "nist-sp-800-53")!;
    const http = fakeHttp({
      "https://catalog/x.json": { bytes: fixture("oscal-catalog-5.2.0.json") },
      [nist.url]: { bytes: fixture("oscal-catalog-5.2.0.json") },
      "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final": { bytes: fixture("csrc-80053.html") },
    });
    await ingestDocumentTarget(db, dataDir, nist, nistCatalogAdapter, { key: "catalog", url: "https://catalog/x.json" }, { http, now: () => at });
    const catalog = latestDocument(db, "nist-sp-800-53", "catalog")!;
    const note = explanationsFor(db, catalog.id);
    expect(note[0]?.kind).toBe("publisher");
    expect(note[0]?.text).toMatch(/^Planning Note \(08\/27\/2025\): On August 27, 2025/);
    expect(note[0]?.source_url).toBe("https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final");
    // The regular source fetch takes the same path.
    const again = await ingestSource(db, dataDir, nist, { http, now: () => at });
    expect(again.status).toBe("unchanged");
  });
});
