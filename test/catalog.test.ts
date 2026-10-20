import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { nasaPolicyAdapter } from "../src/adapters/index.ts";
import { getSource, ingestDocumentTarget } from "../src/ingest.ts";
import { fakeHttp, fixture, startTestApp, type TestApp } from "./helpers.ts";

const docxUrl = "https://www.nasa.gov/wp-content/uploads/2026/09/cybersecurity-policy-reference-2026-q3.docx";
const at = new Date("2026-10-20T12:00:00Z");

describe("the all-standards catalog", () => {
  let app: TestApp;

  beforeEach(async () => {
    app = await startTestApp({ now: () => at });
  });
  afterEach(async () => {
    await app.close();
  });

  it("serves /standards with the three bands and sits in the Standards menu", async () => {
    const response = await fetch(`${app.base}/standards`);
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).toContain("<h1>All standards</h1>");
    expect(text).toContain('<a href="/standards" aria-current="page">All standards</a>');
    expect(text).toContain('<a href="#by-os">By operating system</a>');
    expect(text).toContain('<a href="#nist">NIST publications</a>');
    expect(text).toContain('<a href="#nasa">NASA (CSET / OCIO)</a>');
    // Nothing fetched yet: each band says so instead of standing empty.
    expect(text).toContain("the NIST sources fill this table on their first fetch");
    expect(text).toContain("drafts-open-for-comment feed has not been fetched yet");
    expect(text).toContain("The reference has not been fetched yet");
    expect(text).toContain("cset.nasa.gov");
  });

  it("shows the NASA reference once it is loaded, standards open and citation lists folded", async () => {
    const http = fakeHttp({ [docxUrl]: { bytes: fixture("nasa/cybersecurity-policy-reference-2026-q3.docx") } });
    const source = getSource(app.db, "nasa-cyber-ref")!;
    const outcome = await ingestDocumentTarget(app.db, app.dataDir, source, nasaPolicyAdapter, { key: "reference", url: docxUrl, title: "NASA Cybersecurity Policy Reference" }, { http, now: () => at });
    expect(outcome.status).toBe("ok");

    const text = await (await fetch(`${app.base}/standards`)).text();
    expect(text).toContain("as of 2026-09-15");
    expect(text).toContain("NASA-SPEC-2600");
    expect(text).toContain("Enumeration of ASCS Cybersecurity Requirements");
    expect(text).toMatch(/<h3 id="nasa-standards">Standards \(\d+\)<\/h3>/);
    expect(text).toMatch(/<details><summary>FIPS Documents \(\d+\)/);
    expect(text).toMatch(/<details><summary>NIST Documents \(\d+\)/);
    // A row links into the Register's requirement page for the reference document.
    expect(text).toContain(`/standards/nasa-cyber-ref/${outcome.documentId}/${encodeURIComponent("standard:nasa-spec-2600")}`);
  });
});
