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
    expect(text).toContain('<a class="entry" href="/standards" aria-current="page"><b>Standards</b>');
    expect(text).toContain('<a href="#by-os">By operating system</a>');
    expect(text).toContain('<a href="#nist">NIST publications</a>');
    expect(text).toContain('<a href="#nasa">NASA (CSET / OCIO)</a>');
    // Nothing fetched yet: each band says so instead of standing empty.
    expect(text).toContain("the NIST sources fill this on their first fetch");
    expect(text).toContain("drafts-open-for-comment feed has not been fetched yet");
    expect(text).toContain("The reference has not been fetched yet");
    expect(text).toContain("cset.nasa.gov");
  });

  it("shows the NASA reference once it is loaded, each family folded to its count", async () => {
    const http = fakeHttp({ [docxUrl]: { bytes: fixture("nasa/cybersecurity-policy-reference-2026-q3.docx") } });
    const source = getSource(app.db, "nasa-cyber-ref")!;
    const outcome = await ingestDocumentTarget(app.db, app.dataDir, source, nasaPolicyAdapter, { key: "reference", url: docxUrl, title: "NASA Cybersecurity Policy Reference" }, { http, now: () => at });
    expect(outcome.status).toBe("ok");

    const text = await (await fetch(`${app.base}/standards`)).text();
    expect(text).toContain("as of 2026-09-15");
    expect(text).toContain("NASA-SPEC-2600");
    expect(text).toContain("Enumeration of ASCS Cybersecurity Requirements");
    // Every family folds to one line with its count; the citation lists say they repeat the tracked versions.
    expect(text).toMatch(/<details class="fold" id="nasa-standards">\s*<summary><b>Standards<\/b><span class="fold-meta">\d+ documents<\/span>/);
    expect(text).toMatch(/<summary><b>FIPS Documents<\/b><span class="fold-meta">\d+ documents? · NASA(?:'|&#39;)s citation list/);
    expect(text).toMatch(/<summary><b>NIST Documents<\/b><span class="fold-meta">\d+ documents? · NASA(?:'|&#39;)s citation list/);
    // The id leads to NASA's own page for the document; the title to the Register's row.
    expect(text).toMatch(/<a href="https:\/\/cset\.nasa\.gov\/ascs\/[^"]*" target="_blank" rel="noopener">NASA-SPEC-2600 Version 6\.0<\/a>/);
    expect(text).toContain(`/standards/nasa-cyber-ref/${outcome.documentId}/${encodeURIComponent("standard:nasa-spec-2600")}`);
  });
});
