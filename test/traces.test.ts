import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { getSource, ingestSource } from "../src/ingest.ts";
import { traceIndicators } from "../src/traces.ts";
import { fakeHttp, fixture, startTestApp, type FakeRoute, type TestApp } from "./helpers.ts";

/** Traces (S8): the page, its policy, the list it reads against, and the script it carries. */

const at = new Date("2026-10-19T12:00:00Z");
const raw = "https://raw.githubusercontent.com/interplains/zero-breach";
const api = "https://api.github.com/repos/interplains/zero-breach/commits?path=";
const head = "7253316421e481973e1d9fd3b2bdb88eafc99029";
const first = "e36dc961b8c60060c3b164d1a1c78d401e231a5e";

/** The indicator list's real captured responses: GitHub's commit listing and the two versions of the file. */
function indicatorRoutes(): Record<string, FakeRoute> {
  const file = "iocs/adfection_iocs.txt";
  return {
    [`${api}${file}&per_page=1`]: { bytes: fixture("blocklists/commits-domains.json"), contentType: "application/json" },
    [`${raw}/${head}/${file}`]: { bytes: fixture("blocklists/adfection_iocs-2026-10-18b.txt"), contentType: "text/plain" },
    [`${raw}/${first}/${file}`]: { bytes: fixture("blocklists/adfection_iocs-2026-10-18a.txt"), contentType: "text/plain" },
  };
}

let empty: TestApp;
let held: TestApp;

beforeAll(async () => {
  empty = await startTestApp();
  held = await startTestApp();
  const result = await ingestSource(held.db, held.dataDir, getSource(held.db, "adfection-indicators")!, { http: fakeHttp(indicatorRoutes()), now: () => at });
  expect(result.status).toBe("ok");
});

afterAll(async () => {
  await empty.close();
  await held.close();
});

describe("the Traces page", () => {
  it("renders whole before the script runs, under a policy that allows this origin alone", async () => {
    const response = await fetch(`${held.base}/scan/traces`);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const policy = response.headers.get("content-security-policy") ?? "";
    expect(policy).toContain("script-src 'self';");
    expect(policy).toContain("connect-src 'self';");
    expect(policy).not.toMatch(/connect-src[^;]*https?:/);
    const text = await response.text();
    expect(text).toContain('<script type="module" src="/assets/traces.js?v=');
    expect(text).toContain('<section class="scan scan-traces" id="traces">');
    expect(text).toContain('<input type="file" id="traces-folder" webkitdirectory multiple>');
    expect(text).toContain('<button type="button" class="primary" id="traces-run" disabled>Read them</button>');
    expect(text).toContain('<div class="verdict" id="traces-verdict" hidden>');
    expect(text).toContain('<div class="box notice-help" id="traces-help" hidden>');
    for (const id of ["where-windows", "where-macos", "where-linux", "sys-windows", "sys-macos", "sys-linux"]) expect(text).toContain(`id="${id}"`);
    expect(text).toContain("reg export HKCU\\Software\\Classes\\CLSID");
    expect(text).toContain('<a class="entry" href="/scan/traces" aria-current="page"><b>Traces</b>');
    expect(text).toContain('<a href="/standards/adfection-indicators">tracked in the Register</a>');
    expect(text).toMatch(/405 indicators — 292 domains, 111 addresses, 2 file fingerprints — version /);
    expect(text).not.toMatch(/<script>/);
    expect(text).not.toMatch(/ style="/);
    expect(text).not.toMatch(/<form[^>]*enctype/);
  });

  it("says so when the list has never been fetched", async () => {
    const text = await (await fetch(`${empty.base}/scan/traces`)).text();
    expect(text).toContain("Not fetched yet");
    expect(await (await fetch(`${empty.base}/scan/traces/indicators.json`)).json()).toEqual({ version: null, publishedAt: null, indicators: [] });
  });

  it("serves the list the Register holds, each indicator with its type and tier", async () => {
    const response = await fetch(`${held.base}/scan/traces/indicators.json`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as ReturnType<typeof traceIndicators>;
    expect(body.indicators).toHaveLength(405);
    expect(body.indicators.find((i) => i.value === "fearevolve.com")).toEqual({ value: "fearevolve.com", type: "domain", tier: "cc", confidence: "primary", source: "citizenlab-adfection-2026" });
    expect(body.indicators.filter((i) => i.type === "sha256").map((i) => i.tier).sort()).toEqual(["sample", "vuln-driver"]);
    expect(body).toEqual(traceIndicators(held.db));
  });

  it("serves the script as a module that builds the page without innerHTML or eval", async () => {
    const response = await fetch(`${held.base}/assets/traces.js`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toMatch(/javascript/);
    const text = await response.text();
    expect(text).toContain("export function wire(");
    expect(text).not.toMatch(/innerHTML|\beval\(|new Function\(/);
    // The one request the script makes is for the list, on this origin.
    expect(text.match(/fetch\(/g)).toHaveLength(1);
    expect(text).toContain('view.fetch("/scan/traces/indicators.json"');
  });

  it("is linked from the Scan page and listed in the sitemap", async () => {
    expect(await (await fetch(`${held.base}/scan/why`)).text()).toContain('<a href="/scan/traces">Traces</a>');
    expect(await (await fetch(`${held.base}/sitemap.xml`)).text()).toContain("/scan/traces</loc>");
  });
});
