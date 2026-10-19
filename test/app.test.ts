import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { HealthReport } from "../src/app.ts";
import { productVersion } from "../src/version.ts";
import { startTestApp, type TestApp } from "./helpers.ts";

let app: TestApp;

beforeAll(async () => {
  app = await startTestApp({ env: { BW_BASE_URL: "https://cybercard.net/", BW_NVD_API_KEY: "not-shown" } });
});

afterAll(async () => {
  await app.close();
});

describe("health", () => {
  it("reports the version and the database counts", async () => {
    const response = await fetch(`${app.base}/health`);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = (await response.json()) as HealthReport;
    expect(body.ok).toBe(true);
    expect(body.version).toBe(productVersion);
    expect(body.uptimeSeconds).toBeGreaterThanOrEqual(5);
    expect(body.database.migrations).toBeGreaterThanOrEqual(3);
    expect(body.database.sources).toBeGreaterThan(20);
    expect(body.database.snapshots).toBe(0);
  });

  it("answers at the versioned path too", async () => {
    const response = await fetch(`${app.base}/api/v1/health`);
    expect(response.status).toBe(200);
  });
});

describe("pages", () => {
  it("serves the Register home with the standards and the empty state", async () => {
    const response = await fetch(`${app.base}/register`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toMatch(/text\/html/);
    const text = await response.text();
    expect(text).toContain("<!doctype html>");
    expect(text).toContain("NIST SP 800-53 (controls)");
    expect(text).toContain("The Register has no diffs yet.");
    expect(text).toContain("https://cybercard.net");
    expect(text).not.toContain("not-shown");
    expect(text).toContain("NVD API key</dt><dd>set");
  });

  it("serves the Sources register and an empty Wire", async () => {
    const text = await (await fetch(`${app.base}/sources`)).text();
    expect(text).toContain("CISA Known Exploited Vulnerabilities");
    expect(text).toContain("r/netsec");
    const wire = await (await fetch(`${app.base}/wire`)).text();
    expect(wire).toContain("Nothing here yet.");
  });

  it("serves the guide and links it from the masthead and the footer", async () => {
    const response = await fetch(`${app.base}/guide`);
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).toContain("How to read this site");
    expect(text).toContain("Known Exploited Vulnerabilities");
    expect(text).toContain("Exploit Prediction Scoring System");
    expect(text).toContain('href="/vulnerabilities?kev=1"');
    expect(text).toContain('href="/vulnerabilities?min_epss=0.5"');
    expect(text).toContain('href="/vulnerabilities?min_cvss=9"');
    expect(text).toContain('href="/stigs"');
    const home = await (await fetch(`${app.base}/`)).text();
    expect(home).toContain('<a class="cap" href="/guide">');
    expect(home).toContain('<a href="/guide">how to read this site</a>');
  });

  it("sends strict security headers and no inline script", async () => {
    const response = await fetch(`${app.base}/`);
    expect(response.headers.get("content-security-policy")).toContain("script-src 'none'");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-powered-by")).toBeNull();
    expect(await response.text()).not.toMatch(/<script/i);
  });

  it("serves the stylesheet and a 404 page", async () => {
    const css = await fetch(`${app.base}/assets/app.css`);
    expect(css.status).toBe(200);
    expect(css.headers.get("content-type")).toMatch(/text\/css/);
    const missing = await fetch(`${app.base}/nope/<b>`);
    expect(missing.status).toBe(404);
    const text = await missing.text();
    expect(text).toContain("Nothing at");
    expect(text).not.toContain("<b>");
    expect(text).toContain("&lt;b&gt;");
  });
});
