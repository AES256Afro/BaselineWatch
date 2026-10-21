import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { HealthReport } from "../src/app.ts";
import { productVersion } from "../src/version.ts";
import { formPost, startTestApp, type TestApp } from "./helpers.ts";

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
    // The totals strip and the side boxes lead to where each figure is counted.
    expect(text).toMatch(/<a href="\/sources#standards"><small>Standards tracked<\/small><b>\d+<\/b><\/a>/);
    expect(text).toContain('<a href="/sources"><small>Sources enabled</small>');
    expect(text).toContain('<a href="#tracked"><small>Snapshots</small>');
    expect(text).toContain('<a href="/?kind=release"><small>Changes</small>');
    expect(text).toContain('<a href="/?unread=1"><small>News, unread</small>');
    expect(text).toContain('<a href="#instance"><small>Database</small>');
    expect(text).toContain('<h2><a href="/triage">Needs you</a></h2>');
    expect(text).toContain('<h2><a href="/?kind=kev">Known exploited, newest</a>');
    expect(text).toContain('<section class="box" id="instance">\n          <h2><a href="/health">This instance</a></h2>');
    expect(text).toContain('<a href="https://github.com/AES256Afro/BaselineWatch/blob/main/docs/PLAN.md" target="_blank" rel="noopener">What comes next</a>');
    expect(text).toMatch(/<a class="n" href="\/standards\/nist-sp-800-53">0 snapshots · 0 changes<\/a>/);
  });

  it("serves the Sources register and an empty Wire", async () => {
    const text = await (await fetch(`${app.base}/sources`)).text();
    expect(text).toContain("CISA Known Exploited Vulnerabilities");
    expect(text).toContain("r/netsec");
    // Each group heads to the News filtered to it, its count to the table, and an item count to that source's items.
    expect(text).toMatch(/<section id="standards">\s*<h2><a href="\/\?group=standards">Standards and baselines<\/a> <span class="count"><a href="#standards">\d+<\/a><\/span><\/h2>/);
    expect(text).toContain('<td class="n"><a href="/?source=cisa-kev">0</a></td>');
    const wire = await (await fetch(`${app.base}/wire`)).text();
    expect(wire).toContain("Nothing here yet.");
    expect(wire).toContain('<h2><a href="/sources">Sources</a> <span class="count"><a href="/?unread=1">0 unread</a></span></h2>');
    expect(wire).toContain('<a href="/">All sources</a><b><a href="/?unread=1">0</a></b>');
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
    expect(home).toContain('<a class="cap" href="/guide#ladder">');
    // The Standards menu is the ladder, each rung with the line that says what it is.
    expect(home).toContain('<a class="entry" href="/standards"><b>Standards</b><small>the rulebooks this instance tracks</small></a>');
    expect(home).toContain("<b>Baselines</b><small>the set of rules chosen for a platform</small>");
    expect(home).toContain("<b>Controls</b><small>one rule at a time, and what changed</small>");
    expect(home).toContain('<a href="/guide">how to read this site</a>');
  });

  it("sends strict security headers and no inline script", async () => {
    const response = await fetch(`${app.base}/`);
    expect(response.headers.get("content-security-policy")).toContain("script-src 'none'");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-powered-by")).toBeNull();
    expect(await response.text()).not.toMatch(/<script/i);
  });

  it("lets the Scan page alone run its one script, under its own policy", async () => {
    const scan = await fetch(`${app.base}/scan`);
    expect(scan.status).toBe(200);
    const policy = scan.headers.get("content-security-policy") ?? "";
    expect(policy).toContain("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';");
    expect(policy).toContain("connect-src 'self' https://*.adguard-dns.com https://test.nextdns.io https://*.test.nextdns.io;");
    expect(policy).toContain("frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    expect(policy).not.toContain("unsafe-inline");
    expect(policy).not.toContain("script-src 'none'");
    expect(scan.headers.get("x-content-type-options")).toBe("nosniff");
    const text = await scan.text();
    expect(text.match(/<script/g)).toHaveLength(1);
    expect(text).toMatch(/<script type="module" src="\/assets\/scan\.js\?v=[^"]+"><\/script>/);
    for (const path of ["/", "/scan/why", "/scan/probe/control.gif", "/assets/scan.js", "/vulnerabilities"]) {
      const other = await fetch(`${app.base}${path}`);
      expect(other.headers.get("content-security-policy"), path).toContain("script-src 'none'");
      expect(other.headers.get("content-security-policy"), path).not.toContain("adguard");
    }
  });

  it("serves the stylesheet and a 404 page", async () => {
    const css = await fetch(`${app.base}/assets/app.css`);
    expect(css.status).toBe(200);
    expect(css.headers.get("content-type")).toMatch(/text\/css/);
    const missing = await fetch(`${app.base}/nope/<b>`);
    expect(missing.status).toBe(404);
    const text = await missing.text();
    expect(text).toContain("Nothing at");
    // The path is echoed escaped: the raw tag from the URL never reaches the page.
    expect(text).not.toContain("/nope/<b>");
    expect(text).toContain("&lt;b&gt;");
  });
});

describe("a request that is the client's fault", () => {
  it("is answered with its own status, not a 500 and a stack trace in the log", async () => {
    const app = await startTestApp();
    try {
      // 16 kB is the limit for every route but the builder's; a note this long is the client's doing.
      const big = await formPost(app.base, "/triage", { kind: "item", id: "1", state: "new", note: "x".repeat(40_000) });
      expect(big.status).toBe(413);
      expect(await big.text()).toContain("larger than this page accepts");
    } finally {
      await app.close();
    }
  });
});
