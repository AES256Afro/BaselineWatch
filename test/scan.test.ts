import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.ts";
import { probePaths } from "../src/scan.ts";
import { startTestApp, type TestApp } from "./helpers.ts";

let app: TestApp;
let withProbe: TestApp;

beforeAll(async () => {
  app = await startTestApp();
  withProbe = await startTestApp({ env: { BW_PROBE_ORIGIN: "https://probe.example.net/" } });
});

afterAll(async () => {
  await app.close();
  await withProbe.close();
});

describe("the Scan page", () => {
  it("renders the five rows at not run, the run button, the limits and privacy boxes and the one module script", async () => {
    const response = await fetch(`${app.base}/scan`);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const text = await response.text();
    for (const id of ["hiding", "requests", "dns", "apps", "network"]) expect(text).toContain(`data-check="${id}"`);
    expect(text.match(/<span class="state na">Not run<\/span>/g)).toHaveLength(3);
    expect(text.match(/Not a page's to test/g)).toHaveLength(1);
    expect(text).toContain("Not run from this server");
    expect(text).toContain('<a href="/scan/network">network check</a>');
    expect(text).toContain('<button type="button" class="primary" id="scan-run" disabled>Run the check</button>');
    expect(text).toContain("Limits of this check");
    expect(text).toContain("Privacy of the test");
    expect(text).toContain("The one page with a script");
    for (const id of ["hiding", "requests", "dns"]) expect(text).toContain(`href="/scan/why#${id}"`);
    expect(text).toContain('<a class="entry" href="/scan" aria-current="page"><b>This browser</b>');
    expect(text).toContain('data-probe-origin=""');
    expect(text).toContain("3 test images, 2 controls");
    expect(text).toContain('<section class="scan" id="scan"');
    expect(text).toContain('<div class="verdict" id="scan-verdict" hidden>');
    expect(text).toContain('<div class="fix" id="fix-requests" hidden>');
    expect(text).toContain('<div class="fix" id="fix-dns" hidden>');
    for (const key of ["firefox", "chrome", "edge", "safari", "brave", "inapp", "other"]) expect(text).toContain(`<li data-for="${key}">`);
    for (const key of ["macos", "ios", "windows", "android", "linux"]) expect(text).toContain(`<li data-for="${key}">`);
    expect(text.match(/data-guide/g)).toHaveLength(2);
    expect(text).toContain("How this row is tested");
    expect(text).toContain('id="scan-open" hidden');
    expect(text).not.toMatch(/<script>/);
    expect(text).not.toMatch(/ style="/);
    expect(text).toContain('<p class="crumbs"><a href="/">Home</a><span>›</span><b>Scan</b></p>');
  });

  it("names the probe origin for the script and allows its images when one is set", async () => {
    const response = await fetch(`${withProbe.base}/scan`);
    expect(response.headers.get("content-security-policy")).toContain("img-src 'self' data: https://probe.example.net;");
    const text = await response.text();
    expect(text).toContain('data-probe-origin="https://probe.example.net"');
    expect(text).toContain("6 test images, 4 controls");
    expect(text).toContain("and on one cross-site host");
    const home = await fetch(`${withProbe.base}/`);
    expect(home.headers.get("content-security-policy")).not.toContain("probe.example.net");
  });

  it("refuses a probe origin that is more than an origin", () => {
    expect(() => loadConfig({ BW_PROBE_ORIGIN: "https://probe.example.net/scan" })).toThrow(/http\(s\) origin/);
    expect(() => loadConfig({ BW_PROBE_ORIGIN: "probe.example.net" })).toThrow(/http\(s\) origin/);
    expect(() => loadConfig({ BW_PROBE_ORIGIN: "ftp://probe.example.net" })).toThrow(/http\(s\) origin/);
    expect(loadConfig({ BW_PROBE_ORIGIN: "https://probe.example.net:8443/" }).probeOrigin).toBe("https://probe.example.net:8443");
    expect(loadConfig({ BW_PROBE_ORIGIN: " " }).probeOrigin).toBeNull();
  });

  it("serves the script as a JavaScript module from /assets", async () => {
    const response = await fetch(`${app.base}/assets/scan.js`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toMatch(/javascript/);
    const text = await response.text();
    expect(text).toContain("export function wire(");
    expect(text).not.toMatch(/\beval\(/);
    expect(text).not.toMatch(/new Function\(/);
    expect(text).not.toMatch(/innerHTML/);
  });

  it("serves the probe images with identical bytes, no caching and open cross-origin reads", async () => {
    expect(probePaths).toEqual(["/scan/probe/control.gif", "/scan/probe/ad_images/1.gif", "/scan/probe/adsbanner-1.gif", "/scan/probe/ad_skyscraper.gif"]);
    const bodies: string[] = [];
    for (const path of probePaths) {
      const response = await fetch(`${app.base}${path}?r=abc123`);
      expect(response.status, path).toBe(200);
      expect(response.headers.get("content-type"), path).toBe("image/gif");
      expect(response.headers.get("cache-control"), path).toBe("no-store");
      expect(response.headers.get("access-control-allow-origin"), path).toBe("*");
      expect(response.headers.get("cross-origin-resource-policy"), path).toBe("cross-origin");
      const bytes = new Uint8Array(await response.arrayBuffer());
      expect(bytes.length, path).toBe(42);
      expect(new TextDecoder().decode(bytes.subarray(0, 6)), path).toBe("GIF89a");
      bodies.push(Buffer.from(bytes).toString("base64"));
    }
    expect(new Set(bodies).size).toBe(1);
    const missing = await fetch(`${app.base}/scan/probe/other.gif`);
    expect(missing.status).toBe(404);
  });

  it("explains why on /scan/why with the primary sources and the row anchors", async () => {
    const response = await fetch(`${app.base}/scan/why`);
    expect(response.status).toBe(200);
    const text = await response.text();
    for (const id of ["ads", "hiding", "requests", "dns", "harden"]) expect(text).toContain(`id="${id}"`);
    for (const host of ["citizenlab.ca", "easylist.to", "ublockorigin.com", "adguard-dns.io", "test.nextdns.io", "docs.pi-hole.net", "support.apple.com/en-us/105120", "docs.mvt.re"]) {
      expect(text, host).toContain(`href="https://${host}`);
    }
    expect(text).toContain("/ad_images/*$image");
    expect(text).toContain('<a href="/scan">Scan</a><span>›</span><b>Why these checks</b>');
    expect(text).not.toMatch(/<script/);
  });
});
