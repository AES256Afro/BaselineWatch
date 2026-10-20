import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { guidePlatforms, guideSections } from "../src/pages/scan-guide.ts";
import { startTestApp, type TestApp } from "./helpers.ts";

let app: TestApp;

beforeAll(async () => {
  app = await startTestApp();
});

afterAll(async () => {
  await app.close();
});

describe("the manual guide", () => {
  it("lists the five platforms and both scripts with their sums on /scan/guide", async () => {
    const response = await fetch(`${app.base}/scan/guide`);
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).toContain('<a href="/scan">Scan</a><span>›</span><b>Do it by hand</b>');
    for (const platform of guidePlatforms) expect(text).toContain(`href="/scan/guide/${platform.id}"`);
    expect(text).toContain('href="/scan/scripts/bw-check.ps1" download');
    expect(text).toContain('href="/scan/scripts/bw-check.sh" download');
    expect(text).toContain('href="/scan/scripts/SHA256SUMS"');
    expect(text.match(/<code class="sum">[0-9a-f]{64}<\/code>/g)).toHaveLength(2);
    expect(text).toContain('<a href="/scan" aria-current="page">Scan</a>');
    expect(text).toContain('href="/scan/why"');
    expect(text).not.toMatch(/<script/);
    expect(text).not.toMatch(/ style="/);
    expect(response.headers.get("content-security-policy")).toContain("script-src 'none'");
  });

  it("renders each platform with breadcrumbs, the router and network sections, why links and primary sources", async () => {
    for (const platform of guidePlatforms) {
      const response = await fetch(`${app.base}/scan/guide/${platform.id}`);
      expect(response.status, platform.id).toBe(200);
      const text = await response.text();
      expect(text, platform.id).toContain(`<a href="/scan/guide">Do it by hand</a><span>›</span><b>${platform.label}</b>`);
      expect(text, platform.id).toContain(`<h1>Do it by hand <span class="arrow">${platform.label}</span></h1>`);
      expect(text, platform.id).toContain(`Pick a platform: `);
      // The picker and the aside name the current platform without linking it to itself.
      expect(text, platform.id).toContain(`<b>${platform.label}</b>`);
      expect(text, platform.id).not.toContain(`href="/scan/guide/${platform.id}"`);
      for (const id of ["dns", "blocker", "router", "network", "past"]) expect(text, `${platform.id} ${id}`).toContain(`id="${id}"`);
      for (const anchor of ["dns", "router", "upnp", "exposure", "bypass", "device"]) expect(text, `${platform.id} why#${anchor}`).toContain(`href="/scan/why#${anchor}"`);
      for (const href of [
        "https://www.cisa.gov/news-events/news/home-network-security",
        "https://www.kb.cert.org/vuls/id/357851",
        "https://internetdb.shodan.io/",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "https://docs.mvt.re/en/latest/",
      ]) {
        expect(text, `${platform.id} ${href}`).toContain(`href="${href}`);
      }
      expect(text, platform.id).toContain('<a href="/scan" aria-current="page">Scan</a>');
      expect(text, platform.id).toContain("<b>Clean:</b>");
      expect(text, platform.id).toContain("<b>A finding:</b>");
      expect(text, platform.id).not.toMatch(/<script/);
      expect(text, platform.id).not.toMatch(/ style="/);
      // Other platforms are linked from the aside; the current one is not linked to itself there.
      for (const other of guidePlatforms) {
        if (other.id !== platform.id) expect(text, `${platform.id} -> ${other.id}`).toContain(`<dt><a href="/scan/guide/${other.id}">${other.label}</a></dt>`);
      }
    }
  });

  it("gives each computer its script with the sum and the phones the MVT pointer instead", async () => {
    const windows = await (await fetch(`${app.base}/scan/guide/windows`)).text();
    expect(windows).toContain("Get-NetFirewallProfile");
    expect(windows).toContain("Resolve-DnsName ad.doubleclick.net");
    expect(windows).toContain('href="/scan/scripts/bw-check.ps1" download');
    expect(windows).toContain("Get-FileHash");
    expect(windows).not.toContain("bw-check.sh");
    const macos = await (await fetch(`${app.base}/scan/guide/macos`)).text();
    expect(macos).toContain("socketfilterfw");
    expect(macos).toContain("Lockdown Mode");
    expect(macos).toContain('href="/scan/scripts/bw-check.sh" download');
    expect(macos).toContain("shasum -a 256");
    expect(macos).not.toContain("bw-check.ps1");
    const linux = await (await fetch(`${app.base}/scan/guide/linux`)).text();
    expect(linux).toContain("resolvectl status");
    expect(linux).toContain("nft list ruleset");
    expect(linux).toContain('href="/scan/scripts/bw-check.sh" download');
    for (const phone of ["ios", "android"]) {
      const text = await (await fetch(`${app.base}/scan/guide/${phone}`)).text();
      expect(text, phone).toContain("No script for phones");
      expect(text, phone).toContain("https://docs.mvt.re/en/latest/");
      expect(text, phone).not.toContain('href="/scan/scripts/bw-check');
      expect(text, phone).toContain("No firewall to check on the phone");
    }
    const ios = await (await fetch(`${app.base}/scan/guide/ios`)).text();
    expect(ios).toContain("https://support.apple.com/en-us/105120");
    expect(ios).toContain("VPN &amp; Device Management");
    const android = await (await fetch(`${app.base}/scan/guide/android`)).text();
    expect(android).toContain("Private DNS");
    expect(android).toContain("https://support.google.com/android/answer/9654714");
  });

  it("cites a primary https source on every step and points every why link at a section that exists", async () => {
    const why = await (await fetch(`${app.base}/scan/why`)).text();
    for (const platform of guidePlatforms) {
      for (const section of guideSections(platform.id)) {
        expect(section.steps.length, `${platform.id} ${section.id}`).toBeGreaterThan(0);
        for (const step of section.steps) {
          expect(step.sources.length, `${platform.id} ${section.id} "${step.title}"`).toBeGreaterThan(0);
          for (const source of step.sources) expect(source.href, `${platform.id} ${step.title}`).toMatch(/^https:\/\/[^ "]+$/);
          if (step.more) expect(why, `${platform.id} ${step.title} -> why#${step.more}`).toContain(`id="${step.more}"`);
        }
      }
    }
  });

  it("answers 404 for a platform it does not have", async () => {
    const response = await fetch(`${app.base}/scan/guide/beos`);
    expect(response.status).toBe(404);
  });

  it("links the browser check and the why page to the guides, and the why page carries the router and network sections", async () => {
    const scan = await (await fetch(`${app.base}/scan`)).text();
    expect(scan).toContain('href="/scan/guide"');
    for (const platform of guidePlatforms) expect(scan).toContain(`href="/scan/guide/${platform.id}"`);
    expect(scan).toContain('href="/scan/guide/windows#router"');
    const why = await (await fetch(`${app.base}/scan/why`)).text();
    for (const id of ["ads", "hiding", "requests", "dns", "router", "upnp", "exposure", "bypass", "device", "harden"]) {
      expect(why, id).toContain(`id="${id}"`);
      expect(why, id).toContain(`href="#${id}"`);
    }
    expect(why).toContain('href="/scan/guide"');
    expect(why).toContain('href="/scan/guide/windows#router"');
    expect(why).toContain('href="/scan/guide/android#dns"');
    for (const host of ["www.cisa.gov/news-events/news/home-network-security", "www.kb.cert.org/vuls/id/357851", "openconnectivity.org", "internetdb.shodan.io", "www.rfc-editor.org/rfc/rfc8484", "discourse.pi-hole.net"]) {
      expect(why, host).toContain(`href="https://${host}`);
    }
    expect(why).not.toMatch(/<script/);
  });
});
