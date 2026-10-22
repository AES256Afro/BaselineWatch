import path from "node:path";
import { pathToFileURL } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { startTestApp } from "./helpers.ts";

type Row = { state: string; text: string; lines: string[] };
interface PrivacyScript {
  describeSignals(nav: Record<string, unknown>): Row;
  judgeWebRtc(result: { supported: boolean; candidates: string[]; error?: string }): Row;
  describeFingerprint(surface: Record<string, unknown>): Row;
  describeReferrer(same: { referer: string | null } | null, cross: { referer: string | null } | null, policy: string, pageUrl: string): Row;
  describeTransport(echo: Record<string, unknown> | null, nav: Record<string, unknown>): Row;
  privacyLine(sig: { state: string }, rtc: { state: string }, fp: { state: string }, ref: { state: string }): { seen: number; text: string };
  compareDotted(a: string, b: string): number;
  browserVersion(nav: Record<string, unknown>): Promise<{ family: string | null; version: string | null; os: { line: string; version: string } | null }>;
  describeOs(os: { line: string; version: string } | null, answer: Record<string, unknown> | null): { state: string; text: string } | null;
  describeVersion(who: { family: string | null; version: string | null }, answer: Record<string, unknown> | null): Row;
}
let s: PrivacyScript;
beforeAll(async () => {
  // The script is plain JS for the browser; the test loads it the way the other script test does.
  s = (await import(pathToFileURL(path.join(import.meta.dirname, "..", "public", "scan.js")).href)) as PrivacyScript;
});
const describeSignals: PrivacyScript["describeSignals"] = (nav) => s.describeSignals(nav);
const judgeWebRtc: PrivacyScript["judgeWebRtc"] = (r) => s.judgeWebRtc(r);
const describeFingerprint: PrivacyScript["describeFingerprint"] = (x) => s.describeFingerprint(x);
const describeReferrer: PrivacyScript["describeReferrer"] = (a, b, c, d) => s.describeReferrer(a, b, c, d);
const describeTransport: PrivacyScript["describeTransport"] = (a, b) => s.describeTransport(a, b);
const privacyLine: PrivacyScript["privacyLine"] = (a, b, c, d) => s.privacyLine(a, b, c, d);

/** What this browser gives away (Scan 2.0, S1): the judges, on what browsers actually hand a page. */

describe("privacy signals", () => {
  it("read GPC and DNT as sent", () => {
    expect(describeSignals({ globalPrivacyControl: true, doNotTrack: "1" })).toMatchObject({ state: "ok", text: "GPC sent" });
    expect(describeSignals({ globalPrivacyControl: true, doNotTrack: "1" }).lines[1]).toContain("DNT: 1 is sent");
    expect(describeSignals({})).toMatchObject({ state: "na", text: "No GPC" });
  });
});

describe("WebRTC candidates", () => {
  const host = (address: string) => `candidate:1 1 udp 2122260223 ${address} 54321 typ host generation 0`;
  it("tell an mDNS name from a LAN address from a public one, and no WebRTC from nothing offered", () => {
    expect(judgeWebRtc({ supported: true, candidates: [host("3f2a1b4c-aaaa-bbbb-cccc-123456789abc.local")] })).toMatchObject({ state: "ok", text: "Hidden (mDNS)" });
    expect(judgeWebRtc({ supported: true, candidates: [host("192.168.1.23"), host("x.local")] })).toMatchObject({ state: "warn", text: "LAN address exposed" });
    expect(judgeWebRtc({ supported: true, candidates: [host("203.0.113.9")] })).toMatchObject({ state: "bad", text: "Public address exposed" });
    expect(judgeWebRtc({ supported: true, candidates: [host("fd12:3456::1")] }).state).toBe("warn");
    expect(judgeWebRtc({ supported: true, candidates: [] })).toMatchObject({ state: "ok", text: "Nothing exposed" });
    expect(judgeWebRtc({ supported: false, candidates: [] })).toMatchObject({ state: "ok", text: "No WebRTC" });
  });
});

describe("the fingerprint surface", () => {
  const surface = { screen: "1512×982×30", dpr: 2, timezone: "America/Chicago", languages: "en-US,en", cores: 10, memory: 8, touch: 0, canvas: "a1b2c3d4e5f6", canvasAgain: "a1b2c3d4e5f6", fonts: ["Arial", "Georgia"] };
  it("calls a canvas that draws the same twice stable, and one that differs randomised", () => {
    const stable = describeFingerprint(surface);
    expect(stable).toMatchObject({ state: "warn", text: "Stable surface" });
    expect(stable.lines[1]).toBe("Canvas stable: the same drawing hashes to a1b2c3d4e5f6 every time.");
    expect(stable.lines[2]).toBe("2 of 12 common fonts detectable: Arial, Georgia.");
    expect(describeFingerprint({ ...surface, canvasAgain: "ffffffffffff" })).toMatchObject({ state: "ok", text: "Randomised" });
  });
});

describe("the referrer", () => {
  const page = "https://site.example/scan?x=1";
  it("reads what arrived against the policy", () => {
    expect(describeReferrer({ referer: page }, null, "strict-origin-when-cross-origin", page)).toMatchObject({ state: "ok", text: "Policy as set" });
    expect(describeReferrer({ referer: page }, { referer: "https://site.example/" }, "", page)).toMatchObject({ state: "ok", text: "Origin only" });
    expect(describeReferrer({ referer: page }, { referer: null }, "no-referrer", page)).toMatchObject({ state: "ok", text: "Nothing cross-site" });
    expect(describeReferrer({ referer: page }, { referer: page }, "unsafe-url", page)).toMatchObject({ state: "warn", text: "Full URL cross-site" });
    expect(describeReferrer(null, null, "", page).state).toBe("na");
    expect(describeReferrer({ referer: page }, null, "", page).lines[0]).toBe("To this site: the full address of this page.");
  });
});

describe("the transport and the tally", () => {
  it("say what the server saw", () => {
    expect(describeTransport({ family: "IPv6", httpVersion: "2.0", protocol: "https", tls: "TLSv1.3" }, {})).toMatchObject({ state: "ok", text: "IPv6 · HTTP/2.0" });
    const v4 = describeTransport({ family: "IPv4", httpVersion: "1.1", protocol: "https", tls: null }, { connection: { effectiveType: "4g", saveData: true } });
    expect(v4.lines).toEqual(["Reached this site over IPv4, HTTP/1.1 (TLS ended at the edge in front of the server).", "No IPv6 on this path: either the network has none or the browser preferred IPv4.", "The browser rates the connection 4g, with Save-Data on."]);
    expect(describeTransport(null, {}).state).toBe("na");
    expect(privacyLine({ state: "ok" }, { state: "ok" }, { state: "warn" }, { state: "ok" })).toEqual({ seen: 3, text: "Privacy: 3 of 4 — GPC sent ✓, WebRTC hidden ✓, fingerprint randomised ✗, referrer trimmed ✓." });
  });
});

describe("the echo", () => {
  it("answers what it received, readable from another origin, and the page carries the rows", async () => {
    const app = await startTestApp({ env: { BW_PROBE_ORIGIN: "https://probe.example.net/" } });
    try {
      const echo = await fetch(`${app.base}/scan/echo`, { headers: { referer: `${app.base}/scan`, origin: "https://other.example" } });
      expect(echo.headers.get("access-control-allow-origin")).toBe("*");
      expect(echo.headers.get("cache-control")).toBe("no-store");
      expect(await echo.json()).toMatchObject({ referer: `${app.base}/scan`, origin: "https://other.example", family: "IPv4", httpVersion: "1.1", protocol: "http", tls: null });
      const page = await fetch(`${app.base}/scan`);
      const text = await page.text();
      for (const id of ["signals", "webrtc", "fingerprint", "referrer", "transport"]) expect(text).toContain(`data-check="${id}"`);
      expect(text).toContain("What this browser gives away");
      expect(text).toContain('<p class="small" id="scan-privacy" hidden></p>');
      expect(page.headers.get("content-security-policy")).toContain("connect-src 'self' https://probe.example.net");
      const why = await (await fetch(`${app.base}/scan/why`)).text();
      for (const id of ["signals", "webrtc", "fingerprint", "referrer", "transport"]) expect(why).toContain(`<section class="box" id="${id}">`);
    } finally {
      await app.close();
    }
  });
});

describe("this browser's version", () => {
  it("reads the fullest version the browser gives, and judges it against the vendor's newest", async () => {
    const chrome = { userAgent: "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.8059.85 Safari/537.36", userAgentData: { getHighEntropyValues: async () => ({ fullVersionList: [{ brand: "Not;A=Brand", version: "99.0.0.0" }, { brand: "Google Chrome", version: "155.0.8059.85" }] }) } };
    expect(await s.browserVersion(chrome)).toEqual({ family: "chrome", version: "155.0.8059.85", os: null });
    expect(await s.browserVersion({ userAgent: "Mozilla/5.0 (X11; Linux) Gecko/20100101 Firefox/158.0" })).toEqual({ family: "firefox", version: "158.0", os: null });
    expect(await s.browserVersion({ userAgent: "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/26.1 Safari/605.1.15" })).toEqual({ family: "safari", version: "26.1", os: null });
    expect(await s.browserVersion({ userAgent: "Mozilla/5.0 (Windows) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.3351.55" })).toEqual({ family: "edge", version: "156.0.3351.55", os: null });
    expect(await s.browserVersion({ userAgent: "Mozilla/5.0 (Linux; Android) Chrome/156.0.0.0 SamsungBrowser/28.0" })).toMatchObject({ family: null, os: null });
    const iphone = await s.browserVersion({ userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 26_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.7 Mobile/15E148 Safari/604.1" });
    expect(iphone).toEqual({ family: "safari", version: "26.7", os: { line: "ios", version: "26.7.1" } });
    expect(s.describeOs(iphone.os, { latest: "26.7.1", newerLine: "27.0.1", newer: [] })).toEqual({ state: "ok", text: "iOS 26.7.1 is the newest of its line (26.7.1). iOS 27.0.1 exists for devices that support it." });
    expect(s.describeOs({ line: "ios", version: "26.7" }, { latest: "26.7.1", newerLine: null, newer: [{ version: "26.7.1" }] })).toMatchObject({ state: "warn", text: expect.stringContaining("Software Update") });
    expect(s.describeOs(null, null)).toBeNull();
    expect(s.compareDotted("156.0.8078.47", "156.0.8078.46")).toBeGreaterThan(0);
    expect(s.compareDotted("26.7", "26.7.1")).toBeLessThan(0);
    expect(s.describeVersion({ family: "chrome", version: "155.0.8059.85" }, { latest: "156.0.8078.47", newer: [{ version: "156.0.8078.47", title: "Stable Channel Update for Desktop", published: "2026-10-20T20:09:05.710Z" }, { version: "155.0.8059.130", title: "Stable Channel Update for Desktop", published: "2026-10-15" }] })).toMatchObject({ state: "bad", text: "Behind by 2" });
    expect(s.describeVersion({ family: "firefox", version: "158.0" }, { latest: "158.0.1", newer: [{ version: "158.0.1", title: "MFSA 2026-111", published: null }] })).toMatchObject({ state: "warn", text: "Behind by 1" });
    expect(s.describeVersion({ family: "safari", version: "26.1" }, { latest: "26.1", newer: [] })).toMatchObject({ state: "ok", text: "Current" });
    expect(s.describeVersion({ family: null, version: null }, null).state).toBe("na");
    expect(s.describeVersion({ family: "chrome", version: "1.0" }, { latest: null, newer: [] })).toMatchObject({ state: "na", text: "Unknown" });
  });
});
