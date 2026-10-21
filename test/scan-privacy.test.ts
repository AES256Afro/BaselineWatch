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
