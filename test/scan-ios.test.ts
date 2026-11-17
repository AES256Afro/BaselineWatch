import path from "node:path";
import { pathToFileURL } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

/**
 * The browser check on an iPhone or iPad (public/scan.js): since iOS 26 WebKit freezes the user
 * agent's OS token at "iPhone OS 18_6" (WebKit bug 298260), so the OS line is read from Safari's
 * own version or left unread, and Safari on the device is judged through the OS, never against
 * Safari for macOS.
 */

type Os = { line: string; version: string | null; source?: string } | null;
interface Script {
  browserVersion(nav: Record<string, unknown>): Promise<{ family: string | null; version: string | null; os: Os }>;
  describeOs(os: Os, answer: Record<string, unknown> | null): { state: string; text: string } | null;
  describeVersion(who: { family: string | null; version: string | null; os?: Os }, answer: Record<string, unknown> | null): { state: string; text: string; lines: string[] };
  isMobileSafari(who: { family: string | null; os?: Os }): boolean;
}
let s: Script;
beforeAll(async () => {
  s = (await import(pathToFileURL(path.join(import.meta.dirname, "..", "public", "scan.js")).href)) as Script;
});

const frozenSafari = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Mobile/15E148 Safari/604.1";

describe("an iPhone's iOS version", () => {
  it("is read from Safari's version when the OS token is the frozen 18_6", async () => {
    const who = await s.browserVersion({ userAgent: frozenSafari });
    expect(who).toEqual({ family: "safari", version: "26.1", os: { line: "ios", version: "26.1", source: "safari" } });
    expect(s.isMobileSafari(who)).toBe(true);
  });

  it("stays 18.6 on a real iOS 18.6, and is left unread in another browser on a frozen token", async () => {
    expect((await s.browserVersion({ userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1" })).os).toEqual({ line: "ios", version: "18.6" });
    const chrome = await s.browserVersion({ userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/156.0.8078.50 Mobile/15E148 Safari/604.1" });
    expect(chrome.os).toEqual({ line: "ios", version: null, source: "frozen" });
    expect(s.describeOs(chrome.os, null)).toMatchObject({ state: "na", text: expect.stringContaining("does not state the iOS version") });
  });

  it("is judged at the precision Safari gives: a newer minor is behind, a newer patch is not known", () => {
    const os = { line: "ios", version: "26.1", source: "safari" };
    // 26.1 against 26.1.2: Safari does not say the patch level, so this is neither current nor behind.
    expect(s.describeOs(os, { latest: "26.1.2", newerLine: null, newer: [{ version: "26.1.1" }, { version: "26.1.2" }] })).toMatchObject({ state: "na", text: expect.stringContaining("read from Safari's version") });
    expect(s.describeOs(os, { latest: "26.1", newerLine: null, newer: [] })).toMatchObject({ state: "ok" });
    const behind = s.describeOs(os, { latest: "26.3.1", newerLine: null, newer: [{ version: "26.1.1" }, { version: "26.2" }, { version: "26.3.1" }] });
    expect(behind).toMatchObject({ state: "bad", text: expect.stringContaining("is behind 26.3.1: 2 newer releases") });
    // Never "18.6 is behind 18.7.10".
    expect(behind!.text).not.toContain("18.6");
  });
});

describe("Safari on an iPhone or iPad", () => {
  it("is judged through the OS, not against Safari for macOS", async () => {
    const who = await s.browserVersion({ userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.7 Mobile/15E148 Safari/604.1" });
    const row = s.describeVersion(who, { latest: "27.0", newer: [{ version: "27.0", title: "Safari 27", published: null }] });
    expect(row).toMatchObject({ state: "na", text: "With the OS" });
    expect(row.lines[0]).toContain("not against Safari for macOS");
    const ipad = await s.browserVersion({ userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Safari/605.1.15", maxTouchPoints: 5 });
    expect(ipad.os).toEqual({ line: "ipados", version: "26.1", source: "safari" });
    expect(s.isMobileSafari(ipad)).toBe(true);
    // A Mac stays a Mac.
    const mac = await s.browserVersion({ userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Safari/605.1.15", maxTouchPoints: 0 });
    expect(mac.os).toBeNull();
    expect(s.describeVersion(mac, { latest: "27.0", newer: [{ version: "27.0", title: "Safari 27", published: null }] })).toMatchObject({ state: "warn", text: "Behind by 1" });
  });
});
