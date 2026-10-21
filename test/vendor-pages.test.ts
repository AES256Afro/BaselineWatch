import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { appleLine, appleReleasesUrl, parseAppleReleases } from "../src/adapters/apple-security.ts";
import { parseMfsaIndex } from "../src/adapters/mozilla-mfsa.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { fakeHttp, fixture } from "./helpers.ts";

/**
 * The two vendors that publish no feed (N5): Apple's security releases table and Mozilla's
 * advisory index, each the real page as served on 2026-10-21, cut short.
 */

const text = (name: string) => new TextDecoder().decode(fixture(name));
const now = new Date("2026-10-21T22:00:00Z");

describe("Apple's security releases table", () => {
  const items = parseAppleReleases(text("apple/releases.html"));

  it("reads each row: the linked ones by article number, the unlinked ones by name and date", () => {
    expect(items.length).toBeGreaterThanOrEqual(25);
    const linked = items.find((i) => i.externalId === "149226")!;
    expect(linked.title).toBe("iOS 26.7.1 and iPadOS 26.7.1");
    expect(linked.url).toBe("https://support.apple.com/en-us/149226");
    expect(linked.publishedAt).toBe("2026-09-28T12:00:00.000Z");
    expect(linked.summary).toMatch(/^For iPhone 11 and later/);
    expect(linked.signals).toMatchObject({ line: "iOS" });
    const unlinked = items.find((i) => i.title === "iOS 27.0.1 and iPadOS 27.0.1")!;
    expect(unlinked.externalId).toBe("iOS 27.0.1 and iPadOS 27.0.1@2026-09-28");
    expect(unlinked.url).toBe(appleReleasesUrl);
    expect(unlinked.summary).toBe("This update has no published CVE entries.");
  });

  it("names the line from the release's first word", () => {
    expect(appleLine("macOS Golden Gate 27.0.1")).toBe("macOS");
    expect(appleLine("Safari 26.1")).toBe("Safari");
    expect(items.map((i) => (i.signals as { line: string }).line)).toContain("macOS");
  });

  it("keeps the newest rows only", () => {
    expect(parseAppleReleases(text("apple/releases.html"), 3).length).toBe(3);
  });
});

describe("Mozilla's advisory index", () => {
  const items = parseMfsaIndex(text("mozilla/advisories.html"));

  it("reads each advisory under its dated heading, with the impact and the product fixed", () => {
    expect(items.length).toBeGreaterThanOrEqual(12);
    const first = items[0]!;
    expect(first.externalId).toBe("mfsa2026-116");
    expect(first.title).toBe("MFSA 2026-116: Security Vulnerabilities fixed in Firefox for Android 158.0.2");
    expect(first.url).toBe("https://www.mozilla.org/en-US/security/advisories/mfsa2026-116/");
    expect(first.publishedAt).toBe("2026-10-21T12:00:00.000Z");
    expect(first.summary).toBe("Impact high. Firefox for Android 158.0.2.");
    expect(first.signals).toEqual({ impact: "high", product: "Firefox for Android 158.0.2" });
    expect(items[1]?.externalId).toBe("mfsa2026-115");
    expect(items[1]?.publishedAt).toBe("2026-10-20T12:00:00.000Z");
  });

  it("keeps the newest advisories only", () => {
    expect(parseMfsaIndex(text("mozilla/advisories.html"), 2).map((i) => i.externalId)).toEqual(["mfsa2026-116", "mfsa2026-115"]);
  });
});

describe("through the pipeline", () => {
  let db: DatabaseSync;
  let dataDir: string;
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-vendor-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("stores both pages' items under the vulnerabilities group, and a page with no rows is a failure", async () => {
    for (const [id, name] of [["apple-security", "apple/releases.html"], ["mozilla-mfsa", "mozilla/advisories.html"]] as const) {
      const source = getSource(db, id)!;
      expect(source.group_name).toBe("vulnerabilities");
      const result = await ingestSource(db, dataDir, source, { http: fakeHttp({ [source.url]: { bytes: fixture(name) } }), now: () => now });
      expect(result.status).toBe("ok");
      expect(result.inserted).toBeGreaterThanOrEqual(12);
      const broken = await ingestSource(db, dataDir, source, { http: fakeHttp({ [source.url]: { text: "<html><body>moved</body></html>" } }), now: () => now });
      expect(broken.status).toBe("error");
      expect(broken.error).toMatch(/no (rows|advisories) BaselineWatch could read/);
    }
  });
});
