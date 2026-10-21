import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { endoflifeBase, eolItems, parseEolProduct } from "../src/adapters/endoflife.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { eolCyclesFor, eolFor, eolProducts, eolWord } from "../src/eol.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { fakeHttp, fixture, startTestApp } from "./helpers.ts";

/** endoflife.date (N5): the seven products' files as served on 2026-10-21. */

const now = new Date("2026-10-21T22:00:00Z");
const text = (p: string) => new TextDecoder().decode(fixture(`endoflife/${p}.json`));

describe("a product's file", () => {
  it("becomes rows with the dates as published and the flags as words", () => {
    const rows = parseEolProduct("windows", text("windows"));
    const home = rows.find((r) => r.cycle === "11-24h2-w")!;
    expect(home).toMatchObject({ product: "windows", label: "11 24H2 (W)", eol: "2026-10-13", support: "2026-10-13", latest: "10.0.26100" });
    const mac = parseEolProduct("macos", text("macos")).find((r) => r.cycle === "27")!;
    expect(mac).toMatchObject({ label: "Golden Gate", eol: "false", support: null, latest: "27.0.1" });
    expect(eolWord(mac.eol)).toBe("not yet");
    expect(eolWord("2026-10-13")).toBe("2026-10-13");
    expect(() => parseEolProduct("x", '{"a":1}')).toThrow(/not the list/);
  });

  it("makes an item for a cycle near or just past its end, and none for the rest", () => {
    const items = eolItems(parseEolProduct("windows", text("windows")), now);
    const ended = items.find((i) => i.externalId === "windows:11-24h2-w")!;
    expect(ended.title).toBe("Windows 11 24H2 (W) support ended 2026-10-13");
    expect(ended.publishedAt).toBe("2026-07-15T00:00:00.000Z");
    expect(ended.signals).toMatchObject({ ended: true, eol: "2026-10-13" });
    expect(items.some((i) => i.externalId === "windows:11-24h2-e")).toBe(false);
    // macOS 14 ended 37 days ago: past the month's grace, so no longer news.
    expect(eolItems(parseEolProduct("macos", text("macos")), now).some((i) => i.externalId === "macos:14")).toBe(false);
  });
});

describe("the fleet's releases", () => {
  it("map to endoflife.date's cycles, Windows to its two editions", () => {
    expect(eolCyclesFor("windows", "24H2")).toEqual([{ product: "windows", cycle: "11-24h2-w", edition: "Home and Pro" }, { product: "windows", cycle: "11-24h2-e", edition: "Enterprise and Education" }]);
    expect(eolCyclesFor("windows", "10-22H2").map((c) => c.cycle)).toEqual(["10-22h2-w", "10-22h2-e"]);
    expect(eolCyclesFor("macos", "27")).toEqual([{ product: "macos", cycle: "27", edition: null }]);
    expect(eolCyclesFor("linux", "rhel-9")).toEqual([{ product: "rhel", cycle: "9", edition: null }]);
    expect(eolCyclesFor("linux", "ubuntu-24.04")).toEqual([{ product: "ubuntu", cycle: "24.04", edition: null }]);
    expect(eolCyclesFor("collaboration", "zoom-rooms-2026")).toEqual([]);
  });
});

describe("the pull", () => {
  it("reads the seven products, keeps their cycles, and answers a fleet release", async () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-eol-"));
    try {
      const source = getSource(db, "endoflife")!;
      expect(source.url).toBe(endoflifeBase);
      const routes = Object.fromEntries(eolProducts.map((p) => [`${endoflifeBase}${p}.json`, { bytes: fixture(`endoflife/${p}.json`) }]));
      const result = await ingestSource(db, dataDir, source, { http: fakeHttp(routes), now: () => now });
      expect(result.status).toBe("ok");
      expect(result.items).toBeGreaterThan(150);
      expect(result.detail).toMatch(/cycles across 7 products; \d+ ending inside the window/);
      const win = eolFor(db, "windows", "24H2");
      expect(win.map((c) => [c.edition, c.eol])).toEqual([["Home and Pro", "2026-10-13"], ["Enterprise and Education", "2027-10-12"]]);
      expect(eolFor(db, "linux", "rhel-9")[0]).toMatchObject({ eol: "2032-05-31", support: "2027-05-31" });
      const items = db.prepare("SELECT external_id, title FROM items WHERE source_id = 'endoflife' ORDER BY external_id").all() as { external_id: string; title: string }[];
      expect(items.some((i) => i.external_id === "windows:11-24h2-w")).toBe(true);
      // A second read replaces, never doubles.
      await ingestSource(db, dataDir, source, { http: fakeHttp(routes), now: () => now });
      expect((db.prepare("SELECT COUNT(*) AS n FROM eol_cycles").get() as { n: number }).n).toBe(result.items);
    } finally {
      db.close();
      rmSync(dataDir, { recursive: true, force: true });
    }
  });
});

describe("the Fleet page", () => {
  it("shows the vendor's end beside the owner's date, per edition", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      const routes = Object.fromEntries(eolProducts.map((p) => [`${endoflifeBase}${p}.json`, { bytes: fixture(`endoflife/${p}.json`) }]));
      await ingestSource(app.db, app.dataDir, getSource(app.db, "endoflife")!, { http: fakeHttp(routes), now: () => now });
      const page = await (await fetch(`${app.base}/fleet`)).text();
      expect(page).toContain("endoflife.date: Home and Pro 2026-10-13 · latest 10.0.26100 · Enterprise and Education 2027-10-12 · latest 10.0.26100");
      expect(page).toContain("endoflife.date: 2032-05-31 (support 2027-05-31) · latest 9.");
    } finally {
      await app.close();
    }
  });
});
