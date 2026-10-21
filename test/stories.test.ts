import { describe, expect, it } from "vitest";
import { upsertItems } from "../src/items.ts";
import { startTestApp } from "./helpers.ts";

/** One story from several sources is one card on the News (N6). */

const now = new Date("2026-10-21T22:00:00Z");
const at = now.toISOString();

describe("the News", () => {
  it("draws a story once and names the other sources on it, by address or by headline", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      const db = app.db;
      upsertItems(db, "bleeping", [
        { kind: "article", externalId: "s1", title: "Vendor patches the thing", url: "https://vendor.example/advisory?utm_source=rss", summary: null, publishedAt: "2026-10-21T12:00:00.000Z" },
        { kind: "article", externalId: "s2", title: "Same headline, different link", url: "https://b/2", summary: null, publishedAt: "2026-10-21T11:00:00.000Z" },
        { kind: "article", externalId: "s3", title: "Same headline, different link", url: "https://b/3", summary: null, publishedAt: "2026-10-21T10:00:00.000Z" },
      ], at);
      upsertItems(db, "krebs", [
        { kind: "article", externalId: "k1", title: "Krebs: vendor patches the thing", url: "https://vendor.example/advisory", summary: null, publishedAt: "2026-10-21T11:30:00.000Z" },
        { kind: "article", externalId: "k2", title: "Same headline, different link", url: "https://k/2", summary: null, publishedAt: "2026-10-21T09:00:00.000Z" },
      ], at);
      const page = await (await fetch(`${app.base}/?group=news`)).text();
      // The same advisory from two sources: once, with the other named.
      expect(page.match(/vendor\.example\/advisory/g)?.length).toBe(2);
      expect(page).toContain('<a class="chip also" href="https://vendor.example/advisory" target="_blank" rel="noopener">also on Krebs on Security</a>');
      expect(page).not.toContain("Krebs: vendor patches the thing</a></h3>");
      // The same headline from two sources: once; the same source twice is two items.
      expect(page).toContain('also on Krebs on Security</a>');
      expect(page.match(/Same headline, different link<\/a><\/h3>/g)?.length).toBe(2);
    } finally {
      await app.close();
    }
  });
});
