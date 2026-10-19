import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseNewsbitesIndex, parseNewsbitesIssue, sansNewsbitesAdapter } from "../src/adapters/sans-newsbites.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { fakeHttp, fixture } from "./helpers.ts";

const text = (name: string) => new TextDecoder().decode(fixture(`sans-newsbites/${name}`));

describe("SANS NewsBites index", () => {
  it("reads each card's slug, title and date, newest first", () => {
    const issues = parseNewsbitesIndex(text("index.html"));
    expect(issues).toHaveLength(12);
    expect(issues[0]).toEqual({
      slug: "xxviii-77",
      url: "https://www.sans.org/newsletters/newsbites/xxviii-77",
      title: "Microsoft Patches 1,400+ Flaws, Debuts Risk Cohorts System; Cisco Secure Email Gateway Vulnerability Exploited; Ivanti Patches Exploited Connect Secure Flaw",
      publishedAt: "2026-10-16T12:00:00.000Z",
    });
    expect(issues[1]!.slug).toBe("xxviii-76");
    expect(issues[1]!.publishedAt).toBe("2026-10-13T12:00:00.000Z");
    expect(parseNewsbitesIndex("<html></html>")).toEqual([]);
  });
});

describe("SANS NewsBites issue page", () => {
  const issue = { slug: "xxviii-77", url: "https://www.sans.org/newsletters/newsbites/xxviii-77", title: "Issue 77", publishedAt: "2026-10-16T12:00:00.000Z" };

  it("reads one story per section and not the duplicates in the page's script payload", () => {
    const items = parseNewsbitesIssue(text("issue-xxviii-77.html"), issue);
    expect(items).toHaveLength(9);
    expect(items[0]).toMatchObject({
      kind: "article",
      externalId: "xxviii-77#1",
      title: "Microsoft Releases 1,400+ Patches and “Risk Cohorts” System",
      url: "https://isc.sans.edu/diary/33422", // the first read-more link, trimmed of SANS's trailing space
      publishedAt: "2026-10-14T12:00:00.000Z", // the story's own date, not the issue's
      signals: { issue: "xxviii-77", cves: ["CVE-2026-96951"] },
    });
    expect(items[0]!.summary).toMatch(/^Microsoft's Patch Tuesday release for October 2026/);
    expect(items[0]!.summary!.length).toBeLessThanOrEqual(400);
    expect(items[8]!.externalId).toBe("xxviii-77#9");
    expect(items.every((i) => i.url!.startsWith("https://"))).toBe(true);
    expect(parseNewsbitesIssue("<html></html>", issue)).toEqual([]);
  });

  it("falls back to the issue's URL and date when a story names no link or date", () => {
    const bare = '<section class="c-newsletter-news"><header><h3>A story</h3></header><div class="c-rich-text"><p>Body.</p></div></section>';
    const items = parseNewsbitesIssue(bare, issue);
    expect(items).toEqual([
      {
        kind: "article",
        externalId: "xxviii-77#1",
        title: "A story",
        url: issue.url,
        summary: "Body.",
        publishedAt: "2026-10-16T12:00:00.000Z",
        signals: { issue: "xxviii-77" },
      },
    ]);
  });
});

describe("SANS NewsBites adapter end to end", () => {
  let db: ReturnType<typeof openDatabase>;
  let dataDir = "";
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-sans-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("fetches the two newest unseen issues once each, snapshots the pages, and stores every story", async () => {
    const source = getSource(db, "sans-newsbites")!;
    expect(source.group_name).toBe("news");
    expect(source.schedule).toBe("daily");
    const http = fakeHttp({
      [source.url]: { bytes: fixture("sans-newsbites/index.html"), contentType: "text/html" },
      "https://www.sans.org/newsletters/newsbites/xxviii-77": { bytes: fixture("sans-newsbites/issue-xxviii-77.html"), contentType: "text/html" },
      "https://www.sans.org/newsletters/newsbites/xxviii-76": { bytes: fixture("sans-newsbites/issue-xxviii-76.html"), contentType: "text/html" },
    });
    const first = await ingestSource(db, dataDir, source, { http, now: () => new Date("2026-10-17T10:00:00Z") });
    expect(first.status).toBe("ok");
    expect(first.inserted).toBe(18);
    expect(first.detail).toBe("2 new issue(s) of 12 listed");
    expect(http.calls.map((c) => c.url)).toEqual([source.url, "https://www.sans.org/newsletters/newsbites/xxviii-77", "https://www.sans.org/newsletters/newsbites/xxviii-76"]);
    expect((db.prepare("SELECT COUNT(*) AS n FROM snapshots WHERE source_id = 'sans-newsbites'").get() as { n: number }).n).toBe(3);

    // The next pull sees both issues stored and reads only the index again: the date cursor
    // keeps it off the ten older issues the index also lists.
    const second = await ingestSource(db, dataDir, getSource(db, "sans-newsbites")!, { http, now: () => new Date("2026-10-18T10:00:00Z") });
    expect(second.status).toBe("ok");
    expect(second.inserted).toBe(0);
    expect(second.detail).toBe("0 new issue(s) of 12 listed");
    expect(http.calls).toHaveLength(4);

    // An unseen issue on or after the cursor is news and is fetched once more; issue 75 and
    // older stay archive even though they were never fetched.
    db.prepare("DELETE FROM items WHERE source_id = 'sans-newsbites' AND external_id LIKE 'xxviii-77#%'").run();
    const third = await ingestSource(db, dataDir, getSource(db, "sans-newsbites")!, { http, now: () => new Date("2026-10-19T10:00:00Z") });
    expect(third.inserted).toBe(9);
    expect(http.calls).toHaveLength(6);
    expect(http.calls.at(-1)!.url).toBe("https://www.sans.org/newsletters/newsbites/xxviii-77");
    expect(sansNewsbitesAdapter.id).toBe("sans-newsbites");
  });
});
