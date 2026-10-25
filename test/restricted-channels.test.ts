import { afterEach, describe, expect, it } from "vitest";
import { canaryCount } from "../src/adapters/blocklists.ts";
import { latestDocument, loadRequirements } from "../src/register.ts";
import { cookieFrom, fakeHttp, fixture, formPost, startTestApp, type TestApp } from "./helpers.ts";

/**
 * The channels test/restricted.test.ts does not reach. It covers the pages, the API and the MCP
 * tools thoroughly; this covers the feeds, the sitemap, the OPML, the calendar, the search, the
 * Controls page, the Atlas and — since the audit of 25 October split it in two — both halves of
 * the digest. The sweep of 25 October found all of them already sound; this is what keeps them so.
 */
const sourceId = "canary-phishing";
const feedUrl = "https://openphish.com/feed.txt";
const feed = new TextDecoder().decode(fixture("blocklists/openphish-feed.txt"));
const password = "hunter2hunter2";

describe("S7: a restricted source in the channels not already covered", () => {
  let app: TestApp | null = null;
  afterEach(async () => { await app?.close(); app = null; });

  it("names no entry in a feed, the sitemap, a search, an export or the digest", async () => {
    const http = fakeHttp({ [feedUrl]: { bytes: new TextEncoder().encode(feed), contentType: "text/plain" } });
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: password }, http, now: () => new Date("2026-10-25T12:00:00Z") });
    const cookie = cookieFrom(await formPost(app.base, "/login", { password, next: "/" }));
    await formPost(app.base, `/sources/${sourceId}/enable`, {}, cookie);
    await formPost(app.base, `/sources/${sourceId}/fetch`, {}, cookie);
    const doc = latestDocument(app.db, sourceId, "canaries")!;
    const names = loadRequirements(app.db, doc.id).map((r) => r.ref);
    expect(names).toHaveLength(canaryCount);

    const { writeDigest, digestTextFor, latestDigest } = await import("../src/digest.ts");
    writeDigest(app.db, { now: new Date("2026-10-25T12:00:00Z"), baseUrl: "https://bw.example", period: "daily" });

    const channels = ["/feed.xml", "/vulnerabilities/feed.xml", "/sitemap.xml", "/sources.opml", "/vulnerabilities/kev.ics",
      "/search?q=canary", "/api/v1/items", "/api/v1/changes", "/api/v1/standards",
      "/api/v1/digest", "/digest", "/atlas", "/register", "/controls", "/today", "/"];
    // A page echoing the visitor's own search term back to them is not disclosure; a *result*
    // naming the entry is. Checked separately so the two are not confused.
    for (const probe of [`/search?q=${encodeURIComponent(names[0]!)}`, `/controls?q=${encodeURIComponent(names[0]!)}`]) {
      const text = await (await fetch(`${app.base}${probe}`)).text();
      const occurrences = text.split("\n").filter((line) => line.includes(names[0]!)).length;
      // The four places a page repeats what was typed: the <title>, the og:title, the heading
      // and the input's value. A fifth would be a result, which is the thing being tested for.
      // The places a page repeats what was typed: the <title>, the og:title, the "nothing
      // found" heading and the input's value. Any further occurrence would be a *result*, which
      // is the thing being tested for — a search box that confirmed a name was on a restricted
      // list would be an oracle over it.
      const echoes = text
        .split("\n")
        .filter((line) => line.includes(names[0]!))
        .filter((line) => /<title>|og:title" content=|Nothing (for|matches)|name="q" value=/.test(line)).length;
      expect(occurrences, `${probe} named the entry outside the places a page echoes the query`).toBe(echoes);
    }

    for (const path of channels) {
      for (const who of [{}, { cookie }]) {
        const body: string = await (await fetch(`${app.base}${path}`, { headers: who })).text();
        const leaked = names.filter((n) => body.includes(n));
        // The owner may see entries on a *page*; no feed, export or API may name one, to anyone.
        const pageForOwner = "cookie" in who && ["/register", "/controls", "/atlas", "/search?q=canary", "/today", "/"].includes(path);
        if (leaked.length && !pageForOwner) {
          expect.fail(`${path} (${"cookie" in who ? "owner" : "anon"}) named ${leaked.length} restricted entr(y|ies), e.g. ${leaked[0]}`);
        }
      }
    }

    // The digest's two halves, directly.
    const row = latestDigest(app.db)!;
    for (const owner of [true, false]) {
      const leaked = names.filter((n) => digestTextFor(row, owner).includes(n));
      expect(leaked, `digest (owner=${owner})`).toEqual([]);
    }
  });
});
