import { existsSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { feedAdapter } from "../src/adapters/feed.ts";
import type { SourceRow } from "../src/adapters/types.ts";
import { blobRelativePath, putBlob } from "../src/blobs.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { backfillImages, extractOgImage, imageFor, imageType } from "../src/images.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { fakeHttp, startTestApp, type TestApp } from "./helpers.ts";

const pngBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 73, 72, 68, 82]);
const jpegBytes = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 16, 74, 70, 73, 70, 0, 1, 1, 0, 0, 1]);

describe("image type and og:image extraction", () => {
  it("sniffs magic bytes and trusts only image content types", () => {
    expect(imageType(null, pngBytes)).toBe("image/png");
    expect(imageType(null, jpegBytes)).toBe("image/jpeg");
    expect(imageType("image/webp; charset=binary", new TextEncoder().encode("RIFF....WEBPVP8 "))).toBe("image/webp");
    expect(imageType("text/html", new TextEncoder().encode("<html>not an image</html>"))).toBe(null);
    expect(imageType("image/svg+xml", new TextEncoder().encode("<svg xmlns='x'/>"))).toBe(null);
  });

  it("reads og:image whatever the attribute order, and twitter:image as a fallback", () => {
    expect(extractOgImage('<meta property="og:image" content="https://a.test/x.jpg">')).toBe("https://a.test/x.jpg");
    expect(extractOgImage("<meta content='https://a.test/y.png' property='og:image:secure_url' />")).toBe("https://a.test/y.png");
    expect(extractOgImage('<meta name="twitter:image" content="https://a.test/z.webp?w=1200&amp;h=630">')).toBe("https://a.test/z.webp?w=1200&h=630");
    expect(extractOgImage('<meta property="og:image" content="/relative.jpg">')).toBe(null);
    expect(extractOgImage("<p>no meta here</p>")).toBe(null);
  });
});

describe("feed adapter image extraction", () => {
  const stub = { id: "x", name: "X" } as SourceRow;
  it("prefers enclosure and media elements, then the first img in the body", () => {
    const rss = `<?xml version="1.0"?><rss version="2.0" xmlns:media="http://search.yahoo.com/mrss/" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><title>t</title>
      <item><title>enclosure</title><guid>e1</guid><enclosure url="https://img.test/a.jpg" type="image/jpeg"/></item>
      <item><title>media</title><guid>e2</guid><media:content url="https://img.test/b.png" medium="image"/></item>
      <item><title>body</title><guid>e3</guid><content:encoded><![CDATA[<p>hi</p><img src="https://img.test/c.webp" alt="">]]></content:encoded></item>
      <item><title>audio enclosure, no image</title><guid>e4</guid><enclosure url="https://img.test/a.mp3" type="audio/mpeg"/></item>
    </channel></rss>`;
    const { items } = feedAdapter.parse!(new TextEncoder().encode(rss), stub, new Date());
    expect(items.map((i) => [i.imageUrl ?? null, i.imageOrigin ?? null])).toEqual([
      ["https://img.test/a.jpg", "enclosure"],
      ["https://img.test/b.png", "enclosure"],
      ["https://img.test/c.webp", "body"],
      [null, null],
    ]);
  });
});

describe("ingest caches article images passively", () => {
  let dataDir = "";
  let db: ReturnType<typeof openDatabase>;
  const now = () => new Date("2026-10-14T07:00:00Z");

  beforeEach(() => {
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-img-"));
    db = openDatabase(":memory:");
    migrate(db);
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("stores feed media, falls back to og:image, and never fails the fetch over an image", async () => {
    const source = getSource(db, "bleeping");
    if (!source) throw new Error("no bleeping source");
    const rss = `<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
      <item><title>with enclosure</title><guid>i1</guid><link>https://news.test/one/</link><enclosure url="https://img.test/one.png" type="image/png"/></item>
      <item><title>og fallback</title><guid>i2</guid><link>https://news.test/two/</link></item>
      <item><title>image breaks</title><guid>i3</guid><link>https://news.test/three/</link><enclosure url="https://img.test/missing.png" type="image/png"/></item>
    </channel></rss>`;
    const http = fakeHttp({
      [source.url]: { bytes: new TextEncoder().encode(rss) },
      "https://img.test/one.png": { bytes: pngBytes, contentType: "image/png" },
      "https://news.test/two/": { text: '<html><head><meta property="og:image" content="https://img.test/two.jpg"></head></html>', contentType: "text/html" },
      "https://img.test/two.jpg": { bytes: jpegBytes, contentType: "image/jpeg" },
    });
    const result = await ingestSource(db, dataDir, source, { http, now, settings: { nvdApiKey: null, nvdBackfillDays: 7, newsImages: true } });
    expect(result.status).toBe("ok");
    expect(result.inserted).toBe(3);

    const rows = db.prepare("SELECT external_id, image_blob, image_type, image_origin FROM items ORDER BY external_id").all() as { external_id: string; image_blob: string | null; image_type: string | null; image_origin: string | null }[];
    expect(rows[0]).toMatchObject({ external_id: "i1", image_type: "image/png", image_origin: "enclosure" });
    expect(rows[1]).toMatchObject({ external_id: "i2", image_type: "image/jpeg", image_origin: "og" });
    expect(rows[2]).toMatchObject({ external_id: "i3", image_blob: null });
    expect(existsSync(path.join(dataDir, blobRelativePath(rows[0]!.image_blob!)))).toBe(true);

    // Only hashes an item carries are servable; a snapshot's hash is not.
    expect(imageFor(db, rows[0]!.image_blob!)).toMatchObject({ type: "image/png" });
    const snapshot = db.prepare("SELECT sha256 FROM snapshots LIMIT 1").get() as { sha256: string };
    expect(imageFor(db, snapshot.sha256)).toBe(null);
    expect(imageFor(db, "not-a-hash")).toBe(null);

    // The same fetch again changes nothing and fetches nothing new.
    const again = await ingestSource(db, dataDir, { ...source, etag: null, last_modified: null }, { http, now, settings: { nvdApiKey: null, nvdBackfillDays: 7, newsImages: true } });
    expect(again.status).toBe("unchanged");
  });
});

describe("image backfill for existing articles", () => {
  let dataDir = "";
  let db: ReturnType<typeof openDatabase>;

  beforeEach(() => {
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-imgbf-"));
    db = openDatabase(":memory:");
    migrate(db);
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("fills only imageless news articles, newest first, within the limit", async () => {
    const insert = db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at) VALUES (?, 'article', ?, ?, ?, ?, '2026-10-19T00:00:00Z')");
    insert.run("bleeping", "a1", "newest", "https://news.test/a1/", "2026-10-19T09:00:00Z");
    insert.run("bleeping", "a2", "older", "https://news.test/a2/", "2026-10-18T09:00:00Z");
    insert.run("bleeping", "a3", "no og image", "https://news.test/a3/", "2026-10-17T09:00:00Z");
    insert.run("gitlab-security", "v1", "vendor advisory, skipped", "https://vendor.test/v1/", "2026-10-19T10:00:00Z");
    const http = fakeHttp({
      "https://news.test/a1/": { text: '<html><head><meta property="og:image" content="https://img.test/a1.png"></head></html>', contentType: "text/html" },
      "https://news.test/a2/": { text: '<html><head><meta property="og:image" content="https://img.test/a2.jpg"></head></html>', contentType: "text/html" },
      "https://news.test/a3/": { text: "<html><head></head></html>", contentType: "text/html" },
      "https://img.test/a1.png": { bytes: pngBytes, contentType: "image/png" },
      "https://img.test/a2.jpg": { bytes: jpegBytes, contentType: "image/jpeg" },
    });

    const limited = await backfillImages(db, dataDir, { http }, { limit: 1, delayMs: 0 });
    expect(limited).toEqual({ examined: 1, stored: 1 });
    expect(http.calls.map((c) => c.url)).toEqual(["https://news.test/a1/", "https://img.test/a1.png"]);

    const rest = await backfillImages(db, dataDir, { http }, { limit: 10, delayMs: 0 });
    expect(rest).toEqual({ examined: 2, stored: 1 });
    const rows = db.prepare("SELECT external_id, image_origin FROM items WHERE image_blob IS NOT NULL ORDER BY external_id").all();
    expect(rows).toEqual([
      { external_id: "a1", image_origin: "og" },
      { external_id: "a2", image_origin: "og" },
    ]);
    // The vendor advisory was never asked for its page.
    expect(http.calls.some((c) => c.url.startsWith("https://vendor.test/"))).toBe(false);

    // The page without an og:image is remembered and never asked again.
    const third = await backfillImages(db, dataDir, { http }, { limit: 10, delayMs: 0 });
    expect(third).toEqual({ examined: 0, stored: 0 });
  });
});

describe("the /img route", () => {
  let app: TestApp;
  afterEach(async () =>
    await app.close());

  it("serves only blobs an item claims, with long-lived caching", async () => {
    app = await startTestApp();
    const blob = putBlob(app.dataDir, pngBytes);
    app.db
      .prepare("INSERT INTO items (source_id, kind, external_id, title, url, summary, published_at, fetched_at, image_blob, image_type, image_origin) VALUES ('bleeping', 'article', 'img-1', 't', NULL, NULL, NULL, '2026-10-14T07:00:00Z', ?, 'image/png', 'enclosure')")
      .run(blob.sha256);
    const served = await fetch(`${app.base}/img/${blob.sha256}`);
    expect(served.status).toBe(200);
    expect(served.headers.get("content-type")).toContain("image/png");
    expect(served.headers.get("cache-control")).toContain("immutable");
    expect(new Uint8Array(await served.arrayBuffer())).toEqual(pngBytes);

    const orphan = putBlob(app.dataDir, jpegBytes);
    expect((await fetch(`${app.base}/img/${orphan.sha256}`)).status).toBe(404);
    expect((await fetch(`${app.base}/img/zz`)).status).toBe(404);
  });
});
