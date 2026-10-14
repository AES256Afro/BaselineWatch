import { existsSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { SourceRow } from "../src/adapters/types.ts";
import { countRows, migrate, openDatabase } from "../src/db.ts";
import type { HttpGet } from "../src/http.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { dueSources, groupByHost, startScheduler } from "../src/scheduler.ts";
import { listWire, markAllRead, sourceCounts } from "../src/wire.ts";
import { fakeHttp, fixture } from "./helpers.ts";

let dataDir = "";
let db: ReturnType<typeof openDatabase>;
const now = () => new Date("2026-10-14T07:00:00Z");

beforeEach(() => {
  dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-ingest-"));
  db = openDatabase(":memory:");
  migrate(db);
});
afterEach(() => {
  db.close();
  rmSync(dataDir, { recursive: true, force: true });
});

function source(id: string): SourceRow {
  const row = getSource(db, id);
  if (!row) throw new Error(`no source ${id}`);
  return row;
}

describe("ingestSource", () => {
  it("fetches, snapshots, parses and inserts; then reports unchanged on 304 and on identical bytes", async () => {
    const bleeping = source("bleeping");
    const http = fakeHttp({ [bleeping.url]: { bytes: fixture("rss.xml"), etag: '"v1"', notModifiedFor: '"v1"' } });

    const first = await ingestSource(db, dataDir, bleeping, { http, now });
    expect(first.status).toBe("ok");
    expect(first).toMatchObject({ items: 3, inserted: 3, updated: 0 });
    expect(first.snapshotId).toBeGreaterThan(0);
    expect(countRows(db, "snapshots")).toBe(1);
    const snapshot = db.prepare("SELECT blob_path, bytes FROM snapshots").get() as { blob_path: string; bytes: number };
    expect(existsSync(path.join(dataDir, snapshot.blob_path))).toBe(true);
    const after = source("bleeping");
    expect(after.last_status).toBe("ok");
    expect(after.etag).toBe('"v1"');
    expect(after.fetch_count).toBe(1);
    expect(after.last_fetch_at).toBe("2026-10-14T07:00:00.000Z");

    const second = await ingestSource(db, dataDir, source("bleeping"), { http, now });
    expect(second.status).toBe("unchanged");
    expect(http.calls[1]?.etag).toBe('"v1"');
    expect(countRows(db, "items")).toBe(3);

    // Same bytes without the conditional headers: still one snapshot, nothing re-inserted.
    const fresh = { ...source("bleeping"), etag: null, last_modified: null };
    const third = await ingestSource(db, dataDir, fresh, { http, now });
    expect(third.status).toBe("unchanged");
    expect(countRows(db, "snapshots")).toBe(1);
    expect(source("bleeping").fetch_count).toBe(3);
  });

  it("updates changed items, keeps read state, and keeps every version as a snapshot", async () => {
    const bleeping = source("bleeping");
    const v1 = new TextDecoder().decode(fixture("rss.xml"));
    const v2 = v1.replace("Ransomware group claims breach of logistics firm", "Ransomware group confirms breach of logistics firm");
    const http = fakeHttp({ [bleeping.url]: { text: v1 } });
    await ingestSource(db, dataDir, bleeping, { http, now });
    db.prepare("UPDATE items SET read = 1 WHERE external_id = ?").run("https://news.example.test/ransomware-logistics/");

    const http2 = fakeHttp({ [bleeping.url]: { text: v2 } });
    const result = await ingestSource(db, dataDir, source("bleeping"), { http: http2, now });
    expect(result).toMatchObject({ status: "ok", inserted: 0, updated: 1 });
    const row = db.prepare("SELECT title, read FROM items WHERE external_id = ?").get("https://news.example.test/ransomware-logistics/") as { title: string; read: number };
    expect(row.title).toContain("confirms");
    expect(row.read).toBe(1);
    expect(countRows(db, "snapshots")).toBe(2);
  });

  it("records a failure on the source and never throws", async () => {
    const krebs = source("krebs");
    const http = fakeHttp({ [krebs.url]: { status: 503 } });
    const result = await ingestSource(db, dataDir, krebs, { http, now });
    expect(result.status).toBe("error");
    expect(result.error).toMatch(/503/);
    const after = source("krebs");
    expect(after.last_status).toBe("error");
    expect(after.last_error).toMatch(/503/);

    const bad = fakeHttp({ [krebs.url]: { text: "<html>not a feed</html>" } });
    expect((await ingestSource(db, dataDir, source("krebs"), { http: bad, now })).error).toMatch(/not an RSS/);
  });

  it("skips a source that has no adapter yet", async () => {
    const result = await ingestSource(db, dataDir, source("complianceascode"), { http: fakeHttp({}), now });
    expect(result.status).toBe("skipped");
    expect(source("complianceascode").last_fetch_at).toBeNull();
  });

  it("loads the KEV catalog with its version and marks the document", async () => {
    const kev = source("cisa-kev");
    const result = await ingestSource(db, dataDir, kev, { http: fakeHttp({ [kev.url]: { bytes: fixture("kev.json") } }), now });
    expect(result).toMatchObject({ status: "ok", items: 3, inserted: 3 });
    const doc = db.prepare("SELECT version_label FROM documents WHERE source_id = 'cisa-kev'").get() as { version_label: string };
    expect(doc.version_label).toBe("2026.10.14");
    expect(countRows(db, "items", "WHERE kind = 'kev'")).toBe(3);
  });
});

describe("the Wire", () => {
  it("hides the same link seen from a second source, filters, searches and marks read", async () => {
    const bleeping = source("bleeping");
    const netsec = source("reddit-netsec");
    await ingestSource(db, dataDir, bleeping, { http: fakeHttp({ [bleeping.url]: { bytes: fixture("atom.xml") } }), now });
    await ingestSource(db, dataDir, netsec, { http: fakeHttp({ [netsec.url]: { bytes: fixture("reddit.json") } }), now });
    expect(countRows(db, "items")).toBe(4);

    // The OAuth write-up is in the Atom feed and on r/netsec with the same link: shown once, from the earlier source.
    const all = listWire(db);
    expect(all).toHaveLength(3);
    expect(all.filter((i) => i.url === "https://blog.example.test/2026/oauth-device-code")).toHaveLength(1);
    expect(all.find((i) => i.url === "https://blog.example.test/2026/oauth-device-code")?.source_id).toBe("bleeping");

    expect(listWire(db, { source: "reddit-netsec" }).map((i) => i.external_id)).toEqual(["t3_1abcdg"]);
    expect(listWire(db, { q: "oauth" }).map((i) => i.title)).toEqual(["Abusing OAuth device code flow in enterprise SSO"]);
    expect(listWire(db, { q: "cve-2026-31417" })).toHaveLength(1);
    expect(listWire(db, { q: '"unbalanced' })).toHaveLength(0);

    expect(markAllRead(db, { source: "reddit-netsec" })).toBe(1);
    expect(listWire(db, { unread: true })).toHaveLength(2);
    const counts = sourceCounts(db);
    expect(counts.find((c) => c.source_id === "reddit-netsec")).toMatchObject({ total: 2, unread: 1 });
  });

  it("pages by id cursor", async () => {
    const kev = source("cisa-kev");
    await ingestSource(db, dataDir, kev, { http: fakeHttp({ [kev.url]: { bytes: fixture("kev.json") } }), now });
    const firstPage = listWire(db, { limit: 2 });
    expect(firstPage).toHaveLength(2);
    const next = listWire(db, { limit: 2, before: firstPage[1]!.id });
    expect(next).toHaveLength(1);
    expect(next[0]!.id).toBeLessThan(firstPage[1]!.id);
  });
});

describe("scheduler", () => {
  it("picks sources whose interval has passed, retries errors sooner, and runs them with the fake network", async () => {
    const at = new Date("2026-10-14T07:00:00Z");
    const due = dueSources(db, at);
    expect(due.every((s) => s.last_fetch_at === null)).toBe(true);
    expect(due.map((s) => s.id)).toContain("bleeping");
    expect(due.map((s) => s.id)).not.toContain("complianceascode");
    expect(due.map((s) => s.id)).not.toContain("cis-benchmarks");

    db.prepare("UPDATE sources SET last_fetch_at = ?, last_status = 'ok' WHERE id = 'bleeping'").run("2026-10-14T06:30:00.000Z");
    db.prepare("UPDATE sources SET last_fetch_at = ?, last_status = 'error' WHERE id = 'krebs'").run("2026-10-14T06:20:00.000Z");
    db.prepare("UPDATE sources SET last_fetch_at = ?, last_status = 'ok' WHERE id = 'sans-isc'").run("2026-10-13T06:00:00.000Z");
    const ids = dueSources(db, at).map((s) => s.id);
    expect(ids).not.toContain("bleeping"); // hourly, fetched 30 min ago
    expect(ids).toContain("krebs"); // daily but failed 40 min ago: retry after 30
    expect(ids).toContain("sans-isc"); // daily, 25 h ago

    db.prepare("UPDATE sources SET enabled = 0 WHERE id NOT IN ('bleeping', 'cisa-kev')").run();
    db.prepare("UPDATE sources SET last_fetch_at = NULL WHERE id = 'bleeping'").run();
    const lines: string[] = [];
    const http = fakeHttp({ [source("bleeping").url]: { bytes: fixture("rss.xml") }, [source("cisa-kev").url]: { bytes: fixture("kev.json") } });
    const scheduler = startScheduler({ db, dataDir, http, now: () => at, tickMs: 60_000, log: (l) => lines.push(l) });
    const results = await scheduler.runOnce();
    scheduler.stop();
    expect(results.map((r) => [r.sourceId, r.status]).sort()).toEqual([
      ["bleeping", "ok"],
      ["cisa-kev", "ok"],
    ]);
    expect(lines.some((l) => l.includes("2 source(s) due"))).toBe(true);
    expect(await scheduler.runOnce()).toEqual([]);
  });

  it("asks one host for one thing at a time, with a pause between", async () => {
    db.prepare("UPDATE sources SET enabled = 0 WHERE id NOT IN ('reddit-netsec', 'reddit-cybersecurity', 'bleeping')").run();
    const stamps: { url: string; at: number }[] = [];
    const urls = ["reddit-netsec", "reddit-cybersecurity", "bleeping"].map((id) => source(id).url);
    const http = fakeHttp(Object.fromEntries(urls.map((u) => [u, { bytes: fixture(u.includes("reddit") ? "reddit-atom.xml" : "rss.xml") }])));
    const timed: HttpGet = async (url, options) => {
      stamps.push({ url, at: Date.now() });
      return http(url, options);
    };
    const scheduler = startScheduler({ db, dataDir, http: timed, now: () => new Date("2026-10-14T07:00:00Z"), hostDelayMs: 120, log: () => {} });
    const results = await scheduler.runOnce();
    scheduler.stop();
    expect(results.filter((r) => r.status === "ok")).toHaveLength(3);
    const reddit = stamps.filter((s) => s.url.includes("reddit.com")).sort((a, b) => a.at - b.at);
    expect(reddit).toHaveLength(2);
    expect(reddit[1]!.at - reddit[0]!.at).toBeGreaterThanOrEqual(100);
    expect(groupByHost(["reddit-netsec", "reddit-cybersecurity", "bleeping"].map(source)).map((g) => g.length).sort()).toEqual([1, 2]);
  });
});
