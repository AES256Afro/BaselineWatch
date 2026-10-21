import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { fakeHttp, fixture } from "./helpers.ts";

/**
 * The feeds added in N5, each replayed from its first ten items as served on 2026-10-21, so a
 * feed that changes shape fails here before it fails on the instance.
 */

const now = new Date("2026-10-21T22:00:00Z");

const feeds: { id: string; file: string; group: string; title: RegExp; cve?: string; format?: string; count?: number }[] = [
  { id: "zdi-published", file: "zdi-published.xml", group: "vulnerabilities", title: /^ZDI-26-785: FreeBSD Kernel/ },
  { id: "zdi-upcoming", file: "zdi-upcoming.xml", group: "vulnerabilities", title: /^ZDI-CAN-33882: FreeBSD/ },
  { id: "hashicorp-security", file: "hashicorp.xml", group: "vulnerabilities", title: /^HCSEC-2026-45/ },
  { id: "aws-security-bulletins", file: "aws-bulletins.xml", group: "vulnerabilities", title: /virtio-net/, cve: "CVE-2026-89049" },
  { id: "cisco-talos", file: "talos.xml", group: "news", title: /eMudhra/ },
  { id: "certcc", file: "certcc.xml", group: "vulnerabilities", title: /^VU#645818/, format: "atom", count: 5 },
  { id: "microsoft-security-blog", file: "msft-blog.xml", group: "news", title: /ARTEX/, count: 5 },
  { id: "rapid7-blog", file: "rapid7.xml", group: "news", title: /CVE-2026-109618/, cve: "CVE-2026-109618", count: 5 },
  { id: "sentinellabs", file: "sentinel.xml", group: "news", title: /TraderTraitor/, count: 5 },
  { id: "greynoise", file: "greynoise.xml", group: "news", title: /Proxyjacking/ },
  { id: "wiz-blog", file: "wiz.xml", group: "news", title: /PHP2Shell/ },
  { id: "huntress-blog", file: "huntress.xml", group: "news", title: /ClickFix/ },
];

let db: DatabaseSync;
let dataDir: string;
beforeEach(() => {
  db = openDatabase(":memory:");
  migrate(db);
  dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-feeds-"));
});
afterEach(() => {
  db.close();
  rmSync(dataDir, { recursive: true, force: true });
});

describe.each(feeds)("$id", ({ id, file, group, title, cve, format, count }) => {
  it("is seeded in its group and reads its real feed", async () => {
    const source = getSource(db, id)!;
    expect(source.enabled).toBe(1);
    expect(source.group_name).toBe(group);
    expect(source.format).toBe(format ?? "rss");
    const result = await ingestSource(db, dataDir, source, { http: fakeHttp({ [source.url]: { bytes: fixture(`feeds/${file}`) } }), now: () => now });
    expect(result.status).toBe("ok");
    expect(result.inserted).toBe(count ?? 10);
    const rows = db.prepare("SELECT title, url, published_at, signals_json FROM items WHERE source_id = ? ORDER BY id").all(id) as { title: string; url: string | null; published_at: string | null; signals_json: string | null }[];
    expect(rows[0]?.title).toMatch(title);
    // ZDI still links its own advisories over plain http; the feed adapter keeps a link as given.
    expect(rows.every((r) => /^https?:\/\//.test(r.url ?? ""))).toBe(true);
    expect(rows.every((r) => r.published_at !== null)).toBe(true);
    if (cve) expect(rows.some((r) => (r.signals_json ?? "").includes(cve))).toBe(true);
  });
});
