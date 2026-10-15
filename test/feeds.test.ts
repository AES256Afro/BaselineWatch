import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import type { HttpGet } from "../src/http.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { listWire } from "../src/wire.ts";
import { fixture } from "./helpers.ts";

const at = new Date("2026-10-15T14:00:00Z");

describe("advisory feeds added on 2026-10-15", () => {
  let db: DatabaseSync;
  let dataDir = "";
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-feeds-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("are seeded in the right groups", () => {
    const rows = db.prepare("SELECT id, group_name, format, schedule, enabled FROM sources WHERE id IN ('cisa-ics-advisories', 'chrome-releases', 'gitlab-security', 'jenkins-security', 'google-security-blog') ORDER BY id").all() as {
      id: string;
      group_name: string;
      format: string;
      schedule: string;
      enabled: number;
    }[];
    expect(rows.map((r) => `${r.id}:${r.group_name}:${r.format}:${r.schedule}`)).toEqual([
      "chrome-releases:vulnerabilities:atom:daily",
      "cisa-ics-advisories:vulnerabilities:rss:hourly",
      "gitlab-security:vulnerabilities:atom:daily",
      "google-security-blog:news:atom:daily",
      "jenkins-security:vulnerabilities:rss:daily",
    ]);
    expect(rows.every((r) => r.enabled === 1)).toBe(true);
  });

  it("reads CISA's ICS advisories feed as it is published", async () => {
    const http: HttpGet = async (url) => ({ url, status: 200, notModified: false, bytes: fixture("cisa-ics.xml"), etag: null, lastModified: null, contentType: "application/rss+xml" });
    const source = getSource(db, "cisa-ics-advisories")!;
    const result = await ingestSource(db, dataDir, source, { http, now: () => at });
    expect(result.status).toBe("ok");
    const items = listWire(db, { source: "cisa-ics-advisories" });
    expect(items).toHaveLength(3);
    expect(items.map((i) => i.title)).toContain("Swann Communications SWIFI-SE2KIC");
    expect(items.every((i) => i.url?.startsWith("https://www.cisa.gov/news-events/ics-advisories/"))).toBe(true);
    expect(items.every((i) => i.kind === "article")).toBe(true);
    expect(items[0]?.published_at?.slice(0, 10)).toBe("2026-10-13");
    // The Wire files them with the vendor advisories, apart from the news.
    expect(listWire(db, { group: "vulnerabilities" }).map((i) => i.source_id)).toEqual(["cisa-ics-advisories", "cisa-ics-advisories", "cisa-ics-advisories"]);
    expect(listWire(db, { group: "news" })).toHaveLength(0);
  });
});
