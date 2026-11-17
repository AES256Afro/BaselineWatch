import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { storeCvelistRecords } from "../src/adapters/cvelist.ts";
import { storeNvdRecords, type NvdCve } from "../src/adapters/nvd.ts";
import { feedAdapter } from "../src/adapters/feed.ts";
import type { HostResolver } from "../src/http.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { applyEpss, epssNotable, getVuln, notableInWindowSql, notableSql, publishedWithin, vulnChanges } from "../src/vulns.ts";
import { epssPercent } from "../src/words.ts";

/** Rows found by the audit of 16 November, each held by the case that showed it. */

function fresh() {
  const db = openDatabase(":memory:");
  migrate(db);
  return db;
}

function nvd(id: string, score: number | null, overrides: Partial<NvdCve> = {}): { cve: NvdCve } {
  return {
    cve: {
      id,
      sourceIdentifier: "security@example.org",
      published: "2026-11-10T08:00:00.000",
      lastModified: "2026-11-10T09:00:00.000",
      vulnStatus: "Analyzed",
      descriptions: [{ lang: "en", value: "A remote code execution flaw in Example Widget." }],
      metrics:
        score === null
          ? {}
          : { cvssMetricV31: [{ type: "Primary", source: "nvd@nist.gov", cvssData: { version: "3.1", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", baseScore: score, baseSeverity: score >= 9 ? "CRITICAL" : "HIGH" } }] },
      ...overrides,
    },
  };
}

const items = (db: ReturnType<typeof fresh>, id: string) => (db.prepare("SELECT COUNT(*) AS n FROM items WHERE kind = 'vulnerability' AND external_id LIKE ?").get(`%${id}%`) as { n: number }).n;

describe("a new critical (BUG1A-1)", () => {
  it("reaches the News when the CVE list's record arrived seconds before NVD's", () => {
    const db = fresh();
    const id = "CVE-2026-112403";
    const record = { dataType: "CVE_RECORD", cveMetadata: { cveId: id, state: "PUBLISHED", datePublished: "2026-11-10T08:00:00Z", dateUpdated: "2026-11-10T08:00:00Z" }, containers: { cna: { descriptions: [{ lang: "en", value: "A remote code execution flaw in Example Widget." }], references: [] } } };
    storeCvelistRecords({ db, now: () => new Date("2026-11-10T10:00:00Z") }, [record] as unknown as Parameters<typeof storeCvelistRecords>[1]);
    expect(items(db, id)).toBe(0);
    storeNvdRecords({ db, now: () => new Date("2026-11-10T10:00:30Z") }, [nvd(id, 9.8)] as unknown as Parameters<typeof storeNvdRecords>[1]);
    expect(items(db, id)).toBe(1);
  });

  it("reaches the News when NVD scores it critical days after publishing it", () => {
    const db = fresh();
    const id = "CVE-2026-104586";
    storeNvdRecords({ db, now: () => new Date("2026-11-10T10:00:00Z") }, [nvd(id, null, { vulnStatus: "Awaiting Analysis" })] as unknown as Parameters<typeof storeNvdRecords>[1]);
    expect(items(db, id)).toBe(0);
    storeNvdRecords({ db, now: () => new Date("2026-11-14T10:00:00Z") }, [nvd(id, 9.8, { lastModified: "2026-11-14T09:00:00.000" })] as unknown as Parameters<typeof storeNvdRecords>[1]);
    expect(items(db, id)).toBe(1);
    // And Today's window counts it, though it was published before the window opened.
    const since = "2026-11-13T00:00:00.000Z";
    const inWindow = db.prepare(`SELECT COUNT(*) AS n FROM vulns v WHERE v.cve_id = ? AND ${notableInWindowSql}`).get(id, since, since) as { n: number };
    expect(inWindow.n).toBe(1);
  });
});

describe("CVSS 4.0 vectors that spell out undefined metrics (BUG1A-6)", () => {
  it("are not a change when only the X metrics differ", () => {
    const db = fresh();
    const id = "CVE-2026-200001";
    const v4 = (vector: string) => nvd(id, null, { lastModified: vector.length > 80 ? "2026-11-11T09:00:00.000" : "2026-11-10T09:00:00.000", metrics: { cvssMetricV40: [{ type: "Secondary", source: "cna@example.org", cvssData: { version: "4.0", vectorString: vector, baseScore: 9.2, baseSeverity: "CRITICAL" } }] } as NonNullable<NvdCve["metrics"]> });
    const short = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
    storeNvdRecords({ db, now: () => new Date("2026-11-10T10:00:00Z") }, [v4(short)] as unknown as Parameters<typeof storeNvdRecords>[1]);
    storeNvdRecords({ db, now: () => new Date("2026-11-11T10:00:00Z") }, [v4(`${short}/E:X/CR:X/IR:X/AR:X/MAV:X/S:X/AU:X/R:X/V:X/RE:X/U:X`)] as unknown as Parameters<typeof storeNvdRecords>[1]);
    expect(vulnChanges(db, id).filter((c) => c.field === "cvss")).toEqual([]);
  });
});

describe("EPSS crossing 50% (BUG1A-2, BUG1A-13)", () => {
  it("is a change written as a percentage, and puts the CVE on the News", () => {
    const db = fresh();
    const id = "CVE-2024-6387";
    storeNvdRecords({ db, now: () => new Date("2024-07-02T10:00:00Z") }, [nvd(id, 8.1, { published: "2024-07-01T13:15:00.000" })] as unknown as Parameters<typeof storeNvdRecords>[1]);
    applyEpss(db, [{ cveId: id, epss: 0.04, percentile: 0.9 }], "2026-11-14", "2026-11-14T06:00:00.000Z");
    expect(items(db, id)).toBe(0);
    applyEpss(db, [{ cveId: id, epss: 0.61, percentile: 0.99 }], "2026-11-15", "2026-11-15T06:00:00.000Z");
    expect(vulnChanges(db, id).find((c) => c.field === "epss")).toMatchObject({ before_text: "4.0%", after_text: "61%" });
    expect(items(db, id)).toBe(1);
    // Staying above 50% is not news again.
    applyEpss(db, [{ cveId: id, epss: 0.63, percentile: 0.99 }], "2026-11-16", "2026-11-16T06:00:00.000Z");
    expect(vulnChanges(db, id).filter((c) => c.field === "epss")).toHaveLength(1);
  });

  it("dates the News item the day it was scored, not at NVD's last modification", () => {
    const db = fresh();
    const id = "CVE-2025-63387";
    storeNvdRecords({ db, now: () => new Date("2026-10-13T10:00:00Z") }, [nvd(id, 7.5, { published: "2025-12-01T13:15:00.000", lastModified: "2026-10-13T09:00:00.000" })] as unknown as Parameters<typeof storeNvdRecords>[1]);
    applyEpss(db, [{ cveId: id, epss: 0.1, percentile: 0.9 }], "2026-11-14", "2026-11-14T06:00:00.000Z");
    applyEpss(db, [{ cveId: id, epss: 0.55, percentile: 0.99 }], "2026-11-15", "2026-11-15T06:00:00.000Z");
    const item = db.prepare("SELECT published_at FROM items WHERE kind = 'vulnerability' AND external_id = ?").get(id) as { published_at: string };
    expect(item.published_at).toBe("2026-11-15T06:00:00.000Z");
  });

  it("counts a first score only for a CVE published in the last thirty days", () => {
    const db = fresh();
    const old = "CVE-2019-11510";
    const recent = "CVE-2026-112404";
    // Both first met today, as a backfill meets them; only the one published lately is news.
    storeNvdRecords({ db, now: () => new Date("2026-11-14T10:00:00Z") }, [nvd(old, 7.5, { published: "2019-04-26T00:00:00.000" }), nvd(recent, 7.5)] as unknown as Parameters<typeof storeNvdRecords>[1]);
    applyEpss(db, [{ cveId: old, epss: 0.97, percentile: 1 }, { cveId: recent, epss: 0.7, percentile: 0.99 }], "2026-11-15", "2026-11-15T06:00:00.000Z");
    expect(items(db, old)).toBe(0);
    expect(items(db, recent)).toBe(1);
  });

  it("does not resurface a score that hovers around 50%", () => {
    const db = fresh();
    const id = "CVE-2024-3400";
    storeNvdRecords({ db, now: () => new Date("2024-04-13T10:00:00Z") }, [nvd(id, 8.1, { published: "2024-04-12T08:00:00.000" })] as unknown as Parameters<typeof storeNvdRecords>[1]);
    const day = (n: number, epss: number) => applyEpss(db, [{ cveId: id, epss, percentile: 0.99 }], `2026-11-${n}`, `2026-11-${n}T06:00:00.000Z`);
    day(10, 0.3);
    day(11, 0.52); // crossed from below 40%: news
    day(12, 0.47);
    day(13, 0.53); // back over from 47%: not news again
    expect(vulnChanges(db, id).filter((c) => c.field === "epss")).toHaveLength(1);
    day(14, 0.35);
    day(15, 0.6); // fell below 40% first: news again
    expect(vulnChanges(db, id).filter((c) => c.field === "epss")).toHaveLength(2);
  });

  it("counts a gradual rise past 50% once (bug sweep 3a)", () => {
    const db = fresh();
    const id = "CVE-2024-21762";
    storeNvdRecords({ db, now: () => new Date("2024-02-09T10:00:00Z") }, [nvd(id, 8.1, { published: "2024-02-09T08:00:00.000" })] as unknown as Parameters<typeof storeNvdRecords>[1]);
    const day = (n: number, epss: number) => applyEpss(db, [{ cveId: id, epss, percentile: 0.99 }], `2026-11-${n}`, `2026-11-${n}T06:00:00.000Z`);
    day(10, 0.35);
    day(11, 0.45);
    day(12, 0.55); // never below 40% the day before, but armed: news
    expect(vulnChanges(db, id).filter((c) => c.field === "epss")).toMatchObject([{ before_text: "45%", after_text: "55%" }]);
    expect(items(db, id)).toBe(1);
    day(13, 0.45);
    day(14, 0.52); // dipped, not below 40%: not again
    expect(vulnChanges(db, id).filter((c) => c.field === "epss")).toHaveLength(1);
  });
});

describe("a keyword watch on a row the CVE list rewords (CODE1-3)", () => {
  it("is recomputed with the new words", () => {
    const db = fresh();
    const id = "CVE-2026-300001";
    db.prepare("INSERT INTO watchlist (kind, value, created_at) VALUES ('keyword', 'remote code execution', '2026-11-10T00:00:00Z')").run();
    storeNvdRecords({ db, now: () => new Date("2026-11-10T10:00:00Z") }, [nvd(id, null, { vulnStatus: "Awaiting Analysis", descriptions: [{ lang: "en", value: "Reserved." }] })] as unknown as Parameters<typeof storeNvdRecords>[1]);
    expect(getVuln(db, id)?.watch_hit).toBe(0);
    const record = { dataType: "CVE_RECORD", cveMetadata: { cveId: id, state: "PUBLISHED", datePublished: "2026-11-10T08:00:00Z", dateUpdated: "2026-11-11T08:00:00Z" }, containers: { cna: { descriptions: [{ lang: "en", value: "A remote code execution flaw in Example Widget." }], references: [] } } };
    storeCvelistRecords({ db, now: () => new Date("2026-11-11T10:00:00Z") }, [record] as unknown as Parameters<typeof storeCvelistRecords>[1]);
    expect(getVuln(db, id)?.watch_hit).toBe(1);
  });
});

describe("a feed item that names its CVE at the end of a long body (BUG1A-3)", () => {
  it("still carries the CVE", () => {
    const body = `${"Cisco has released software updates that address this vulnerability. ".repeat(20)}CVE: CVE-2026-20019`;
    const xml = `<?xml version="1.0"?><rss version="2.0"><channel><title>Cisco</title><item><title>Snort 3 Denial of Service</title><link>https://example.org/a</link><guid>a</guid><description>${body}</description></item></channel></rss>`;
    const item = feedAdapter.parse!(new TextEncoder().encode(xml), {} as never, new Date()).items[0]!;
    expect(item.summary!.length).toBeLessThanOrEqual(600);
    expect(item.signals?.cves).toEqual(["CVE-2026-20019"]);
  });
});

describe("a feed item that lists hundreds of CVEs in its body", () => {
  it("keeps the title's and summary's, then at most fifty more", () => {
    const ids = Array.from({ length: 428 }, (_, i) => `CVE-2026-${String(40000 + i)}`);
    const xml = `<?xml version="1.0"?><rss version="2.0"><channel><title>CISA ICS</title><item><title>Siemens SIMATIC (CVE-2026-39999)</title><link>https://example.org/icsa</link><guid>icsa</guid><description>Siemens reports ${ids.join(", ")}.</description></item></channel></rss>`;
    const item = feedAdapter.parse!(new TextEncoder().encode(xml), {} as never, new Date()).items[0]!;
    const cves = item.signals?.cves as string[];
    // The title's one, the summary's (as many as fit in its 600 characters), then fifty from the body.
    expect(cves[0]).toBe("CVE-2026-39999");
    const inSummary = ids.filter((id) => item.summary!.includes(id)).length;
    expect(cves).toHaveLength(1 + inSummary + 50);
    expect(new Set(cves).size).toBe(cves.length);
    expect(cves).not.toContain(ids[427]);
  });
});

describe("anonymous heavy work (SEC1-1, SEC1-2)", () => {
  it("keys an IPv6 allowance by /56 when asked, and by /64 for sign-in", async () => {
    const { throttleKey } = await import("../src/auth.ts");
    expect(throttleKey("2001:db8:77:1::1", 56)).toBe(throttleKey("2001:db8:77:2::1", 56));
    expect(throttleKey("2001:db8:77:1::1", 56)).toBe("2001:0db8:0077:0000::/56");
    expect(throttleKey("2001:db8:77:1ff::1", 56)).not.toBe(throttleKey("2001:db8:77:2ff::1", 56));
    expect(throttleKey("2001:db8:77:1::1")).not.toBe(throttleKey("2001:db8:77:2::1"));
    expect(throttleKey("203.0.113.9", 56)).toBe("203.0.113.9");
  });

  it("keeps one address to its share, and serves light readers when everyone's budget is spent (SEC2-1)", async () => {
    const { WorkBudget } = await import("../src/auth.ts");
    const budget = new WorkBudget(1000, 60_000, 400, 100);
    budget.spend("a", 400, 0);
    expect(budget.check("a", 1)).toBe("self");
    budget.spend("b", 350, 2);
    budget.spend("c", 300, 3);
    expect(budget.check("light", 4)).toBe("ok");
    expect(budget.check("b", 4)).toBe("busy");
    expect(budget.check("a", 60_001)).toBe("ok");
  });

  it("answers a page past the end of the list without sorting it", async () => {
    const { listVulns } = await import("../src/vulns.ts");
    const { vulnFilters } = await import("../src/routes/query.ts");
    const { maxOffset } = await import("../src/vulns.ts");
    const db = fresh();
    storeNvdRecords({ db, now: () => new Date("2026-11-10T10:00:00Z") }, [nvd("CVE-2026-400001", 7.5)] as unknown as Parameters<typeof storeNvdRecords>[1]);
    expect(listVulns(db, { offset: 5 })).toEqual({ rows: [], total: 1 });
    expect(vulnFilters({ offset: "900000" }, new Date()).offset).toBe(maxOffset);
  });
});

describe("a triaged setting of a licensed standard through the API (SEC1-4)", () => {
  it("names the standard and version only, never the setting's key, label or address", async () => {
    const { apiTriage } = await import("../src/api.ts");
    const db = fresh();
    db.prepare("INSERT INTO snapshots (id, source_id, document_key, sha256, bytes, blob_path, fetched_at) VALUES (9, 'microsoft-sct', 'windows-11', 'ab', 1, 'blobs/ab/ab', '2026-11-10')").run();
    db.prepare("INSERT INTO documents (id, source_id, document_key, snapshot_id, version_label, parsed_at, published_at) VALUES (49, 'microsoft-sct', 'windows-11', 9, 'v26h2', '2026-11-10', '2026-11-10')").run();
    const key = "internet explorer 11 - computer|computer|software\\microsoft\\windows\\currentversion\\policies\\ext\\runthistimeenabled";
    db.prepare("INSERT INTO requirements (document_id, ref, label, title) VALUES (49, ?, 'RunThisTimeEnabled', 'Turn off Run this time')").run(key);
    db.prepare("INSERT INTO triage (subject_kind, subject_id, subject_key, state, created_at, updated_at) VALUES ('control', 49, ?, 'reviewing', '2026-11-16', '2026-11-16')").run(key);
    const [row] = apiTriage(db, {}, "https://example.org");
    expect(row).toBeDefined();
    expect(row!.key).toBeNull();
    expect(JSON.stringify(row)).not.toMatch(/runthistime|RunThisTime|software\\\\microsoft/i);
    expect(row!.url).toBe("https://example.org/standards/microsoft-sct/49");
  });
});

describe("a zip entry that lies about its size (SEC1-5)", () => {
  it("is refused before it is inflated", async () => {
    const { zipSync } = await import("fflate");
    const { unzipAll } = await import("../src/zip.ts");
    const honest = zipSync({ "a.xml": new TextEncoder().encode("<a>".repeat(1000)) });
    expect(unzipAll(honest)).toHaveLength(1);
    const bomb = zipSync({ "z.bin": new Uint8Array(8 * 1024 * 1024) }, { level: 9 });
    expect(() => unzipAll(bomb)).toThrow(/thousand/);
    // The same bomb with both size fields rewritten to 1 KB.
    const lying = bomb.slice();
    const view = new DataView(lying.buffer);
    for (let i = 0; i < lying.length - 4; i++) {
      const sig = view.getUint32(i, true);
      if (sig === 0x04034b50) view.setUint32(i + 22, 1024, true);
      if (sig === 0x02014b50) view.setUint32(i + 24, 1024, true);
    }
    expect(() => unzipAll(lying)).toThrow(/declares 1024/);
  });
});

describe("a lost DNS packet (resolveHost)", () => {
  const timeout = () => Object.assign(new Error("queryA ETIMEOUT example.org"), { code: "ETIMEOUT" });
  /** Times out `fails` times, then answers; counts the A questions asked. */
  const flaky = (fails: number, code = "ETIMEOUT") => {
    const asked = { v4: 0 };
    const resolver = {
      resolve4: async () => {
        asked.v4 += 1;
        if (asked.v4 <= fails) throw code === "ETIMEOUT" ? timeout() : Object.assign(new Error(code), { code });
        return ["198.51.100.7"];
      },
      resolve6: async () => {
        throw Object.assign(new Error("ENODATA"), { code: "ENODATA" });
      },
    };
    return { asked, resolver: resolver as unknown as HostResolver };
  };

  it("asks once more for a scheduled fetch, and once only for a name a visitor typed", async () => {
    const { resolveHost } = await import("../src/http.ts");
    const scheduled = flaky(1);
    await expect(resolveHost("example.org", { resolver: scheduled.resolver })).resolves.toEqual([{ address: "198.51.100.7" }]);
    expect(scheduled.asked.v4).toBe(2);
    const visitor = flaky(1);
    await expect(resolveHost("example.org", { resolver: visitor.resolver, tries: 1 })).rejects.toMatchObject({ code: "ETIMEOUT" });
    expect(visitor.asked.v4).toBe(1);
    // Two losses in a row still fail, after two questions; "no such name" is not asked again.
    const twice = flaky(2);
    await expect(resolveHost("example.org", { resolver: twice.resolver })).rejects.toMatchObject({ code: "ETIMEOUT" });
    expect(twice.asked.v4).toBe(2);
    const missing = flaky(5, "ENOTFOUND");
    await expect(resolveHost("example.org", { resolver: missing.resolver })).rejects.toMatchObject({ code: "ENOTFOUND" });
    expect(missing.asked.v4).toBe(1);
  });
});

describe("sweep 3 lows", () => {
  it("gives a versioned release the history has not reached no notes (BUG3A-7)", async () => {
    const { parseStigRevisionHistory } = await import("../src/explain.ts");
    const text = "Revision History\nV2R10\n- WN11-00-000001 - Updated the check. 30 September 2026\n";
    expect(parseStigRevisionHistory(text, "V2R11").notes).toEqual([]);
    expect(parseStigRevisionHistory(text, "Y26M10").version).toBe("V2R10");
  });
});

describe("EPSS change rows from before the percentage form (migration 0064)", () => {
  it("are rewritten by epssPercent's rule, and a second run changes nothing", () => {
    const db = fresh();
    const id = "CVE-2024-0001";
    storeNvdRecords({ db, now: () => new Date("2024-01-02T10:00:00Z") }, [nvd(id, 8.1, { published: "2024-01-01T08:00:00.000" })] as unknown as Parameters<typeof storeNvdRecords>[1]);
    const old = ["0.52", "0.05", "0.10", "1.00", "0.00", "0.01"];
    const insert = db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, nvd_modified_at, field, before_text, after_text) VALUES (?, ?, NULL, 'epss', ?, ?)");
    for (const [i, v] of old.entries()) insert.run(id, `2026-10-0${i + 1}T00:00:00Z`, v, "61%");
    insert.run(id, "2026-10-09T00:00:00Z", null, "0.97");
    const sql = readFileSync(path.join(import.meta.dirname, "../src/migrations/0064_epss_changes_as_percent.sql"), "utf8");
    db.exec(sql);
    const rows = () => db.prepare("SELECT before_text, after_text FROM vuln_changes WHERE cve_id = ? AND field = 'epss' ORDER BY observed_at").all(id) as { before_text: string | null; after_text: string }[];
    const after = rows();
    expect(after.map((r) => r.before_text)).toEqual([...old.map((v) => epssPercent(Number(v))), null]);
    expect(after.map((r) => r.after_text)).toEqual([...old.map(() => "61%"), epssPercent(0.97)]);
    db.exec(sql);
    expect(rows()).toEqual(after);
  });
});

describe("one threshold and one window (CODE3-8, CODE3-9)", () => {
  it("names 50% once and reads published-within the same way everywhere", () => {
    expect(epssNotable).toBe(0.5);
    expect(notableSql).toContain(`>= ${epssNotable}`);
    expect(notableInWindowSql).toContain(`>= ${epssNotable}`);
    expect(publishedWithin("2026-10-20T00:00:00.000Z", "2026-11-16T00:00:00.000Z", 30)).toBe(true);
    expect(publishedWithin("2026-10-01T00:00:00.000Z", "2026-11-16T00:00:00.000Z", 30)).toBe(false);
    expect(publishedWithin(null, "2026-11-16T00:00:00.000Z", 30)).toBe(false);
  });
});
