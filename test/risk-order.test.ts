import { describe, expect, it } from "vitest";
import { storeNvdRecords, type NvdCve } from "../src/adapters/nvd.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { listVulns } from "../src/vulns.ts";
import { vulnFilters } from "../src/routes/query.ts";

/**
 * The table's default order. It used to be "last modified", which on a real instance put a page of
 * unscored, zero-EPSS, single-vendor records at the top — the least useful list the data can
 * produce, on the page a practitioner opens first. "Risk" is the same rule the Wire already keeps
 * ("the Wire is for what matters"), applied to a table that still holds every CVE.
 */

const now = new Date("2026-10-25T12:00:00Z");

const record = (id: string, score: number | null, severity: string | null, modified: string): { cve: NvdCve } => ({
  cve: {
    id,
    sourceIdentifier: "nvd@nist.gov",
    published: "2026-10-01T00:00:00.000",
    lastModified: modified,
    vulnStatus: "Analyzed",
    descriptions: [{ lang: "en", value: `a flaw in ${id}` }],
    metrics: score === null ? {} : { cvssMetricV31: [{ source: "nvd@nist.gov", type: "Primary", cvssData: { version: "3.1", vectorString: "CVSS:3.1/AV:N", baseScore: score, baseSeverity: severity } }] },
  } as NvdCve,
});

function seeded() {
  const db = openDatabase(":memory:");
  migrate(db);
  storeNvdRecords({ db, now: () => now }, [
    // Touched most recently and worth the least: the row the old default led with.
    record("CVE-2026-0001", null, null, "2026-10-24T00:00:00.000"),
    record("CVE-2026-0002", 9.8, "CRITICAL", "2026-10-01T00:00:00.000"),
    record("CVE-2026-0003", 4.0, "MEDIUM", "2026-10-02T00:00:00.000"),
    record("CVE-2026-0004", 7.5, "HIGH", "2026-10-03T00:00:00.000"),
  ]);
  // 0003 is on the KEV, which outranks a higher score; 0004 has a public exploit; 0002 has the
  // highest EPSS of the rest.
  db.prepare("UPDATE vulns SET kev = 1, kev_date_added = '2026-10-02' WHERE cve_id = 'CVE-2026-0003'").run();
  db.prepare("INSERT INTO exploits (cve_id, source_id, ref, title, url, verified, seen_at) VALUES ('CVE-2026-0004', 'exploit-db', 'r', 't', 'https://e/1', 0, ?)").run(now.toISOString());
  db.prepare("UPDATE vulns SET epss = 0.4 WHERE cve_id = 'CVE-2026-0002'").run();
  return db;
}

const order = (db: ReturnType<typeof seeded>, sort?: "risk" | "modified" | "cvss") =>
  listVulns(db, { ...(sort ? { sort } : {}) }).rows.map((r) => r.cve_id);

describe("the table's default order", () => {
  it("leads with what is known to be exploited, then what has an exploit, then EPSS, then CVSS", () => {
    const db = seeded();
    try {
      expect(order(db)).toEqual(["CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0002", "CVE-2026-0001"]);
    } finally {
      db.close();
    }
  });

  it("is what a request with no sort asks for, and what an unrecognised one falls back to", () => {
    expect(vulnFilters({}, now).sort).toBe("risk");
    expect(vulnFilters({ sort: "alphabetical" }, now).sort).toBe("risk");
    expect(vulnFilters({ sort: "modified" }, now).sort).toBe("modified");
  });

  it("still answers the other orders exactly as before", () => {
    const db = seeded();
    try {
      // The old default, one click away: the most recently touched record, whatever it is worth.
      expect(order(db, "modified")[0]).toBe("CVE-2026-0001");
      expect(order(db, "cvss")[0]).toBe("CVE-2026-0002");
    } finally {
      db.close();
    }
  });

  it("holds every CVE either way: the order changed, not what the table carries", () => {
    const db = seeded();
    try {
      expect(order(db)).toHaveLength(4);
      expect([...order(db)].sort()).toEqual([...order(db, "modified")].sort());
    } finally {
      db.close();
    }
  });
});

describe("the table as a file", () => {
  it("carries the rows on screen, in the order on screen, with numbers as numbers", async () => {
    const { vulnsCsv } = await import("../src/vulns.ts");
    const db = seeded();
    try {
      const csv = vulnsCsv(db, {}, "https://bw.example");
      const rows = csv.trimEnd().split("\r\n");
      expect(rows[0]).toBe("cve,published,modified,cvss,severity,epss,epss percentile,kev,kev due,public exploit,vendors,products,watchlist labels,description,link");
      // The risk order, the same four rows the page shows.
      expect(rows.slice(1).map((r) => r.split(",")[0])).toEqual(["CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0002", "CVE-2026-0001"]);
      // A spreadsheet is going to do arithmetic on these, so they are numbers and not "9.8/10".
      const critical = rows.find((r) => r.startsWith("CVE-2026-0002"))!.split(",");
      expect(critical[3]).toBe("9.8");
      expect(critical[5]).toBe("0.4");
      expect(critical[7]).toBe("no");
      expect(rows.find((r) => r.startsWith("CVE-2026-0003"))!.split(",")[7]).toBe("yes");
      expect(rows.find((r) => r.startsWith("CVE-2026-0004"))!.split(",")[9]).toBe("yes");
      expect(csv).toContain("https://bw.example/vulnerabilities/CVE-2026-0003");
    } finally {
      db.close();
    }
  });

  it("answers the same filters the page does", async () => {
    const { vulnsCsv } = await import("../src/vulns.ts");
    const db = seeded();
    try {
      const kevOnly = vulnsCsv(db, { kev: true }, "https://bw.example").trimEnd().split("\r\n");
      expect(kevOnly).toHaveLength(2);
      expect(kevOnly[1]).toMatch(/^CVE-2026-0003,/);
      expect(vulnsCsv(db, { limit: 2 }, "https://bw.example").trimEnd().split("\r\n")).toHaveLength(3);
    } finally {
      db.close();
    }
  });
});
