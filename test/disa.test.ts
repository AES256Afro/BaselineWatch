import { zipSync } from "fflate";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { defaultStigs, disaAdapter, followedPatterns, parseXccdf, selectStigs, stigTarget, type DisaListingItem } from "../src/adapters/disa.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { diffRequirements, summarizeChanges } from "../src/differ.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { listDocuments } from "../src/register.ts";
import { fakeHttp, fixture } from "./helpers.ts";

const text = (name: string) => new TextDecoder().decode(fixture(name));
const listing = (): DisaListingItem[] => (JSON.parse(text("disa-listing.json")) as { returnValue: DisaListingItem[] }).returnValue;

describe("STIG library listing", () => {
  it("keeps the manual STIG zips, drops SCAP, Sunset and automation content, and reads versions", () => {
    const items = listing();
    expect(items.length).toBeGreaterThanOrEqual(14);
    const targets = selectStigs(items, defaultStigs);
    const keys = targets.map((t) => t.key);
    expect(keys).toEqual(expect.arrayContaining(["stig:microsoft-windows-server-2025", "stig:microsoft-windows-11", "stig:red-hat-enterprise-linux-9", "stig:canonical-ubuntu-24-04-lts", "stig:cisco-ios-xe-router", "stig:application-security-and-development"]));
    expect(keys.some((k) => k.includes("benchmark") || k.includes("ansible") || k.includes("chef"))).toBe(false);
    const ws = targets.find((t) => t.key === "stig:microsoft-windows-server-2025")!;
    expect(ws).toMatchObject({ versionLabel: "V1R4", publishedAt: "2026-10-05T00:00:00.000Z" });
    expect(ws.url).toMatch(/U_MS_Windows_Server_2025_V1R4_STIG\.zip$/);
    const cisco = targets.find((t) => t.key === "stig:cisco-ios-xe-router")!;
    expect(cisco.versionLabel).toBe("Y26M04");
    expect(stigTarget({ FileName: "Sunset - Thing STIG - Ver 1, Rel 1", DownloadLink: "https://x/y.zip", UploadDate: "2024-01-01", RawDownloadType: "STIGs;Sunset" })).toBeNull();
    expect(stigTarget({ FileName: "A memo", DownloadLink: "https://x/y.pdf", UploadDate: "2024-01-01", RawDownloadType: "STIGs" })).toBeNull();
    expect(selectStigs(items, ["ubuntu 24.04"]).map((t) => t.key)).toEqual(["stig:canonical-ubuntu-24-04-lts"]);
  });
});

describe("XCCDF", () => {
  it("reads rules with stable V- refs, STIG ids, severity, discussion, check and fix", () => {
    const parsed = parseXccdf(text("stig.xccdf.xml"));
    expect(parsed.title).toBe("Microsoft Windows Server 2025 Security Technical Implementation Guide");
    expect(parsed.benchmarkId).toBe("MS_Windows_Server_2025_STIG");
    expect(parsed.publishedAt).toBe("2026-09-01T00:00:00.000Z");
    expect(parsed.requirements).toHaveLength(3);
    const first = parsed.requirements[0]!;
    expect(first.ref).toBe("v-277982");
    expect(first.label).toBe("WN25-00-000001");
    expect(first.family).toBe("CAT II");
    expect(first.title).toMatch(/^Windows Server 2025 must install security-relevant software updates/);
    expect(first.guidance).toMatch(/^Security flaws with operating systems are discovered daily/);
    expect(first.guidance).not.toContain("VulnDiscussion");
    expect(first.statement).toMatch(/^Review the operating system documentation/);
    expect(first.related).toEqual(["CCI-002605"]);
    expect(first.extra).toMatchObject({ ruleId: "SV-277982r1181944_rule", severity: "medium", srg: "SRG-OS-000439-GPOS-00195" });
    expect(typeof first.extra.fix).toBe("string");
  });

  it("diffs two releases rule by rule", () => {
    const before = parseXccdf(text("stig.xccdf.xml")).requirements;
    const after = parseXccdf(text("stig.xccdf.xml").replace('severity="medium"', 'severity="high"').replace("within 30 days", "within 14 days")).requirements;
    const changes = diffRequirements(before, after);
    const summary = summarizeChanges(changes);
    expect(summary.substantive).toContain("v-277982"); // title changed
    expect(changes.some((c) => c.ref === "v-277982" && c.field === "extra")).toBe(true); // severity moved
  });
});

describe("DISA adapter end to end", () => {
  let db: ReturnType<typeof openDatabase>;
  let dataDir = "";
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-disa-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("lists from the Apex call, honours the watchlist, downloads zips, and skips unchanged listings without fetching", async () => {
    const source = getSource(db, "disa-stigs")!;
    expect(source.url).toContain("apex/execute");
    expect(followedPatterns({ db })).toEqual(defaultStigs);
    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('baseline', 'stig: Microsoft Windows Server 2025', 'Servers', ?)").run(new Date().toISOString());
    expect(followedPatterns({ db })).toEqual(["Microsoft Windows Server 2025"]);

    const zip = zipSync({ "U_MS_Windows_Server_2025_V1R4_Manual_STIG/U_MS_Windows_Server_2025_STIG_V1R4_Manual-xccdf.xml": fixture("stig.xccdf.xml") });
    const wsUrl = listing().find((i) => /Windows Server 2025 STIG - Ver/i.test(i.FileName))!.DownloadLink;
    const http = fakeHttp({ [source.url]: { bytes: fixture("disa-listing.json") }, [wsUrl]: { bytes: new Uint8Array(zip) } });
    const first = await ingestSource(db, dataDir, source, { http, now: () => new Date("2026-10-15T02:00:00Z") });
    expect(first.status).toBe("ok");
    expect(first.detail).toContain("stig:microsoft-windows-server-2025 V1R4: first version, 3 requirements");
    const docs = listDocuments(db, "disa-stigs");
    expect(docs).toHaveLength(1);
    expect(docs[0]).toMatchObject({ version_label: "V1R4", requirement_count: 3, published_at: "2026-10-05T00:00:00.000Z" });

    const calls = http.calls.length;
    const second = await ingestSource(db, dataDir, source, { http, now: () => new Date("2026-10-15T03:00:00Z") });
    expect(second.status).toBe("unchanged");
    expect(http.calls.length).toBe(calls + 1); // the listing only; the zip was not fetched again
    expect(disaAdapter.id).toBe("disa-stig");
  });
});
