import { zipSync } from "fflate";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cciAdapter, cciListingTarget, cciListUrl, controlRef, parseCciList } from "../src/adapters/cci.ts";
import type { DisaListingItem } from "../src/adapters/disa.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { listDocuments } from "../src/register.ts";
import { cciMap, controlsFor } from "../src/stigs.ts";
import { fakeHttp, fixture } from "./helpers.ts";

const text = (name: string) => new TextDecoder().decode(fixture(name));

describe("CCI index to control ref", () => {
  it("drops statement letters and assessment sub-indexes and keeps the enhancement", () => {
    expect(controlRef("AC-1 a 1 (a)")).toBe("ac-1");
    expect(controlRef("AC-11 (1)")).toBe("ac-11.1");
    expect(controlRef("IA-5 (2) (a) (1)")).toBe("ia-5.2");
    expect(controlRef("RA-5 (9).1")).toBe("ra-5.9");
    expect(controlRef("IA-13 (03) (d)")).toBe("ia-13.3");
    expect(controlRef("SC-28")).toBe("sc-28");
    expect(controlRef("AC-14.1 (ii)")).toBe("ac-14");
    expect(controlRef("nonsense")).toBeNull();
  });
});

describe("CCI list", () => {
  it("reads every identifier with its definition, type and the Revision 5 controls it indexes", () => {
    const parsed = parseCciList(text("cci/CCI_List.xml"));
    expect(parsed.version).toBe("2026-07-14");
    expect(parsed.versionLabel).toBe("2026-07-14");
    expect(parsed.publishedAt).toBe("2026-07-14T00:00:00.000Z");
    expect(parsed.requirements).toHaveLength(19);
    const screenLock = parsed.requirements.find((r) => r.label === "CCI-000056")!;
    expect(screenLock.ref).toBe("cci-000056");
    expect(screenLock.family).toBe("Technical");
    expect(screenLock.related).toEqual(["ac-11"]);
    expect(screenLock.extra).toMatchObject({ type: "technical", rev5: ["AC-11 b"] });
    expect(parsed.requirements.find((r) => r.label === "CCI-000060")!.related).toEqual(["ac-11.1"]);
    expect(parsed.requirements.find((r) => r.label === "CCI-000186")!.related).toEqual(["ia-5.2"]);
    expect(parsed.requirements.find((r) => r.label === "CCI-002605")!.related).toEqual(["si-2"]);
    const policy = parsed.requirements.find((r) => r.label === "CCI-000003")!;
    expect(policy.family).toBe("Policy");
    expect(policy.statement).toMatch(/^Review and update the current access control policy/);
    // An identifier DISA has not indexed to Revision 5 falls back to its Revision 4 index.
    const old = parsed.requirements.find((r) => r.label === "CCI-000001")!;
    expect(old.related).toEqual(["ac-1"]);
    expect(old.extra).toMatchObject({ mappedThrough: "rev4" });
    expect(() => parseCciList("<nope/>")).toThrow(/not a CCI list/);
  });

  it("finds the zip in the STIG library listing", () => {
    const items = (JSON.parse(text("disa-listing.json")) as { returnValue: DisaListingItem[] }).returnValue;
    const target = cciListingTarget(items);
    expect(target).toMatchObject({ key: "cci", url: cciListUrl, publishedAt: "2026-07-15T00:00:00.000Z" });
    expect(cciListingTarget([])).toBeNull();
  });
});

describe("CCI adapter end to end", () => {
  let db: ReturnType<typeof openDatabase>;
  let dataDir = "";
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-cci-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("loads the list through the listing, maps both ways, and skips an unchanged listing without downloading", async () => {
    const source = getSource(db, "disa-cci")!;
    expect(source.schedule).toBe("weekly");
    const listingUrl = getSource(db, "disa-stigs")!.url;
    const zip = zipSync({ "CCI_List.xml": fixture("cci/CCI_List.xml"), "README.TXT": new TextEncoder().encode("list") });
    const http = fakeHttp({ [listingUrl]: { bytes: fixture("disa-listing.json") }, [cciListUrl]: { bytes: new Uint8Array(zip) } });
    const first = await ingestSource(db, dataDir, source, { http, now: () => new Date("2026-10-17T10:00:00Z") });
    expect(first.status).toBe("ok");
    expect(first.detail).toContain("cci 2026-07-14: first version, 19 requirements");
    const docs = listDocuments(db, "disa-cci");
    expect(docs).toHaveLength(1);
    expect(docs[0]).toMatchObject({ version_label: "2026-07-14", published_at: "2026-07-15T00:00:00.000Z", requirement_count: 19 });

    const map = cciMap(db);
    expect(map.version).toBe("2026-07-14");
    expect(map.controls.get("CCI-000056")).toEqual(["ac-11"]);
    expect(map.ccis.get("ac-11")).toEqual(expect.arrayContaining(["CCI-000056", "CCI-000057"]));
    expect(controlsFor({ related: ["CCI-000057", "CCI-001199", "CCI-000060"] }, map)).toEqual(["ac-11", "ac-11.1", "sc-28"]);

    const calls = http.calls.length;
    const second = await ingestSource(db, dataDir, source, { http, now: () => new Date("2026-10-18T10:00:00Z") });
    expect(second.status).toBe("unchanged");
    expect(http.calls.length).toBe(calls + 1); // the listing only
    expect(cciAdapter.id).toBe("disa-cci");
  });

  it("falls back to the fixed address when the listing cannot be read", async () => {
    const source = getSource(db, "disa-cci")!;
    const listingUrl = getSource(db, "disa-stigs")!.url;
    const zip = zipSync({ "U_CCI_List.xml": fixture("cci/CCI_List.xml") });
    const http = fakeHttp({ [listingUrl]: { status: 503 }, [cciListUrl]: { bytes: new Uint8Array(zip) } });
    const result = await ingestSource(db, dataDir, source, { http, now: () => new Date("2026-10-17T10:00:00Z") });
    expect(result.status).toBe("ok");
    expect(listDocuments(db, "disa-cci")[0]).toMatchObject({ version_label: "2026-07-14", published_at: "2026-07-14T00:00:00.000Z" });
  });
});
