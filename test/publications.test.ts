import { describe, expect, it } from "vitest";
import { draftNumber, numberOfKey, seriesKey, seriesOf, type OpenDraft } from "../src/publications.ts";
import type { DocumentRow } from "../src/register.ts";

let nextId = 1;
function doc(key: string, version: string, published: string, title: string | null = null): DocumentRow {
  const id = nextId++;
  return {
    id,
    source_id: "nist-piv",
    document_key: key,
    snapshot_id: id,
    version_label: version,
    title,
    published_at: `${published}T00:00:00.000Z`,
    parsed_at: "2026-10-26T00:00:00.000Z",
    source_url: null,
    requirement_count: 10,
    previous_document_id: null,
  };
}

describe("publications grouped for reading", () => {
  it("reads a key as the publisher's number, and finds the series it belongs to", () => {
    expect(numberOfKey("sp-800-63b")).toBe("SP 800-63B");
    expect(numberOfKey("sp-800-73-pt1")).toBe("SP 800-73 Part 1");
    expect(numberOfKey("fips-201")).toBe("FIPS 201");
    expect(numberOfKey("ir-8320d")).toBe("IR 8320D");
    expect(numberOfKey("catalog")).toBeNull();
    expect(seriesKey("sp-800-63c")).toBe("sp-800-63");
    expect(seriesKey("sp-800-73-pt3")).toBe("sp-800-73");
    expect(seriesKey("sp-800-147b")).toBe("sp-800-147");
    expect(seriesKey("catalog-rev4")).toBe("catalog");
    expect(draftNumber("SP 800-73-6, Interfaces for Personal Identity Verification: Part 1 – PIV Card ApplicationInitial Working Draft")).toBe("SP 800-73");
    expect(draftNumber("FIPS 201-4, Personal Identity Verification")).toBe("FIPS 201");
  });

  it("gathers SP 800-63's volumes under one series, each with its current version and the ones before", () => {
    const series = seriesOf("nist-piv", [
      doc("sp-800-63", "SP 800-63-3", "2020-03-02", "Digital Identity Guidelines"),
      doc("sp-800-63", "SP 800-63-4", "2025-07-31", "Digital Identity Guidelines"),
      doc("sp-800-63c", "SP 800-63C-4", "2025-07-31", "Digital Identity Guidelines: Federation and Assertions"),
      doc("sp-800-63b", "SP 800-63B-4", "2025-07-31", "Digital Identity Guidelines: Authentication and Lifecycle Management"),
      doc("fips-201", "FIPS 201-3", "2022-01-24", "Personal Identity Verification (PIV) of Federal Employees and Contractors"),
    ]);
    expect(series.map((s) => s.key)).toEqual(["fips-201", "sp-800-63"]);
    const sp63 = series[1]!;
    expect(sp63.number).toBe("SP 800-63");
    expect(sp63.title).toBe("Digital Identity Guidelines");
    expect(sp63.publications.map((p) => p.label)).toEqual(["SP 800-63", "SP 800-63B", "SP 800-63C"]);
    expect(sp63.publications[0]!.current?.version_label).toBe("SP 800-63-4");
    expect(sp63.publications[0]!.earlier.map((d) => d.version_label)).toEqual(["SP 800-63-3"]);
  });

  it("keeps a draft apart from the version in force, and pins CSRC's open draft to the part it names", () => {
    const drafts: OpenDraft[] = [
      { title: "SP 800-73-6, Interfaces for Personal Identity Verification: Part 2 – Card Command InterfaceInitial Working Draft", url: "https://csrc.nist.gov/pubs/sp/800/73/pt2/6/iwd", published_at: "2026-06-12T04:00:00.000Z" },
      { title: "SP 800-221 Rev. 1, Enterprise Impact of ICT RiskInitial Public Draft", url: null, published_at: null },
    ];
    const series = seriesOf(
      "nist-piv",
      [
        doc("sp-800-73-pt1", "SP 800-73-5", "2024-07-15", "Interfaces for Personal Identity Verification"),
        doc("sp-800-73-pt2", "SP 800-73-5", "2024-07-15", "Interfaces for Personal Identity Verification"),
        doc("sp-800-157", "SP 800-157", "2014-12-19", "Guidelines for Derived PIV Credentials"),
        doc("sp-800-157", "SP 800-157 Rev. 1 (Draft)", "2024-11-14", "Guidelines for Derived PIV Credentials"),
      ],
      drafts,
    );
    const [pt1, pt2] = series.find((s) => s.key === "sp-800-73")!.publications;
    expect(pt1!.openDrafts).toEqual([]);
    expect(pt2!.openDrafts.map((d) => d.url)).toEqual(["https://csrc.nist.gov/pubs/sp/800/73/pt2/6/iwd"]);
    const derived = series.find((s) => s.key === "sp-800-157")!.publications[0]!;
    expect(derived.current?.version_label).toBe("SP 800-157");
    expect(derived.draft?.version_label).toBe("SP 800-157 Rev. 1 (Draft)");
    expect(derived.earlier).toEqual([]);
  });

  it("reads a superseded revision held under its own key as an earlier version of the same publication", () => {
    const series = seriesOf("nist-sp-800-53", [
      { ...doc("catalog", "5.2.0", "2025-08-26"), source_id: "nist-sp-800-53" },
      { ...doc("catalog", "5.1.1", "2023-10-12"), source_id: "nist-sp-800-53" },
      { ...doc("catalog-rev4", "Revision 4", "2015-01-22"), source_id: "nist-sp-800-53" },
    ]);
    expect(series).toHaveLength(1);
    const catalog = series[0]!.publications[0]!;
    expect(catalog.label).toBe("Catalog");
    expect(catalog.number).toBe("SP 800-53");
    expect(catalog.current?.version_label).toBe("5.2.0");
    expect(catalog.earlier.map((d) => d.version_label)).toEqual(["5.1.1", "Revision 4"]);
  });
});
