import { afterEach, describe, expect, it } from "vitest";
import type { SourceRow } from "../src/adapters/types.ts";
import type { NormalizedRequirement } from "../src/oscal.ts";
import type { DocumentRow } from "../src/register.ts";
import { controlAtPublisher, documentSources, publisherLinks, requirementSources } from "../src/sourcelinks.ts";
import { startTestApp, type TestApp } from "./helpers.ts";

/**
 * Where a control's own words live. The point of the module is that a page never ends at its own
 * text: a reader who wants the publisher's wording can always get there, and the address is either
 * one checked against the publisher's site or none at all.
 */

function source(over: Partial<SourceRow> & { id: string }): SourceRow {
  return {
    name: over.id,
    kind: "requirement-set",
    group_name: "standards",
    url: "https://example.test/",
    format: "json",
    schedule: "daily",
    enabled: 1,
    restricted: 0,
    licence: null,
    attribution: null,
    notes: null,
    last_fetch_at: null,
    last_status: null,
    last_error: null,
    etag: null,
    last_modified: null,
    last_duration_ms: null,
    fetch_count: 0,
    ...over,
  };
}

function document(over: Partial<DocumentRow> = {}): DocumentRow {
  return {
    id: 1,
    source_id: "nist-sp-800-53",
    document_key: "catalog",
    snapshot_id: 1,
    version_label: "5.2.0",
    title: null,
    published_at: "2025-08-27",
    parsed_at: "2026-10-20T00:00:00.000Z",
    source_url: "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
    requirement_count: 42,
    previous_document_id: null,
    ...over,
  };
}

function requirement(over: Partial<NormalizedRequirement> & { ref: string; label: string }): NormalizedRequirement {
  return {
    parentRef: null,
    family: null,
    title: "A control",
    statement: null,
    guidance: null,
    params: [],
    related: [],
    sortKey: over.ref,
    status: "active",
    extra: {},
    ...over,
  };
}

describe("a control at its publisher", () => {
  it("addresses a NIST control in CPRT by the label it already carries", () => {
    const link = controlAtPublisher(source({ id: "nist-sp-800-53", name: "NIST SP 800-53 (controls)" }), document(), requirement({ ref: "ac-2", label: "AC-02" }))!;
    expect(link.href).toBe("https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_2_0/home?element=AC-02");
    expect(link.access).toBe("public");
    const enhancement = controlAtPublisher(source({ id: "nist-sp-800-53" }), document(), requirement({ ref: "ac-2.1", label: "AC-02(01)" }))!;
    expect(enhancement.href).toContain("element=AC-02(01)");
  });

  it("sends 800-53A and 800-53B to the same element, because CPRT keeps them as tabs of the control", () => {
    const b = controlAtPublisher(source({ id: "nist-sp-800-53b" }), document({ source_id: "nist-sp-800-53b", document_key: "profile:high" }), requirement({ ref: "ac-1", label: "AC-01" }))!;
    expect(b.href).toContain("/SP_800_53_5_2_0/home?element=AC-01");
    const a = controlAtPublisher(source({ id: "nist-sp-800-53a" }), document({ source_id: "nist-sp-800-53a" }), requirement({ ref: "ac-1", label: "AC-01" }))!;
    expect(a.href).toContain("/SP_800_53_5_2_0/home?element=AC-01");
  });

  it("names the revision for 800-171, whose file states its OSCAL version rather than the publication's", () => {
    const link = controlAtPublisher(
      source({ id: "nist-sp-800-171" }),
      document({ source_id: "nist-sp-800-171", version_label: "OSCAL 1.1.0" }),
      requirement({ ref: "03.01.01", label: "03.01.01" }),
    )!;
    expect(link.href).toBe("https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_171_3_0_0/home?element=03.01.01");
  });

  it("invents nothing: no deep link for a version CPRT does not number this way, or a label that is not a control", () => {
    expect(controlAtPublisher(source({ id: "nist-sp-800-53" }), document({ version_label: "rev5" }), requirement({ ref: "ac-2", label: "AC-02" }))).toBeNull();
    expect(controlAtPublisher(source({ id: "nist-sp-800-53" }), document(), requirement({ ref: "ac-2_odp.01", label: "AC-02_ODP[01]" }))).toBeNull();
    expect(controlAtPublisher(source({ id: "nist-sp-800-171" }), document({ version_label: null }), requirement({ ref: "a.03.01.01", label: "A.03.01.01" }))).toBeNull();
    // A STIG rule exists only inside DISA's package; the package itself is the honest answer.
    expect(controlAtPublisher(source({ id: "disa-stigs" }), document({ source_id: "disa-stigs" }), requirement({ ref: "v-253254", label: "WN11-00-000005" }))).toBeNull();
  });

  it("points an mSCP rule at its file in the commit the version was read from", () => {
    const link = controlAtPublisher(
      source({ id: "nist-mscp" }),
      document({ source_id: "nist-mscp", source_url: "https://codeload.github.com/usnistgov/macos_security/zip/cf656e844a4091868b2eeb8e6405f8f83952d08f" }),
      requirement({ ref: "audit_acls_files_configure", label: "audit_acls_files_configure", extra: { section: "audit" } }),
    )!;
    expect(link.href).toBe("https://github.com/usnistgov/macos_security/blob/cf656e844a4091868b2eeb8e6405f8f83952d08f/rules/audit/audit_acls_files_configure.yaml");
    // Without the section there is no path to build, so nothing is guessed.
    expect(
      controlAtPublisher(
        source({ id: "nist-mscp" }),
        document({ source_id: "nist-mscp", source_url: "https://codeload.github.com/usnistgov/macos_security/zip/cf656e8" }),
        requirement({ ref: "audit_acls_files_configure", label: "audit_acls_files_configure" }),
      ),
    ).toBeNull();
  });

  it("uses the address an adapter read from the publisher's own list", () => {
    const nasa = controlAtPublisher(
      source({ id: "nasa-cyber-ref" }),
      document({ source_id: "nasa-cyber-ref", version_label: "as of 2026-09-15" }),
      requirement({ ref: "directive:npd-1382.17", label: "NPD 1382.17K", extra: { url: "https://nodis3.gsfc.nasa.gov/displayDir.cfm?t=NPD&c=1382&s=17K" } }),
    )!;
    expect(nasa.href).toBe("https://nodis3.gsfc.nasa.gov/displayDir.cfm?t=NPD&c=1382&s=17K");
    const frr = controlAtPublisher(
      source({ id: "fedramp-rules" }),
      document({ source_id: "fedramp-rules" }),
      requirement({ ref: "afc-cso-ack", label: "AFC-CSO-ACK", extra: { reference: "https://www.fedramp.gov/rules/" } }),
    )!;
    expect(frr.href).toBe("https://www.fedramp.gov/rules/");
    // Anything that is not an http address is not a link.
    expect(controlAtPublisher(source({ id: "fedramp-rules" }), document({ source_id: "fedramp-rules" }), requirement({ ref: "x", label: "X", extra: { reference: "see appendix B" } }))).toBeNull();
  });
});

describe("the trail from one control", () => {
  it("ends at the rule, the document it was read from and the body that wrote it, each address once", () => {
    const links = requirementSources(source({ id: "nist-sp-800-53", name: "NIST SP 800-53 (controls)" }), document(), requirement({ ref: "ac-2", label: "AC-02" }));
    expect(links[0]?.href).toContain("cprt");
    expect(links[1]?.href).toContain("NIST_SP-800-53_rev5_catalog.json");
    expect(links[1]?.label).toBe("NIST SP 800-53 (controls) 5.2.0 as published");
    // The authority registry's own addresses for NIST follow, and no address is listed twice.
    expect(links.some((l) => l.href.startsWith("https://csrc.nist.gov/pubs/sp/800/53/"))).toBe(true);
    expect(new Set(links.map((l) => l.href)).size).toBe(links.length);
  });

  it("still names somewhere to read it when the publisher gives no page for the rule", () => {
    const links = requirementSources(
      source({ id: "canary-malware", name: "Malware canaries (URLhaus)", url: "https://urlhaus.abuse.ch/downloads/hostfile/" }),
      document({ source_id: "canary-malware", document_key: "canaries", version_label: "2026-10-20 10:27 UTC", source_url: "https://urlhaus.abuse.ch/downloads/hostfile/" }),
      requirement({ ref: "breezeclient.org", label: "breezeclient.org" }),
    );
    expect(links).toHaveLength(1);
    expect(links[0]?.href).toBe("https://urlhaus.abuse.ch/downloads/hostfile/");
  });

  it("says what it takes to read a licensed publisher, and never links the entry itself", () => {
    const cis = source({ id: "cis-benchmarks", name: "CIS Benchmarks (manual upload)", url: "https://www.cisecurity.org/cis-benchmarks", restricted: 1, licence: "CIS licence; internal use, no redistribution" });
    const links = publisherLinks(cis);
    expect(links.length).toBeGreaterThan(0);
    expect(links.some((l) => l.access === "registration" || l.access === "licence")).toBe(true);
    // An uploaded PDF has no address of its own, so nothing stands in for one.
    expect(documentSources(cis, document({ source_id: "cis-benchmarks", source_url: null }))).toEqual(links);
  });
});

describe("the pages that show a control", () => {
  let app: TestApp;
  afterEach(async () => {
    await app?.close();
  });

  it("carries the publisher's address on a control, a version and the Controls page", async () => {
    app = await startTestApp({ now: () => new Date("2026-10-25T09:00:00Z") });
    app.db.exec(
      `INSERT INTO snapshots (source_id, document_key, sha256, bytes, media_type, blob_path, fetched_at)
         VALUES ('nist-sp-800-53', 'catalog', 'abc', 1, 'application/json', 'blobs/ab/abc', '2026-10-20T00:00:00.000Z');
       INSERT INTO documents (source_id, document_key, snapshot_id, version_label, published_at, parsed_at, source_url, requirement_count)
         VALUES ('nist-sp-800-53', 'catalog', 1, '5.2.0', '2025-08-27', '2026-10-20T00:00:00.000Z', 'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json', 1);
       INSERT INTO requirements (document_id, ref, family, label, title, statement, params_json, related_json, sort_key, status, extra_json)
         VALUES (1, 'ac-2', 'AC', 'AC-02', 'Account Management', 'a. Define and document the types of accounts allowed', '[]', '[]', 'ac-02', 'active', '{}');`,
    );

    const control = await (await fetch(`${app.base}/standards/nist-sp-800-53/1/ac-2`)).text();
    expect(control).toContain('id="at-publisher"');
    expect(control).toContain("https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_2_0/home?element=AC-02");
    expect(control).toContain("Read AC-02 at the publisher");
    expect(control).toContain("NIST_SP-800-53_rev5_catalog.json");

    const browse = await (await fetch(`${app.base}/standards/nist-sp-800-53/1/browse`)).text();
    expect(browse).toContain("Read this version at the publisher");
    expect(browse).toContain('id="at-publisher"');

    const controls = await (await fetch(`${app.base}/controls`)).text();
    expect(controls).toContain("At the publisher");
    expect(controls).toContain("as published");
  });
});
