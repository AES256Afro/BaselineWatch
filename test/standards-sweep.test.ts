import { zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { cisAdapter, parseCisText } from "../src/adapters/cis.ts";
import { disaAdapter, parseXccdf } from "../src/adapters/disa.ts";
import type { ParsedDocument } from "../src/adapters/types.ts";
import type { Profile, ProfileItem } from "../src/baselines.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { parseStigRevisionHistory, stripPageHeaders } from "../src/explain.ts";
import { exportProfile, sections } from "../src/exports.ts";
import { getSource } from "../src/ingest.ts";
import type { NormalizedRequirement } from "../src/oscal.ts";
import { latestVersions, searchControls } from "../src/pages/controls.ts";
import { renderControl } from "../src/pages/register.ts";
import { storeDocument } from "../src/register.ts";
import { buildTestPlan, exportPlan, noProcedureReason, payloadProcedure } from "../src/testplans.ts";
import { fixture } from "./helpers.ts";
import { simplePdf } from "./pdf-helper.ts";

/**
 * The sweep of the Register, the baseline exports and the test plans on 16 November: each case is
 * one reproduced against the live data before it was fixed.
 */

const at = "2026-11-16T12:00:00.000Z";
const text = (name: string) => new TextDecoder().decode(fixture(name));

function freshDb() {
  const db = openDatabase(":memory:");
  migrate(db);
  return db;
}

type Db = ReturnType<typeof freshDb>;

function req(ref: string, over: Partial<NormalizedRequirement> = {}): NormalizedRequirement {
  return { ref, parentRef: null, family: null, label: ref.toUpperCase(), title: `Title of ${ref}`, statement: null, guidance: null, params: [], related: [], sortKey: ref, status: "active", extra: {}, ...over };
}

/** A document stored the way the ingester stores one, behind a snapshot row of its own. */
function addDocument(db: Db, sourceId: string, key: string, parsed: Partial<ParsedDocument> & { requirements: NormalizedRequirement[] }): number {
  const sha = `${sourceId}:${key}:${Math.random()}`;
  const snapshot = db.prepare("INSERT INTO snapshots (source_id, document_key, sha256, bytes, media_type, blob_path, fetched_at) VALUES (?, ?, ?, 1, 'application/json', 'blobs/x', ?)").run(sourceId, key, sha, at);
  const doc: ParsedDocument = { title: key, versionLabel: "1", publishedAt: at, ...parsed };
  return storeDocument(db, { source: getSource(db, sourceId)!, target: { key, url: `https://example.test/${key}` }, parsed: doc, snapshotId: Number(snapshot.lastInsertRowid), fetchedAt: at }).documentId;
}

function profileItem(id: string, kind: ProfileItem["kind"], severity: string | null, section: string): ProfileItem {
  return { id, kind, label: id, title: `Rule ${id}`, severity, section, check: null, fix: null, controls: [], stigIds: [], mscp: null, registry: [], gpoPath: null, intune: [], checklist: null, sctValue: null, url: `/x/${id}`, implementedBy: [], decision: null, included: true };
}

describe("the baseline export's sections", () => {
  // A STIG lists its rules by rule id, CAT I and CAT II interleaved, then what Microsoft adds and the controls.
  const items = [
    profileItem("stig:v-1", "stig", "CAT II", "CAT II"),
    profileItem("stig:v-2", "stig", "CAT I", "CAT I"),
    profileItem("stig:v-3", "stig", "CAT II", "CAT II"),
    profileItem("stig:v-4", "stig", "CAT I", "CAT I"),
    profileItem("sct:a", "sct", null, "Microsoft baseline: Defender"),
    profileItem("control:ac-2", "control", null, "SP 800-53 High: AC"),
    profileItem("stig:v-5", "stig", "CAT II", "CAT II"),
    profileItem("sct:b", "sct", null, "Microsoft baseline: Edge"),
    profileItem("sct:c", "sct", null, "Microsoft baseline: Defender"),
  ];
  const profile = {
    platform: "windows",
    options: { platform: "windows" },
    components: { stig: null, sct: null, mscp: null, controls: null, cciVersion: null, intune: null, checklist: null },
    choices: { stigs: [], scts: [], mscps: [] },
    items,
    next: [],
    counts: { included: items.length, dropped: 0, byKind: { stig: 5, sct: 3, mscp: 0, control: 1 }, decisions: { apply: items.length, modify: 0, exclude: 0 } },
  } as unknown as Profile;

  it("draws one heading per section, CAT I first, items in profile order within each", () => {
    expect(sections(profile).map((s) => [s.section, s.items.map((i) => i.id)])).toEqual([
      ["CAT I", ["stig:v-2", "stig:v-4"]],
      ["CAT II", ["stig:v-1", "stig:v-3", "stig:v-5"]],
      ["Microsoft baseline: Defender", ["sct:a", "sct:c"]],
      ["Microsoft baseline: Edge", ["sct:b"]],
      ["SP 800-53 High: AC", ["control:ac-2"]],
    ]);
    const md = exportProfile(profile, "md", "plain", { baseUrl: "https://example.test", generatedAt: at, version: "0.0.0" }).body;
    expect(md.match(/^## .*$/gm)).toEqual(["## CAT I (2)", "## CAT II (3)", "## Microsoft baseline: Defender (2)", "## Microsoft baseline: Edge (1)", "## SP 800-53 High: AC (1)", "## Attribution"]);
    const page = exportProfile(profile, "html", "plain", { baseUrl: "https://example.test", generatedAt: at, version: "0.0.0" }).body;
    expect(page.match(/<h2>CAT I /g)).toHaveLength(1);
  });
});

describe("the test plan's mSCP rules with no check text", () => {
  it("tests a rule from its profile payload, and lists one with neither as not tested", () => {
    const db = freshDb();
    const ios = (ref: string, over: Partial<NormalizedRequirement>) => req(ref, { family: "iOS/iPadOS", label: ref, ...over, extra: { baselines: ["ios_stig"], ...over.extra } });
    addDocument(db, "nist-mscp", "mscp:ios_26", {
      title: "iOS/iPadOS 26.0: iOS 26 Guidance",
      requirements: [
        // mSCP's iOS guidance carries a blank check on every rule.
        ios("icloud_backup_disabled", { title: "Disable iCloud Backup", statement: " ", extra: { mobileconfigInfo: { "com.apple.applicationaccess": { allowCloudBackup: false } } } }),
        ios("os_allowlist", { title: "Allow listed apps only", statement: null, extra: { mobileconfigInfo: { "com.apple.applicationaccess": { allowListedAppBundleIDs: ["a", "b"] } } } }),
        ios("os_checked", { title: "A rule with a check", statement: "Run the check.", extra: { mobileconfigInfo: { "com.apple.applicationaccess": { allowAirDrop: false } } } }),
        ios("os_nothing", { title: "A rule with nothing to test from", statement: "  " }),
      ],
    });
    const plan = buildTestPlan(db, { platform: "ios", mscp: "mscp:ios_26", templates: false });
    const byLabel = new Map(plan.items.map((i) => [i.label, i]));
    expect(byLabel.get("icloud_backup_disabled")).toMatchObject({ source: "mscp", included: true, procedure: "Verify the installed profile sets com.apple.applicationaccess allowCloudBackup = false." });
    expect(byLabel.get("icloud_backup_disabled")!.sourceTitle).toContain("configuration-profile payload");
    expect(byLabel.get("os_allowlist")!.procedure).toBe('Verify the installed profile sets com.apple.applicationaccess allowListedAppBundleIDs = ["a","b"].');
    expect(byLabel.get("os_checked")!.procedure).toBe("Run the check.");
    expect(byLabel.has("os_nothing")).toBe(false);
    expect(plan.noProcedure.map((i) => i.label)).toEqual(["os_nothing"]);
    expect(plan.counts).toMatchObject({ derived: 3, noProcedure: 1 });
    const json = JSON.parse(exportPlan(plan, "json", { baseUrl: "https://example.test", generatedAt: at, version: "0.0.0" }).body as string) as { notTested: { label: string; why: string }[] };
    expect(json.notTested).toEqual([{ label: "os_nothing", title: "A rule with nothing to test from", why: noProcedureReason }]);
    expect(payloadProcedure({ mscp: null })).toBeNull();
    db.close();
  });
});

describe("a continuous STIG's revision history", () => {
  it("reads only the release the XCCDF names, once per note, whatever the file token says", () => {
    const history = parseStigRevisionHistory(text("stig-revision-history-continuous.txt"), "V1R4");
    expect(history.version).toBe("V1R4");
    // COBO and COPE carry the same note; it is kept once, and no earlier release's leaks in.
    expect(history.notes).toEqual([
      { label: "GOOG-16-008700", text: "Removed references to WPA2." },
      { label: "GOOG-16-009800", text: "Removed references to WPA2." },
    ]);
    expect(history.general).toEqual(["Requirements were updated throughout to reflect the change from DOD to DoW."]);
    // A label the history does not head (the file token) reads the newest release, never the whole text.
    const token = parseStigRevisionHistory(text("stig-revision-history-continuous.txt"), "Y26M10");
    expect(token).toEqual(history);
    const older = parseStigRevisionHistory(text("stig-revision-history-continuous.txt"), "V1R3");
    expect(older.notes.map((n) => n.label)).toEqual(["GOOG-16-010600", "GOOG-16-013100"]);
    expect(older.general).toEqual([]);
  });

  it("does not take a wrapped document-revised label for a release heading", () => {
    const wrapped = ["REVISION HISTORY", "V2R10 Canonical", "Ubuntu 22.04", "LTS STIG,", "V2R9", "- UBTU-22-231010 - Updated requirement to", "CAT 1.", "- Requirements were updated throughout.", "30 September 2026", "", "V2R9 - Canonical", "Ubuntu 22.04", "LTS STIG,", "V2R8", "- UBTU-22-215040 - Updated severity.", "01 July 2026"].join("\n");
    const history = parseStigRevisionHistory(wrapped, "V2R10");
    expect(history.notes).toEqual([{ label: "UBTU-22-231010", text: "Updated requirement to CAT 1." }]);
    expect(history.general).toEqual(["Requirements were updated throughout."]);
    // An id the PDF broke at its hyphen, and Chrome's two-part ids.
    const ios = parseStigRevisionHistory(["V1R3 Apple", "26 STIG,", "V1R2", "- AIOS-26-016100, AIOS-", "26-016300 - Removed requirement per CIO.", "- DTBC-0055 - Updated settings.", "13 May 2026"].join("\n"), "V1R3");
    expect(ios.notes.map((n) => n.label)).toEqual(["AIOS-26-016100", "AIOS-26-016300", "DTBC-0055"]);
  });

  it("does not take wrapped prose that opens with a release label for a heading", () => {
    const prose = ["V2R10 Canonical", "Ubuntu 22.04", "LTS STIG,", "V2R9", "- UBTU-22-215040 - Updated the severity from", "V2R9 to V2R11.", "- UBTU-22-231010 - Updated the check.", "30 September 2026"].join("\n");
    const history = parseStigRevisionHistory(prose, "V2R10");
    expect(history.version).toBe("V2R10");
    expect(history.notes).toEqual([
      { label: "UBTU-22-215040", text: "Updated the severity from V2R9 to V2R11." },
      { label: "UBTU-22-231010", text: "Updated the check." },
    ]);
    // The heading forms still read: a label ending the line, before " -", ":" or a capitalised word.
    for (const heading of ["V2R10", "V2R10 - Canonical", "V2R10: Canonical", "V2R10 Canonical"]) {
      expect(parseStigRevisionHistory([heading, "- UBTU-22-1 - x.", "30 September 2026"].join("\n"), "V2R10").version, heading).toBe("V2R10");
    }
  });

  it("strips DISA's page headers before reading the blocks", () => {
    // A page break inside V1R4's block, the header wrapped so its release opens a line ("V1R4 DISA").
    const paged = [
      "V1R4 Microsoft", "Windows", "Server 2025", "STIG, V1R3",
      "- WN25-00-000020 - Updated max password age", "value to 180 days.",
      "\fUNCLASSIFIED", "", "MS Windows Server 2025 STIG Revision History,", "V1R4 DISA", "", "30 September 2026 Developed by DISA for the DoW", "", "2", "", "UNCLASSIFIED", "", "REVISION HISTORY", "", "Revision", "", "Number", "", "Document", "", "Revised ", "Description of Change Release Date", "",
      "- WN25-00-000140 - Revised default", "permissions in Check text.", "30 September 2026",
      "V1R3 Microsoft", "Windows", "Server 2025", "STIG, V1R2", "- WN25-00-000332 - Added.", "10 August 2026",
    ].join("\n");
    const history = parseStigRevisionHistory(paged, "V1R4");
    expect(history.notes).toEqual([
      { label: "WN25-00-000020", text: "Updated max password age value to 180 days." },
      { label: "WN25-00-000140", text: "Revised default permissions in Check text." },
    ]);
    expect(history.general).toEqual([]);
    // The fixture's own headers go, and the row date the page break cut stays.
    const stripped = stripPageHeaders(text("stig-revision-history.txt").replace(/\f/g, "\n"));
    expect(stripped).not.toContain("Revision History, V1R4 DISA");
    expect(stripped).toContain("10 August 2026");
    expect(stripPageHeaders(text("stig-revision-history-continuous.txt"))).not.toContain("Google Android 16 STIG Revision History DISA");
  });

  it("names the release from the XCCDF when the listing labels it by month", async () => {
    expect(parseXccdf(text("stig.xccdf.xml")).revision).toBe("V1R4");
    const historyText = text("stig-revision-history-continuous.txt").replace(/\f/g, "\n").split("\n");
    const zip = zipSync({ "U_Google_Android_16_STIG/U_Google_Android_16_STIG_V1R4_Manual-xccdf.xml": fixture("stig.xccdf.xml"), "U_Google_Android_16_Revision_History.pdf": simplePdf(historyText) });
    const db = freshDb();
    const parsed = await disaAdapter.parseDocument!(new Uint8Array(zip), { key: "stig:google-android-16", url: "https://example.test/android.zip", versionLabel: "Y26M10" }, { db, source: getSource(db, "disa-stigs")!, http: async () => { throw new Error("no network"); } });
    expect(parsed.versionLabel).toBe("Y26M10");
    expect(parsed.rationale?.text).toBe("Revision History, V1R4 (Y26M10):\n- GOOG-16-008700: Removed references to WPA2.\n- GOOG-16-009800: Removed references to WPA2.\n- Requirements were updated throughout to reflect the change from DOD to DoW.");
    expect(parsed.rationale?.text).not.toContain("Initial Release");
    db.close();
  });
});

describe("the control search", () => {
  it("finds a STIG rule by the SV id DISA prints", () => {
    const db = freshDb();
    addDocument(db, "disa-stigs", "stig:microsoft-windows-server-2022", { title: "Windows Server 2022", requirements: [req("v-254238", { label: "WN22-00-000010", family: "CAT II", extra: { ruleId: "SV-254238r991589_rule" } }), req("v-254239", { label: "WN22-00-000020" })] });
    const versions = latestVersions(db);
    for (const q of ["SV-254238", "sv-254238r991589_rule", "SV-254238r991589"]) expect(searchControls(db, versions, q).map((h) => h.ref), q).toEqual(["v-254238"]);
    expect(searchControls(db, versions, "SV-25423").map((h) => h.ref)).toEqual(["v-254238", "v-254239"]);
    expect(searchControls(db, versions, "WN22-00-000010").map((h) => h.ref)).toEqual(["v-254238"]);
    db.close();
  });
});

describe("the part-of pill", () => {
  const who = { owner: true, open: false, look: { look: "register" as const, scheme: "system" as const, back: "/" }, now: new Date(at) };

  it("links a parent the document holds, the catalogue's when the baseline leaves it out, and nothing for a CIS section", () => {
    const db = freshDb();
    const catalog = addDocument(db, "nist-sp-800-53", "catalog", { requirements: [req("ac-3"), req("ac-3.14", { parentRef: "ac-3" }), req("pt-2"), req("pt-2.1", { parentRef: "pt-2" })] });
    const privacy = addDocument(db, "nist-sp-800-53b", "profile:privacy", { requirements: [req("ac-3.14", { parentRef: "ac-3" }), req("pt-2"), req("pt-2.1", { parentRef: "pt-2" })] });
    const cis = addDocument(db, "cis-benchmarks", "cis:ubuntu-linux-24-04-lts", { requirements: [req("1.1.1", { parentRef: "1.1" })] });
    const page = (sourceId: string, documentId: number, ref: string) => renderControl({ db, sourceId, documentId, ref, ...who })!;
    expect(page("nist-sp-800-53b", privacy, "pt-2.1")).toContain(`<a class="pill" href="/standards/nist-sp-800-53b/${privacy}/pt-2">part of PT-2</a>`);
    expect(page("nist-sp-800-53b", privacy, "ac-3.14")).toContain(`<a class="pill" href="/standards/nist-sp-800-53/${catalog}/ac-3">part of AC-3 in SP 800-53</a>`);
    expect(page("nist-sp-800-53b", privacy, "ac-3.14")).not.toContain(`/standards/nist-sp-800-53b/${privacy}/ac-3"`);
    const section = page("cis-benchmarks", cis, "1.1.1");
    expect(section).toContain('<span class="pill">part of 1.1</span>');
    expect(section).not.toContain(`/standards/cis-benchmarks/${cis}/1.1"`);
    db.close();
  });
});

describe("a CIS benchmark's cover date", () => {
  const cover = (date: string) => ["CIS Microsoft Windows 11 Enterprise Benchmark", `v4.0.0 - ${date}`, "1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)' (Automated)", "Description:", "Password history.", "Remediation:", "Set it to 24."];

  it("is read beside the version and stands in for a blank Published date", async () => {
    expect(parseCisText(cover("03-31-2025").join("\n"))).toMatchObject({ version: "4.0.0", publishedAt: "2025-03-31" });
    expect(parseCisText(cover("13-31-2025").join("\n")).publishedAt).toBeNull();
    const db = freshDb();
    const ctx = { db, source: getSource(db, "cis-benchmarks")!, http: async () => { throw new Error("no network"); } };
    const pdf = simplePdf(cover("03-31-2025"));
    expect((await cisAdapter.parseDocument!(pdf, { key: "upload", url: "upload:cis.pdf", publishedAt: null }, ctx)).publishedAt).toBe("2025-03-31T00:00:00.000Z");
    // A date the owner gives still wins.
    expect((await cisAdapter.parseDocument!(simplePdf(cover("03-31-2025")), { key: "upload", url: "upload:cis.pdf", publishedAt: "2025-04-02T00:00:00.000Z" }, ctx)).publishedAt).toBe("2025-04-02T00:00:00.000Z");
    db.close();
  });
});
