import { describe, expect, it } from "vitest";
import type { ParsedDocument } from "../src/adapters/types.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource } from "../src/ingest.ts";
import type { NormalizedRequirement } from "../src/oscal.ts";
import { pipelineHealth, pipelineSummary, staleCveLine } from "../src/pipeline.ts";
import { renderControl, renderRelease, sortRefs } from "../src/pages/register.ts";
import { renderStigsIndex } from "../src/pages/stigs.ts";
import { renderToday } from "../src/pages/today.ts";
import { documentName, publisherListedRules, storeDocument, stigRuleName } from "../src/register.ts";
import { setTriage, triageInboxCount } from "../src/triage.ts";
import { durationWord } from "../src/words.ts";

/**
 * The readability pass of 16 November: each case is one the audit found on the live data, written
 * as the smallest input that shows it.
 */

const at = "2026-11-16T12:00:00.000Z";
const now = new Date(at);
const look = { look: "register" as const, scheme: "system" as const, back: "/" };
const who = { owner: true, open: false, look, now };

function freshDb() {
  const db = openDatabase(":memory:");
  migrate(db);
  return db;
}
type Db = ReturnType<typeof freshDb>;

function req(ref: string, over: Partial<NormalizedRequirement> = {}): NormalizedRequirement {
  return { ref, parentRef: null, family: null, label: ref.toUpperCase(), title: `Title of ${ref}`, statement: null, guidance: null, params: [], related: [], sortKey: ref, status: "active", extra: {}, ...over };
}

function addDocument(db: Db, sourceId: string, key: string, parsed: Partial<ParsedDocument> & { requirements: NormalizedRequirement[] }): number {
  const snapshot = db.prepare("INSERT INTO snapshots (source_id, document_key, sha256, bytes, media_type, blob_path, fetched_at) VALUES (?, ?, ?, 1, 'application/json', 'blobs/x', ?)").run(sourceId, key, `${sourceId}:${key}:${Math.random()}`, at);
  const doc: ParsedDocument = { title: key, versionLabel: "1", publishedAt: at, ...parsed };
  return storeDocument(db, { source: getSource(db, sourceId)!, target: { key, url: `https://example.test/${key}` }, parsed: doc, snapshotId: Number(snapshot.lastInsertRowid), fetchedAt: at }).documentId;
}

const hoursAgo = (h: number) => new Date(now.getTime() - h * 3_600_000).toISOString();

describe("a stopped CVE stream", () => {
  it("is said on the page, in days, and comes before a failing source in the pipeline line", () => {
    const db = freshDb();
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-1', ?, 'cvss')").run("2026-10-26T15:47:40.386Z");
    db.prepare("UPDATE sources SET last_status = 'error', failing_since = ? WHERE id = 'bleeping'").run(hoursAgo(619));
    expect(staleCveLine(db, now)).toBe("CVE data last updated 26 Oct (20 days ago); counts stop there.");
    expect(pipelineSummary(pipelineHealth(db, now))).toBe("the CVE pull is 20 days behind; BleepingComputer has failed for 25 days");
    const today = renderToday({ db, ...who, hours: 24 });
    expect(today).toContain('<p class="notice warn stale-cves" role="status">CVE data last updated 26 Oct (20 days ago); counts stop there.');
    db.close();
  });

  it("says nothing inside two days, and hours stay hours until then", () => {
    const db = freshDb();
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-1', ?, 'cvss')").run(hoursAgo(30));
    expect(staleCveLine(db, now)).toBeNull();
    expect(renderToday({ db, ...who, hours: 24 })).not.toContain("stale-cves");
    expect(durationWord(40)).toBe("40 h");
    expect(durationWord(619)).toBe("25 days");
    db.close();
  });
});

describe("the owner's desk on Today", () => {
  it("counts the whole inbox, not the six it draws", () => {
    const db = freshDb();
    const add = db.prepare("INSERT INTO items (source_id, kind, external_id, title, published_at, fetched_at) VALUES ('cisa-kev', 'kev', ?, ?, ?, ?)");
    for (let i = 0; i < 9; i += 1) add.run(`CVE-2026-${100 + i}`, `CVE-2026-${100 + i} · thing`, at, at);
    expect(triageInboxCount(db, now)).toBe(9);
    const page = renderToday({ db, ...who, hours: 24 });
    expect(page).toContain('<span class="count">9 waiting for a decision (6 shown) · 0 under review or affecting us</span>');
    expect(page).not.toContain("placed,");
    db.close();
  });
});

describe("an empty window on Today", () => {
  it("is one line with the wider windows, not five zeros and four empty boxes", () => {
    const db = freshDb();
    const page = renderToday({ db, ...who, hours: 24 });
    expect(page).toContain("<p>Nothing moved in the last 24 h.</p>");
    expect(page).toContain('<a class="" href="/today?since=72">3 days</a>');
    expect(page).not.toContain('<div class="stats today">');
    expect(page).not.toContain('id="install"');
    expect(page).not.toContain('id="nofix"');
    db.close();
  });

  it("keeps the tiles and groups when anything happened, even only a card marked done", () => {
    const db = freshDb();
    const item = db.prepare("INSERT INTO items (source_id, kind, external_id, title, published_at, fetched_at) VALUES ('cisa-kev', 'kev', 'CVE-2026-5', 'CVE-2026-5 · thing', ?, ?)").run(at, at);
    setTriage(db, { kind: "item", id: Number(item.lastInsertRowid), key: "" }, { state: "done" }, at);
    const page = renderToday({ db, ...who, hours: 24 });
    expect(page).toContain('<div class="stats today">');
    expect(page).not.toContain("Nothing moved in the last");
    db.close();
  });
});

describe("a STIG loaded for the first time", () => {
  it("says how many rules DISA lists as changed, and links each rule its note names", () => {
    const db = freshDb();
    const id = addDocument(db, "disa-stigs", "stig:microsoft-windows-11", {
      title: "Microsoft Windows 11 Security Technical Implementation Guide",
      versionLabel: "V2R11",
      rationale: { text: "Revision History, V2R11:\n- WN11-00-000040: Revised Check.\n- WN11-00-000045, V-253286: Revised Fix. Replaced CCI-000366.\n- WN11-99-000001: Not held here.", url: null },
      requirements: [req("v-253263", { label: "WN11-00-000040", family: "CAT II" }), req("v-253264", { label: "WN11-00-000045", family: "CAT II" }), req("v-253286", { label: "WN11-00-000160", family: "CAT II" })],
    });
    expect(publisherListedRules(db, id)).toEqual(["WN11-00-000040", "WN11-00-000045", "V-253286", "WN11-99-000001"]);
    const index = renderStigsIndex({ db, ...who });
    expect(index).toContain(`<a href="/standards/disa-stigs/${id}">DISA lists 4 changed rules</a>`);
    expect(index).not.toContain("first version loaded");
    const release = renderRelease({ db, sourceId: "disa-stigs", documentId: id, ...who })!;
    expect(release).toContain(`- <a href="/standards/disa-stigs/${id}/v-253263">WN11-00-000040</a>: Revised Check.`);
    expect(release).toContain(`<a href="/standards/disa-stigs/${id}/v-253286">V-253286</a>`);
    // A CCI is not a rule, and a rule the instance does not hold stays text.
    expect(release).not.toContain(">CCI-000366</a>");
    expect(release).toContain("- WN11-99-000001: Not held here.");
    expect(release).toContain("<title>Windows 11 STIG V2R11 · ");
    db.close();
  });

  it("is named by its own title, never by the library that fetched it", () => {
    expect(documentName("disa-stigs", "DISA STIG library", { title: "Microsoft Windows 11 Security Technical Implementation Guide", document_key: "stig:microsoft-windows-11", version_label: "V2R11" })).toBe("Windows 11 STIG V2R11");
    expect(documentName("disa-stigs", "DISA STIG library", { title: "Google Android 16 COBO Security Technical Implementation Guide", document_key: "stig:google-android-16", version_label: "Y26M10" })).toBe("Google Android 16 COBO STIG Y26M10");
    expect(documentName("nist-sp-800-53", "NIST SP 800-53 (controls)", { title: "x", document_key: "catalog", version_label: "5.2.0" })).toBe("NIST SP 800-53 (controls) 5.2.0");
    expect(stigRuleName("WN11-00-000160", "v-253286")).toBe("WN11-00-000160 (V-253286)");
  });
});

describe("a control's related controls", () => {
  it("are links in reading order, ac-3 before ac-20", () => {
    expect(sortRefs(["ac-20", "au-2", "ac-3", "ac-2.1", "ac-2"])).toEqual(["ac-2", "ac-2.1", "ac-3", "ac-20", "au-2"]);
    const db = freshDb();
    const id = addDocument(db, "nist-sp-800-53", "catalog", { versionLabel: "5.2.0", requirements: [req("ac-2", { related: ["ac-20", "pm-9", "ac-3"] }), req("ac-3"), req("ac-20")] });
    const page = renderControl({ db, sourceId: "nist-sp-800-53", documentId: id, ref: "ac-2", ...who })!;
    expect(page).toContain(`<h3>Related controls</h3><p class="prose related"><a href="/standards/nist-sp-800-53/${id}/ac-3">AC-3</a>, <a href="/standards/nist-sp-800-53/${id}/ac-20">AC-20</a>, PM-9</p>`);
    // The only version there is: no "5.2.0 against 5.2.0".
    expect(page).toContain('<div class="when">NIST SP 800-53 (controls) 5.2.0<br>');
    db.close();
  });
});
