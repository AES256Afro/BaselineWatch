import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { nistBaselinesAdapter, nistCatalogAdapter } from "../src/adapters/oscal-nist.ts";
import { countRows, migrate, openDatabase } from "../src/db.ts";
import { diffRequirements, summarizeChanges } from "../src/differ.ts";
import type { HttpGet } from "../src/http.ts";
import { getSource, ingestDocumentTarget, ingestSource } from "../src/ingest.ts";
import { normalizeCatalog, normalizeProfile, resolveParams, type OscalCatalog, type OscalProfile } from "../src/oscal.ts";
import { redline, wordDiff } from "../src/redline.ts";
import { baselinesFor, explanationsFor, latestDocument, listDocuments, releaseChanges, relinkSource } from "../src/register.ts";
import { parseNotifyUrl, recentAlerts } from "../src/notify.ts";
import { listWire } from "../src/wire.ts";
import { fixture, startTestApp, type TestApp } from "./helpers.ts";

const load = <T>(name: string): T => JSON.parse(new TextDecoder().decode(fixture(name))) as T;
const at = new Date("2026-10-15T01:00:00Z");

describe("OSCAL normalisation", () => {
  it("flattens a catalog into requirements with labels, resolved parameters and related controls", () => {
    const doc = normalizeCatalog(load<OscalCatalog>("oscal-catalog-5.2.0.json"));
    expect(doc.version).toBe("5.2.0");
    expect(doc.requirements).toHaveLength(42);
    const si712 = doc.requirements.find((r) => r.ref === "si-7.12")!;
    expect(si712.label).toBe("SI-07(12)");
    expect(si712.family).toBe("SI");
    expect(si712.parentRef).toBe("si-7");
    expect(si712.sortKey).toBe("si-07.12");
    expect(si712.title).toBe("Integrity Verification");
    expect(si712.statement).toContain("[Assignment: user-installed software]");
    expect(si712.related).toEqual(expect.arrayContaining(["si-2", "cm-11"]));
    expect(si712.params[0]).toMatchObject({ id: "si-07.12_odp", label: "user-installed software" });
    expect(typeof si712.extra.assessmentObjective).toBe("string");
    expect(doc.requirements.find((r) => r.ref === "sa-24")?.title).toBe("Design For Cyber Resiliency");
    const ac1 = doc.requirements.find((r) => r.ref === "ac-1")!;
    expect(ac1.statement).toMatch(/^a\. /m);
    expect(ac1.statement?.split("\n").length).toBeGreaterThan(3);
  });

  it("turns a profile into one requirement per included control", () => {
    const doc = normalizeProfile(load<OscalProfile>("oscal-profile-moderate-5.2.0.json"), new Map([["ac-2.1", "Automated System Account Management"]]));
    expect(doc.requirements).toHaveLength(287);
    const ac21 = doc.requirements.find((r) => r.ref === "ac-2.1")!;
    expect(ac21.label).toBe("AC-02(01)");
    expect(ac21.title).toBe("Automated System Account Management");
    expect(ac21.parentRef).toBe("ac-2");
  });

  it("resolves parameter insertions to the printed form", () => {
    const params = new Map([
      ["p1", { id: "p1", label: "frequency" }],
      ["p2", { id: "p2", select: { "how-many": "one-or-more", choice: ["a", "b"] } }],
    ]);
    expect(resolveParams("Review {{ insert: param, p1 }} and {{ insert: param, p2 }}; {{ insert: param, nope }}.", params)).toBe(
      "Review [Assignment: frequency] and [Selection (one or more): a; b]; [Assignment: nope].",
    );
  });
});

describe("differ", () => {
  it("finds what NIST changed between Release 5.1.1 and 5.2.0", () => {
    const before = normalizeCatalog(load<OscalCatalog>("oscal-catalog-5.1.1.json")).requirements;
    const after = normalizeCatalog(load<OscalCatalog>("oscal-catalog-5.2.0.json")).requirements;
    const changes = diffRequirements(before, after);
    const summary = summarizeChanges(changes);
    expect(summary.added).toEqual(expect.arrayContaining(["sa-24", "si-2.7", "sa-15.13"]));
    expect(summary.removed).toEqual([]);
    expect(summary.modified).toContain("si-7.12");
    expect(summary.modified).toContain("si-2"); // discussion update
    const si712Fields = changes.filter((c) => c.ref === "si-7.12").map((c) => c.field);
    expect(si712Fields.some((f) => f === "statement" || f === "guidance" || f === "params")).toBe(true);
    // NIST's note says every -01 control had its related controls updated; the OSCAL catalog shows AC-1 unchanged.
    expect(summary.modified).not.toContain("ac-1");
    // The same text twice is never a change.
    expect(diffRequirements(after, after)).toEqual([]);
  });

  it("word-diffs and renders a redline", () => {
    expect(wordDiff("a b c", "a x c")).toEqual([
      { kind: "same", text: "a " },
      { kind: "del", text: "b" },
      { kind: "ins", text: "x" },
      { kind: "same", text: " c" },
    ]);
    const out = redline("Require integrity of user-installed software.", "Require integrity of user-installed software and updates.").value;
    expect(out).toContain("<ins> and updates</ins>");
    expect(out).not.toContain("<del>");
    expect(redline("gone", null).value).toBe("<del>gone</del>");
  });
});

/** Serves the adapter's history and current URLs from the fixtures: the 5.2.0 fixture for the current catalog too. */
function nistHttp(): HttpGet {
  return async (url) => {
    let name: string;
    if (url.includes("_catalog.json")) name = url.includes("941c978d14") ? "oscal-catalog-5.1.1.json" : "oscal-catalog-5.2.0.json";
    else if (url.includes("baseline_profile.json")) name = url.includes("941c978d14") ? "oscal-profile-moderate-5.1.1.json" : "oscal-profile-moderate-5.2.0.json";
    else throw new Error(`no fixture for ${url}`);
    return { url, status: 200, notModified: false, bytes: fixture(name), etag: null, lastModified: null, contentType: "application/json" };
  };
}

async function loadNist(db: DatabaseSync, dataDir: string): Promise<void> {
  const http = nistHttp();
  const catalog = getSource(db, "nist-sp-800-53")!;
  for (const target of nistCatalogAdapter.history!(catalog)) await ingestDocumentTarget(db, dataDir, catalog, nistCatalogAdapter, target, { http, now: () => at });
  const baselines = getSource(db, "nist-sp-800-53b")!;
  for (const target of nistBaselinesAdapter.history!(baselines).filter((t) => t.key === "profile:moderate")) {
    await ingestDocumentTarget(db, dataDir, baselines, nistBaselinesAdapter, target, { http, now: () => at });
  }
}

describe("Register ingestion", () => {
  let db: DatabaseSync;
  let dataDir = "";
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-reg-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("loads history in order, diffs each release against the last, explains it and posts it to the Wire", async () => {
    await loadNist(db, dataDir);
    const docs = listDocuments(db, "nist-sp-800-53");
    expect(docs).toHaveLength(2);
    const latest = latestDocument(db, "nist-sp-800-53", "catalog")!;
    expect(latest.version_label).toBe("5.2.0");
    expect(latest.previous_document_id).not.toBeNull();
    expect(latest.requirement_count).toBe(42);
    expect(countRows(db, "requirements")).toBe(39 + 42 + 287 + 287);

    const changes = releaseChanges(db, latest.id);
    expect(changes.some((c) => c.ref === "sa-24" && c.kind === "added")).toBe(true);
    expect(changes.some((c) => c.ref === "si-7.12" && c.kind === "modified")).toBe(true);
    const explanations = explanationsFor(db, latest.id);
    expect(explanations).toHaveLength(1);
    expect(explanations[0]).toMatchObject({ kind: "publisher", source_url: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final" });
    expect(explanations[0]?.text).toContain("SA-15(13), SA-24, SI-02(07)");

    const releases = listWire(db, { kind: "release" });
    expect(releases.map((i) => i.source_id)).toEqual(expect.arrayContaining(["nist-sp-800-53", "nist-sp-800-53b"]));
    const catalogRelease = releases.find((i) => i.external_id === `catalog#${latest.id}`)!;
    expect(catalogRelease.title).toMatch(/5\.2\.0: 3 added/);
    expect(catalogRelease.url).toBe(`/standards/nist-sp-800-53/${latest.id}`);
    expect(baselinesFor(db, "ac-1")).toEqual(["moderate"]);
    expect(baselinesFor(db, "sa-24")).toEqual([]);

    // Fetching the current catalog again finds the same bytes: unchanged, no new document.
    const again = await ingestSource(db, dataDir, getSource(db, "nist-sp-800-53")!, { http: nistHttp(), now: () => at });
    expect(again.status).toBe("unchanged");
    expect(listDocuments(db, "nist-sp-800-53")).toHaveLength(2);
    expect(getSource(db, "nist-sp-800-53")?.last_status).toBe("unchanged");
  });

  it("loads a standard's history on its first scheduled fetch, quietly, and only the current document after that", async () => {
    const http = nistHttp();
    const transport = parseNotifyUrl("ntfy://h/t");
    const catalog = getSource(db, "nist-sp-800-53")!;
    const first = await ingestSource(db, dataDir, catalog, { http, now: () => at, transport });
    expect(first.status).toBe("ok");
    expect(first.items).toBe(3); // the two history entries, then the current file, which is the 5.2.0 bytes again
    const docs = listDocuments(db, "nist-sp-800-53");
    expect(docs.map((d) => d.version_label)).toEqual(["5.2.0", "5.1.1+u4"]);
    expect(releaseChanges(db, docs[0]!.id).some((c) => c.ref === "sa-24" && c.kind === "added")).toBe(true);
    expect(recentAlerts(db, 10)).toHaveLength(0); // a back catalogue is not news

    const again = await ingestSource(db, dataDir, catalog, { http, now: () => at, transport });
    expect(again.status).toBe("unchanged");
    expect(again.items).toBe(1);
    expect(listDocuments(db, "nist-sp-800-53")).toHaveLength(2);
  });

  it("slots a history loaded after the current release into publication order", async () => {
    // The current catalog (the 5.2.0 bytes) arrived first, on its own, and is the only document.
    const http = nistHttp();
    const catalog = getSource(db, "nist-sp-800-53")!;
    expect((await ingestDocumentTarget(db, dataDir, catalog, nistCatalogAdapter, { key: "catalog", url: catalog.url }, { http, now: () => at })).status).toBe("ok");
    const current = latestDocument(db, "nist-sp-800-53", "catalog")!;
    expect(current.previous_document_id).toBeNull();
    expect(explanationsFor(db, current.id)).toHaveLength(0);

    // Then the backfill: 5.1.1 is older than what is loaded; the 5.2.0 entry is the same bytes.
    const outcomes = [];
    for (const target of nistCatalogAdapter.history!(catalog)) outcomes.push(await ingestDocumentTarget(db, dataDir, catalog, nistCatalogAdapter, target, { http, now: () => at }));
    expect(outcomes.map((o) => o.status)).toEqual(["ok", "unchanged"]);
    expect(outcomes[0]?.summary).toBe("first version, 39 requirements");

    const docs = listDocuments(db, "nist-sp-800-53");
    expect(docs).toHaveLength(2);
    const older = docs.find((d) => d.id !== current.id)!;
    const latest = latestDocument(db, "nist-sp-800-53", "catalog")!;
    expect(latest.id).toBe(current.id);
    expect(older.previous_document_id).toBeNull();
    expect(latest.previous_document_id).toBe(older.id);
    expect(releaseChanges(db, older.id)).toHaveLength(0);
    const changes = releaseChanges(db, latest.id);
    expect(changes.some((c) => c.ref === "sa-24" && c.kind === "added")).toBe(true);
    expect(changes.some((c) => c.kind === "removed")).toBe(false);
    // The history entry knew why 5.2.0 happened, and the document had no reason yet: it adopts it.
    expect(explanationsFor(db, latest.id).map((e) => e.kind)).toEqual(["publisher"]);

    const releases = listWire(db, { kind: "release" }).filter((i) => i.source_id === "nist-sp-800-53");
    expect(releases.find((i) => i.external_id === `catalog#${latest.id}`)?.title).toMatch(/5\.2\.0: 3 added/);
    expect(releases.find((i) => i.external_id === `catalog#${older.id}`)?.title).toMatch(/5\.1\.1.*: loaded as the first version/);
    expect(relinkSource(db, catalog, at.toISOString())).toEqual({ keys: 1, relinked: 0 });
  });

  it("relink repairs a chain whose predecessors were wrong and leaves a correct one alone", async () => {
    await loadNist(db, dataDir);
    const catalog = getSource(db, "nist-sp-800-53")!;
    const [newer, older] = listDocuments(db, "nist-sp-800-53");
    expect(newer!.version_label).toBe("5.2.0");
    expect(relinkSource(db, catalog, at.toISOString())).toEqual({ keys: 1, relinked: 0 });

    // What a backfill into a non-empty database used to produce: the old release hanging off the new one.
    db.prepare("UPDATE documents SET previous_document_id = ? WHERE id = ?").run(newer!.id, older!.id);
    db.prepare("UPDATE documents SET previous_document_id = NULL WHERE id = ?").run(newer!.id);
    db.prepare("DELETE FROM changes WHERE to_document_id = ?").run(newer!.id);
    expect(relinkSource(db, catalog, at.toISOString())).toEqual({ keys: 1, relinked: 2 });

    const latest = latestDocument(db, "nist-sp-800-53", "catalog")!;
    expect(latest.id).toBe(newer!.id);
    expect(latest.previous_document_id).toBe(older!.id);
    expect(listDocuments(db, "nist-sp-800-53").find((d) => d.id === older!.id)?.previous_document_id).toBeNull();
    expect(releaseChanges(db, latest.id).some((c) => c.ref === "sa-24" && c.kind === "added")).toBe(true);
    expect(releaseChanges(db, older!.id)).toHaveLength(0);
    // The publisher's reason stays with the release; the Wire entry says what changed again.
    expect(explanationsFor(db, latest.id).map((e) => e.kind)).toEqual(["publisher"]);
    const release = listWire(db, { kind: "release" }).find((i) => i.external_id === `catalog#${latest.id}`);
    expect(release?.title).toMatch(/5\.2\.0: 3 added/);
    expect(relinkSource(db, catalog, at.toISOString())).toEqual({ keys: 1, relinked: 0 });
  });
});

describe("Register pages", () => {
  let app: TestApp;
  afterEach(async () => {
    await app?.close();
  });

  it("shows the standard, the release with the publisher's reason, and a control redline", async () => {
    app = await startTestApp({ now: () => at });
    await loadNist(app.db, app.dataDir);
    const latest = latestDocument(app.db, "nist-sp-800-53", "catalog")!;

    const home = await (await fetch(`${app.base}/register`)).text();
    expect(home).toContain('href="/standards/nist-sp-800-53"');
    expect(home).toContain("5.2.0");

    const standard = await (await fetch(`${app.base}/standards/nist-sp-800-53`)).text();
    expect(standard).toContain("5.1.1+u4");
    expect(standard).toContain("3 added");

    const release = await (await fetch(`${app.base}/standards/nist-sp-800-53/${latest.id}`)).text();
    expect(release).toContain("SA-24");
    expect(release).toContain("Design For Cyber Resiliency");
    expect(release).toContain("in the publisher's words");
    expect(release).toContain("NIST issued a minor release");
    expect(release).toContain("Controls added, removed or revised");
    // The Atlas map leads here one family at a time.
    const saOnly = await (await fetch(`${app.base}/standards/nist-sp-800-53/${latest.id}?family=SA`)).text();
    expect(saOnly).toContain("<b>SA-24</b>");
    expect(saOnly).not.toContain("<b>SI-07(12)</b>");
    expect(saOnly).toContain("Controls added, removed or revised in SA");
    expect(saOnly).toContain(`class="on" href="/standards/nist-sp-800-53/${latest.id}?family=SA"`);
    const acOnly = await (await fetch(`${app.base}/standards/nist-sp-800-53/${latest.id}?family=AC`)).text();
    expect(acOnly).toContain("No control in AC changed in this release");

    const control = await (await fetch(`${app.base}/standards/nist-sp-800-53/${latest.id}/si-7.12`)).text();
    expect(control).toContain("Integrity Verification");
    expect(control).toContain("<ins>");
    expect(control).toContain("Before · 5.1.1+u4");
    const ac1 = await (await fetch(`${app.base}/standards/nist-sp-800-53/${latest.id}/ac-1`)).text();
    expect(ac1).toContain("Moderate baseline");
    expect(ac1).toContain("Policy and Procedures");

    const added = await (await fetch(`${app.base}/standards/nist-sp-800-53/${latest.id}/sa-24`)).text();
    expect(added).toContain("added");
    expect(added).not.toContain("<del>");

    const browse = await (await fetch(`${app.base}/standards/nist-sp-800-53/${latest.id}/browse?family=SA`)).text();
    expect(browse).toContain("SA-24");
    expect(browse).toContain("Design For Cyber Resiliency");
    expect(browse).toContain("changed here");
    expect(browse).not.toContain("Integrity Verification"); // SI family filtered out
    const search = await (await fetch(`${app.base}/standards/nist-sp-800-53/${latest.id}/browse?q=integrity+verification`)).text();
    expect(search).toContain("SI-07(12)");
    expect(search).toMatch(/\d+ of 42\./);
    expect(search).not.toContain("SA-24");
    expect(release).toContain("Read every requirement in this version");

    expect((await fetch(`${app.base}/standards/nope`)).status).toBe(404);
    expect((await fetch(`${app.base}/standards/nist-sp-800-53/999999`)).status).toBe(404);
    expect((await fetch(`${app.base}/standards/nist-sp-800-53/${latest.id}/zz-99`)).status).toBe(404);
    expect((await fetch(`${app.base}/standards`, { redirect: "manual" })).status).toBe(302);
  });
});
