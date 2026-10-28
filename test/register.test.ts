import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { nistBaselinesAdapter, nistCatalogAdapter } from "../src/adapters/oscal-nist.ts";
import { countRows, migrate, openDatabase } from "../src/db.ts";
import { diffRequirements, summarizeChanges } from "../src/differ.ts";
import { getSource, ingestDocumentTarget, ingestSource } from "../src/ingest.ts";
import { normalizeCatalog, normalizeProfile, resolveParams, type OscalCatalog, type OscalProfile } from "../src/oscal.ts";
import { redline, wordDiff } from "../src/redline.ts";
import { baselinesFor, explanationsFor, latestDocument, listDocuments, releaseChanges, relinkSource } from "../src/register.ts";
import { parseNotifyUrl, recentAlerts } from "../src/notify.ts";
import { listWire } from "../src/wire.ts";
import { fixture, nistCurrentRelease, nistFixtureHttp, nistOneDiff, startTestApp, type TestApp } from "./helpers.ts";

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
async function loadNist(db: DatabaseSync, dataDir: string): Promise<void> {
  const http = nistFixtureHttp();
  const catalog = getSource(db, "nist-sp-800-53")!;
  for (const target of nistCatalogAdapter.history!(catalog).filter(nistOneDiff)) {
    await ingestDocumentTarget(db, dataDir, catalog, nistCatalogAdapter, target, { http, now: () => at });
  }
  const baselines = getSource(db, "nist-sp-800-53b")!;
  for (const target of nistBaselinesAdapter.history!(baselines).filter((t) => t.key === "profile:moderate" && nistOneDiff(t))) {
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

    // Fetching the current catalog brings what NIST republished under the same version number: one
    // control's text moved, and 5.2.0 therefore appears twice, which is what the publisher did.
    const again = await ingestSource(db, dataDir, getSource(db, "nist-sp-800-53")!, { http: nistFixtureHttp(), now: () => at });
    expect(again.status).toBe("ok");
    const republished = latestDocument(db, "nist-sp-800-53", "catalog")!;
    expect(republished.version_label).toBe("5.2.0");
    expect(republished.previous_document_id).toBe(latest.id);
    expect(releaseChanges(db, republished.id).map((c) => `${c.ref} ${c.field}`)).toEqual(["sa-15.13 statement"]);
    expect(listDocuments(db, "nist-sp-800-53")).toHaveLength(3);
  });

  it("loads a standard's whole published history on its first scheduled fetch, quietly, with Revision 4 as its own revision", async () => {
    const http = nistFixtureHttp();
    const transport = parseNotifyUrl("ntfy://h/t");
    const catalog = getSource(db, "nist-sp-800-53")!;
    const first = await ingestSource(db, dataDir, catalog, { http, now: () => at, transport });
    expect(first.status).toBe("ok");
    expect(first.items).toBe(8); // Revision 4, the six pinned releases of Revision 5, then the current file
    const docs = listDocuments(db, "nist-sp-800-53");
    expect(docs.map((d) => `${d.document_key} ${d.version_label}`)).toEqual([
      "catalog 5.2.0",
      "catalog 5.2.0",
      "catalog 5.1.1+u4",
      "catalog 5.1.1+u3",
      "catalog 5.1.1+u2",
      "catalog 5.1.1",
      "catalog Revision 5 (Dec 2020 errata)",
      "catalog-rev4 Revision 4",
    ]);
    expect(recentAlerts(db, 10)).toHaveLength(0); // a back catalogue is not news

    // Revision 4 is a different book, not an earlier release of this one: its own key, its own
    // floor, nothing diffed into Revision 5, and the publisher's own words on why it is withdrawn.
    const rev4 = docs.find((d) => d.document_key === "catalog-rev4")!;
    expect(rev4.previous_document_id).toBeNull();
    expect(rev4.requirement_count).toBe(37);
    expect(releaseChanges(db, rev4.id)).toHaveLength(0);
    expect(explanationsFor(db, rev4.id)[0]?.text).toContain("officially withdrawn on September 23, 2021");

    // The Revision 5 chain runs oldest to newest, each release diffed against the one before it.
    const chain = [...docs.filter((d) => d.document_key === "catalog")].reverse();
    expect(chain[0]?.previous_document_id).toBeNull();
    for (const [i, doc] of chain.entries()) if (i > 0) expect(doc.previous_document_id).toBe(chain[i - 1]!.id);
    // Every pinned release carries the publisher's reason; the current file's comes from the page.
    for (const doc of chain.slice(0, -1)) expect(explanationsFor(db, doc.id).map((e) => e.kind)).toEqual(["publisher"]);

    // What each step says of itself. The releases that only changed how the content is represented
    // touch no control text, which is the whole reason the conversions before the floor are left out.
    const byVersion = (label: string, at = 0) => chain.filter((d) => d.version_label === label)[at]!;
    const conversionOnly = releaseChanges(db, byVersion("5.1.1").id);
    expect(conversionOnly.length).toBeGreaterThan(0);
    expect(conversionOnly.every((c) => c.field === "extra" || c.field === "params")).toBe(true);
    // 5.1.1+u2 carried NIST's new control IA-13, which is outside this fixture's families: the
    // release is still kept, with its note, rather than folded into the next one.
    expect(releaseChanges(db, byVersion("5.1.1+u2").id)).toHaveLength(0);
    expect(explanationsFor(db, byVersion("5.1.1+u2").id)[0]?.text).toContain("one new control (IA-13)");
    const minorRelease = releaseChanges(db, byVersion("5.2.0").id);
    expect(minorRelease.filter((c) => c.kind === "added").map((c) => c.ref).sort()).toEqual(["sa-15.13", "sa-24", "si-2.7"]);

    const again = await ingestSource(db, dataDir, catalog, { http, now: () => at, transport });
    expect(again.status).toBe("unchanged");
    expect(again.items).toBe(1);
    expect(listDocuments(db, "nist-sp-800-53")).toHaveLength(8);
  });

  it("slots a history loaded after the current release into publication order", async () => {
    // The current catalog (the 5.2.0 bytes) arrived first, on its own, and is the only document.
    const http = nistFixtureHttp();
    const catalog = getSource(db, "nist-sp-800-53")!;
    expect((await ingestDocumentTarget(db, dataDir, catalog, nistCatalogAdapter, { key: "catalog", url: catalog.url }, { http, now: () => at })).status).toBe("ok");
    const current = latestDocument(db, "nist-sp-800-53", "catalog")!;
    expect(current.previous_document_id).toBeNull();
    expect(explanationsFor(db, current.id)).toHaveLength(0);

    // Then the backfill: both pinned releases are older than the republished file already loaded.
    const outcomes = [];
    for (const target of nistCatalogAdapter.history!(catalog).filter(nistOneDiff)) outcomes.push(await ingestDocumentTarget(db, dataDir, catalog, nistCatalogAdapter, target, { http, now: () => at }));
    expect(outcomes.map((o) => o.status)).toEqual(["ok", "ok"]);
    expect(outcomes[0]?.summary).toBe("first version, 39 requirements");

    const docs = listDocuments(db, "nist-sp-800-53");
    expect(docs).toHaveLength(3);
    const [, asPublished, older] = docs;
    const latest = latestDocument(db, "nist-sp-800-53", "catalog")!;
    expect(latest.id).toBe(current.id);
    expect(older!.previous_document_id).toBeNull();
    expect(asPublished!.previous_document_id).toBe(older!.id);
    expect(latest.previous_document_id).toBe(asPublished!.id);
    expect(releaseChanges(db, older!.id)).toHaveLength(0);
    const changes = releaseChanges(db, asPublished!.id);
    expect(changes.some((c) => c.ref === "sa-24" && c.kind === "added")).toBe(true);
    expect(changes.some((c) => c.kind === "removed")).toBe(false);
    // The history entry knew why 5.2.0 happened, and the document had no reason yet: it adopts it.
    expect(explanationsFor(db, asPublished!.id).map((e) => e.kind)).toEqual(["publisher"]);

    const releases = listWire(db, { kind: "release" }).filter((i) => i.source_id === "nist-sp-800-53");
    expect(releases.find((i) => i.external_id === `catalog#${asPublished!.id}`)?.title).toMatch(/5\.2\.0: 3 added/);
    expect(releases.find((i) => i.external_id === `catalog#${older!.id}`)?.title).toMatch(/5\.1\.1.*: loaded as the first version/);
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

  it("lets a release's own reason replace one scraped from a page that has since moved on", async () => {
    const http = nistFixtureHttp();
    const catalog = getSource(db, "nist-sp-800-53")!;
    const target = nistCurrentRelease(nistCatalogAdapter.history!(catalog));
    expect((await ingestDocumentTarget(db, dataDir, catalog, nistCatalogAdapter, target, { http, now: () => at })).status).toBe("ok");
    const doc = latestDocument(db, "nist-sp-800-53", "catalog")!;

    // What an earlier fetch of this release left behind: the publication page's note about another one.
    db.prepare("DELETE FROM explanations WHERE to_document_id = ?").run(doc.id);
    db.prepare("INSERT INTO explanations (change_id, to_document_id, kind, text, source_url, created_at) VALUES (NULL, ?, 'publisher', ?, ?, ?)").run(
      doc.id,
      "Planning Note (01/01/2030): a release this document knows nothing about",
      "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
      at.toISOString(),
    );

    // The same bytes again, under the history entry that names the reason for this release.
    expect((await ingestDocumentTarget(db, dataDir, catalog, nistCatalogAdapter, target, { http, now: () => at })).status).toBe("unchanged");
    const reasons = explanationsFor(db, doc.id);
    expect(reasons).toHaveLength(1);
    expect(reasons[0]?.text).toContain("SA-15(13), SA-24, SI-02(07)");
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
    // At a glance: the publication with its version in force; then every version, the only publication's fold open.
    expect(standard).toContain(`<td class="pub"><a href="/standards/nist-sp-800-53#doc-catalog"><b>Catalog</b></a></td>`);
    expect(standard).toContain(`<a href="/standards/nist-sp-800-53/${latest.id}"><b>5.2.0</b></a>`);
    expect(standard).toContain(`<details class="fold" id="doc-catalog" open>\n      <summary><b>Catalog</b><span class="fold-meta">2 versions · newest 5.2.0</span></summary>`);
    expect(standard).toContain(`<td class="n"><a href="/standards/nist-sp-800-53/${latest.id}/browse">42</a></td>`);
    expect(standard).toMatch(new RegExp(`<td><a href="/standards/nist-sp-800-53/${latest.id}">3 added[^<]*</a></td>`));

    const release = await (await fetch(`${app.base}/standards/nist-sp-800-53/${latest.id}`)).text();
    expect(release).toContain("SA-24");
    expect(release).toContain("Design For Cyber Resiliency");
    expect(release).toContain("in the publisher's words");
    expect(release).toContain("NIST issued a minor release");
    expect(release).toContain('<section class="box" id="substantive"><h2><a href="#substantive">Controls added, removed or revised</a> <span class="count"><a href="#substantive">');
    expect(release).toContain('<a class="pill ins" href="#substantive">+ 3 added: ');
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
    expect(ac1).toContain('<a class="pill" href="/standards/nist-sp-800-53b">Moderate baseline</a>');
    expect(ac1).toContain("Policy and Procedures");
    // The family pill narrows the release to that family, the way the Atlas does.
    expect(ac1).toContain(`<a class="pill" href="/standards/nist-sp-800-53/${latest.id}?family=AC">AC</a>`);
    expect(ac1).toContain(`<a class="pill none" href="/standards/nist-sp-800-53/${latest.id}">unchanged</a>`);

    const added = await (await fetch(`${app.base}/standards/nist-sp-800-53/${latest.id}/sa-24`)).text();
    expect(added).toContain("added");
    expect(added).not.toContain("<del>");

    const browse = await (await fetch(`${app.base}/standards/nist-sp-800-53/${latest.id}/browse?family=SA`)).text();
    expect(browse).toContain("SA-24");
    expect(browse).toContain(`<a href="/standards/nist-sp-800-53/${latest.id}/browse">42 requirements</a>`);
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
    // /standards was a redirect to /register until the all-standards catalog took the path.
    const catalog = await fetch(`${app.base}/standards`);
    expect(catalog.status).toBe(200);
    expect(await catalog.text()).toContain("<h1>All standards</h1>");
  });
});
