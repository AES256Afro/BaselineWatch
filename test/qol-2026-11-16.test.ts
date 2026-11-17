import { mkdtempSync, readdirSync, rmSync, utimesSync, existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { ParsedDocument } from "../src/adapters/types.ts";
import { releaseChangesCsv, apiChanges } from "../src/api.ts";
import { putBlob } from "../src/blobs.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { buildDigest } from "../src/digest.ts";
import { runHousekeeping, sweepImages } from "../src/housekeeping.ts";
import { getSource } from "../src/ingest.ts";
import type { NormalizedRequirement } from "../src/oscal.ts";
import { renderFeeds } from "../src/pages/feeds.ts";
import { renderToday } from "../src/pages/today.ts";
import { renderTriage } from "../src/pages/triage.ts";
import { renderVulnDetail, renderVulnList, watchCandidates } from "../src/pages/vulnerabilities.ts";
import { renderNews } from "../src/pages/wire.ts";
import { metricsText, pipelineHealth } from "../src/pipeline.ts";
import { loadRequirements, storeDocument } from "../src/register.ts";
import { vulnFilters, wireFilters } from "../src/routes/query.ts";
import { followedStigs, stigRulesForControl, type CciMap } from "../src/stigs.ts";
import { dismissBacklog, firstSentence, setTriage, triageBacklogCount, triageInbox, triageInboxCount } from "../src/triage.ts";
import { cweOf, fillKevRansomware, listVulns, overdueKev, upsertVuln, type NormalizedVuln } from "../src/vulns.ts";
import { listWire } from "../src/wire.ts";
import { cookieFrom, formPost, startTestApp } from "./helpers.ts";

/**
 * The quality-of-life, feature and optimisation pass of 16 November: each case is the smallest
 * input that shows the item working.
 */

const at = "2026-11-16T12:00:00.000Z";
const now = new Date(at);
const look = { look: "register" as const, scheme: "system" as const, back: "/" };
const daysAgo = (d: number) => new Date(now.getTime() - d * 86_400_000).toISOString();

function freshDb() {
  const db = openDatabase(":memory:");
  migrate(db);
  return db;
}
type Db = ReturnType<typeof freshDb>;

function addVuln(db: Db, cveId: string, over: Record<string, unknown> = {}): number {
  const row = { cwes_json: "[]", vendors_json: "[]", products_json: "[]", cpes_json: "[]", kev: 0, kev_due_date: null, kev_ransomware: null, watch_hit: 0, description: `${cveId} is a flaw.`, ...over };
  const result = db
    .prepare(
      `INSERT INTO vulns (cve_id, last_modified_at, vuln_status, description, cwes_json, cpes_json, vendors_json, products_json, kev, kev_due_date, kev_ransomware, watch_hit, first_seen_at, last_seen_at)
       VALUES (?, ?, 'Analyzed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(cveId, at, row.description as string, row.cwes_json as string, row.cpes_json as string, row.vendors_json as string, row.products_json as string, row.kev as number, row.kev_due_date as string | null, row.kev_ransomware as number | null, row.watch_hit as number, at, at);
  return Number(result.lastInsertRowid);
}

function addItem(db: Db, over: { source?: string; kind?: string; externalId: string; title?: string; publishedAt?: string; signals?: unknown; starred?: number; image?: string | null }): number {
  const result = db
    .prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at, signals_json, starred, image_blob, image_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .run(
      over.source ?? "cisa-kev",
      over.kind ?? "kev",
      over.externalId,
      over.title ?? `${over.externalId} · thing`,
      `https://example.test/${over.externalId}`,
      over.publishedAt ?? at,
      over.publishedAt ?? at,
      JSON.stringify(over.signals ?? {}),
      over.starred ?? 0,
      over.image ?? null,
      over.image ? "image/png" : null,
    );
  return Number(result.lastInsertRowid);
}

function req(ref: string, over: Partial<NormalizedRequirement> = {}): NormalizedRequirement {
  return { ref, parentRef: null, family: null, label: ref.toUpperCase(), title: `Title of ${ref}`, statement: null, guidance: null, params: [], related: [], sortKey: ref, status: "active", extra: {}, ...over };
}

function addDocument(db: Db, sourceId: string, key: string, parsed: Partial<ParsedDocument> & { requirements: NormalizedRequirement[] }, publishedAt = at): number {
  const snapshot = db.prepare("INSERT INTO snapshots (source_id, document_key, sha256, bytes, media_type, blob_path, fetched_at) VALUES (?, ?, ?, 1, 'application/json', 'blobs/x', ?)").run(sourceId, key, `${sourceId}:${key}:${Math.random()}`, publishedAt);
  const doc: ParsedDocument = { title: key, versionLabel: "1", publishedAt, ...parsed };
  return storeDocument(db, { source: getSource(db, sourceId)!, target: { key, url: `https://example.test/${key}` }, parsed: doc, snapshotId: Number(snapshot.lastInsertRowid), fetchedAt: publishedAt }).documentId;
}

describe("FT1-1: the CWE filter", () => {
  it("finds every CVE NVD files under a weakness, not the few whose text spells it", () => {
    const db = freshDb();
    addVuln(db, "CVE-2026-1", { cwes_json: JSON.stringify(["CWE-787"]) });
    addVuln(db, "CVE-2026-2", { cwes_json: JSON.stringify(["CWE-79", "CWE-787"]) });
    addVuln(db, "CVE-2026-3", { cwes_json: JSON.stringify(["CWE-7870"]), description: "Mentions CWE-787 in passing." });
    expect(listVulns(db, { cwe: "CWE-787" }).rows.map((r) => r.cve_id).sort()).toEqual(["CVE-2026-1", "CVE-2026-2"]);
    expect(vulnFilters({ cwe: "cwe-787" }, now).cwe).toBe("CWE-787");
    expect(vulnFilters({ cwe: "787" }, now).cwe).toBe("CWE-787");
    expect(vulnFilters({ cwe: "x' OR 1" }, now).cwe).toBeUndefined();
    expect(cweOf("NVD-CWE-noinfo")).toBe("NVD-CWE-noinfo");

    const detail = renderVulnDetail({ db, cveId: "CVE-2026-2", owner: false, open: true, now, look })!;
    expect(detail).toContain('<a href="/vulnerabilities?cwe=CWE-787" title="Every CVE NVD files under CWE-787">CWE-787</a>');
    const list = renderVulnList({ db, filters: vulnFilters({ cwe: "CWE-787" }, now), owner: false, open: true, now, look });
    expect(list).toContain("Weakness: CWE-787 ×");
    expect(list).toContain('id="cwe" name="cwe" value="CWE-787"'); // the search form carries it, now as its own Weakness field
    expect(list).toContain("2 of 2");
    db.close();
  });
});

describe("FT1-2: ransomware", () => {
  it("filters on CISA's mark, and fills it on a KEV row NVD made after the catalogue was read", () => {
    const db = freshDb();
    addVuln(db, "CVE-2026-10", { kev: 1, kev_ransomware: 1 });
    addVuln(db, "CVE-2026-11", { kev: 1, kev_ransomware: 0 });
    // NVD's row: in KEV, no ransomware mark; the catalogue's item says Known.
    addVuln(db, "CVE-2026-12", { kev: 1, kev_ransomware: null });
    addItem(db, { externalId: "CVE-2026-12", signals: { kev: true, ransomware: true } });
    addVuln(db, "CVE-2026-13", { kev: 1, kev_ransomware: null });
    addItem(db, { externalId: "CVE-2026-13", signals: { kev: true, ransomware: false } });
    expect(listVulns(db, { ransomware: true }).rows.map((r) => r.cve_id)).toEqual(["CVE-2026-10"]);
    expect(fillKevRansomware(db)).toBe(2);
    expect(listVulns(db, { ransomware: true }).rows.map((r) => r.cve_id).sort()).toEqual(["CVE-2026-10", "CVE-2026-12"]);
    expect((db.prepare("SELECT kev_ransomware FROM vulns WHERE cve_id = 'CVE-2026-13'").get() as { kev_ransomware: number }).kev_ransomware).toBe(0);

    // An NVD upsert of a new KEV CVE reads the mark from the catalogue item at once.
    addItem(db, { externalId: "CVE-2026-14", signals: { kev: true, ransomware: true } });
    const n: NormalizedVuln = {
      cveId: "CVE-2026-14", sourceIdentifier: "cve@example.test", publishedAt: at, lastModifiedAt: at, vulnStatus: "Analyzed", description: "A flaw.", cvss: null, ssvc: null,
      cwes: [], cpes: [], vendors: [], products: [], references: [], kev: { dateAdded: "2026-11-01", dueDate: "2026-11-22", requiredAction: null, name: null },
    };
    upsertVuln(db, n, at, []);
    expect((db.prepare("SELECT kev_ransomware FROM vulns WHERE cve_id = 'CVE-2026-14'").get() as { kev_ransomware: number }).kev_ransomware).toBe(1);

    const list = renderVulnList({ db, filters: vulnFilters({ ransomware: "1" }, now), owner: false, open: true, now, look });
    expect(list).toContain('<a class="on" href="/vulnerabilities" title="KEV entries CISA marks as known to be used in ransomware campaigns">Ransomware (KEV)</a>');
    expect(renderFeeds({ baseUrl: "https://example.test", owner: false, open: true, look })).toContain('<a href="/vulnerabilities/feed.xml?ransomware=1">');
    db.close();
  });
});

describe("QL1-1: the triage inbox", () => {
  it("holds the last thirty days and the watchlist, counts all of it, and leads a CVE to its page here", () => {
    const db = freshDb();
    addVuln(db, "CVE-2026-1020", { description: "A heap overflow in Thing 1.2 lets a remote attacker run code. Fixed in 1.3." });
    addVuln(db, "CVE-2026-1021", { watch_hit: 1 });
    addVuln(db, "CVE-2026-1022");
    const fresh = addItem(db, { externalId: "CVE-2026-1020", publishedAt: daysAgo(2) });
    const watchedOld = addItem(db, { externalId: "CVE-2026-1021", publishedAt: daysAgo(400) });
    const old = addItem(db, { externalId: "CVE-2026-1022", publishedAt: daysAgo(400) });
    for (let i = 0; i < 31; i += 1) addItem(db, { kind: "vulnerability", source: "nvd-cves", externalId: `CVE-2026-${3000 + i}`, publishedAt: daysAgo(5) });

    expect(triageInboxCount(db, now, { owner: true })).toBe(33);
    expect(triageBacklogCount(db, now)).toBe(1);
    const inbox = triageInbox(db, now, 40, { owner: true });
    expect(inbox.map((i) => i.id)).toContain(watchedOld);
    expect(inbox.map((i) => i.id)).not.toContain(old);
    const card = inbox.find((i) => i.id === fresh)!;
    expect(card.cve_id).toBe("CVE-2026-1020");
    expect(card.lead).toBe("A heap overflow in Thing 1.2 lets a remote attacker run code.");

    const board = renderTriage({ db, owner: true, open: false, now, look });
    expect(board).toContain('<a href="#new">33</a>');
    expect(board).toContain('<a href="/vulnerabilities/CVE-2026-1020" >CVE-2026-1020 · thing</a>');
    expect(board).toContain("Mark the 1 older than 2026-10-17 not ours…");
    expect(renderTriage({ db, owner: false, open: true, now, look })).not.toContain("dismiss-older");

    expect(dismissBacklog(db, "2026-10-17T00:00:00.000Z", at)).toBe(1);
    expect(triageBacklogCount(db, now)).toBe(0);
    expect((db.prepare("SELECT state FROM triage WHERE subject_id = ?").get(old) as { state: string }).state).toBe("dismissed");
    expect(triageInboxCount(db, now, { owner: true })).toBe(33);
    db.close();
  });

  it("cuts a first sentence where a sentence ends, not at a version number", () => {
    expect(firstSentence("Thing v1.2.3 is affected. More text.")).toBe("Thing v1.2.3 is affected.");
    expect(firstSentence("No full stop at all")).toBe("No full stop at all");
    expect(firstSentence(null)).toBeNull();
    expect(firstSentence(`${"word ".repeat(80)}end.`, 60)!.length).toBeLessThanOrEqual(60);
  });

  it("marks the backlog only for the owner, through the same-origin form", async () => {
    const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" }, now: () => now });
    try {
      addVuln(app.db, "CVE-2026-40");
      addItem(app.db, { externalId: "CVE-2026-40", publishedAt: daysAgo(100) });
      expect((await formPost(app.base, "/triage/dismiss-older", { before: "2026-10-17" })).status).toBe(403);
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
      const cross = await fetch(`${app.base}/triage/dismiss-older`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://evil.test", cookie }, body: "before=2026-10-17&confirm=1", redirect: "manual" });
      expect(cross.status).toBe(403);
      const done = await formPost(app.base, "/triage/dismiss-older", { before: "2030-01-01", confirm: "1", count: "1" }, cookie);
      expect(done.status).toBe(303);
      // A later date than the inbox's window is held to the window's own.
      expect((app.db.prepare("SELECT COUNT(*) AS n FROM triage WHERE state = 'dismissed'").get() as { n: number }).n).toBe(1);
    } finally {
      await app.close();
    }
  });
});

describe("QL1-2: starred", () => {
  it("lists the owner's starred items, and a visitor's link that asks for them gets the whole list", () => {
    const db = freshDb();
    addItem(db, { source: "bleeping", kind: "article", externalId: "a1", title: "Kept story", starred: 1 });
    addItem(db, { source: "bleeping", kind: "article", externalId: "a2", title: "Other story" });
    expect(listWire(db, { starred: true }).map((i) => i.title)).toEqual(["Kept story"]);
    expect(wireFilters({ starred: "1" }).starred).toBe(false);
    expect(wireFilters({ starred: "1" }, true).starred).toBe(true);
    const page = renderNews({ db, filters: wireFilters({ starred: "1" }, true), owner: true, open: false, now, look });
    expect(page).toContain('<a class="on" href="/">Starred</a>');
    expect(page).toContain('<a class="entry" href="/?starred=1"><b>Starred</b>');
    expect(page).not.toContain("Other story");
    const visitor = renderNews({ db, filters: { starred: true }, owner: false, open: true, now, look });
    expect(visitor).toContain("Other story");
    expect(visitor).not.toContain('href="/?starred=1"');
    db.close();
  });
});

describe("QL1-3: watch from the CVE page", () => {
  it("offers each vendor and CPE pair to the owner alone", () => {
    const db = freshDb();
    addVuln(db, "CVE-2026-50", { vendors_json: JSON.stringify(["fortinet"]), products_json: JSON.stringify(["fortios"]), cpes_json: JSON.stringify(["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"]) });
    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('product', 'fortinet', NULL, ?)").run(at);
    expect(watchCandidates(["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"], ["fortinet"], ["fortios"])).toEqual(["fortinet", "fortinet:fortios"]);
    // A CPE-less row offers the vendor alone; CISA's pair comes from its own columns (B10-1).
    expect(watchCandidates([], ["acme"], ["widget"])).toEqual(["acme"]);
    expect(watchCandidates([], ["acme"], ["widget"], { vendor: "acme", product: "widget" })).toEqual(["acme", "acme:widget"]);
    const owner = renderVulnDetail({ db, cveId: "CVE-2026-50", owner: true, open: false, now, look })!;
    expect(owner).toContain('<input type="hidden" name="value" value="fortinet:fortios"><input type="hidden" name="back" value="/vulnerabilities/CVE-2026-50#watch">');
    expect(owner).toContain("<li><code>fortinet</code> <span class=\"small\">watched</span></li>");
    expect(renderVulnDetail({ db, cveId: "CVE-2026-50", owner: false, open: true, now, look })).not.toContain('id="watch"');
    db.close();
  });

  it("adds one entry a line and goes back to the CVE", async () => {
    const app = await startTestApp();
    try {
      const one = await formPost(app.base, "/watchlist", { kind: "product", value: "acme:widget", back: "/vulnerabilities/CVE-2026-50#watch" });
      expect(one.status).toBe(303);
      expect(one.headers.get("location")).toBe("/vulnerabilities/CVE-2026-50#watch");
      const many = await formPost(app.base, "/watchlist", { kind: "product", value: "cisco:ios_xe\r\n\r\nfortinet\nacme:widget\n" });
      expect(many.headers.get("location")).toBe("/watchlist");
      const values = (app.db.prepare("SELECT value FROM watchlist ORDER BY value").all() as { value: string }[]).map((r) => r.value);
      expect(values).toEqual(["acme:widget", "cisco:ios_xe", "fortinet"]);
      expect((await formPost(app.base, "/watchlist", { kind: "package", value: "npm:express\nnot-a-package" })).status).toBe(400);
      expect((await formPost(app.base, "/watchlist", { kind: "product", value: "x", back: "https://evil.test/" })).headers.get("location")).toBe("/watchlist");
      const page = await (await fetch(`${app.base}/watchlist`)).text();
      expect(page).toContain('<textarea id="value" name="value" required rows="4"');
    } finally {
      await app.close();
    }
  });
});

describe("FT1-4: a release's changes as CSV", () => {
  function twoVersions(db: Db, sourceId: string): number {
    addDocument(db, sourceId, "catalog", { versionLabel: "1", requirements: [req("ac-1", { statement: "Old words." }), req("ac-2")] }, "2026-01-01T00:00:00.000Z");
    return addDocument(db, sourceId, "catalog", { versionLabel: "2", requirements: [req("ac-1", { statement: "New words." }), req("ac-3")] }, "2026-06-01T00:00:00.000Z");
  }

  it("writes a public-domain release's rows and refuses a licensed or restricted one", async () => {
    const app = await startTestApp();
    try {
      const nist = twoVersions(app.db, "nist-sp-800-53");
      const cis = twoVersions(app.db, "cis-benchmarks");
      const csv = await fetch(`${app.base}/standards/nist-sp-800-53/${nist}/changes.csv`);
      expect(csv.status).toBe(200);
      expect(csv.headers.get("content-type")).toMatch(/text\/csv/);
      const text = await csv.text();
      expect(text.split("\n")[0]).toBe("source,document,version,published,ref,label,title,kind,field,before,after,publisher_note,url");
      expect(text).toContain("Old words.");
      expect(text).toContain("New words.");
      expect(text).toContain(",ac-3,");
      const release = await (await fetch(`${app.base}/standards/nist-sp-800-53/${nist}`)).text();
      expect(release).toContain(`<a href="/standards/nist-sp-800-53/${nist}/changes.csv">These changes as CSV</a>`);

      const licensed = await fetch(`${app.base}/standards/cis-benchmarks/${cis}/changes.csv`);
      expect(licensed.status).toBe(403);
      expect(await licensed.text()).not.toContain("words");
      expect(await (await fetch(`${app.base}/standards/cis-benchmarks/${cis}`)).text()).not.toContain("changes.csv");
      app.db.prepare("UPDATE sources SET restricted = 1 WHERE id = 'nist-sp-800-53'").run();
      expect((await fetch(`${app.base}/standards/nist-sp-800-53/${nist}/changes.csv`)).status).toBe(403);
      // A document of another source under this source's address is not this source's.
      expect((await fetch(`${app.base}/standards/nist-sp-800-53/${cis}/changes.csv`)).status).toBe(404);
    } finally {
      await app.close();
    }
  });

  it("narrows the API to one document, and refuses a licensed document there", () => {
    const db = freshDb();
    const nist = twoVersions(db, "nist-sp-800-53");
    const cis = twoVersions(db, "cis-benchmarks");
    const rows = apiChanges(db, { document: String(nist) }, "https://example.test");
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r) => r.url.includes(`/standards/nist-sp-800-53/${nist}/`))).toBe(true);
    expect(() => apiChanges(db, { document: String(cis) }, "https://example.test")).toThrow(expect.objectContaining({ status: 404 }));
    expect(releaseChangesCsv(db, getSource(db, "cis-benchmarks")!, cis, "https://example.test")).toBeNull();
    db.close();
  });
});

describe("OP1-1: image retention", () => {
  it("lets go of an old article's image unless starred or triaged, and the sweep frees the file", () => {
    const db = freshDb();
    const dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-images-"));
    try {
      const blob = (n: number) => putBlob(dataDir, new Uint8Array(Array.from({ length: 100 + n }, (_, i) => (i * n) % 256)));
      const [oldImg, starredImg, triagedImg, newImg, sharedImg] = [1, 2, 3, 4, 5].map(blob);
      // Every file is old: the grace window is for bytes a fetch has just written.
      const longAgo = new Date(now.getTime() - 200 * 86_400_000);
      for (const b of [oldImg, starredImg, triagedImg, newImg, sharedImg]) utimesSync(b!.absolutePath, longAgo, longAgo);
      const article = (id: string, published: string, image: string, starred = 0) => addItem(db, { source: "bleeping", kind: "article", externalId: id, publishedAt: published, image, starred });
      const oldItem = article("old", daysAgo(120), oldImg!.sha256);
      article("starred", daysAgo(120), starredImg!.sha256, 1);
      const triaged = article("triaged", daysAgo(120), triagedImg!.sha256);
      setTriage(db, { kind: "item", id: triaged }, { state: "reviewing" }, at);
      article("new", daysAgo(10), newImg!.sha256);
      // The same picture on an old item and a new one stays for the new one.
      article("shared-old", daysAgo(120), sharedImg!.sha256);
      article("shared-new", daysAgo(5), sharedImg!.sha256);

      const result = runHousekeeping(db, dataDir, { now: () => now });
      expect(result.imagesReleased).toBe(2);
      expect(result.imageBytesFreed).toBe(oldImg!.bytes);
      expect(existsSync(oldImg!.absolutePath)).toBe(false);
      for (const kept of [starredImg, triagedImg, newImg, sharedImg]) expect(existsSync(kept!.absolutePath)).toBe(true);
      expect(result.imageBytesHeld).toBe(starredImg!.bytes + triagedImg!.bytes + newImg!.bytes + sharedImg!.bytes);
      expect((db.prepare("SELECT image_blob FROM items WHERE id = ?").get(oldItem) as { image_blob: string | null }).image_blob).toBeNull();
      expect(sweepImages(db, now).released).toBe(0);

      // /metrics weighs the images from the pass, and says how much memory the process holds.
      const health = pipelineHealth(db, now);
      expect(health.imageBytes).toBe(result.imageBytesHeld);
      const text = metricsText({ health, now, counts: { sources: 1, items: 1, vulns: 0, changes: 0, snapshots: 0, exploits: 0, msrcVulns: 0, certificates: null, deviceReadings: null }, bytes: { database: 1, snapshots: 0 }, images: 4, housekeeping: null, uptimeSeconds: 1 });
      expect(text).toContain(`baselinewatch_bytes{store="images"} ${result.imageBytesHeld}`);
      expect(text).toMatch(/baselinewatch_process_resident_bytes \d+/);
      expect(readdirSync(path.join(dataDir, "blobs")).length).toBeGreaterThan(0);
    } finally {
      db.close();
      rmSync(dataDir, { recursive: true, force: true });
    }
  });
});

describe("OP1-2: STIG rules by CCI", () => {
  it("answers from the kept index exactly as reading every rule did", () => {
    const db = freshDb();
    addDocument(db, "disa-stigs", "Windows_11", { title: "Microsoft Windows 11 STIG", requirements: [
      req("sv-3_rule", { related: ["CCI-000015"], sortKey: "c" }),
      req("sv-1_rule", { related: ["cci-000015", "CCI-000016"], sortKey: "a" }),
      req("sv-2_rule", { related: ["CCI-000366"], sortKey: "b" }),
    ] });
    addDocument(db, "disa-stigs", "RHEL_9", { title: "Red Hat Enterprise Linux 9 STIG", requirements: [req("sv-9_rule", { related: ["CCI-000016"] })] });
    const map: CciMap = { controls: new Map(), ccis: new Map([["ac-2", ["CCI-000015", "CCI-000016"]]]), documentId: 1, version: null };
    const naive = followedStigs(db)
      .map((stig) => ({ stig, rules: loadRequirements(db, stig.latest.id).filter((r) => r.related.some((c) => ["CCI-000015", "CCI-000016"].includes(c.toUpperCase()))) }))
      .filter((h) => h.rules.length);
    const first = stigRulesForControl(db, "ac-2", map);
    expect(first).toEqual(naive);
    expect(first.find((h) => h.stig.key === "Windows_11")!.rules.map((r) => r.ref)).toEqual(["sv-1_rule", "sv-3_rule"]);
    // The second call reads the kept index and answers the same.
    expect(stigRulesForControl(db, "ac-2", map)).toEqual(naive);
    expect(stigRulesForControl(db, "cm-6", map)).toEqual([]);
    db.close();
  });
});

describe("OP1-3: the unread-platforms index", () => {
  it("is there, and the start-up question uses it", () => {
    const db = freshDb();
    expect(db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'vulns_platforms_unread'").get()).toBeTruthy();
    const plan = db.prepare("EXPLAIN QUERY PLAN SELECT cve_id, description FROM vulns WHERE platforms_json IS NULL LIMIT 100").all() as { detail: string }[];
    expect(plan.map((p) => p.detail).join(" ")).toContain("vulns_platforms_unread");
    db.close();
  });
});

describe("FT1-7: KEV past its due date", () => {
  it("counts the owner's KEV entries past CISA's date on Today and in the digest", () => {
    const db = freshDb();
    addVuln(db, "CVE-2026-60", { kev: 1, kev_due_date: "2026-11-01", watch_hit: 1 });
    const affects = addVuln(db, "CVE-2026-61", { kev: 1, kev_due_date: "2026-10-20" });
    setTriage(db, { kind: "vuln", id: affects }, { state: "affects" }, at);
    // Watched but done; watched but not due yet; due but not the owner's.
    const done = addVuln(db, "CVE-2026-62", { kev: 1, kev_due_date: "2026-11-01", watch_hit: 1 });
    setTriage(db, { kind: "vuln", id: done }, { state: "done" }, at);
    addVuln(db, "CVE-2026-63", { kev: 1, kev_due_date: "2026-12-01", watch_hit: 1 });
    addVuln(db, "CVE-2026-64", { kev: 1, kev_due_date: "2026-11-01" });
    // Triaged "affects" through its KEV item.
    addVuln(db, "CVE-2026-65", { kev: 1, kev_due_date: "2026-11-10" });
    setTriage(db, { kind: "item", id: addItem(db, { externalId: "CVE-2026-65" }) }, { state: "affects" }, at);

    const overdue = overdueKev(db, "2026-11-16");
    expect(overdue.total).toBe(3);
    expect(overdue.cves.map((c) => c.cveId)).toEqual(["CVE-2026-61", "CVE-2026-60", "CVE-2026-65"]);

    const today = renderToday({ db, owner: true, open: false, now, hours: 24, look });
    expect(today).toContain("<b>3 KEV entries past CISA's due date</b>");
    expect(today).not.toContain("watch=1&amp;kev=1");
    expect(renderToday({ db, owner: false, open: true, now, hours: 24, look })).not.toContain("past CISA's due date");

    const digest = buildDigest(db, { from: daysAgo(1), to: at, baseUrl: "https://example.test", period: "daily" });
    expect(digest.text).toContain("KEV past CISA's due date on your watchlist or affecting you: 3 (CVE-2026-61, due 2026-10-20, https://example.test/vulnerabilities/CVE-2026-61;");
    expect(digest.publicText).not.toContain("past CISA's due date");
    db.close();
  });
});
