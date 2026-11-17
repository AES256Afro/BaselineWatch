import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { ParsedDocument } from "../src/adapters/types.ts";
import { apiChanges } from "../src/api.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { buildDigest } from "../src/digest.ts";
import { getSource } from "../src/ingest.ts";
import type { NormalizedRequirement } from "../src/oscal.ts";
import { staleNotice } from "../src/pages/layout.ts";
import { renderToday } from "../src/pages/today.ts";
import { renderTriage } from "../src/pages/triage.ts";
import { newestCveChange, pipelineHealth, staleCveHours } from "../src/pipeline.ts";
import { storeDocument } from "../src/register.ts";
import { listNetScans, tallyRun } from "../src/scanhistory.ts";
import { dismissBacklog, firstSentence, lastBacklogDismissal, setTriage, triageBacklogCount, triageCsv, triageInbox, triageInboxCount, undoBacklog } from "../src/triage.ts";
import { cookieFrom, formPost, startTestApp } from "./helpers.ts";

/**
 * The desk's fixes from the audit of 16 November: the inbox a visitor sees, the API's one-release
 * change list, KEV titles, the stale notice and heading, the bulk dismissal's confirm and undo.
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

function addVuln(db: Db, cveId: string, over: { watch_hit?: number; description?: string } = {}): number {
  return Number(
    db
      .prepare(
        `INSERT INTO vulns (cve_id, last_modified_at, vuln_status, description, cwes_json, cpes_json, vendors_json, products_json, kev, watch_hit, first_seen_at, last_seen_at)
         VALUES (?, ?, 'Analyzed', ?, '[]', '[]', '[]', '[]', 0, ?, ?, ?)`,
      )
      .run(cveId, at, over.description ?? `${cveId} is a flaw.`, over.watch_hit ?? 0, at, at).lastInsertRowid,
  );
}

function addItem(db: Db, over: { source?: string; kind?: string; externalId: string; title?: string; publishedAt?: string; signals?: unknown }): number {
  return Number(
    db
      .prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at, signals_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(over.source ?? "cisa-kev", over.kind ?? "kev", over.externalId, over.title ?? `${over.externalId} · thing`, `https://example.test/${over.externalId}`, over.publishedAt ?? at, over.publishedAt ?? at, JSON.stringify(over.signals ?? {}))
      .lastInsertRowid,
  );
}

function req(ref: string, over: Partial<NormalizedRequirement> = {}): NormalizedRequirement {
  return { ref, parentRef: null, family: null, label: ref.toUpperCase(), title: `Title of ${ref}`, statement: null, guidance: null, params: [], related: [], sortKey: ref, status: "active", extra: {}, ...over };
}

function addDocument(db: Db, sourceId: string, parsed: Partial<ParsedDocument> & { requirements: NormalizedRequirement[] }, publishedAt: string): number {
  const snapshot = db.prepare("INSERT INTO snapshots (source_id, document_key, sha256, bytes, media_type, blob_path, fetched_at) VALUES (?, 'catalog', ?, 1, 'application/json', 'blobs/x', ?)").run(sourceId, `${sourceId}:${Math.random()}`, publishedAt);
  const doc: ParsedDocument = { title: "catalog", versionLabel: "1", publishedAt, ...parsed };
  return storeDocument(db, { source: getSource(db, sourceId)!, target: { key: "catalog", url: "https://example.test/catalog" }, parsed: doc, snapshotId: Number(snapshot.lastInsertRowid), fetchedAt: publishedAt }).documentId;
}

/** Two releases of a source, the second adding `added` requirements. */
function twoReleases(db: Db, sourceId: string, added: number): number {
  addDocument(db, sourceId, { versionLabel: "1", requirements: [req("ac-1")] }, "2026-01-01T00:00:00.000Z");
  const reqs = [req("ac-1"), ...Array.from({ length: added }, (_, i) => req(`zz-${String(i).padStart(4, "0")}`))];
  return addDocument(db, sourceId, { versionLabel: "2", requirements: reqs }, "2026-06-01T00:00:00.000Z");
}

describe("S5-1: a visitor's inbox is the window alone", () => {
  it("leaves out an old card whose CVE is watched, from the list, the count and the sentence", () => {
    const db = freshDb();
    addVuln(db, "CVE-2026-1021", { watch_hit: 1 });
    const watchedOld = addItem(db, { externalId: "CVE-2026-1021", publishedAt: daysAgo(400) });
    const fresh = addItem(db, { externalId: "CVE-2026-1030", publishedAt: daysAgo(2) });

    expect(triageInbox(db, now, 30, { owner: true }).map((i) => i.id)).toEqual([fresh, watchedOld]);
    expect(triageInboxCount(db, now, { owner: true })).toBe(2);
    expect(triageInbox(db, now, 30).map((i) => i.id)).toEqual([fresh]);
    expect(triageInboxCount(db, now)).toBe(1);

    const visitor = renderTriage({ db, owner: false, open: true, now, look });
    expect(visitor).not.toContain("CVE-2026-1021");
    expect(visitor).not.toContain("on your watchlist");
    expect(visitor).toContain('<a href="#new">1</a>');
    expect(renderTriage({ db, owner: true, open: false, now, look })).toContain("anything older that is on your watchlist");
    expect(renderToday({ db, owner: false, open: true, look, now, hours: 24 })).not.toContain("CVE-2026-1021");
    db.close();
  });
});

describe("QL2-1: the inbox pages", () => {
  it("shows which thirty of how many, with a link to the next", () => {
    const db = freshDb();
    for (let i = 0; i < 45; i += 1) addItem(db, { externalId: `CVE-2026-${4000 + i}`, publishedAt: daysAgo(1 + i / 100) });
    const first = renderTriage({ db, owner: true, open: false, now, look });
    expect(first).toContain("1–30 of 45 shown");
    expect(first).toContain('<a href="/triage?offset=30#new">Next 15</a>');
    const second = renderTriage({ db, owner: true, open: false, now, look, offset: 30 });
    expect(second).toContain("31–45 of 45 shown");
    expect(second).toContain('<a href="/triage#new">Previous 30</a>');
    expect(second).toContain("CVE-2026-4044");
    expect(second).not.toContain("CVE-2026-4000 ·");
    db.close();
  });
});

describe("RD2-7: a card leads with the flaw", () => {
  it("skips a project's blurb when the next sentence names the flaw, and keeps the first otherwise", () => {
    expect(firstSentence("Wasmtime is a runtime for WebAssembly. A bug in the Cranelift backend allows a guest to read host memory.")).toBe(
      "A bug in the Cranelift backend allows a guest to read host memory.",
    );
    expect(firstSentence("Thing v1.2.3 is affected. More text.")).toBe("Thing v1.2.3 is affected.");
    expect(firstSentence("The daemon builds a shell command from client fields. The session path performs no check.")).toBe("The daemon builds a shell command from client fields.");
  });

  it("does not repeat a CVSS score the title already carries", () => {
    const db = freshDb();
    addItem(db, { kind: "vulnerability", source: "nvd-cves", externalId: "CVE-2026-5000", title: "CVE-2026-5000 · CVSS 9.8", signals: { cvss: 9.8 } });
    const board = renderTriage({ db, owner: true, open: false, now, look });
    expect(board).toContain("CVE-2026-5000 · CVSS 9.8");
    expect(board).not.toContain('<span class="chip">CVSS 9.8</span>');
    db.close();
  });
});

describe("QL2-2 and B5-5: the bulk dismissal", () => {
  it("takes KEV and CVE items only, and the last one can be undone within a day", () => {
    const db = freshDb();
    const kev = addItem(db, { externalId: "CVE-2020-0001", publishedAt: daysAgo(400) });
    const release = addItem(db, { kind: "release", source: "nist-sp-800-53", externalId: "rel-1", title: "SP 800-53 5.1.1", publishedAt: daysAgo(400) });
    expect(triageBacklogCount(db, now)).toBe(1);
    const stamp = daysAgo(0);
    expect(dismissBacklog(db, "2026-10-17T00:00:00.000Z", stamp)).toBe(1);
    expect(db.prepare("SELECT subject_id FROM triage").all()).toEqual([{ subject_id: kev }]);
    expect(db.prepare("SELECT 1 FROM triage WHERE subject_id = ?").get(release)).toBeUndefined();

    expect(lastBacklogDismissal(db, now)).toEqual({ at: stamp, count: 1 });
    expect(lastBacklogDismissal(db, new Date(now.getTime() + 25 * 3_600_000))).toBeNull();
    expect(undoBacklog(db, now)).toBe(1);
    expect(triageBacklogCount(db, now)).toBe(1);
    expect(undoBacklog(db, now)).toBe(0);

    // A row the owner moved after the sweep stays theirs.
    dismissBacklog(db, "2026-10-17T00:00:00.000Z", stamp);
    setTriage(db, { kind: "item", id: kev }, { state: "affects" }, daysAgo(-0.01));
    expect(undoBacklog(db, now)).toBe(0);
    expect((db.prepare("SELECT state FROM triage WHERE subject_id = ?").get(kev) as { state: string }).state).toBe("affects");
    db.close();
  });

  it("asks before it marks, showing the count, and offers the undo", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      addItem(app.db, { externalId: "CVE-2020-0002", publishedAt: daysAgo(400) });
      addItem(app.db, { externalId: "CVE-2020-0003", publishedAt: daysAgo(400) });
      const first = await formPost(app.base, "/triage/dismiss-older", { before: "2026-10-17" });
      expect(first.status).toBe(303);
      expect(first.headers.get("location")).toBe("/triage?confirm=older#backlog");
      expect((app.db.prepare("SELECT COUNT(*) AS n FROM triage").get() as { n: number }).n).toBe(0);
      const confirm = await (await fetch(`${app.base}/triage?confirm=older`)).text();
      expect(confirm).toContain("Mark 2 KEV entries and CVEs from before 2026-10-17 not ours?");
      expect(confirm).toContain('<input type="hidden" name="confirm" value="1"><input type="hidden" name="count" value="2">');

      // B6-10: the count confirmed is the count marked; one more item since, and nothing is marked.
      addItem(app.db, { externalId: "CVE-2020-0004", publishedAt: daysAgo(400) });
      const stale = await formPost(app.base, "/triage/dismiss-older", { before: "2026-10-17", confirm: "1", count: "2" });
      expect(stale.headers.get("location")).toBe("/triage?confirm=older#backlog");
      expect((app.db.prepare("SELECT COUNT(*) AS n FROM triage").get() as { n: number }).n).toBe(0);
      expect((await formPost(app.base, "/triage/dismiss-older", { before: "2026-10-17", confirm: "1" })).status).toBe(400);

      const done = await formPost(app.base, "/triage/dismiss-older", { before: "2026-10-17", confirm: "1", count: "3" });
      expect(done.status).toBe(303);
      expect((app.db.prepare("SELECT COUNT(*) AS n FROM triage").get() as { n: number }).n).toBe(3);
      const board = await (await fetch(`${app.base}/triage`, { headers: { cookie: cookieFrom(done) } })).text();
      expect(board).toContain("Undo the last bulk dismissal");

      expect((await formPost(app.base, "/triage/undo-dismiss", {})).status).toBe(303);
      expect((app.db.prepare("SELECT COUNT(*) AS n FROM triage").get() as { n: number }).n).toBe(0);
    } finally {
      await app.close();
    }
  });

  it("writes every card to the CSV, past five hundred", () => {
    const db = freshDb();
    for (let i = 0; i < 520; i += 1) setTriage(db, { kind: "item", id: addItem(db, { externalId: `CVE-2019-${1000 + i}` }) }, { state: "dismissed" }, at);
    expect(triageCsv(db).trim().split("\n")).toHaveLength(521);
    db.close();
  });
});

describe("B5-1: one release's changes through the API", () => {
  it("returns every row of the release, past the list's cap", () => {
    const db = freshDb();
    const nist = twoReleases(db, "nist-sp-800-53", 230);
    const rows = apiChanges(db, { document: String(nist) }, "https://example.test");
    expect(rows.length).toBeGreaterThanOrEqual(230);
    expect(apiChanges(db, { source: "nist-sp-800-53" }, "https://example.test")).toHaveLength(100);
    db.close();
  });

  it("answers 404 alike for a licensed, a restricted and an unknown release (S6-1)", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      const cis = twoReleases(app.db, "cis-benchmarks", 2);
      const nist = twoReleases(app.db, "nist-sp-800-53", 2);
      const licensed = await fetch(`${app.base}/api/v1/changes?document=${cis}`);
      const unknown = await fetch(`${app.base}/api/v1/changes?document=999999`);
      expect(licensed.status).toBe(404);
      expect(unknown.status).toBe(404);
      expect(await licensed.text()).toBe(await unknown.text());
      expect((await fetch(`${app.base}/api/v1/changes?document=${nist}`)).status).toBe(200);
      app.db.prepare("UPDATE sources SET restricted = 1 WHERE id = 'nist-sp-800-53'").run();
      expect((await fetch(`${app.base}/api/v1/changes?document=${nist}`)).status).toBe(404);
    } finally {
      await app.close();
    }
  });
});

describe("B5-2: KEV titles the first rewrite missed", () => {
  it("rewrites a doubled title to the CVE id and CISA's name, once", () => {
    const db = freshDb();
    const doubled = addItem(db, { externalId: "CVE-2026-48558", title: "SimpleHelp SimpleHelp: SimpleHelp Authentication Bypass Vulnerability", signals: { vendor: "SimpleHelp ", product: "SimpleHelp" } });
    const fine = addItem(db, { externalId: "CVE-2026-1", title: "CVE-2026-1 · Thing: Other Vulnerability" });
    const sql = readFileSync(path.join(import.meta.dirname, "..", "src", "migrations", "0069_kev_titles_trimmed.sql"), "utf8");
    db.exec(sql);
    db.exec(sql);
    const title = (id: number) => (db.prepare("SELECT title FROM items WHERE id = ?").get(id) as { title: string }).title;
    expect(title(doubled)).toBe("CVE-2026-48558 · SimpleHelp Authentication Bypass Vulnerability");
    expect(title(fine)).toBe("CVE-2026-1 · Thing: Other Vulnerability");
    db.close();
  });
});

describe("B5-4, RD2-2, US2-5: when the CVE data stopped", () => {
  it("reads NVD and CVE-list rows only, with one threshold, and says so on Today", () => {
    const db = freshDb();
    expect(staleCveHours).toBe(48);
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-1', '2026-10-26T15:47:40.000Z', 'new')").run();
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-1', ?, 'kev')").run(daysAgo(0.1));
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-1', ?, 'epss')").run(daysAgo(0.1));
    expect(newestCveChange(db)).toBe("2026-10-26T15:47:40.000Z");
    expect(pipelineHealth(db, now).state).toBe("bad");

    const notice = String(staleNotice(db, now));
    expect(notice).toContain("No CVE source reports an error; the schedule may not be running.");
    expect(notice).toContain('<a href="/health">');
    db.prepare("UPDATE sources SET last_status = 'error' WHERE id = 'nvd-cves'").run();
    expect(String(staleNotice(db, now))).toContain("shows which feed is failing");

    const today = renderToday({ db, owner: true, open: false, look, now, hours: 24 });
    expect(today).toContain("CVE data stopped on 26 Oct");
    expect(today).toContain("Nothing has arrived since 26 Oct.");
    expect(today).not.toContain("No CVE that matters changed");
    expect(today).toContain("This window: 0 updates");
    const digest = buildDigest(db, { from: daysAgo(1), to: at, baseUrl: "https://example.test", period: "daily" });
    expect(digest.text).toContain("the CVE pull may be stuck");
    db.close();
  });
});

describe("C5-1: the scan history counts as a run does", () => {
  it("adds grouped counts", () => {
    expect(tallyRun([{ outcome: "resolved", n: 2 }, { outcome: "sinkholed", n: 3 }, { outcome: "timeout" }])).toEqual({ total: 6, resolved: 2, sinkholed: 3, timeout: 1 });
    const db = freshDb();
    expect(listNetScans(db)).toEqual([]);
    db.close();
  });
});
