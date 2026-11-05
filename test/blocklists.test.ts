import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  apexHosts,
  canaryCount,
  canaryDocument,
  canaryLists,
  filterListDomains,
  hostfileHosts,
  indicatorType,
  parseAdblockList,
  parseDomainList,
  parseIndicators,
  pickCanaries,
  ruleName,
  urlHosts,
  type CanaryList,
} from "../src/adapters/blocklists.ts";
import { adapterFor } from "../src/adapters/index.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { changeSummaryFor, explanationsFor, latestDocument, listDocuments, loadRequirements, releaseChanges } from "../src/register.ts";
import { listWire } from "../src/wire.ts";
import { fakeHttp, fixture, startTestApp, type FakeRoute, type TestApp } from "./helpers.ts";

const at = new Date("2026-10-19T12:00:00Z");
const text = (name: string): string => new TextDecoder().decode(fixture(`blocklists/${name}`));
const list = (id: string): CanaryList => canaryLists.find((l) => l.id === id)!;
const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

const raw = "https://raw.githubusercontent.com/interplains/zero-breach";
const api = "https://api.github.com/repos/interplains/zero-breach/commits?path=";
/** The commit the fixture listing names (2026-10-18 22:36 UTC) and the one the adapter's history starts from (14:01 UTC). */
const head = "7253316421e481973e1d9fd3b2bdb88eafc99029";
const first = "e36dc961b8c60060c3b164d1a1c78d401e231a5e";

/** GitHub's commit listing (one real response, the same commit touched all three files) and the two captured versions of each file. */
function zeroBreachRoutes(): Record<string, FakeRoute> {
  const listing: FakeRoute = { bytes: fixture("blocklists/commits-domains.json"), contentType: "application/json" };
  const routes: Record<string, FakeRoute> = {};
  for (const [filePath, stem] of [
    ["dist/adfection.domains.txt", "adfection.domains"],
    ["dist/adfection.adblock.txt", "adfection.adblock"],
    ["iocs/adfection_iocs.txt", "adfection_iocs"],
  ] as const) {
    routes[`${api}${filePath}&per_page=1`] = listing;
    routes[`${raw}/${head}/${filePath}`] = { bytes: fixture(`blocklists/${stem}-2026-10-18b.txt`), contentType: "text/plain" };
    routes[`${raw}/${first}/${filePath}`] = { bytes: fixture(`blocklists/${stem}-2026-10-18a.txt`), contentType: "text/plain" };
  }
  return routes;
}

describe("Zero Breach lists", () => {
  it("reads the indicator list with each indicator's tier, confidence, type and the report it came from", () => {
    const doc = parseIndicators(text("adfection_iocs-2026-10-18b.txt"));
    expect(doc.title).toBe("AdFection / Discover-Tech / Candiru indicators");
    expect(doc.versionLabel).toBe("2026-10-18");
    expect(doc.publishedAt).toBe("2026-10-18T00:00:00.000Z");
    expect(doc.requirements).toHaveLength(405);
    expect(new Set(doc.requirements.map((r) => r.ref)).size).toBe(405);
    const byRef = new Map(doc.requirements.map((r) => [r.ref, r]));

    const cc = byRef.get("fearevolve.com")!;
    expect(cc.family).toBe("Command-and-control");
    expect(cc.title).toBe("Command-and-control (domain, primary source)");
    expect(cc.statement).toBe("Tier: cc (Command-and-control). Confidence: primary. Source: citizenlab-adfection-2026.");
    expect(cc.guidance).toContain("Exposing AdFection");
    expect(cc.guidance).toContain("https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/");
    expect(cc.extra).toEqual({ type: "domain", tier: "cc", confidence: "primary", source: "citizenlab-adfection-2026" });

    const amnesty = byRef.get("aqaf.net")!;
    expect(amnesty.family).toBe("Historical Candiru infrastructure");
    expect(amnesty.guidance).toBe("Source: amnesty-candiru-indonesia-2024; published 2024-05-01\nhttps://securitylab.amnesty.org/latest/2024/05/a-web-of-surveillance/");

    const kinds = new Map<string, number>();
    for (const r of doc.requirements) kinds.set(String(r.extra.type), (kinds.get(String(r.extra.type)) ?? 0) + 1);
    // The plan's count of the list when it was read: 292 domains and 111 addresses, plus the two file hashes.
    expect(kinds.get("ip")).toBe(111);
    expect(kinds.get("sha256")).toBe(2);
    expect(kinds.get("domain")).toBe(292);
    expect(doc.requirements.find((r) => r.extra.tier === "sample")?.title).toBe("Spyware sample (SHA-256, primary source)");
    expect(doc.requirements.filter((r) => r.family === "Candiru infrastructure address").every((r) => indicatorType(r.ref) === "ip")).toBe(true);
  });

  it("reads the domain and Adblock Plus exports line by line, one requirement per name", () => {
    const domains = parseDomainList(text("adfection.domains-2026-10-18b.txt"));
    expect(domains.title).toBe("adint-scan denylist (domains)");
    expect(domains.versionLabel).toBe("2026-10-18");
    expect(domains.requirements).toHaveLength(291);
    expect(domains.requirements[0]).toMatchObject({ ref: "addthis.events", label: "addthis.events", title: "Listed domain", statement: "addthis.events", family: "Domains" });

    const adblock = parseAdblockList(text("adfection.adblock-2026-10-18b.txt"));
    expect(adblock.title).toBe("AdFection / Candiru blocklist");
    expect(adblock.versionLabel).toBe("2026-10-18");
    expect(adblock.requirements).toHaveLength(291);
    expect(adblock.requirements[0]).toMatchObject({ ref: "addthis.events", title: "Network rule", statement: "||addthis.events^" });
    expect(adblock.requirements.map((r) => r.ref)).toEqual(domains.requirements.map((r) => r.ref));
    expect(ruleName("||Example.com^$third-party")).toBe("example.com");
    expect(ruleName("/ad_images/*$image")).toBe("/ad_images/*$image");
  });

  it("refuses a document that is not the list it expects", () => {
    expect(() => parseDomainList("# only comments\n")).toThrow(/no domain lines/);
    expect(() => parseIndicators("<html>nope</html>")).toThrow(/no indicator lines/);
    expect(() => canaryDocument(list("canary-ads"), "[Adblock Plus 2.0]\n! Version: 1\n")).toThrow(/no canary candidates/);
  });

  describe("ingestion", () => {
    let db: DatabaseSync;
    let dataDir = "";
    beforeEach(() => {
      db = openDatabase(":memory:");
      migrate(db);
      dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-lists-"));
    });
    afterEach(() => {
      db.close();
      rmSync(dataDir, { recursive: true, force: true });
    });

    it("loads the first export and the current commit on the first fetch and shows what the release added and removed", async () => {
      const http = fakeHttp(zeroBreachRoutes());
      const source = getSource(db, "adfection-dns")!;
      expect(source.group_name).toBe("standards");
      expect(source.enabled).toBe(1);
      const result = await ingestSource(db, dataDir, source, { http, now: () => at });
      expect(result.status).toBe("ok");
      expect(result.items).toBe(2);

      const docs = listDocuments(db, "adfection-dns");
      expect(docs.map((d) => d.version_label)).toEqual(["2026-10-18 (7253316)", "2026-10-18 (e36dc96)"]);
      expect(docs.map((d) => d.published_at)).toEqual(["2026-10-18T22:36:53.000Z", "2026-10-18T14:01:41.000Z"]);
      const latest = latestDocument(db, "adfection-dns", "domains")!;
      expect(latest.previous_document_id).toBe(docs[1]!.id);
      expect(latest.source_url).toBe(`${raw}/${head}/dist/adfection.domains.txt`);

      const before = new Set(parseDomainList(text("adfection.domains-2026-10-18a.txt")).requirements.map((r) => r.ref));
      const after = new Set(parseDomainList(text("adfection.domains-2026-10-18b.txt")).requirements.map((r) => r.ref));
      const summary = changeSummaryFor(db, latest.id);
      expect(summary.removed).toEqual(["adtimizer.co"]);
      expect([...summary.removed].sort()).toEqual([...before].filter((r) => !after.has(r)).sort());
      expect([...summary.added].sort()).toEqual([...after].filter((r) => !before.has(r)).sort());
      expect(summary.added).toEqual(expect.arrayContaining(["adtrack.link", "aqaf.net", "armenpress.net"]));
      expect(summary.modified).toEqual([]);
      expect(releaseChanges(db, latest.id).every((c) => c.field === null)).toBe(true);

      const explanations = explanationsFor(db, latest.id);
      expect(explanations.map((e) => e.kind)).toEqual(["publisher"]);
      expect(explanations[0]?.text).toBe("Commit 7253316: Expand reviewed Candiru feeds and narrow blocking scope");
      expect(explanations[0]?.source_url).toBe(`https://github.com/interplains/zero-breach/commit/${head}`);
      const release = listWire(db, { kind: "release" }).find((i) => i.source_id === "adfection-dns" && i.external_id === `domains#${latest.id}`)!;
      expect(release.title).toBe(`AdFection / Candiru DNS blocklist (Zero Breach) 2026-10-18 (7253316): ${summary.added.length} added, 1 removed`);
      expect(release.url).toBe(`/standards/adfection-dns/${latest.id}`);

      // The next day: the listing still names the same commit, so nothing is downloaded and nothing changes.
      const calls = http.calls.length;
      const again = await ingestSource(db, dataDir, getSource(db, "adfection-dns")!, { http, now: () => at });
      expect(again.status).toBe("unchanged");
      expect(http.calls.slice(calls).map((c) => c.url)).toEqual([`${api}dist/adfection.domains.txt&per_page=1`]);
      expect(listDocuments(db, "adfection-dns")).toHaveLength(2);
    });

    it("loads the indicator list and the ad blocklist the same way", async () => {
      const http = fakeHttp(zeroBreachRoutes());
      for (const [id, key, count] of [
        ["adfection-indicators", "indicators", 405],
        ["adfection-adblock", "adblock", 291],
      ] as const) {
        const result = await ingestSource(db, dataDir, getSource(db, id)!, { http, now: () => at });
        expect(result.status, id).toBe("ok");
        const latest = latestDocument(db, id, key)!;
        expect(latest.requirement_count).toBe(count);
        expect(latest.previous_document_id).not.toBeNull();
        const summary = changeSummaryFor(db, latest.id);
        expect(summary.added.length, id).toBeGreaterThan(0);
      }
      // The indicator list's entries carry their report, and a tier change would be a revision, not a new entry.
      const indicators = latestDocument(db, "adfection-indicators", "indicators")!;
      expect(loadRequirements(db, indicators.id).find((r) => r.ref === "fearevolve.com")?.guidance).toContain("citizenlab.ca");
    });
  });
});

describe("canary sets", () => {
  const easylist = text("easylist.txt");

  it("derives twelve ad canaries from EasyList's outright domain rules, deterministically, by the hash of the name", () => {
    const candidates = filterListDomains(easylist);
    expect(candidates.length).toBeGreaterThan(10_000);
    expect(candidates.every((c) => /^\|\|[a-z0-9.-]+\^(\$third-party)?$/.test(c.line))).toBe(true);
    expect(candidates.some((c) => c.line.endsWith("$third-party"))).toBe(true);
    expect(candidates.some((c) => c.line === "||ad.doubleclick.net^")).toBe(true);
    // A rule with any other option ($popup, $image) is not an outright block and never a canary.
    expect(candidates.some((c) => c.name === "doubleclick.net")).toBe(false);

    const doc = canaryDocument(list("canary-ads"), easylist);
    expect(doc.title).toBe("Ad canaries from EasyList");
    expect(doc.versionLabel).toBe("202610200112");
    expect(doc.publishedAt).toBe("2026-10-20T01:12:00.000Z");
    expect(doc.requirements).toHaveLength(canaryCount);
    const lines = new Set(easylist.split(/\r?\n/).map((l) => l.trim()));
    for (const r of doc.requirements) {
      expect(lines.has(r.statement!)).toBe(true);
      expect(r.statement!.startsWith(`||${r.ref}^`)).toBe(true);
      expect(r.title).toBe("Ad canary");
      expect(r.family).toBe("Ad canaries (EasyList)");
    }
    const names = doc.requirements.map((r) => r.ref);
    expect(names).toEqual([...names].sort((a, b) => a.localeCompare(b)));
    // Hash each of the ~50,000 names once, not inside the comparator: a sort that hashes as it compares ran past CI's five-second limit.
    const hashed = [...new Set(candidates.map((c) => c.name))].map((name) => ({ name, hash: sha256(name) }));
    const lowest = hashed
      .sort((a, b) => a.hash.localeCompare(b.hash))
      .slice(0, canaryCount)
      .map((x) => x.name)
      .sort((a, b) => a.localeCompare(b));
    expect(names).toEqual(lowest);
    expect(canaryDocument(list("canary-ads"), easylist).requirements).toEqual(doc.requirements);
  });

  it("derives tracker canaries from EasyPrivacy", () => {
    const doc = canaryDocument(list("canary-trackers"), text("easyprivacy.txt"));
    expect(doc.title).toBe("Tracker canaries from EasyPrivacy");
    expect(doc.versionLabel).toBe("202610200112");
    expect(doc.requirements).toHaveLength(canaryCount);
    expect(doc.requirements.every((r) => r.title === "Tracker canary" && /^\|\|[a-z0-9.-]+\^/.test(r.statement ?? ""))).toBe(true);
  });

  it("keeps only registrable names a resolver could sinkhole without collateral", () => {
    const kept = apexHosts([
      { name: "1.2.3.4", line: "a" },
      { name: "pub-6dc1.r2.dev", line: "b" },
      { name: "www.Example.COM", line: "c" },
      { name: "example.org.", line: "d" },
      { name: "shrabana-56.github.io", line: "e" },
      { name: "sky.money.irish", line: "f" },
      { name: "bad-.com", line: "g" },
      { name: "name.123", line: "h" },
      { name: "[2001:db8::1]", line: "i" },
    ]);
    expect(kept).toEqual([
      { name: "example.com", line: "c" },
      { name: "example.org", line: "d" },
    ]);
  });

  it("derives malware canaries from the URLhaus host file, dated by its header", () => {
    const hostfile = text("urlhaus-hostfile.txt");
    const hosts = hostfileHosts(hostfile);
    expect(hosts.length).toBeGreaterThan(100);
    expect(hosts.every((h) => /^127\.0\.0\.1\s+\S+$/.test(h.line))).toBe(true);
    const doc = canaryDocument(list("canary-malware"), hostfile);
    expect(doc.title).toBe("Malware canaries from URLhaus");
    expect(doc.versionLabel).toBe("2026-10-20 01:17 UTC");
    expect(doc.publishedAt).toBe("2026-10-20T01:17:09.000Z");
    expect(doc.requirements).toHaveLength(canaryCount);
    const names = new Set(hosts.map((h) => h.name));
    for (const r of doc.requirements) {
      expect(r.ref.split(".")).toHaveLength(2);
      expect(names.has(r.ref) || names.has(`www.${r.ref}`)).toBe(true);
      expect(r.statement!.toLowerCase()).toMatch(new RegExp(`^127\\.0\\.0\\.1\\s+(www\\.)?${r.ref.replace(/\./g, "\\.")}$`));
    }
  });

  it("reads malware-filter's keyless copy of the URLhaus hosts the same way, dated by its own header", () => {
    const hostfile = text("urlhaus-filter-hosts.txt");
    const hosts = hostfileHosts(hostfile);
    expect(hosts.length).toBeGreaterThan(1000);
    expect(hosts.every((h) => /^0\.0\.0\.0\s+\S+$/.test(h.line))).toBe(true);
    const doc = canaryDocument(list("canary-malware"), hostfile);
    expect(doc.versionLabel).toBe("2026-10-28 12:13 UTC");
    expect(doc.publishedAt).toBe("2026-10-28T12:13:03.000Z");
    expect(doc.requirements).toHaveLength(canaryCount);
    for (const r of doc.requirements) expect(r.ref.split(".")).toHaveLength(2);
  });

  it("derives phishing canaries from the OpenPhish feed, keeping each host's origin and never a path", () => {
    const feed = text("openphish-feed.txt");
    const hosts = urlHosts(feed);
    expect(hosts.length).toBeGreaterThan(100);
    expect(hosts.every((h) => /^https?:\/\/[^/]+\/$/.test(h.line))).toBe(true);
    const doc = canaryDocument(list("canary-phishing"), feed);
    expect(doc.title).toBe("Phishing canaries from OpenPhish");
    expect(doc.versionLabel).toMatch(/^feed [0-9a-f]{7}$/);
    expect(doc.publishedAt).toBeNull();
    expect(doc.requirements).toHaveLength(canaryCount);
    for (const r of doc.requirements) {
      expect(r.ref.split(".")).toHaveLength(2);
      expect(r.statement).toMatch(/^https?:\/\/(www\.)?[a-z0-9.-]+(:\d+)?\/$/);
      expect(feed).toContain(r.ref);
    }
  });

  it("picks the lowest hashes once per name and returns them in name order", () => {
    const picked = pickCanaries(
      [
        { name: "b.example", line: "1" },
        { name: "a.example", line: "2" },
        { name: "a.example", line: "3" },
        { name: "c.example", line: "4" },
      ],
      2,
    );
    const order = ["a.example", "b.example", "c.example"].sort((x, y) => sha256(x).localeCompare(sha256(y))).slice(0, 2).sort();
    expect(picked.map((p) => p.name)).toEqual(order);
    expect(picked.find((p) => p.name === "a.example")?.line).toBe("2");
  });

  describe("ingestion", () => {
    let db: DatabaseSync;
    let dataDir = "";
    beforeEach(() => {
      db = openDatabase(":memory:");
      migrate(db);
      dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-canary-"));
    });
    afterEach(() => {
      db.close();
      rmSync(dataDir, { recursive: true, force: true });
    });

    it("stores the set as a version and shows a changed list as a line-level diff", async () => {
      const source = getSource(db, "canary-ads")!;
      expect(source.schedule).toBe("weekly");
      const served = { text: easylist };
      const http = fakeHttp({ [source.url]: { get bytes() { return new TextEncoder().encode(served.text); }, contentType: "text/plain" } });
      const first = await ingestSource(db, dataDir, source, { http, now: () => at });
      expect(first.status).toBe("ok");
      expect(first.detail).toBe("canaries 202610200112: first version, 12 requirements");
      const v1 = latestDocument(db, "canary-ads", "canaries")!;
      const picked = loadRequirements(db, v1.id);
      expect(picked).toHaveLength(canaryCount);

      // EasyList moves: one canary's rule gains $third-party (a revision), one is dropped (a removal and a new twelfth name).
      const [revised, dropped] = picked;
      const flipped = revised!.statement!.endsWith("$third-party") ? revised!.statement!.replace(/\$third-party$/, "") : `${revised!.statement}$third-party`;
      served.text = easylist
        .replace("! Version: 202610200112", "! Version: 202610210300")
        .replace("! Last modified: 20 Oct 2026 01:12 UTC", "! Last modified: 21 Oct 2026 03:00 UTC")
        .replace(`\n${revised!.statement}\n`, `\n${flipped}\n`)
        .replace(`\n${dropped!.statement}\n`, "\n");
      const second = await ingestSource(db, dataDir, getSource(db, "canary-ads")!, { http, now: () => new Date("2026-10-26T12:00:00Z") });
      expect(second.status).toBe("ok");
      const v2 = latestDocument(db, "canary-ads", "canaries")!;
      expect(v2.id).not.toBe(v1.id);
      expect(v2.version_label).toBe("202610210300");
      expect(v2.published_at).toBe("2026-10-21T03:00:00.000Z");
      expect(v2.previous_document_id).toBe(v1.id);
      const summary = changeSummaryFor(db, v2.id);
      expect(summary.removed).toEqual([dropped!.ref]);
      expect(summary.substantive).toEqual([revised!.ref]);
      expect(summary.added).toHaveLength(1);
      expect(picked.map((r) => r.ref)).not.toContain(summary.added[0]);
      const change = releaseChanges(db, v2.id).find((c) => c.ref === revised!.ref)!;
      expect(change).toMatchObject({ kind: "modified", field: "statement", before_text: revised!.statement, after_text: flipped });
      expect(explanationsFor(db, v2.id).map((e) => e.kind)).toEqual(["none"]);
      const release = listWire(db, { kind: "release" }).find((i) => i.source_id === "canary-ads" && i.external_id === `canaries#${v2.id}`)!;
      expect(release.title).toBe("Ad canaries (EasyList) 202610210300: 1 added, 1 removed, 1 revised");

      // The same bytes again are the same version.
      const third = await ingestSource(db, dataDir, getSource(db, "canary-ads")!, { http, now: () => new Date("2026-11-02T12:00:00Z") });
      expect(third.status).toBe("unchanged");
      expect(listDocuments(db, "canary-ads")).toHaveLength(2);
    });
  });
});

describe("the lists on the pages", () => {
  let app: TestApp;
  beforeEach(async () => {
    app = await startTestApp({ now: () => at });
  });
  afterEach(async () => {
    await app.close();
  });

  it("registers every list as a standards source, OpenPhish off, and draws a list's versions, changes and lines", async () => {
    for (const id of ["adfection-indicators", "adfection-dns", "adfection-adblock", "canary-ads", "canary-trackers", "canary-malware", "canary-phishing"]) {
      const source = getSource(app.db, id)!;
      expect(source.group_name, id).toBe("standards");
      expect(source.kind, id).toBe("requirement-set");
      expect(adapterFor(source)?.id, id).toBe(id);
      expect(source.licence, id).not.toBeNull();
    }
    expect(getSource(app.db, "canary-phishing")?.enabled).toBe(0);

    const result = await ingestSource(app.db, app.dataDir, getSource(app.db, "adfection-dns")!, { http: fakeHttp(zeroBreachRoutes()), now: () => at });
    expect(result.status).toBe("ok");
    const latest = latestDocument(app.db, "adfection-dns", "domains")!;

    const register = await (await fetch(`${app.base}/register`)).text();
    expect(register).toContain("AdFection / Candiru DNS blocklist (Zero Breach)");
    expect(register).toContain("2026-10-18 (7253316)");
    expect(register).toContain("Phishing canaries (OpenPhish)");
    expect(register).toContain("plain text list");

    const sources = await (await fetch(`${app.base}/sources`)).text();
    expect(sources).toContain("Ad canaries (EasyList)");
    expect(sources).toContain("GPLv3 or CC BY-SA 3.0");
    expect(sources).toContain("CC0 1.0");
    expect(sources).toMatch(/<tr id="src-[a-z0-9-]+" class="off">\s*<td><a href="https:\/\/openphish\.com\/feed\.txt"/);
    expect(sources).toContain("OpenPhish Community Feed terms");

    const standard = await (await fetch(`${app.base}/standards/adfection-dns`)).text();
    expect(standard).toContain("2 versions");
    expect(standard).toContain("1 removed");

    const release = await (await fetch(`${app.base}/standards/adfection-dns/${latest.id}`)).text();
    expect(release).toContain("adtimizer.co");
    expect(release).toContain("adtrack.link");
    expect(release).toContain("Commit 7253316: Expand reviewed Candiru feeds and narrow blocking scope");

    const browse = await (await fetch(`${app.base}/standards/adfection-dns/${latest.id}/browse`)).text();
    expect(browse).toContain("addthis.events");
    expect(browse).toContain("291 of 291");

    const control = await (await fetch(`${app.base}/standards/adfection-dns/${latest.id}/adtrack.link`)).text();
    expect(control).toContain("Listed domain");
    expect(control).toContain(">added<");

    // Listed names are quoted, never linked: no page carries a link to one.
    for (const page of [register, standard, release, browse, control]) {
      expect(page).not.toMatch(/href="https?:\/\/[^"]*(addthis\.events|adtrack\.link|adtimizer\.co)/);
    }
    const home = await (await fetch(`${app.base}/`)).text();
    expect(home).toContain("Zero Breach project");
  });
});
