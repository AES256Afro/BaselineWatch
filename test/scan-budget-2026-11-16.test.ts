import { afterEach, describe, expect, it, vi } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { validDomain, type DnsLookup } from "../src/domaincheck.ts";
import { fixFor } from "../src/domainfix.ts";
import { parseStigRevisionHistory } from "../src/explain.ts";
import { HttpError, type HttpGet } from "../src/http.ts";
import { matchOs, readReport } from "../src/inventory.ts";
import { netSettingKeys, networkSummary, resolvConfPath, runNetworkScan, setSetting } from "../src/netscan.ts";
import { searchControls } from "../src/pages/controls.ts";
import { renderPdf } from "../src/report.ts";
import { likePattern } from "../src/sql.ts";
import { fakeHttp, startTestApp } from "./helpers.ts";

/**
 * The audit of 16 November, second pass: the anonymous budget charged waiting as work, the /scan
 * pill and the category tones read silence as a block, the Controls search took % as a wildcard,
 * and the smaller findings beside them.
 */

const now = new Date("2026-11-16T12:00:00Z");
const realNow = performance.now.bind(performance);

afterEach(() => vi.restoreAllMocks());

const from = (address: string, extra: Record<string, string> = {}): RequestInit => ({ headers: { "x-forwarded-for": address, ...extra } });

describe("the anonymous budget charges the event loop, not the wait (S4-1)", () => {
  it("does not lock an address out of / after two slow domain checks", async () => {
    let offset = 0;
    vi.spyOn(performance, "now").mockImplementation(() => realNow() + offset);
    // Each check waits four seconds on the resolver, as a slow name server makes it.
    const dns: DnsLookup = async (name, type) => {
      // The wait is on the network: the clock moves after the handler has yielded.
      await new Promise((resolve) => setImmediate(resolve));
      if (type === "A" && /^(one|two)\.example\.net$/.test(name)) offset += 4000;
      return { records: [], code: "nodata" };
    };
    const app = await startTestApp({ now: () => now, dns, tls: async () => ({ error: "ECONNREFUSED" }), http: fakeHttp({}), env: { BW_ADMIN_PASSWORD: "x" } });
    try {
      for (const name of ["one.example.net", "two.example.net"]) expect((await fetch(`${app.base}/scan/domain?name=${name}`, from("10.20.0.1"))).status).toBe(200);
      expect(offset).toBe(8000);
      const home = await fetch(`${app.base}/`, from("10.20.0.1"));
      expect(home.status).toBe(200);
      expect((await fetch(`${app.base}/today`, from("10.20.0.1"))).status).not.toBe(429);
    } finally {
      await app.close();
    }
  });

  it("serves a light reader when everyone's share is spent, and says so neutrally to the rest", async () => {
    // Every reading of the clock is 400 ms after the last: each request costs a second or two.
    let t = realNow();
    vi.spyOn(performance, "now").mockImplementation(() => (t += 400));
    const app = await startTestApp({ now: () => now, env: { BW_ADMIN_PASSWORD: "x" } });
    try {
      let busyText: string | null = null;
      for (let i = 1; i < 200 && busyText === null; i++) {
        const address = `10.30.${Math.floor(i / 200)}.${(i % 200) + 1}`;
        for (let j = 0; j < 10; j++) {
          const res = await fetch(`${app.base}/search?q=a`, from(address));
          if (res.status === 503) busyText = await res.text();
          else await res.arrayBuffer();
          if (res.status !== 200) break;
        }
      }
      expect(busyText).toBe("The site is busy; try again in half a minute.");
      // A new address that has had its fair part is refused heavy work but still reads the News,
      // a CVE's page and an image.
      const light = async (address: string, path: string): Promise<number> => {
        await (await fetch(`${app.base}/search?q=b`, from(address))).arrayBuffer();
        const res = await fetch(`${app.base}${path}`, from(address));
        await res.arrayBuffer();
        return res.status;
      };
      expect(await light("10.40.0.1", "/")).toBe(200);
      expect(await light("10.40.0.2", "/vulnerabilities/CVE-2024-0001")).not.toBe(503);
      expect(await light("10.40.0.3", "/img/0123456789abcdef")).not.toBe(503);
      expect(await light("10.40.0.4", "/?q=x")).toBe(503);
      expect(await light("10.40.0.5", "/today")).toBe(503);
    } finally {
      await app.close();
    }
  });
});

function seedRun(db: ReturnType<typeof openDatabase>, outcomes: ("sinkholed" | "resolved" | "timeout")[]): void {
  const id = db.prepare("INSERT INTO net_scans (started_at, finished_at, resolver, resolver_source, upstream, doh) VALUES (?, ?, '192.0.2.53', 'resolv.conf', NULL, 'blocked')").run(now.toISOString(), now.toISOString()).lastInsertRowid;
  const canary = db.prepare("INSERT INTO net_canaries (scan_id, category, source_id, name, outcome, answer) VALUES (?, 'ads', 'canary-ads', ?, ?, ?)");
  outcomes.forEach((o, i) => canary.run(id, `c${i}.example.net`, o, o === "timeout" ? "ETIMEOUT" : o === "sinkholed" ? "0.0.0.0" : "198.51.100.7"));
}

describe("a run with some canaries unanswered (C4-1)", () => {
  it("reads warn on /scan, on Today and on /scan/network alike", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      seedRun(app.db, ["sinkholed", "sinkholed", "timeout"]);
      expect(networkSummary(app.db)).toMatchObject({ total: 3, sinkholed: 2, resolved: 0, timeout: 1 });
      const scan = await (await fetch(`${app.base}/scan`)).text();
      expect(scan).toContain('<span class="state warn">2 / 3 sinkholed</span>');
      expect(scan).toContain("2 sinkholed, 0 resolved, 1 unanswered");
      const today = await (await fetch(`${app.base}/today`)).text();
      expect(today).toMatch(/<b class="warn">2\/3 · 1 canary unanswered<\/b>/);
      const network = await (await fetch(`${app.base}/scan/network`)).text();
      expect(network).toContain('<b class="warn-t">2 / 3</b>');
      expect(network).not.toContain('<b class="ok-t">2 / 3</b>');
      seedRun(app.db, ["sinkholed", "sinkholed", "sinkholed"]);
      expect(await (await fetch(`${app.base}/scan`)).text()).toContain('<span class="state ok">3 / 3 sinkholed</span>');
      expect(await (await fetch(`${app.base}/scan/network`)).text()).toContain('<b class="ok-t">3 / 3</b>');
    } finally {
      await app.close();
    }
  });
});

describe("the Controls search takes % and _ as typed (C4-2)", () => {
  it("escapes LIKE's wildcards in one helper", () => {
    expect(likePattern("50%_a\\b")).toBe("%50\\%\\_a\\\\b%");
    const db = openDatabase(":memory:");
    migrate(db);
    db.prepare("INSERT INTO snapshots (id, source_id, document_key, sha256, bytes, blob_path, fetched_at) VALUES (1, 'nist-sp-800-53', 'r5', 'ab', 1, 'blobs/ab/ab', '2026-11-10')").run();
    db.prepare("INSERT INTO documents (id, source_id, document_key, snapshot_id, version_label, parsed_at, published_at) VALUES (7, 'nist-sp-800-53', 'r5', 1, '5.2.0', '2026-11-10', '2026-11-10')").run();
    db.prepare("INSERT INTO requirements (document_id, ref, label, title, statement) VALUES (7, 'ac-2', 'AC-2', 'Account Management', 'Manage accounts.')").run();
    db.prepare("INSERT INTO requirements (document_id, ref, label, title, statement) VALUES (7, 'sc-5', 'SC-5', 'Denial-of-service Protection', 'Limit 100% of load.')").run();
    const versions = [{ documentId: 7 }] as unknown as Parameters<typeof searchControls>[1];
    expect(searchControls(db, versions, "%")).toHaveLength(1);
    expect(searchControls(db, versions, "%")[0]!.ref).toBe("sc-5");
    expect(searchControls(db, versions, "_")).toHaveLength(0);
    expect(searchControls(db, versions, "ac-2").map((h) => h.ref)).toEqual(["ac-2"]);
    db.close();
  });

  it("answers /controls?q=% with the controls that hold a percent sign, not every one", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      const res = await fetch(`${app.base}/controls?q=%25`);
      expect(res.status).toBe(200);
      expect(await res.text()).not.toMatch(/200\+/);
    } finally {
      await app.close();
    }
  });
});

describe("the smaller findings", () => {
  it("refuses the suffixes networks give themselves (S4-3)", () => {
    for (const tld of ["localdomain", "corp", "intranet", "private", "example", "test", "invalid", "home", "lan"]) expect(validDomain(`nas.${tld}`)).toBeNull();
    expect(validDomain("example.com")).toBe("example.com");
  });

  it("reads a cut MTA-STS policy from the finding's flag, not its wording (C4-3)", () => {
    const finding = { id: "mta-sts", group: "mail" as const, title: "MTA-STS", state: "warn" as const, text: "Published in mode testing; enforce is the point.", quoted: ["policy: version: STSv1", "policy: mode: testing", "policy: mx: mx1.example.net"] };
    expect(fixFor(finding, "example.net")!.lines).toContain("mx: mx1.example.net");
    const cut = fixFor({ ...finding, policyCut: true }, "example.net")!;
    expect(cut.lines).not.toContain("mx: mx1.example.net");
    expect(cut.lines.some((l) => l.startsWith("mx: <each"))).toBe(true);
  });

  it("gives no notes for a dotted release the history has not reached (B4-2)", () => {
    const text = "STIG Revision History\nV1R3:\n - V-1 - Changed the check. 30 September 2026\n";
    expect(parseStigRevisionHistory(text, "V1R4.1")).toEqual({ notes: [], general: [], version: null });
  });

  it("asks Pi-hole v5's API only when v6 answered 404 (S4-2)", async () => {
    for (const [failure, note] of [[new HttpError("http://192.0.2.10/api/auth", 500), "pihole: HTTP 500"], [Object.assign(new Error("timed out"), { name: "TimeoutError" }), "pihole: timed out"], [null, "pihole: unreadable"]] as const) {
      const db = openDatabase(":memory:");
      migrate(db);
      setSetting(db, netSettingKeys.piholeUrl, "http://192.0.2.10", now.toISOString());
      setSetting(db, netSettingKeys.piholeToken, "token-abc", now.toISOString());
      const asked: string[] = [];
      const http: HttpGet = async (url) => {
        asked.push(url);
        if (url === "http://192.0.2.10/api/auth") {
          if (failure) throw failure;
          // A 200 that is not JSON: a login page, a captive portal.
          return { url, status: 200, notModified: false, bytes: new TextEncoder().encode("<html>"), etag: null, lastModified: null, contentType: "text/html", headers: {} };
        }
        throw new HttpError(url, 404);
      };
      const scan = await runNetworkScan(db, { now: () => now, resolve: async () => ["0.0.0.0"], readFile: (f) => (f === resolvConfPath ? "nameserver 192.0.2.53\n" : null), http });
      expect(scan).toMatchObject({ clients_seen: null, error: note });
      expect(asked.some((u) => u.includes("/admin/api.php"))).toBe(false);
      db.close();
    }
  });

  it("cuts a long word by each character's width, so a run of wide letters stays inside the measure (B4-3)", () => {
    const pdf = new TextDecoder("latin1").decode(renderPdf([{ type: "p", runs: ["i".repeat(300) + "W".repeat(120)] }]));
    const lines = [...pdf.matchAll(/\(([iW]+)\) Tj/g)].map((m) => m[1]!);
    expect(lines.length).toBeGreaterThan(2);
    // Helvetica's widths: i is 222 units, W 944; every line is within the first, all-narrow one's width and one W.
    const units = (line: string): number => [...line].reduce((sum, ch) => sum + (ch === "W" ? 944 : 222), 0);
    const first = units(lines[0]!);
    for (const line of lines) expect(units(line)).toBeLessThanOrEqual(first + 944);
  });

  it("names a Windows edition it cannot map and reads no support dates for it (B4-4)", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const report = readReport('{"bw":1,"os":{"family":"windows","name":"Windows 11","version":"24H2","build":"10.0.26100.1","display":"24H2","edition":"CloudEditionN"},"browsers":[],"packages":[],"package_source":""}');
    const finding = matchOs(db, report, now);
    expect(finding).toMatchObject({ state: "na" });
    expect(finding.text).toContain("CloudEditionN edition");
    expect(finding.text).toContain("its support dates are not read here");
    db.close();
  });
});

describe("migration 0067 (B4-1)", () => {
  it("marks a CVE between 40% and 50% that crossed 50% and has not fallen below 40% since", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const vuln = db.prepare("INSERT INTO vulns (cve_id, epss, epss_crossed_at, last_modified_at, first_seen_at, last_seen_at) VALUES (?, ?, NULL, '2026-10-01', '2026-10-01', '2026-10-01')");
    const change = db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field, before_text, after_text) VALUES (?, ?, 'epss', ?, ?)");
    vuln.run("CVE-2026-0001", 0.45);
    change.run("CVE-2026-0001", "2026-10-01T00:00:00Z", "30%", "52%");
    change.run("CVE-2026-0001", "2026-10-05T00:00:00Z", "52%", "45%");
    vuln.run("CVE-2026-0002", 0.45);
    change.run("CVE-2026-0002", "2026-10-01T00:00:00Z", "30%", "55%");
    change.run("CVE-2026-0002", "2026-10-03T00:00:00Z", "55%", "35%");
    change.run("CVE-2026-0002", "2026-10-05T00:00:00Z", "35%", "45%");
    vuln.run("CVE-2026-0003", 0.42);
    change.run("CVE-2026-0003", "2026-10-01T00:00:00Z", "30%", "42%");
    db.prepare("DELETE FROM schema_migrations WHERE id = '0067_epss_crossed_before'").run();
    migrate(db);
    const at = (id: string): string | null => (db.prepare("SELECT epss_crossed_at AS at FROM vulns WHERE cve_id = ?").get(id) as { at: string | null }).at;
    expect(at("CVE-2026-0001")).toBe("2026-10-01T00:00:00Z");
    expect(at("CVE-2026-0002")).toBeNull();
    expect(at("CVE-2026-0003")).toBeNull();
    db.close();
  });
});
