import { describe, expect, it } from "vitest";
import { gpoPathFromFix } from "../src/baselines.ts";
import { feedTitle } from "../src/newsource.ts";
import { alternateFeeds } from "../src/repairs.ts";
import { cookieFrom, formPost, startTestApp } from "./helpers.ts";

/** What the audit of 10 November closed, each as the input that showed it. */
describe("the audit of 10 November", () => {
  it("reads hostile markup in linear time", () => {
    const at = performance.now();
    expect(alternateFeeds("<link ".repeat(200_000), "https://example.com/")).toEqual([]);
    expect(feedTitle("<title>".repeat(300_000))).toBeNull();
    expect(gpoPathFromFix(`Computer Configuration${" >> a".repeat(40)} >> x`)).toBeNull();
    expect(gpoPathFromFix(`Computer Configuration${" ".repeat(80_000)}`)).toBeNull();
    expect(gpoPathFromFix("Computer Configuration >> a>b ".repeat(8000))).toBeNull();
    expect(performance.now() - at).toBeLessThan(1500);
  });

  it("still reads a Group Policy path the way it did", () => {
    expect(gpoPathFromFix('Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> "Turn off Toast" to "Enabled".')).toEqual({
      path: "User Configuration >> Administrative Templates >> Windows Components",
      setting: "Turn off Toast",
    });
  });

  it("names a rejected CVE as such and leaves it out of the table", async () => {
    const { isNotable, liveSql, notableInWindowSql } = await import("../src/vulns.ts");
    const row = { vuln_status: "Rejected", kev: 1, watch_hit: 0, cvss_score: 9.8, epss: 0.9, published_at: "2026-11-09T00:00:00Z", ssvc_json: null } as unknown as Parameters<typeof isNotable>[0];
    expect(isNotable(row, true, "2026-11-10T00:00:00Z")).toBe(false);
    expect(isNotable({ ...row, vuln_status: "Analyzed" }, true, "2026-11-10T00:00:00Z")).toBe(true);
    expect(notableInWindowSql).toContain(liveSql);

    const { migrate, openDatabase } = await import("../src/db.ts");
    const { listVulns, vulnStats } = await import("../src/vulns.ts");
    const db = openDatabase(":memory:");
    migrate(db);
    const add = db.prepare("INSERT INTO vulns (cve_id, last_modified_at, vuln_status, kev, has_exploit, first_seen_at, last_seen_at) VALUES (?, '2026-11-10', ?, 0, 1, '2026-11-10', '2026-11-10')");
    add.run("CVE-2026-1000", "Analyzed");
    add.run("CVE-2026-1001", "Rejected");
    expect(listVulns(db, {}).rows.map((r) => r.cve_id)).toEqual(["CVE-2026-1000"]);
    expect(listVulns(db, { rejected: true }).rows.map((r) => r.cve_id)).toEqual(["CVE-2026-1001"]);
    expect(vulnStats(db, "2026-11-01")).toMatchObject({ total: 1, exploit: 1 });
  });

  it("counts each call in an MCP batch, and takes no long batch from a stranger", async () => {
    const app = await startTestApp({ env: { BW_PUBLIC_READ: "true", BW_ADMIN_PASSWORD: "owner-pass" } });
    try {
      const call = (id: number) => ({ jsonrpc: "2.0", id, method: "tools/list", params: {} });
      const post = (body: unknown) => fetch(`${app.base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify(body) });
      const long = await post(Array.from({ length: 11 }, (_, i) => call(i)));
      expect(long.status).toBe(400);
      // Twelve batches of ten spend the allowance of 120; one more single call is refused.
      for (let i = 0; i < 12; i++) expect((await post(Array.from({ length: 10 }, (_, j) => call(j)))).status).not.toBe(429);
      expect((await post(call(1))).status).toBe(429);
      expect(((await long.json()) as { error: { message: string } }).error.message).toContain("more than ten");
    } finally {
      await app.close();
    }
  });

  it("writes the owner's domains, unread and unstar, and sends a stranger's referer nowhere", async () => {
    const app = await startTestApp({ env: { BW_PUBLIC_READ: "true", BW_ADMIN_PASSWORD: "owner-pass" } });
    try {
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "owner-pass", next: "/" }));
      await formPost(app.base, "/scan/domain/own", { domains: "Example.com, bad domain, example.com, example.org" }, cookie);
      expect((app.db.prepare("SELECT value FROM app_settings WHERE key = 'scan.domains'").get() as { value: string }).value).toBe("example.com,example.org");
      await formPost(app.base, "/scan/domain/own", { domains: "" }, cookie);
      expect(app.db.prepare("SELECT value FROM app_settings WHERE key = 'scan.domains'").get()).toBeUndefined();

      const at = "2026-11-10T00:00:00Z";
      const id = Number(app.db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, published_at, fetched_at, read, starred) VALUES ('cisa-kev', 'article', 'x1', 'A story', 'https://example.com/x', ?, ?, 1, 1)").run(at, at).lastInsertRowid);
      const back = await formPost(app.base, `/items/${id}/unread`, { back: "/?group=news" }, cookie);
      expect(back.headers.get("location")).toBe("/?group=news");
      await formPost(app.base, `/items/${id}/unstar`, { back: "/" }, cookie);
      expect(app.db.prepare("SELECT read, starred FROM items WHERE id = ?").get(id)).toEqual({ read: 0, starred: 0 });

      // Signed out, a form sent from another host's page is offered no way back to that host.
      const lapsed = await fetch(`${app.base}/items/${id}/read`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: app.base, "sec-fetch-site": "same-origin", referer: "https://evil.example/phish" }, body: "back=/" });
      expect(lapsed.status).toBe(403);
      expect(await lapsed.text()).toContain('name="next" value="/"');
    } finally {
      await app.close();
    }
  });

  it("gives a stranger ninety heavy reads a minute, and the owner no limit", async () => {
    const app = await startTestApp({ env: { BW_PUBLIC_READ: "true", BW_ADMIN_PASSWORD: "owner-pass" } });
    try {
      let last = 0;
      for (let i = 0; i < 91; i++) last = (await fetch(`${app.base}/search?q=x${i}`)).status;
      expect(last).toBe(429);
      expect((await fetch(`${app.base}/sources`)).status).toBe(200);
      // The same work by another spelling or method is the same allowance.
      expect((await fetch(`${app.base}/SEARCH?q=y`)).status).toBe(429);
      expect((await fetch(`${app.base}/search?q=z`, { method: "HEAD" })).status).toBe(429);
      // The owner is never counted.
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "owner-pass", next: "/" }));
      for (let i = 0; i < 91; i++) last = (await fetch(`${app.base}/search?q=o${i}`, { headers: { cookie } })).status;
      expect(last).toBe(200);
    } finally {
      await app.close();
    }
  });

  it("fills a KEV-only row from the CVE list and NVD without calling an old CVE news", async () => {
    const { migrate, openDatabase } = await import("../src/db.ts");
    const { applyKev, getVuln, vulnChanges } = await import("../src/vulns.ts");
    const { storeCvelistRecords } = await import("../src/adapters/cvelist.ts");
    const { storeNvdRecords } = await import("../src/adapters/nvd.ts");
    const db = openDatabase(":memory:");
    migrate(db);
    const id = "CVE-2021-40444";
    applyKev(db, [{ cveId: id, dateAdded: "2021-11-03", dueDate: "2021-11-17", ransomware: true, description: "MSHTML RCE.", vendor: "Microsoft", product: "MSHTML" }], "2026-11-10T10:00:00.000Z");
    expect(getVuln(db, id)?.vuln_status).toBe("KEV only");
    const record = { dataType: "CVE_RECORD", cveMetadata: { cveId: id, state: "PUBLISHED", datePublished: "2021-09-07T00:00:00Z", dateUpdated: "2026-11-10T09:00:00Z" }, containers: { cna: { descriptions: [{ lang: "en", value: "Microsoft MSHTML Remote Code Execution Vulnerability" }], references: [] } } };
    storeCvelistRecords({ db, now: () => new Date("2026-11-10T11:00:00Z") }, [record] as unknown as Parameters<typeof storeCvelistRecords>[1]);
    expect(getVuln(db, id)?.published_at?.slice(0, 10)).toBe("2021-09-07");
    const nvd = { cve: { id, sourceIdentifier: "secure@microsoft.com", published: "2021-09-15T12:15:00.000", lastModified: "2026-11-10T11:30:00.000", vulnStatus: "Analyzed", descriptions: [{ lang: "en", value: "Microsoft MSHTML Remote Code Execution Vulnerability" }], metrics: { cvssMetricV31: [{ type: "Primary", source: "nvd@nist.gov", cvssData: { version: "3.1", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", baseScore: 8.8, baseSeverity: "HIGH" } }] }, cisaExploitAdd: "2021-11-03", cisaActionDue: "2021-11-17" } };
    storeNvdRecords({ db, now: () => new Date("2026-11-10T12:00:00Z") }, [nvd] as unknown as Parameters<typeof storeNvdRecords>[1]);
    expect(getVuln(db, id)).toMatchObject({ vuln_status: "Analyzed", cvss_score: 8.8, kev: 1 });
    expect(vulnChanges(db, id)).toEqual([]);
    expect(db.prepare("SELECT COUNT(*) AS n FROM items WHERE external_id LIKE ?").get(`%${id}%`)).toEqual({ n: 0 });
  });

  it("marks read only what the page showed, so a later KEV entry stays in the inbox", async () => {
    const { migrate, openDatabase } = await import("../src/db.ts");
    const { markAllRead } = await import("../src/wire.ts");
    const db = openDatabase(":memory:");
    migrate(db);
    const add = db.prepare("INSERT INTO items (source_id, kind, external_id, title, published_at, fetched_at) VALUES ('cisa-kev', 'kev', ?, 'x', '2026-11-10', '2026-11-10')");
    const shown = Number(add.run("CVE-2026-2000").lastInsertRowid);
    add.run("CVE-2026-2001");
    markAllRead(db, {}, shown);
    expect(db.prepare("SELECT external_id, read FROM items ORDER BY id").all()).toEqual([
      { external_id: "CVE-2026-2000", read: 1 },
      { external_id: "CVE-2026-2001", read: 0 },
    ]);
    // An older item that came back unread after the page was drawn keeps its id; its time tells.
    db.prepare("UPDATE items SET read = 0, surfaced_at = '2026-11-10T12:00:00.000Z' WHERE external_id = 'CVE-2026-2000'").run();
    markAllRead(db, {}, shown + 1, "2026-11-10T11:00:00.000Z");
    expect(db.prepare("SELECT external_id, read FROM items ORDER BY id").all()).toEqual([
      { external_id: "CVE-2026-2000", read: 0 },
      { external_id: "CVE-2026-2001", read: 1 },
    ]);
  });

  it("offers the feeds a pasted home page names, when the page itself is not a feed", async () => {
    const { probeFeed } = await import("../src/newsource.ts");
    const page = '<html><head><link rel="alternate" type="application/rss+xml" href="/feed.xml"><title>A blog</title></head><body>Hello</body></html>';
    const http = (async () => ({ bytes: new TextEncoder().encode(page) })) as unknown as Parameters<typeof probeFeed>[0];
    const probe = await probeFeed(http, "https://blog.example/");
    expect(probe).toMatchObject({ ok: false, found: ["https://blog.example/feed.xml"] });
  });

  it("starts a new failure episode when a source is turned back on", async () => {
    const { migrate, openDatabase } = await import("../src/db.ts");
    const { setSourceEnabled } = await import("../src/ingest.ts");
    const db = openDatabase(":memory:");
    migrate(db);
    db.prepare("UPDATE sources SET failing_since = '2026-10-01T00:00:00Z', failing_alerted_at = '2026-10-02T00:00:00Z' WHERE id = 'cisa-kev'").run();
    setSourceEnabled(db, "cisa-kev", false);
    setSourceEnabled(db, "cisa-kev", true);
    expect(db.prepare("SELECT failing_since, failing_alerted_at FROM sources WHERE id = 'cisa-kev'").get()).toEqual({ failing_since: null, failing_alerted_at: null });
  });

  it("lets the owner set the site's wording on Branding, and clear the optional lines", async () => {
    const app = await startTestApp({ env: { BW_PUBLIC_READ: "true", BW_ADMIN_PASSWORD: "owner-pass" } });
    try {
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "owner-pass", next: "/" }));
      const before = await (await fetch(`${app.base}/`)).text();
      expect(before).toContain("change register for security standards; CVE and advisory feed");
      expect((await formPost(app.base, "/branding/text", { siteName: "Lab Watch", footer: "", newsSubtitle: "Feeds for the lab\u0007", description: "" })).status).toBe(403);
      await formPost(app.base, "/branding/text", { siteName: "Lab Watch", footer: "", newsSubtitle: "Feeds for the lab\u0007", description: "" }, cookie);
      const after = await (await fetch(`${app.base}/`)).text();
      expect(after).toContain("<title>News · Lab Watch</title>");
      expect(after).toContain('<small class="motto">Feeds for the lab</small>');
      expect(after).not.toContain("CVE and advisory feed");
      // An empty required field is the default again.
      expect(await (await fetch(`${app.base}/appearance`)).text()).toContain("each control before and after, with the publisher&#39;s stated reason");
    } finally {
      await app.close();
    }
  });

  it("keeps CISA's labelled notes, which the required action refers to", async () => {
    const { migrate, openDatabase } = await import("../src/db.ts");
    const { kevFor } = await import("../src/fix.ts");
    const db = openDatabase(":memory:");
    migrate(db);
    const signals = { requiredAction: "Apply mitigations per BOD 26-04 (see URL in Notes).", notes: "https://vendor.example/advisory ; BOD 26-04: https://www.cisa.gov/bod-26-04 ; Reference CISA's ED 21-04 (https://www.cisa.gov/ed-21-04). https://nvd.nist.gov/vuln/detail/CVE-2026-3000 ; https://vendor.example/advisory-(cve-2026-3000)" };
    db.prepare("INSERT INTO items (source_id, kind, external_id, title, published_at, fetched_at, signals_json) VALUES ('cisa-kev', 'kev', 'CVE-2026-3000', 'Vendor: flaw', '2026-11-01', '2026-11-01', ?)").run(JSON.stringify(signals));
    expect(kevFor(db, "CVE-2026-3000")?.notes).toEqual([
      { url: "https://vendor.example/advisory", label: null },
      { url: "https://www.cisa.gov/bod-26-04", label: "BOD 26-04" },
      { url: "https://www.cisa.gov/ed-21-04", label: null },
      { url: "https://nvd.nist.gov/vuln/detail/CVE-2026-3000", label: null },
      { url: "https://vendor.example/advisory-(cve-2026-3000)", label: null },
    ]);
  });

  it("lists Apple's multi-product KEV entries on the Mobile STIG page as well as macOS", async () => {
    const { migrate, openDatabase } = await import("../src/db.ts");
    const { kevForPlatform } = await import("../src/stigs.ts");
    const db = openDatabase(":memory:");
    migrate(db);
    const add = db.prepare("INSERT INTO items (source_id, kind, external_id, title, published_at, fetched_at, signals_json) VALUES ('cisa-kev', 'kev', ?, 'Apple: flaw', '2026-11-01', '2026-11-01', ?)");
    add.run("CVE-2026-4000", JSON.stringify({ vendor: "Apple", product: "Multiple Products" }));
    add.run("CVE-2026-4001", JSON.stringify({ vendor: "Apple", product: "macOS" }));
    expect(kevForPlatform(db, "mobile").entries.map((e) => e.cve)).toEqual(["CVE-2026-4000"]);
    expect(kevForPlatform(db, "macos").total).toBe(2);
  });

  it("gives domain advice that fits the finding: no step down from reject, no certificate advice for a protocol", async () => {
    const { fixFor } = await import("../src/domainfix.ts");
    const { judgeDmarc } = await import("../src/domaincheck.ts");
    const reject = fixFor(judgeDmarc(["v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com"], true), "example.com");
    expect(reject?.lines).toEqual(['_dmarc.example.com. IN TXT "v=DMARC1; p=reject; rua=mailto:d@example.com"']);
    const none = fixFor(judgeDmarc(["v=DMARC1; p=none; rua=mailto:d@example.com"], true), "example.com");
    expect(none?.lines).toEqual(['_dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:d@example.com"']);
    const tls = fixFor({ id: "tls", group: "web", title: "TLS", state: "warn", text: "TLSv1.2 was negotiated; TLS 1.3 is the current standard.", quoted: [] }, "example.com");
    expect(tls?.text).toContain("Turn on TLS 1.3");
  });

  it("matches a KEV-only row against the watchlist and gives it the catalogue's platform", async () => {
    const { migrate, openDatabase } = await import("../src/db.ts");
    const { applyKev, getVuln } = await import("../src/vulns.ts");
    const db = openDatabase(":memory:");
    migrate(db);
    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('product', 'fortinet', NULL, '2026-11-10')").run();
    applyKev(db, [
      { cveId: "CVE-2026-5000", dateAdded: "2026-11-09", dueDate: null, ransomware: false, description: "FortiOS flaw", vendor: "Fortinet", product: "FortiOS" },
      { cveId: "CVE-2026-5001", dateAdded: "2026-11-09", dueDate: null, ransomware: false, description: "Win32k flaw", vendor: "Microsoft", product: "Win32k" },
    ], "2026-11-10T00:00:00.000Z");
    expect(getVuln(db, "CVE-2026-5000")).toMatchObject({ watch_hit: 1, platforms_json: '["network"]' });
    expect(getVuln(db, "CVE-2026-5001")).toMatchObject({ watch_hit: 0, platforms_json: '["windows"]' });
    expect(db.prepare("SELECT platform FROM vuln_platforms vp JOIN vulns v ON v.id = vp.vuln_id WHERE v.cve_id = 'CVE-2026-5001'").all()).toEqual([{ platform: "windows" }]);
  });
});
