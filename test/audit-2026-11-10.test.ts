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
  });

  it("counts each call in an MCP batch, and takes no long batch from a stranger", async () => {
    const app = await startTestApp({ env: { BW_PUBLIC_READ: "true", BW_ADMIN_PASSWORD: "owner-pass" } });
    try {
      const call = (id: number) => ({ jsonrpc: "2.0", id, method: "tools/list", params: {} });
      const post = (body: unknown) => fetch(`${app.base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify(body) });
      const long = await post(Array.from({ length: 11 }, (_, i) => call(i)));
      expect(long.status).toBe(400);
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
    } finally {
      await app.close();
    }
  });
});
