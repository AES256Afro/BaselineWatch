import { describe, expect, it } from "vitest";
import { gpoPathFromFix } from "../src/baselines.ts";
import { feedTitle } from "../src/newsource.ts";
import { alternateFeeds } from "../src/repairs.ts";
import { startTestApp } from "./helpers.ts";

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
});
