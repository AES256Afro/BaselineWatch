import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { listNetScans, scanTile } from "../src/scanhistory.ts";
import { startTestApp } from "./helpers.ts";

/** The scans over time (S6): the stored runs as a history, and Today's one figure for the area. */

const now = new Date("2026-10-21T22:00:00Z");

function seed(db: ReturnType<typeof openDatabase>): void {
  const scan = db.prepare("INSERT INTO net_scans (started_at, finished_at, resolver, resolver_source, upstream, doh, clients_seen, clients_source, changes_json, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)");
  const canary = db.prepare("INSERT INTO net_canaries (scan_id, category, source_id, name, outcome, answer) VALUES (?, ?, 'canary-ads', ?, ?, ?)");
  scan.run("2026-10-20T03:00:00.000Z", "2026-10-20T03:00:05.000Z", "192.168.1.1", "dhcp lease", null, "reachable", null, null, null);
  canary.run(1, "ads", "a.example", "sinkholed", "0.0.0.0");
  canary.run(1, "ads", "b.example", "sinkholed", "0.0.0.0");
  scan.run("2026-10-21T03:00:00.000Z", "2026-10-21T03:00:05.000Z", "192.168.1.1", "dhcp lease", "pi.hole", "blocked", 14, "pihole", JSON.stringify({ resolverChanged: null, newlyResolving: [{ category: "ads", name: "b.example" }], newlySinkholed: [] }));
  canary.run(2, "ads", "a.example", "sinkholed", "0.0.0.0");
  canary.run(2, "ads", "b.example", "resolved", "203.0.113.5");
  canary.run(2, "ads", "c.example", "timeout", null);
}

describe("the runs", () => {
  it("come newest first with their tallies and changes, and make Today's tile", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    expect(scanTile(db)).toEqual({ state: "na", figure: "—", text: "network check not run", href: "/scan/network" });
    seed(db);
    const runs = listNetScans(db);
    expect(runs.map((r) => [r.id, r.total, r.sinkholed, r.resolved, r.timeout])).toEqual([[2, 3, 1, 1, 1], [1, 2, 2, 0, 0]]);
    expect(runs[0]?.changes?.newlyResolving).toEqual([{ category: "ads", name: "b.example" }]);
    expect(runs[1]?.changes).toBeNull();
    expect(scanTile(db)).toEqual({ state: "warn", figure: "1/3", text: "1 canary resolved, 1 changed", href: "/scan/history" });
    db.close();
  });

  it("are the history page, the exposure runs for the owner alone, and the tile on Today", async () => {
    const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "x" }, now: () => now });
    try {
      seed(app.db);
      const page = await (await fetch(`${app.base}/scan/history`)).text();
      expect(page).toContain("Network check <span class=\"count\">2 run(s)</span>");
      expect(page).toContain("<b>1 newly resolving</b> (b.example)");
      expect(page).toContain("+1 silent");
      expect(page).toContain("theirs alone to see");
      expect(page).toContain('aria-current="page"><b>History</b>');
      const today = await (await fetch(`${app.base}/today`)).text();
      expect(today).toContain('<span><a href="/scan/history">Network check</a></span><b class="warn">1/3 · 1 canary resolved, 1 changed</b>');
    } finally {
      await app.close();
    }
  });
});
