import { describe, expect, it } from "vitest";
import { msrcApi } from "../src/adapters/msrc.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { msrcReleases, releaseName } from "../src/msrc.ts";
import { fakeHttp, fixture, startTestApp } from "./helpers.ts";

/** The Patch Tuesday page (N6): Microsoft's month by update and product, from the rows the MSRC adapter keeps. */

const now = new Date("2026-10-21T22:00:00Z");
const routes = { [`${msrcApi}/updates`]: { bytes: fixture("msrc/updates.json") }, [`${msrcApi}/cvrf/2026-Oct`]: { bytes: fixture("msrc/2026-Oct.json") } };

describe("the page", () => {
  it("says so before anything has been read", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      const page = await (await fetch(`${app.base}/vulnerabilities/microsoft`)).text();
      expect(page).toContain("Nothing read yet from the Security Update Guide");
      expect(page).toContain('aria-current="page"><b>Patch Tuesday</b>');
    } finally {
      await app.close();
    }
  });

  it("lays the month out by update and product, the fleet first, and filters the CVEs", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      const db = app.db;
      await ingestSource(db, app.dataDir, getSource(db, "msrc")!, { http: fakeHttp(routes), now: () => now });
      db.prepare("INSERT INTO vulns (cve_id, last_modified_at, first_seen_at, last_seen_at) VALUES ('CVE-2026-100200', ?, ?, ?)").run(now.toISOString(), now.toISOString(), now.toISOString());
      expect(msrcReleases(db).map((r) => [r.release_id, r.microsoft, r.critical, r.exploited, r.disclosed, r.total])).toEqual([["2026-Oct", 15, 5, 1, 2, 19]]);
      expect(releaseName("2026-Oct")).toBe("October 2026");

      const page = await (await fetch(`${app.base}/vulnerabilities/microsoft`)).text();
      expect(page).toContain("Patch Tuesday · October 2026");
      expect(page).toContain("<small>Microsoft CVEs</small><b>15</b>");
      expect(page).toContain("<small>Exploited</small><b>1</b>");
      expect(page).toContain("<small>Republished</small><b>4</b>");
      // The fleet's Windows 11 24H2 finds its month's KB.
      expect(page).toContain("Your Windows releases");
      expect(page).toContain("<b>Windows 11, version 24H2</b>");
      expect(page).toContain('href="https://support.microsoft.com/help/5127648" target="_blank" rel="noopener">KB5127648</a>');
      // A CVE in the table links to its page; one not yet there does not.
      expect(page).toContain('<a href="/vulnerabilities/CVE-2026-100200">CVE-2026-100200</a>');
      expect(page).toContain("<span title=\"Not in this instance's table yet\">CVE-2026-96951</span><span class=\"chip kev\">exploited</span>");
      // Republished rows are left out until asked for.
      expect(page).not.toContain("(Chrome)");
      const all = await (await fetch(`${app.base}/vulnerabilities/microsoft?all=1`)).text();
      expect(all).toContain("(Chrome)");
      const narrowed = await (await fetch(`${app.base}/vulnerabilities/microsoft?family=Windows%20Update%20Service`)).text();
      expect(narrowed).toContain("CVE-2026-100200");
      expect(narrowed).not.toContain("CVE-2026-96951");
      const searched = await (await fetch(`${app.base}/vulnerabilities/microsoft?q=5127648`)).text();
      expect(searched).toContain("CVE-2026-100200");
      expect((await fetch(`${app.base}/vulnerabilities/microsoft?release=2026-Zzz`)).status).toBe(404);
      expect((await fetch(`${app.base}/vulnerabilities/microsoft?release=nonsense`)).status).toBe(404);
    } finally {
      await app.close();
    }
  });
});
