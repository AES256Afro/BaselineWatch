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
      expect(page).toContain("<small>Republished (Chromium, Azure Linux)</small><b>4</b>");
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
      // A KB is searched as it is written, "KB" and all, which is what the placeholder and /search offer.
      for (const q of ["KB5127648", "kb%205127648"]) {
        const byKb = await (await fetch(`${app.base}/vulnerabilities/microsoft?q=${q}`)).text();
        expect(byKb, q).toContain("CVE-2026-100200");
        expect(byKb, q).not.toContain("No CVE in October 2026 matches");
      }
      expect((await fetch(`${app.base}/vulnerabilities/microsoft?release=2026-Zzz`)).status).toBe(404);
      expect((await fetch(`${app.base}/vulnerabilities/microsoft?release=nonsense`)).status).toBe(404);
    } finally {
      await app.close();
    }
  });

  it("gives each Windows release its own build, keeps KB-less fixes apart, and drops a release whose support has ended", async () => {
    let clock = now;
    const app = await startTestApp({ now: () => clock });
    try {
      await ingestSource(app.db, app.dataDir, getSource(app.db, "msrc")!, { http: fakeHttp(routes), now: () => now });
      const section = (page: string, id: string): string => page.slice(page.indexOf(`id="${id}"`), page.indexOf("</section>", page.indexOf(`id="${id}"`)));
      const line = (mine: string, label: string): string => /<li>[\s\S]*?<\/li>/.exec(mine.slice(mine.indexOf(`<li><b>${label}</b>`)))?.[0] ?? "";

      const october = await (await fetch(`${app.base}/vulnerabilities/microsoft`)).text();
      const mine = section(october, "mine");
      // KB5127648 is 10.0.26100.x on 24H2, 10.0.26200.x on 25H2 and 10.0.26300.x on 26H2.
      expect(line(mine, "Windows 11, version 24H2")).toContain("build 10.0.26100.9711");
      expect(line(mine, "Windows 11, version 25H2")).toContain("build 10.0.26200.9711");
      expect(line(mine, "Windows 11, version 25H2")).not.toContain("10.0.26100.9711");
      expect(line(mine, "Windows 11, version 26H2")).toContain("build 10.0.26300.9711");
      // In October 23H2's Enterprise and Education editions are still serviced.
      expect(line(mine, "Windows 11, version 23H2")).toContain("KB5126653");

      // By update: one line for KB5127648, each product with its own build; Office LTSC 2021 and
      // 2024 share Microsoft's release-notes address but are two updates at two builds.
      const updates = section(october, "updates").split("<tr").slice(2);
      const kb = updates.filter((r) => r.includes(">KB5127648</a>"));
      expect(kb).toHaveLength(1);
      expect(kb[0]).toContain('Windows 11 Version 25H2 <span class="small">10.0.26200.9711</span>');
      expect(kb[0]).not.toContain(" · 10.0.26100.9711");
      const ltsc2021 = updates.find((r) => r.includes("16.0.14334.20974"))!;
      expect(ltsc2021).toContain("Microsoft Office LTSC 2021");
      expect(ltsc2021).not.toContain("Microsoft Office LTSC 2024");
      expect(updates.find((r) => r.includes("16.0.17932.21056"))).toContain("Microsoft Office LTSC 2024");

      // The CVE table names each update once: KB5127648 was "KB5127648, KB5127648", Office's "Release Notes, Release Notes, Release Notes +1".
      const cves = section(october, "cves").split("<tr");
      const windowsRow = cves.find((r) => r.includes("CVE-2026-100200<"))!;
      expect(windowsRow.split(">KB5127648</a>")).toHaveLength(2);
      const officeRow = cves.find((r) => r.includes("CVE-2026-100210<"))!;
      // Microsoft 365's notes (linked under docs. and learn.microsoft.com, at four builds) are one
      // link; Office for Mac's are a different page and keep their own.
      expect(officeRow.split(">Release Notes</a>")).toHaveLength(3);
      expect(officeRow).toContain("release-notes-office-for-mac");
      expect(officeRow).not.toContain('<span class="small">+');

      // On 2026-11-16 23H2's last edition has ended (2026-11-10), whatever data/platforms.yaml's status says.
      clock = new Date("2026-11-16T09:00:00Z");
      const november = section(await (await fetch(`${app.base}/vulnerabilities/microsoft`)).text(), "mine");
      expect(november).not.toContain("Windows 11, version 23H2");
      expect(november).toContain("<b>Windows 11, version 24H2</b>");
    } finally {
      await app.close();
    }
  });
});
