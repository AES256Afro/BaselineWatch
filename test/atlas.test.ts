import type { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { nistBaselinesAdapter, nistCatalogAdapter } from "../src/adapters/oscal-nist.ts";
import { expectedNext, familyHeatmap, releaseTimeline, velocity } from "../src/atlas.ts";
import type { HttpGet } from "../src/http.ts";
import { getSource, ingestDocumentTarget, ingestSource } from "../src/ingest.ts";
import { latestDocument } from "../src/register.ts";
import { fakeHttp, fixture, startTestApp, type TestApp } from "./helpers.ts";

const at = new Date("2026-10-15T07:00:00Z");

function nistHttp(): HttpGet {
  return async (url) => {
    let name: string;
    if (url.includes("_catalog.json")) name = url.includes("941c978d14") ? "oscal-catalog-5.1.1.json" : "oscal-catalog-5.2.0.json";
    else if (url.includes("baseline_profile.json")) name = url.includes("941c978d14") ? "oscal-profile-moderate-5.1.1.json" : "oscal-profile-moderate-5.2.0.json";
    else throw new Error(`no fixture for ${url}`);
    return { url, status: 200, notModified: false, bytes: fixture(name), etag: null, lastModified: null, contentType: "application/json" };
  };
}

async function loadNist(db: DatabaseSync, dataDir: string): Promise<void> {
  const http = nistHttp();
  const catalog = getSource(db, "nist-sp-800-53")!;
  for (const target of nistCatalogAdapter.history!(catalog)) await ingestDocumentTarget(db, dataDir, catalog, nistCatalogAdapter, target, { http, now: () => at });
  const baselines = getSource(db, "nist-sp-800-53b")!;
  for (const target of nistBaselinesAdapter.history!(baselines).filter((t) => t.key === "profile:moderate")) {
    await ingestDocumentTarget(db, dataDir, baselines, nistBaselinesAdapter, target, { http, now: () => at });
  }
}

describe("Atlas data", () => {
  let app: TestApp;
  afterEach(async () => {
    await app?.close();
  });

  it("lays releases on a timeline, maps changes by family, and says what is due", async () => {
    app = await startTestApp({ now: () => at });
    await loadNist(app.db, app.dataDir);
    const kev = getSource(app.db, "cisa-kev")!;
    await ingestSource(app.db, app.dataDir, kev, { http: fakeHttp({ [kev.url]: { bytes: fixture("kev.json") } }), now: () => at });

    const rows = releaseTimeline(app.db, "2023-01-01T00:00:00.000Z", at.toISOString());
    const catalogRow = rows.find((r) => r.sourceId === "nist-sp-800-53")!;
    expect(catalogRow.releases.map((r) => [r.version, r.first, r.changes > 0])).toEqual([
      ["5.1.1+u4", true, false],
      ["5.2.0", false, true],
    ]);
    expect(rows.find((r) => r.sourceId === "nist-sp-800-53b")?.releases).toHaveLength(2);

    const map = familyHeatmap(app.db);
    expect(map.families).toEqual(["AC", "SA", "SI"]);
    expect(map.rows).toHaveLength(2);
    expect(map.rows[0]?.first).toBe(true);
    expect(map.rows[1]?.counts.SA).toBeGreaterThanOrEqual(2); // SA-24 and SA-15(13) added
    expect(map.rows[1]?.counts.SI).toBeGreaterThanOrEqual(2);
    expect(map.rows[1]?.counts.AC ?? 0).toBe(0);
    expect(map.max).toBeGreaterThan(0);

    const v = velocity(app.db, "2024-01-01T00:00:00.000Z");
    expect(v.releases).toBe(2); // the 5.2.0 catalog and the 5.2.0 moderate profile
    expect(v.changedRequirements).toBeGreaterThanOrEqual(4);
    expect(v.kevAdditions).toBe(2); // two of the three fixture entries were added after 2024
    const due = expectedNext(app.db, at);
    expect(due.map((d) => d.what)).toEqual(expect.arrayContaining(["DISA quarterly STIG release", "NIST SP 800-53 patch release", "EPSS scores", "CISA KEV additions"]));
    expect(due.find((d) => d.what === "NIST SP 800-53 patch release")?.basis).toContain("last catalog change 2026-05-11");

    const atlas = await (await fetch(`${app.base}/atlas`)).text();
    expect(atlas).toContain("<svg");
    expect(atlas).toContain("NIST SP 800-53 (controls)");
    expect(atlas).toContain('class="dot changed"');
    expect(atlas).toContain("Expected next");
    expect(atlas).not.toMatch(/style="/);

    const today = await (await fetch(`${app.base}/today`)).text();
    expect(today).toContain("Needs you");
    expect(today).toContain("KEV additions");
    expect(today).toContain("Ahsay AhsayCBS");
    expect(today).toContain("NIST SP 800-53 (controls) 5.2.0");
    const week = await (await fetch(`${app.base}/today?since=168`)).text();
    expect(week).toContain('class="on" href="/today?since=168"');
    const latest = latestDocument(app.db, "nist-sp-800-53", "catalog")!;
    expect(today).toContain(`/standards/nist-sp-800-53/${latest.id}`);
  });
});
