import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cisaDirectivesAdapter, directiveItem, parseDirectivesPage } from "../src/adapters/cisa-directives.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { recentAlerts } from "../src/notify.ts";
import { directivePlatforms, directivesForPlatform } from "../src/stigs.ts";
import { fakeHttp, fixture } from "./helpers.ts";

const text = (name: string) => new TextDecoder().decode(fixture(name));

describe("CISA directives listing", () => {
  it("reads each teaser's date, kind, title and link, and the total", () => {
    const page = parseDirectivesPage(text("cisa-directives/all-page0.html"));
    expect(page.total).toBe(27);
    expect(page.directives).toHaveLength(10);
    const guidance = page.directives[0]!;
    expect(guidance).toMatchObject({
      slug: "bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk",
      url: "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk",
      title: "BOD 26-04: Implementation Guidance for Prioritizing Security Updates Based on Risk",
      kind: "bod",
      code: "BOD 26-04",
      supplemental: true,
      publishedAt: "2026-06-10T12:00:00.000Z",
    });
    const bod = page.directives[1]!;
    expect(bod).toMatchObject({ title: "BOD 26-04: Prioritizing Security Updates Based on Risk", supplemental: false, kind: "bod" });
    const revision = page.directives.find((d) => d.title.startsWith("V1: ED 25-03"))!;
    expect(revision).toMatchObject({ kind: "ed", code: "ED 25-03", supplemental: true });
    const ed = page.directives.find((d) => d.title === "ED 26-01: Mitigate Vulnerabilities in F5 Devices")!;
    expect(ed).toMatchObject({ kind: "ed", code: "ED 26-01", supplemental: false, publishedAt: "2025-10-15T12:00:00.000Z" });
    const last = parseDirectivesPage(text("cisa-directives/all-page2.html"));
    expect(last.directives).toHaveLength(7);
    expect(last.directives[6]!.title).toBe("Homeland Security Presidential Directive 7");
    expect(parseDirectivesPage("<html></html>")).toEqual({ directives: [], total: null });
  });

  it("tags a directive with the platforms its title names", () => {
    expect(directivePlatforms("ED 26-03: Mitigate Vulnerabilities in Cisco SD-WAN Systems")).toEqual(["network"]);
    expect(directivePlatforms("ED 25-02: Mitigate Microsoft Exchange Vulnerability")).toEqual(["windows"]);
    expect(directivePlatforms("ED 26-01: Mitigate Vulnerabilities in F5 Devices")).toEqual(["network"]);
    expect(directivePlatforms("BOD 26-02: Mitigating Risk From End-of-Support Edge Devices")).toEqual(["network"]);
    expect(directivePlatforms("BOD 26-04: Prioritizing Security Updates Based on Risk")).toEqual(["all"]);
    expect(directivePlatforms("BOD 25-01: Implementing Secure Practices for Cloud Services")).toEqual(["all"]);
    const item = directiveItem({ slug: "x", url: "https://www.cisa.gov/news-events/directives/x", title: "ED 25-02: Mitigate Microsoft Exchange Vulnerability", kind: "ed", code: "ED 25-02", supplemental: false, publishedAt: "2025-08-07T12:00:00.000Z" });
    expect(item.summary).toBe("Emergency Directive, 2025-08-07. Platforms named: windows.");
    expect(item.signals).toMatchObject({ directive: "ED 25-02", directiveKind: "ed", platforms: ["windows"] });
  });
});

describe("CISA directives adapter end to end", () => {
  let db: ReturnType<typeof openDatabase>;
  let dataDir = "";
  beforeEach(() => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-cisa-dir-"));
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("walks the pages, stores every directive once, snapshots the pages, and alerts only on a later addition", async () => {
    const source = getSource(db, "cisa-directives")!;
    expect(source.group_name).toBe("news");
    const http = fakeHttp({
      [source.url]: { bytes: fixture("cisa-directives/all-page0.html"), contentType: "text/html" },
      [`${source.url}?page=1`]: { bytes: fixture("cisa-directives/all-page1.html"), contentType: "text/html" },
      [`${source.url}?page=2`]: { bytes: fixture("cisa-directives/all-page2.html"), contentType: "text/html" },
    });
    const at = new Date("2026-10-17T10:00:00Z");
    const first = await ingestSource(db, dataDir, source, { http, now: () => at });
    expect(first.status).toBe("ok");
    expect(first.inserted).toBe(27);
    expect(first.detail).toBe("27 directive(s) over 3 page(s)");
    expect(http.calls).toHaveLength(3);
    expect((db.prepare("SELECT COUNT(*) AS n FROM snapshots WHERE source_id = 'cisa-directives'").get() as { n: number }).n).toBe(3);
    expect(recentAlerts(db)).toHaveLength(0); // a first fetch is a back catalogue

    const network = directivesForPlatform(db, "network");
    expect(network.map((d) => d.code)).toEqual(expect.arrayContaining(["ED 26-03", "ED 25-03", "ED 26-01", "BOD 26-02"]));
    const mac = directivesForPlatform(db, "macos");
    expect(mac.every((d) => d.platforms.includes("all"))).toBe(true);
    expect(mac.some((d) => /Cisco/.test(d.title))).toBe(false);
    expect(mac.map((d) => d.code)).toContain("BOD 26-04");

    // The scheduler re-reads a source before each fetch, so its fetch count is current.
    const second = await ingestSource(db, dataDir, getSource(db, "cisa-directives")!, { http, now: () => new Date("2026-10-18T10:00:00Z") });
    expect(second.status).toBe("ok");
    expect(second.inserted).toBe(0);
    expect(second.updated).toBe(0);

    // A directive that was not there last time is news.
    db.prepare("DELETE FROM items WHERE source_id = 'cisa-directives' AND external_id = 'ed-26-01-mitigate-vulnerabilities-f5-devices'").run();
    const third = await ingestSource(db, dataDir, getSource(db, "cisa-directives")!, { http, now: () => new Date("2026-10-19T10:00:00Z") });
    expect(third.inserted).toBe(1);
    const alerts = recentAlerts(db);
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ kind: "directive", title: "CISA directive: ED 26-01: Mitigate Vulnerabilities in F5 Devices", status: "unconfigured" });
    expect(cisaDirectivesAdapter.id).toBe("cisa-directives");
  });
});
