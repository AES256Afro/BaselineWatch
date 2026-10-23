import type { DatabaseSync } from "node:sqlite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { guideArticles, guideBySlug } from "../src/pages/guides/index.ts";
import { startTestApp, type TestApp } from "./helpers.ts";

/**
 * A guide article (/guide/<slug>): the owner's prose about one subject, with the CVEs it names read
 * from this instance's own table on every request. The point of the wiring is that the page stops
 * saying "nothing published yet" by itself once a patch reference arrives, so that is what these
 * check — the prose is the owner's business, the figures are the pipeline's.
 */

const now = new Date("2026-10-22T14:00:00Z");
const cve = "CVE-2026-102785";
const other = "CVE-2026-112832";

let app: TestApp;
let db: DatabaseSync;

beforeAll(async () => {
  app = await startTestApp({ now: () => now });
  db = app.db;
  // The 10.0 as the table holds it on the day it broke: scored, no EPSS, not in KEV, nothing fixed.
  db.prepare(
    `INSERT INTO vulns (cve_id, last_modified_at, published_at, description, cvss_version, cvss_score, cvss_severity, cvss_vector, kev, first_seen_at, last_seen_at)
     VALUES (?, ?, ?, ?, '4.0', 10.0, 'CRITICAL', 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/E:A', 0, ?, ?)`,
  ).run(cve, now.toISOString(), now.toISOString(), "Unauthenticated remote code execution in a Joomla template's image handler.", now.toISOString(), now.toISOString());
});
afterAll(async () => {
  await app.close();
});

describe("the article registry", () => {
  it("gives every article a unique slug, a description and sections with unique anchors", () => {
    const slugs = guideArticles.map((a) => a.slug);
    expect(new Set(slugs).size, "duplicate slug").toBe(slugs.length);
    for (const a of guideArticles) {
      expect(a.slug, `${a.slug} is a permanent address`).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/);
      expect(a.title.length).toBeGreaterThan(5);
      expect(a.description.length, `${a.slug} description`).toBeGreaterThan(30);
      expect(a.written, `${a.slug} written`).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(a.sections.length, `${a.slug} sections`).toBeGreaterThan(0);
      const ids = a.sections.map((s) => s.id);
      expect(new Set(ids).size, `${a.slug} duplicate section id`).toBe(ids.length);
      for (const id of ids) expect(id).toMatch(/^[a-z0-9-]+$/);
      // An article's CVEs are read from the table, so they must be real ids, not prose.
      for (const c of a.cves) expect(c, `${a.slug} cve`).toMatch(/^CVE-\d{4}-\d{4,}$/);
    }
    expect(guideBySlug("php-applications")).toBeDefined();
    expect(guideBySlug("nothing-like-this")).toBeUndefined();
  });

  it("names the PHP cluster for what it is rather than what it is being called", () => {
    const a = guideBySlug("php-applications")!;
    expect(a.cves).toEqual([cve, other]);
    const prose = a.standfirst.value + a.sections.map((s) => `${s.heading} ${s.body.value}`).join(" ");
    expect(prose).toContain("It is not a flaw in PHP");
    expect(prose).toContain("neither is a flaw in PHP");
    expect(prose).toContain("Joomla");
    expect(prose).toContain("WordPress");
    // The correction that saves a reader the wasted hour.
    expect(prose).toContain("php -v");
  });
});

describe("the article page", () => {
  it("renders the prose and every section, with the sidebar and the limits", async () => {
    const response = await fetch(`${app.base}/guide/php-applications`);
    expect(response.status).toBe(200);
    const page = await response.text();
    expect(page).toContain("it is not PHP");
    expect(page).toContain('id="what-is-known"');
    for (const s of guideBySlug("php-applications")!.sections) {
      expect(page, `section ${s.id}`).toContain(`id="${s.id}"`);
      expect(page, `heading ${s.id}`).toContain(s.heading);
    }
    // The honesty block, which is the reason the page is safe to publish at all.
    expect(page).toContain("No web page can see what your servers run");
    expect(page).toContain("What this page cannot tell you");
    expect(page).toContain('href="/learn"');
  });

  it("reads the CVEs from the table, not from the prose", async () => {
    const page = await (await fetch(`${app.base}/guide/php-applications`)).text();
    // Scored and critical, from the row seeded above.
    expect(page).toContain("10.0");
    expect(page).toContain("CRITICAL");
    expect(page).toContain("CVSS 4.0");
    expect(page).toContain("no EPSS yet");
    expect(page).toContain("not in KEV");
    // No patch reference on the row, so the page says so rather than implying a fix exists.
    expect(page).toContain("Nothing published yet");
    // The second CVE was never ingested, and the page says that rather than inventing it.
    expect(page).toContain("Not in this instance's table yet");
  });

  it("stops saying nothing is published the moment a patch reference lands", async () => {
    db.prepare("UPDATE vulns SET references_json = ? WHERE cve_id = ?").run(
      JSON.stringify([{ url: "https://example.invalid/advisory", tags: ["Vendor Advisory"] }]),
      cve,
    );
    const page = await (await fetch(`${app.base}/guide/php-applications`)).text();
    expect(page).toContain(`href="/vulnerabilities/${cve}#fix"`);
    expect(page).toContain("1 reference(s)");
    // The prose did not change; the table did.
    expect(page).toContain("it is not PHP");
  });

  it("is linked from the guide and the sitemap, and an unknown slug is a 404", async () => {
    const guide = await (await fetch(`${app.base}/guide`)).text();
    expect(guide).toContain('href="/guide/php-applications"');
    expect(guide).toContain("Articles, one subject at a time");

    const sitemap = await (await fetch(`${app.base}/sitemap.xml`)).text();
    expect(sitemap).toContain("/guide/php-applications</loc>");

    expect((await fetch(`${app.base}/guide/no-such-article`)).status).toBe(404);
  });
});
