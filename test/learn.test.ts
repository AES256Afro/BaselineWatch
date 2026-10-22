import type { DatabaseSync } from "node:sqlite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  accessLabels,
  ancestors,
  authorities,
  authorityById,
  authorityForSource,
  chains,
  collisions,
  feedsInto,
  onRung,
  peers,
  rungs,
  sectors,
} from "../src/authorities.ts";
import { startTestApp, type TestApp } from "./helpers.ts";

/**
 * Learn (/learn): where a rule comes from. The registry is committed knowledge, so the invariants
 * below are the only thing standing between a typo and a page that teaches something false — every
 * derivation must resolve, every address must be a real https link with its access stated, and
 * every source it claims to track must be a source this instance actually has.
 */

const now = new Date("2026-10-22T09:00:00Z");

let app: TestApp;
let db: DatabaseSync;

beforeAll(async () => {
  app = await startTestApp({ now: () => now });
  db = app.db;
  // One catalogue version, so the body card and the standard's page can show what is held.
  const snapshot = db
    .prepare("INSERT INTO snapshots (source_id, document_key, sha256, bytes, blob_path, fetched_at) VALUES ('nist-sp-800-53', 'catalog', 'abc', 10, 'p', ?)")
    .run(now.toISOString());
  db.prepare(
    "INSERT INTO documents (source_id, document_key, snapshot_id, version_label, title, published_at, parsed_at, requirement_count) VALUES ('nist-sp-800-53', 'catalog', ?, 'Release 5.2.0', 'NIST SP 800-53', ?, ?, 1)",
  ).run(Number(snapshot.lastInsertRowid), now.toISOString(), now.toISOString());
});
afterAll(async () => {
  await app.close();
});

describe("the authority registry", () => {
  it("gives every body an id of its own, a publisher, a rung and an audience", () => {
    const ids = authorities.map((a) => a.id);
    expect(new Set(ids).size, "duplicate id").toBe(ids.length);
    for (const a of authorities) {
      expect(a.name.length, a.id).toBeGreaterThan(1);
      expect(a.publisher.length, `${a.id} publisher`).toBeGreaterThan(2);
      expect(rungs.some((r) => r.id === a.rung), `${a.id} rung`).toBe(true);
      expect(a.sectors.length, `${a.id} has no audience`).toBeGreaterThan(0);
      for (const s of a.sectors) expect(sectors.some((k) => k.id === s), `${a.id} sector ${s}`).toBe(true);
      // Both sentences are load-bearing on the page: what it is, and why it exists.
      expect(a.what.endsWith("."), `${a.id} what`).toBe(true);
      expect(a.because.length, `${a.id} because`).toBeGreaterThan(20);
    }
  });

  it("resolves every derivation, and nothing derives from itself", () => {
    for (const a of authorities) {
      for (const parent of a.derivesFrom) {
        expect(authorityById(parent), `${a.id} derives from unknown ${parent}`).toBeDefined();
        expect(parent, `${a.id} derives from itself`).not.toBe(a.id);
      }
      // A cycle would make ancestors() lie rather than hang, so the assertion is on the result.
      expect(ancestors(a.id).map((p) => p.id), `${a.id} is its own ancestor`).not.toContain(a.id);
    }
  });

  it("walks the chain upwards: a STIG rule reaches the catalogue, FIPS and the statute", () => {
    const up = ancestors("disa-stig").map((a) => a.id);
    expect(up).toContain("disa-srg");
    expect(up).toContain("sp-800-53");
    expect(up).toContain("fips-199-200");
    expect(up).toContain("fisma");
    // And downwards: the packages that reshape a STIG derive from it.
    expect(feedsInto("disa-stig").map((a) => a.id)).toEqual(expect.arrayContaining(["disa-gpo", "disa-intune", "nasa-ascs", "mscp"]));
    // The catalogue is the most derived-from document here; that is the point of the page.
    expect(feedsInto("sp-800-53").length).toBeGreaterThan(5);
  });

  it("gives every address an https link and an access level, and nothing else", () => {
    for (const a of authorities) {
      expect(a.links.length, `${a.id} has no address`).toBeGreaterThan(0);
      for (const l of a.links) {
        expect(l.href, `${a.id}: ${l.label}`).toMatch(/^https:\/\//);
        expect(accessLabels[l.access], `${a.id}: ${l.label} access`).toBeDefined();
        expect(l.label.length, `${a.id}: a label`).toBeGreaterThan(2);
      }
    }
    for (const c of collisions) {
      expect(c.readings.length, `${c.name} needs more than one reading to collide`).toBeGreaterThan(1);
      for (const r of c.readings) expect(r.href).toMatch(/^https:\/\//);
    }
  });

  it("fills every rung and every audience, so no column of the matrix is empty", () => {
    for (const r of rungs) expect(onRung(r.id).length, `rung ${r.id} is empty`).toBeGreaterThan(0);
    for (const s of sectors) expect(authorities.filter((a) => a.sectors.includes(s.id)).length, `sector ${s.id} is empty`).toBeGreaterThan(0);
    // Peers are the other answers to the same job, which is what the "check which" filter is for.
    expect(peers("sp-800-53").map((a) => a.id)).toContain("sp-800-171");
    expect(peers("sp-800-53").map((a) => a.id)).not.toContain("sp-800-53");
  });

  it("traces the same control down three ladders, in rung order, through bodies that exist", () => {
    expect(chains.map((c) => c.id)).toEqual(["federal", "dod", "business"]);
    const order = rungs.map((r) => r.id);
    for (const chain of chains) {
      expect(chain.steps.map((s) => s.rung), `${chain.id} steps`).toEqual(order);
      for (const step of chain.steps) {
        if (step.authority) expect(authorityById(step.authority), `${chain.id}: unknown ${step.authority}`).toBeDefined();
        expect(step.says.length, `${chain.id} ${step.rung}`).toBeGreaterThan(20);
      }
    }
    // The private chain is the one with a hole in it, and that hole is the lesson.
    const business = chains.find((c) => c.id === "business")!;
    expect(business.steps.find((s) => s.rung === "policy")?.authority).toBeUndefined();
  });

  it("tracks only sources this instance actually has", () => {
    const known = new Set((db.prepare("SELECT id FROM sources").all() as { id: string }[]).map((r) => r.id));
    for (const a of authorities) {
      if (a.tracked) expect(known.has(a.tracked), `${a.id} tracks unknown source ${a.tracked}`).toBe(true);
    }
    expect(authorityForSource("disa-stigs")?.id).toBe("disa-stig");
    expect(authorityForSource("nothing-like-this")).toBeUndefined();
  });
});

describe("the Learn page", () => {
  it("draws the chain, the matrix, the traces and every body", async () => {
    const response = await fetch(`${app.base}/learn`);
    expect(response.status).toBe(200);
    const page = await response.text();
    expect(page).toContain("<h1>Learn: where a rule comes from</h1>");
    // The picture, with the chain spelled out for a reader who cannot see it.
    expect(page).toContain('aria-label="The chain a rule travels down: Law and contract → Policy → Framework → Control catalogue → Baseline → Configuration setting → Check and evidence"');
    for (const r of rungs) {
      expect(page, `rung ${r.id}`).toContain(`href="/learn?rung=${r.id}"`);
      expect(page, `rung ${r.id} line`).toContain(r.line);
    }
    for (const a of authorities) expect(page, `body ${a.id}`).toContain(`id="body-${a.id}"`);
    // Each of the three traces, and the control they all carry.
    for (const c of chains) expect(page).toContain(`id="trace-${c.id}"`);
    expect(page).toContain("AC-11 Device Lock");
    expect(page).toContain("3.1.10");
    // The four normalising mechanisms, and the names that collide.
    expect(page).toContain('id="normalised"');
    expect(page).toContain("Control Correlation Identifiers");
    expect(page).toContain('id="names"');
    expect(page).toContain("Foreign Intelligence Surveillance Act");
    expect(page).toContain("Center for Security and Emerging Technology");
    // Public knowledge of where a document lives, said plainly, with the access marked.
    expect(page).toContain('<span class="chip acc-agency"');
    expect(page).toContain("https://cset.nasa.gov");
    expect(page).toContain("NASA sign-in; the specifications themselves are internal");
  });

  it("shows what this instance holds beside the publisher's own address", async () => {
    const page = await (await fetch(`${app.base}/learn`)).text();
    expect(page).toContain("On this instance");
    expect(page).toContain("Release 5.2.0");
    expect(page).toContain('href="/standards/nist-sp-800-53">every version and what changed</a>');
    // A tracked source with nothing loaded says so rather than standing empty.
    expect(page).toContain("nothing loaded yet");
  });

  it("narrows to one audience, keeping that audience's bodies and dropping the others", async () => {
    const dod = await (await fetch(`${app.base}/learn?sector=us-dod`)).text();
    expect(dod).toContain("DISA STIGs");
    expect(dod).toContain("CNSSI 1253");
    expect(dod).not.toContain('id="body-e8"');
    expect(dod).not.toContain('id="body-ncsc-caf"');
    expect(dod).toContain("writing for US defense");
    // The picture counts what is shown, or it contradicts the page under it.
    const all = await (await fetch(`${app.base}/learn`)).text();
    expect(all).toContain(`>${onRung("setting").length} publishers</text>`);
    expect(dod).toContain(`>${onRung("setting", "us-dod").length} publishers</text>`);
    // Only the DoD trace, and only the DoD column.
    expect(dod).toContain('id="trace-dod"');
    expect(dod).not.toContain('id="trace-business"');
    expect(dod).not.toContain("Private business</a><small>");
  });

  it("narrows to one step of the chain", async () => {
    const page = await (await fetch(`${app.base}/learn?rung=catalog`)).text();
    expect(page).toContain('id="body-sp-800-53"');
    expect(page).toContain('id="body-sp-800-171"');
    expect(page).not.toContain('id="body-disa-stig"');
    expect(page).toContain("at the Control catalogue step");
  });

  it("says so when a combination has nobody in it, and ignores a filter it does not know", async () => {
    const empty = await (await fetch(`${app.base}/learn?sector=international&rung=law`)).text();
    expect(empty).toContain("Nothing at that combination.");
    expect(empty).toContain("No publisher on this page writes at the Law and contract step for Outside the US");

    // A made-up filter is not an error page: the reader gets everything.
    const bogus = await (await fetch(`${app.base}/learn?sector=atlantis&rung=sideways`)).text();
    expect(bogus).toContain(`All <b>${authorities.length}</b> publishers`);
    expect(bogus).toContain('id="body-fisma"');
  });

  it("sits in the Standards menu with the line that says what it is, and in the sitemap", async () => {
    const page = await (await fetch(`${app.base}/learn`)).text();
    const menu = page.slice(page.indexOf("<summary>Standards</summary>"), page.indexOf("</details>", page.indexOf("<summary>Standards</summary>")));
    expect(menu).toContain("Where it all comes from");
    expect(menu).toContain('aria-current="page"><b>Learn</b><small>where every rule comes from, and who derived it from whom</small>');
    // The three rungs still lead, and Learn comes after the tools that cut across them.
    expect(menu.indexOf("<b>Controls</b>")).toBeLessThan(menu.indexOf("<b>STIGs</b>"));
    expect(menu.indexOf("<b>Atlas</b>")).toBeLessThan(menu.indexOf("<b>Learn</b>"));

    const sitemap = await (await fetch(`${app.base}/sitemap.xml`)).text();
    expect(sitemap).toContain("/learn</loc>");
  });
});

describe("a standard's own page", () => {
  it("says who published it, what it rests on, and who else answers the same step", async () => {
    const page = await (await fetch(`${app.base}/standards/nist-sp-800-53`)).text();
    expect(page).toContain("Where this comes from");
    expect(page).toContain("Published by <b>NIST</b>");
    expect(page).toContain('href="/learn?rung=catalog"');
    // Up the chain, down the chain, and sideways to the other bodies at this rung.
    expect(page).toContain('href="/learn?rung=law#body-fisma"');
    expect(page).toContain('href="/learn?rung=baseline#body-sp-800-53b"');
    expect(page).toContain("The same step, another body");
    expect(page).toContain('href="/learn?rung=catalog#body-sp-800-171"');
    // And the publisher's own address, with what it takes to read it.
    expect(page).toContain("https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final");
    expect(page).toContain('<span class="chip acc-public"');
  });

  it("draws nothing on a source the registry does not know", async () => {
    const page = await (await fetch(`${app.base}/standards/cisa-kev`)).text();
    expect(page).not.toContain("Where this comes from");
  });
});

describe("the catalogue and the guide point at it", () => {
  it("send a reader from All standards and the guide to the chain", async () => {
    const catalog = await (await fetch(`${app.base}/standards`)).text();
    expect(catalog).toContain('<a href="/learn">Learn</a> draws the whole chain');
    expect(catalog).toContain('href="/learn#body-sp-800-53">where it comes from</a>');

    const guide = await (await fetch(`${app.base}/guide`)).text();
    expect(guide).toContain("Where the rulebook itself came from");
    expect(guide).toContain('<a href="/learn">Learn</a> draws that whole chain');
  });
});
