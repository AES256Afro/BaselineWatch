import type { DatabaseSync } from "node:sqlite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fleetPlatformKeys, nextActions, platformBreakdown } from "../src/agenda.ts";
import { loadFleet } from "../src/fleet.ts";
import { startTestApp, type TestApp } from "./helpers.ts";

/**
 * The ladder the menus are built from (M17): a standard is the rulebook, a baseline picks its
 * rules for a kind of system, a control is one rule, a setting is how it is enforced. The guide
 * teaches it, the Standards menu is those three words in that order, and Today opens on what to
 * do next with the window's CVEs grouped by the platform they affect.
 */

const now = new Date("2026-10-21T09:00:00Z");
const ago = (hours: number): string => new Date(now.getTime() - hours * 3_600_000).toISOString();

let app: TestApp;
let db: DatabaseSync;

/** One standard with one version and two controls, which is all the Controls page needs to draw. */
function seedStandard(): void {
  const snapshot = db
    .prepare("INSERT INTO snapshots (source_id, document_key, sha256, bytes, blob_path, fetched_at) VALUES ('nist-sp-800-53', 'catalog', 'abc', 10, 'p', ?)")
    .run(ago(48));
  const doc = db
    .prepare("INSERT INTO documents (source_id, document_key, snapshot_id, version_label, title, published_at, parsed_at, requirement_count) VALUES ('nist-sp-800-53', 'catalog', ?, 'Release 5.2.0', 'NIST SP 800-53', ?, ?, 2)")
    .run(Number(snapshot.lastInsertRowid), ago(48), ago(48));
  const requirement = db.prepare(
    "INSERT INTO requirements (document_id, ref, family, title, statement) VALUES (?, ?, ?, ?, ?)",
  );
  requirement.run(Number(doc.lastInsertRowid), "ia-2", "IA", "Identification and Authentication (Organizational Users)", "Uniquely identify and authenticate organizational users and associate that unique identification with processes.");
  requirement.run(Number(doc.lastInsertRowid), "ac-11", "AC", "Device Lock", "Prevent further access to the system by initiating a device lock after a period of inactivity.");
}

beforeAll(async () => {
  app = await startTestApp({ now: () => now });
  db = app.db;
  seedStandard();
});
afterAll(async () => {
  await app.close();
});

describe("the ladder, in the documentation", () => {
  it("teaches the four words, with a worked example and where an agency's own layer fits", async () => {
    const guide = await (await fetch(`${app.base}/guide`)).text();
    expect(guide).toContain('id="ladder"');
    expect(guide).toContain("Standard, baseline, control, setting");
    for (const [word, line] of [
      ["Standard", "the rulebook"],
      ["Baseline", "the set of rules chosen for your kind of system"],
      ["Control", "one specific rule in that set"],
      ["Configuration setting", "how the control is enforced on a device or service"],
    ]) {
      expect(guide).toContain(`<b>${word}</b> <span class="rung">${line}</span>`);
    }
    // The house and the federal system are the same ladder twice, which is how the note put it.
    expect(guide).toContain("A house");
    expect(guide).toContain("IA-2, multi-factor authentication");
    expect(guide).toContain("Intune requires a PIV-derived certificate");
    // NASA's own specifications are internal; the public layer is what this site can track.
    expect(guide).toContain("Cybersecurity Standards and Engineering Team");
    expect(guide).toContain('href="/standards/nasa-cyber-ref"');
  });

  it("is what the Standards menu says, in the same order", async () => {
    const page = await (await fetch(`${app.base}/today`)).text();
    const menu = page.slice(page.indexOf("<summary>Standards</summary>"), page.indexOf("</details>", page.indexOf("<summary>Standards</summary>")));
    expect(menu).toContain('href="/guide#ladder"');
    expect(menu.indexOf("<b>Standards</b>")).toBeLessThan(menu.indexOf("<b>Baselines</b>"));
    expect(menu.indexOf("<b>Baselines</b>")).toBeLessThan(menu.indexOf("<b>Controls</b>"));
    // The tools that cut across the ladder sit under a rule, after the three rungs.
    expect(menu.indexOf("<b>Controls</b>")).toBeLessThan(menu.indexOf("<hr>"));
    expect(menu.indexOf("<hr>")).toBeLessThan(menu.indexOf("<b>STIGs</b>"));
    expect(menu).toContain("<b>Change register</b>");
  });

  it("puts the fleet, the instance and the appearance on the Desk, each with its line", async () => {
    const page = await (await fetch(`${app.base}/today`)).text();
    const desk = page.slice(page.indexOf("<summary>Desk</summary>"));
    expect(desk).toContain("<b>Fleet</b><small>your releases and the hardware they run on</small>");
    expect(desk).toContain("<b>Appearance</b><small>the look and the colour scheme</small>");
    expect(desk).toContain("<b>Branding</b>");
    expect(desk).toContain("Your fleet and your work");
    expect(desk).toContain("This instance");
    expect(desk).toContain("How it is drawn");
  });
});

describe("the Controls page", () => {
  it("opens on what a control is, lists each standard's current version, and leads to the register", async () => {
    const page = await (await fetch(`${app.base}/controls`)).text();
    expect(page).toContain("<h1>Controls");
    expect(page).toContain('href="/guide#ladder"');
    expect(page).toContain("NIST SP 800-53");
    expect(page).toContain("Release 5.2.0");
    expect(page).toContain('href="/standards/nist-sp-800-53/');
    expect(page).toContain('<h2><a href="/register">What changed</a></h2>');
    expect(page).toContain('aria-current="page"><b>Controls</b>');
  });

  it("searches every standard's current version by label, title or text", async () => {
    const byLabel = await (await fetch(`${app.base}/controls?q=ia-2`)).text();
    expect(byLabel).toContain("IA-2");
    expect(byLabel).toContain("Identification and Authentication");
    expect(byLabel).not.toContain("Device Lock");

    const byWords = await (await fetch(`${app.base}/controls?q=device%20lock`)).text();
    expect(byWords).toContain("AC-11");

    const byText = await (await fetch(`${app.base}/controls?q=period%20of%20inactivity`)).text();
    expect(byText).toContain("AC-11");

    const nothing = await (await fetch(`${app.base}/controls?q=zzzz`)).text();
    expect(nothing).toContain("Nothing matches");
  });
});

describe("Appearance, on the Desk", () => {
  it("carries the switch the masthead used to, and says what each choice is", async () => {
    const page = await (await fetch(`${app.base}/appearance`)).text();
    expect(page).toContain("<h1>Appearance</h1>");
    expect(page).toContain('class="look-group" aria-label="Colours"');
    expect(page).toContain('class="look-group" aria-label="Look"');
    expect(page).toContain("follows the device's own light or dark setting");
    // The cookies are this browser's, not an account's, and the page says so.
    expect(page).toContain("two cookies on this device alone");
    expect(page).toContain('href="/branding"');
  });
});

describe("what to do next", () => {
  it("ranks a promise already made above exploitation, and exploitation above what merely moved", () => {
    const item = db.prepare("INSERT INTO items (source_id, kind, external_id, title, published_at, fetched_at) VALUES (?, ?, ?, ?, ?, ?)");
    const kevMine = Number(item.run("cisa-kev", "kev", "CVE-2026-100", "Vendor Thing: remote code execution", ago(3), ago(3)).lastInsertRowid);
    const kevOther = Number(item.run("cisa-kev", "kev", "CVE-2026-200", "Other Thing: privilege escalation", ago(2), ago(2)).lastInsertRowid);
    const overdue = Number(item.run("cisa-kev", "kev", "CVE-2026-300", "Older Thing: bypass", ago(80), ago(80)).lastInsertRowid);
    db.prepare("INSERT INTO vulns (cve_id, last_modified_at, kev, kev_due_date, watch_hit, watch_labels_json, platforms_json, cvss_score, first_seen_at, last_seen_at) VALUES ('CVE-2026-100', ?, 1, '2026-11-01', 1, '[\"windows\"]', '[\"windows\"]', 9.8, ?, ?)").run(ago(3), ago(3), ago(3));
    db.prepare("INSERT INTO vulns (cve_id, last_modified_at, kev, watch_hit, platforms_json, first_seen_at, last_seen_at) VALUES ('CVE-2026-200', ?, 1, 0, '[\"linux\"]', ?, ?)").run(ago(2), ago(2), ago(2));
    db.prepare("INSERT INTO triage (subject_kind, subject_id, subject_key, state, due_at, created_at, updated_at) VALUES ('item', ?, '', 'affects', '2026-10-01', ?, ?)").run(overdue, ago(80), ago(80));

    const actions = nextActions(db, { since: ago(24), now });
    expect(actions[0]?.kind).toBe("overdue");
    expect(actions[0]?.why).toContain("2026-10-01");
    expect(actions[1]?.kind).toBe("kev-mine");
    expect(actions[1]?.why).toContain("CISA has evidence this is being exploited");
    expect(actions[1]?.why).toContain("federal due date 2026-11-01");
    expect(actions[1]?.href).toBe("/vulnerabilities/CVE-2026-100");
    expect(actions[2]?.kind).toBe("kev");
    expect(actions.map((a) => a.itemId)).toContain(kevMine);
    expect(actions.map((a) => a.itemId)).toContain(kevOther);
  });

  it("keeps an overdue promise on the list however narrow the window is", () => {
    // A KEV addition ages out of a one-hour window; a date this instance's owner gave does not.
    const narrow = nextActions(db, { since: ago(1), now });
    expect(narrow.map((a) => a.kind)).toEqual(["overdue"]);
  });
});

describe("the window's CVEs by platform", () => {
  it("counts a CVE under every platform it affects, KEV and watchlist apart, the fleet's own first", () => {
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-100', ?, 'cvss')").run(ago(3));
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-200', ?, 'new')").run(ago(2));
    db.prepare("INSERT INTO vulns (cve_id, last_modified_at, kev, watch_hit, platforms_json, first_seen_at, last_seen_at) VALUES ('CVE-2026-400', ?, 0, 0, '[\"windows\",\"linux\"]', ?, ?)").run(ago(4), ago(4), ago(4));
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-400', ?, 'cvss')").run(ago(4));
    db.prepare("INSERT INTO vulns (cve_id, last_modified_at, platforms_json, first_seen_at, last_seen_at) VALUES ('CVE-2026-500', ?, '[]', ?, ?)").run(ago(5), ago(5), ago(5));
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-500', ?, 'cvss')").run(ago(5));

    const breakdown = platformBreakdown(db, ago(24));
    const windows = breakdown.rows.find((r) => r.key === "windows");
    const linux = breakdown.rows.find((r) => r.key === "linux");
    expect(windows).toMatchObject({ total: 2, kev: 1, mine: 1, inFleet: true });
    expect(linux).toMatchObject({ total: 2, kev: 1, mine: 0, inFleet: true });
    // One CVE names no platform this site can read; it is counted apart rather than dropped.
    expect(breakdown.unplaced).toBe(1);
    expect(breakdown.total).toBe(4);
  });

  it("reads the fleet's platforms in the vocabulary CVEs use", () => {
    const keys = fleetPlatformKeys(loadFleet());
    // data/platforms.yaml runs macOS, iOS and iPadOS, which are all Apple to a CVE.
    expect(keys.has("apple")).toBe(true);
    expect(keys.has("windows")).toBe(true);
    expect(keys.has("android")).toBe(true);
  });

  it("draws the rows on Today, each leading to the table filtered the same way", async () => {
    const today = await (await fetch(`${app.base}/today`)).text();
    expect(today).toContain('<section class="box wide" id="platforms">');
    expect(today).toContain('href="/vulnerabilities?platform=windows&amp;changed=1"');
    expect(today).toContain('<span class="chip ok">in your fleet</span>');
    expect(today).toContain("KEV</a>");
    // And the table itself answers that filter.
    const filtered = await (await fetch(`${app.base}/vulnerabilities?platform=windows`)).text();
    expect(filtered).toContain("CVE-2026-100");
    expect(filtered).not.toContain("CVE-2026-200");
  });
});
