import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { storeNvdRecords } from "../src/adapters/nvd.ts";
import { fixContext, fixesFor, fixSummary, kevFor, loadMitigations, matchingEntries, mitigationsFile } from "../src/fix.ts";
import { platformsOf } from "../src/platforms.ts";
import { getVuln, loadWatchlist, matchWatch, matchWatchDetailed, recomputeWatchHits, upsertVuln, watchLabel } from "../src/vulns.ts";
import { loadBaselineFixtures } from "./baseline-fixtures.ts";
import { cookieFrom, fixture, formPost, startTestApp, type TestApp } from "./helpers.ts";

describe("platforms", () => {
  it("reads a CVE's platform from its CPEs, then NVD's names, then the description", () => {
    expect(platformsOf({ cpes: ["cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:*:*"], vendors: [], products: [], description: null })).toEqual(["windows"]);
    expect(platformsOf({ cpes: ["cpe:2.3:o:apple:macos:15.6:*:*:*:*:*:*:*", "cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*"], vendors: [], products: [], description: null })).toEqual(["apple"]);
    expect(platformsOf({ cpes: ["cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"], vendors: [], products: [], description: null })).toEqual(["linux"]);
    expect(platformsOf({ cpes: ["cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*"], vendors: [], products: [], description: null })).toEqual(["linux"]);
    expect(platformsOf({ cpes: ["cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"], vendors: [], products: [], description: null })).toEqual(["chrome"]);
    expect(platformsOf({ cpes: ["cpe:2.3:o:google:android:14.0:*:*:*:*:*:*:*"], vendors: [], products: [], description: null })).toEqual(["android"]);
    expect(platformsOf({ cpes: ["cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:*:*:*:*"], vendors: [], products: [], description: null })).toEqual(["edge"]);
    expect(platformsOf({ cpes: ["cpe:2.3:o:cisco:ios_xe:17.9:*:*:*:*:*:*:*"], vendors: [], products: [], description: null })).toEqual(["network"]);
    expect(platformsOf({ cpes: ["cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*"], vendors: [], products: [], description: null })).toEqual([]);
    expect(platformsOf({ cpes: [], vendors: ["apple"], products: ["macos"], description: null })).toEqual(["apple"]);
    expect(platformsOf({ cpes: [], vendors: [], products: [], description: "A use-after-free was addressed with improved memory management. This issue is fixed in macOS Sequoia 15.6, iOS 18.6 and iPadOS 18.6." })).toEqual(["apple"]);
    expect(platformsOf({ cpes: [], vendors: [], products: [], description: "In the Linux kernel, the following vulnerability has been resolved: net: fix a leak." })).toEqual(["linux"]);
    expect(platformsOf({ cpes: [], vendors: [], products: [], description: "Microsoft Windows Kernel Elevation of Privilege Vulnerability" })).toEqual(["windows"]);
    expect(platformsOf({ cpes: [], vendors: [], products: [], description: "An issue in Acme Widget allows remote code execution." })).toEqual([]);
  });

  it("matches a platform watch entry and labels it by the platform's name", () => {
    const entries = [
      { id: 1, kind: "platform" as const, value: "apple", label: null },
      { id: 2, kind: "product" as const, value: "fortinet", label: "Edge firewalls" },
    ];
    expect(watchLabel(entries[0]!)).toBe("Apple");
    expect(watchLabel({ kind: "platform", value: "linux", label: "Our fleet" })).toBe("Our fleet");
    const mac = { cpes: ["cpe:2.3:o:apple:macos:15.6:*:*:*:*:*:*:*"], vendors: ["apple"], products: ["macos"], description: "x" };
    expect(matchWatch(mac, entries)).toEqual(["Apple"]);
    expect(matchWatchDetailed(mac, entries)).toEqual([{ label: "Apple", kind: "platform" }]);
    expect(matchWatch({ cpes: ["cpe:2.3:o:fortinet:fortios:7.0:*:*:*:*:*:*:*"], vendors: ["fortinet"], products: ["fortios"], description: "x" }, entries)).toEqual(["Edge firewalls"]);
  });
});

describe("mitigations", () => {
  it("reads the owner's mapping and matches a CVE by id or by words", () => {
    const entries = loadMitigations(mitigationsFile);
    expect(entries.map((e) => e.id)).toEqual(expect.arrayContaining(["smbv1", "bluekeep-nla", "llmnr", "wdigest", "gatekeeper", "sip"]));
    expect(entries.every((e) => e.source === null || e.source.url.startsWith("https://"))).toBe(true);
    expect(matchingEntries(entries, { cveId: "CVE-2017-0144", description: "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code.", kevName: null }).map((e) => e.id)).toEqual(["smbv1"]);
    expect(matchingEntries(entries, { cveId: "CVE-2026-1", description: "A Gatekeeper bypass in macOS.", kevName: null }).map((e) => e.id)).toEqual(["gatekeeper"]);
    expect(matchingEntries(entries, { cveId: "CVE-2026-2", description: "An issue in Acme Widget.", kevName: "Acme Widget Code Injection Vulnerability" })).toEqual([]);
    expect(loadMitigations("C:/nowhere/mitigations.yaml")).toEqual([]);
  });
});

describe("the Fix panel", () => {
  let app: TestApp;
  const at = new Date("2026-10-17T10:00:00Z");

  beforeAll(async () => {
    app = await startTestApp({ now: () => at, env: { BW_ADMIN_PASSWORD: "owner-secret" } });
    await loadBaselineFixtures(app, at);
    // One CVE with every kind of published fix, one with none, and a KEV item for the first.
    const insertItem = app.db.prepare("INSERT INTO items (source_id, kind, external_id, title, url, summary, published_at, fetched_at, signals_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    insertItem.run("cisa-kev", "kev", "CVE-2017-0144", "Microsoft SMBv1: Microsoft SMBv1 Remote Code Execution Vulnerability", "https://nvd.nist.gov/vuln/detail/CVE-2017-0144", "The SMBv1 server allows RCE. Required action: Apply updates per vendor instructions.", "2022-02-10T00:00:00.000Z", at.toISOString(), JSON.stringify({ kev: true, cves: ["CVE-2017-0144"], vendor: "Microsoft", product: "SMBv1", dueDate: "2022-08-10", requiredAction: "Apply updates per vendor instructions." }));
    insertItem.run("ubuntu-usn", "article", "usn-1", "USN-0001-1: Samba vulnerabilities", "https://ubuntu.com/security/notices/USN-0001-1", "Several flaws in Samba.", "2026-10-01T00:00:00.000Z", at.toISOString(), JSON.stringify({ cves: ["CVE-2017-0144"] }));
    const base = { sourceIdentifier: "nvd@nist.gov", vulnStatus: "Analyzed", ssvc: null, cwes: [], cpes: [], vendors: [], products: [], kev: null, lastModifiedAt: at.toISOString() };
    upsertVuln(
      app.db,
      {
        ...base,
        cveId: "CVE-2017-0144",
        publishedAt: "2017-03-17T00:00:00.000Z",
        description: "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets.",
        cvss: { version: "3.1", score: 8.8, severity: "HIGH", vector: null, source: "nvd@nist.gov" },
        cpes: ["cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"],
        vendors: ["microsoft"],
        products: ["windows_10"],
        references: [
          { url: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144", tags: ["Patch", "Vendor Advisory"] },
          { url: "https://www.exploit-db.com/exploits/41891/", tags: ["Exploit", "Third Party Advisory"] },
        ],
        kev: { dateAdded: "2022-02-10", dueDate: "2022-08-10", requiredAction: "Apply updates per vendor instructions.", name: "Microsoft SMBv1 Remote Code Execution Vulnerability" },
        packages: [{ ecosystem: "Debian:12", name: "samba", introduced: ["0"], fixed: ["2:4.17.12"], lastAffected: [], advisory: "DSA-0001-1" }],
      },
      at.toISOString(),
      [],
    );
    // Packages arrive through the advisory path, which writes them beside the CVE row.
    app.db.prepare("UPDATE vulns SET packages_json = ? WHERE cve_id = ?").run(JSON.stringify([{ ecosystem: "Debian:12", name: "samba", introduced: ["0"], fixed: ["2:4.17.12"], lastAffected: [], advisory: "DSA-0001-1" }]), "CVE-2017-0144");
    upsertVuln(app.db, { ...base, cveId: "CVE-2026-99999", publishedAt: at.toISOString(), description: "An issue in Acme Widget allows remote code execution.", cvss: null, references: [{ url: "https://example.test/blog", tags: ["Third Party Advisory"] }] }, at.toISOString(), []);
  });

  afterAll(async () => {
    await app.close();
  });

  it("gathers every published fix for a CVE and says so when there is none", () => {
    const ctx = fixContext(app.db);
    expect(ctx.stigs.length).toBe(4); // Windows 11, macOS 26, iOS/iPadOS 26 and the RHEL 9 stand-in
    const fix = fixesFor(app.db, ctx, getVuln(app.db, "CVE-2017-0144")!);
    expect(fix.empty).toBe(false);
    expect(fix.references.map((r) => r.url)).toEqual(["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144"]);
    expect(fix.advisories.map((a) => a.title)).toEqual(["USN-0001-1: Samba vulnerabilities"]);
    expect(fix.kev).toMatchObject({ requiredAction: "Apply updates per vendor instructions.", dueDate: "2022-08-10", dateAdded: "2022-02-10" });
    expect(fix.packages).toEqual([{ ecosystem: "Debian:12", name: "samba", fixed: ["2:4.17.12"], advisory: "DSA-0001-1" }]);
    expect(fix.mitigations.map((m) => m.id)).toEqual(["smbv1"]);
    expect(fix.mitigations[0]!.rules.map((r) => `${r.stig.product} ${r.rule.label}`)).toEqual(["Microsoft Windows 11 WN11-00-000165"]);
    expect(fixSummary(fix)).toMatch(/^CISA: Apply updates per vendor instructions\. \(due 2022-08-10\) · 1 patch or advisory reference on NVD · vendor advisory: Ubuntu Security Notices · fixed in samba 2:4\.17\.12 · STIG: WN11-00-000165$/);
    const none = fixesFor(app.db, ctx, getVuln(app.db, "CVE-2026-99999")!);
    expect(none.empty).toBe(true);
    expect(fixSummary(none)).toMatch(/^Nothing published yet/);
    // An older KEV item with the action only in its summary still yields it.
    app.db.prepare("UPDATE items SET signals_json = ? WHERE source_id = 'cisa-kev' AND external_id = 'CVE-2017-0144'").run(JSON.stringify({ kev: true, dueDate: "2022-08-10" }));
    expect(kevFor(app.db, "CVE-2017-0144")?.requiredAction).toBe("Apply updates per vendor instructions.");
  });

  it("draws the panel on the CVE page and the fix line on the Wire", async () => {
    const whole = await (await fetch(`${app.base}/vulnerabilities/CVE-2017-0144`)).text();
    const page = whole.slice(whole.indexOf('<section class="box fix">'), whole.indexOf("Change history"));
    expect(page).toContain("CISA KEV required action · due 2022-08-10");
    expect(page).toContain("Apply updates per vendor instructions.");
    expect(page).toContain("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144");
    expect(page).not.toContain("exploit-db.com"); // an Exploit reference is not a fix; the References section below still lists it
    expect(page).toContain("USN-0001-1: Samba vulnerabilities");
    expect(page).toContain("STIG rules that mitigate this class");
    expect(page).toContain("<b>WN11-00-000165</b>");
    expect(page).toContain("Detect, enable and disable SMBv1");
    const empty = await (await fetch(`${app.base}/vulnerabilities/CVE-2026-99999`)).text();
    expect(empty).toContain("Nothing published yet");
    // The Wire: a KEV item carries the fix line.
    const wire = await (await fetch(`${app.base}/wire?kind=kev`)).text();
    expect(wire).toContain("<b>Fix:</b> CISA: Apply updates per vendor instructions. (due 2022-08-10)");
    expect(wire).toContain('<a href="/vulnerabilities/CVE-2017-0144">Fix panel</a>');
  });

  it("takes a platform entry on the watchlist and raises the alert as a new platform CVE", async () => {
    const login = await formPost(app.base, "/login", { password: "owner-secret", next: "/" });
    const cookie = cookieFrom(login);
    const bad = await formPost(app.base, "/watchlist", { kind: "platform", value: "amiga" }, cookie);
    expect(bad.status).toBe(400);
    const ok = await formPost(app.base, "/watchlist", { kind: "platform", value: "Apple" }, cookie);
    expect(ok.status).toBe(303);
    expect(loadWatchlist(app.db).find((e) => e.kind === "platform")).toMatchObject({ value: "apple", label: null });
    const list = await (await fetch(`${app.base}/watchlist`)).text();
    expect(list).toContain("<td>Platform</td>");
    expect(list).toContain("<code>apple</code>");

    // A new macOS CVE from NVD: on the Wire, labelled Apple, with an alert worded for the platform.
    const record = JSON.parse(new TextDecoder().decode(fixture("nvd-window.json"))) as { vulnerabilities: { cve: Record<string, unknown> }[] };
    const cve = JSON.parse(JSON.stringify(record.vulnerabilities[0]!)) as { cve: Record<string, unknown> };
    cve.cve.id = "CVE-2026-55555";
    cve.cve.descriptions = [{ lang: "en", value: "A use-after-free was addressed with improved memory management. This issue is fixed in macOS Sequoia 15.6. An app may be able to cause unexpected system termination." }];
    delete cve.cve.configurations;
    const stored = storeNvdRecords({ db: app.db, now: () => at }, [cve as never]);
    expect(stored.alerts.map((a) => a.title)).toEqual(["New Apple CVE: CVE-2026-55555"]);
    const row = getVuln(app.db, "CVE-2026-55555")!;
    expect(row.watch_hit).toBe(1);
    expect(JSON.parse(row.watch_labels_json!)).toEqual(["Apple"]);
    expect(recomputeWatchHits(app.db)).toBe(0);
    const wire = await (await fetch(`${app.base}/wire?kind=vulnerability`)).text();
    expect(wire).toContain("CVE-2026-55555");
    expect(wire).toContain('<span class="chip mine">Apple</span>');
  });
});
