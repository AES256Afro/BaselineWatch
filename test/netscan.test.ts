import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildDigest } from "../src/digest.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource, setSourceEnabled } from "../src/ingest.ts";
import {
  canarySets,
  categoryTallies,
  classifyAnswer,
  classifyError,
  controlName,
  discoverResolver,
  dohProbeUrl,
  leaseNameserver,
  leasePaths,
  netScanDue,
  netSettingKeys,
  networkSummary,
  parseChanges,
  resolvConfNameserver,
  resolvConfPath,
  runNetworkScan,
  scanCanaries,
  setSetting,
  systemdResolvConfPath,
  type ReadText,
  type Resolve,
} from "../src/netscan.ts";
import { fakeHttp, fixture, formPost, startTestApp, type FakeRoute, type TestApp } from "./helpers.ts";

const at = new Date("2026-10-20T08:00:00Z");
const resolverAddress = "192.168.8.10";

/** The canary sources' real captured responses, replayed the way blocklists.test.ts replays them. */
function canaryRoutes(): Record<string, FakeRoute> {
  const raw = "https://raw.githubusercontent.com/interplains/zero-breach";
  const api = "https://api.github.com/repos/interplains/zero-breach/commits?path=";
  const head = "7253316421e481973e1d9fd3b2bdb88eafc99029";
  const first = "e36dc961b8c60060c3b164d1a1c78d401e231a5e";
  return {
    "https://easylist.to/easylist/easylist.txt": { bytes: fixture("blocklists/easylist.txt") },
    "https://easylist.to/easylist/easyprivacy.txt": { bytes: fixture("blocklists/easyprivacy.txt") },
    "https://urlhaus.abuse.ch/downloads/hostfile/": { bytes: fixture("blocklists/urlhaus-hostfile.txt") },
    "https://openphish.com/feed.txt": { bytes: fixture("blocklists/openphish-feed.txt") },
    [`${api}dist/adfection.domains.txt&per_page=1`]: { bytes: fixture("blocklists/commits-domains.json"), contentType: "application/json" },
    [`${raw}/${head}/dist/adfection.domains.txt`]: { bytes: fixture("blocklists/adfection.domains-2026-10-18b.txt") },
    [`${raw}/${first}/dist/adfection.domains.txt`]: { bytes: fixture("blocklists/adfection.domains-2026-10-18a.txt") },
  };
}

async function seedCanaries(db: DatabaseSync, dataDir: string): Promise<void> {
  const http = fakeHttp(canaryRoutes());
  setSourceEnabled(db, "canary-phishing", true); // registered off (licence); this instance is private
  for (const id of ["canary-ads", "canary-trackers", "canary-malware", "canary-phishing", "adfection-dns"]) {
    const result = await ingestSource(db, dataDir, getSource(db, id)!, { http, now: () => at });
    expect(result.status, id).toBe("ok");
  }
}

/** resolv.conf alone names the LAN resolver; no lease file, no systemd stub. */
const readLan: ReadText = (file) => (file === resolvConfPath ? `# written by the router\nnameserver ${resolverAddress}\nnameserver 192.168.8.1\n` : null);

/**
 * A resolver with a sinkhole set, the way a Pi-hole behaves: 0.0.0.0 for a name on an adlist, a
 * real (documentation-range) address upstream for the rest, and the control naming the upstream.
 */
function fakeResolver(sinkholed: Set<string>): Resolve {
  return async (name, server) => {
    expect(server).toBe(resolverAddress);
    if (name === controlName) return ["203.0.113.53"];
    if (sinkholed.has(name)) return ["0.0.0.0"];
    return ["198.51.100.7"];
  };
}

describe("resolver discovery", () => {
  it("reads the server's lease first: the router's answer, whatever a local stub rewrote", () => {
    const lease = `lease {\n  option domain-name-servers 192.168.8.10, 192.168.8.1;\n}\nlease {\n  option domain-name-servers 192.168.8.10;\n}\n`;
    expect(leaseNameserver(lease)).toBe("192.168.8.10");
    const read: ReadText = (file) => (file === leasePaths[0] ? lease : file === resolvConfPath ? "nameserver 203.0.113.9\n" : null);
    expect(discoverResolver(read)).toEqual({ address: "192.168.8.10", source: "dhcp lease" });
  });

  it("falls back to resolv.conf, and follows systemd-resolved's stub through to the real upstream", () => {
    expect(discoverResolver(readLan)).toEqual({ address: resolverAddress, source: "resolv.conf" });
    expect(resolvConfNameserver("options edns0\nnameserver 192.168.8.10\n")).toBe("192.168.8.10");
    const stubbed: ReadText = (file) =>
      file === resolvConfPath ? "nameserver 127.0.0.53\n" : file === systemdResolvConfPath ? `nameserver ${resolverAddress}\n` : null;
    expect(discoverResolver(stubbed)).toEqual({ address: resolverAddress, source: "systemd-resolved" });
  });

  it("keeps a loopback resolver with no stub behind it (a Pi-hole on this host), and says when there is none", () => {
    const local: ReadText = (file) => (file === resolvConfPath ? "nameserver 127.0.0.1\n" : null);
    expect(discoverResolver(local)).toEqual({ address: "127.0.0.1", source: "resolv.conf" });
    expect(discoverResolver(() => null)).toBeNull();
  });
});

describe("classification", () => {
  it("calls 0.0.0.0, loopback, the resolver's own address and NXDOMAIN sinkholed; a real address resolved; silence a timeout", () => {
    expect(classifyAnswer(["0.0.0.0"], resolverAddress)).toEqual({ outcome: "sinkholed", answer: "0.0.0.0" });
    expect(classifyAnswer(["127.0.0.1"], resolverAddress).outcome).toBe("sinkholed");
    expect(classifyAnswer([resolverAddress], resolverAddress).outcome).toBe("sinkholed");
    expect(classifyAnswer(["198.51.100.7"], resolverAddress)).toEqual({ outcome: "resolved", answer: "198.51.100.7" });
    expect(classifyAnswer(["0.0.0.0", "198.51.100.7"], resolverAddress).outcome).toBe("resolved");
    expect(classifyError({ code: "ENOTFOUND" })).toEqual({ outcome: "sinkholed", answer: "NXDOMAIN" });
    expect(classifyError({ code: "ENODATA" }).outcome).toBe("sinkholed");
    expect(classifyError({ code: "ETIMEOUT" })).toEqual({ outcome: "timeout", answer: "ETIMEOUT" });
    expect(classifyError(new Error("boom"))).toEqual({ outcome: "timeout", answer: "no answer" });
  });
});

describe("the network scan", () => {
  let db: DatabaseSync;
  let dataDir = "";
  beforeEach(async () => {
    db = openDatabase(":memory:");
    migrate(db);
    dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-netscan-"));
    await seedCanaries(db, dataDir);
  });
  afterEach(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("reads the five sets from the Register: twelve names each, the adfection twelve picked by the lowest-hash rule", () => {
    const sets = canarySets(db);
    expect(sets.map((s) => s.category)).toEqual(["ads", "trackers", "malware", "phishing", "adfection"]);
    for (const set of sets) expect(set.names, set.category).toHaveLength(12);
    // The four canary sets are the plan's forty-eight; the adfection list is the mockup's fifth tile.
    expect(sets.slice(0, 4).flatMap((s) => s.names)).toHaveLength(48);
    const again = canarySets(db);
    expect(again).toEqual(sets);
  });

  it("flips a category from resolved to sinkholed when the adfection list is added to the Pi-hole (the milestone's done)", async () => {
    const sets = canarySets(db);
    const adfectionNames = sets.find((s) => s.category === "adfection")!.names;
    // Day one: the Pi-hole carries the usual ad, tracker, malware and phishing lists but not the adfection list.
    const sinkholed = new Set(sets.filter((s) => s.category !== "adfection").flatMap((s) => s.names));
    const http = fakeHttp({ [dohProbeUrl]: { text: "{}" } });

    const first = await runNetworkScan(db, { now: () => at, resolve: fakeResolver(sinkholed), readFile: readLan, http, baseUrl: "https://bw.example" });
    expect(first.resolver).toBe(resolverAddress);
    expect(first.resolver_source).toBe("resolv.conf");
    expect(first.upstream).toBe("203.0.113.53");
    expect(first.doh).toBe("reachable");
    expect(first.changes_json).toBeNull(); // the first run has nothing to differ against
    const tallies = categoryTallies(scanCanaries(db, first.id));
    expect(tallies.find((t) => t.category === "ads")).toMatchObject({ total: 12, sinkholed: 12, resolved: 0 });
    expect(tallies.find((t) => t.category === "adfection")).toMatchObject({ total: 12, sinkholed: 0, resolved: 12 });

    // The owner adds the adfection list as an adlist on the Pi-hole; the next day's run sees every name sinkholed.
    for (const name of adfectionNames) sinkholed.add(name);
    const nextDay = new Date("2026-10-21T08:00:00Z");
    const second = await runNetworkScan(db, { now: () => nextDay, resolve: fakeResolver(sinkholed), readFile: readLan, http, baseUrl: "https://bw.example" });
    const after = categoryTallies(scanCanaries(db, second.id));
    expect(after.find((t) => t.category === "adfection")).toMatchObject({ total: 12, sinkholed: 12, resolved: 0 });

    const changes = parseChanges(second.changes_json)!;
    expect(changes.resolverChanged).toBeNull();
    expect(changes.newlyResolving).toEqual([]);
    expect(changes.newlySinkholed).toHaveLength(12);
    expect(changes.newlySinkholed.every((c) => c.category === "adfection" && adfectionNames.includes(c.name))).toBe(true);

    // Good news alerts nobody: the notifier is for a canary that STARTS resolving, not one that stops.
    expect(db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE kind = 'network'").get()).toEqual({ n: 0 });

    // The digest carries the change as a line.
    const digest = buildDigest(db, { from: at.toISOString(), to: new Date("2026-10-21T09:00:00Z").toISOString(), baseUrl: "https://bw.example", period: "daily" }).text;
    expect(digest).toContain("This network: 12 change(s) https://bw.example/scan/network");
    expect(digest).toContain(`- ${changes.newlySinkholed[0]!.name} (adfection) is now sinkholed`);
  });

  it("alerts like a KEV addition when a canary starts resolving or the resolver changes", async () => {
    const sets = canarySets(db);
    const sinkholed = new Set(sets.flatMap((s) => s.names));
    const http = fakeHttp({ [dohProbeUrl]: { text: "{}" } });
    const deps = { readFile: readLan, http, baseUrl: "https://bw.example" };
    await runNetworkScan(db, { ...deps, now: () => at, resolve: fakeResolver(sinkholed) });

    // The ads list falls off the Pi-hole: two canaries resolve that were sinkholed yesterday.
    const ads = sets.find((s) => s.category === "ads")!.names;
    sinkholed.delete(ads[0]!);
    sinkholed.delete(ads[1]!);
    const second = await runNetworkScan(db, { ...deps, now: () => new Date("2026-10-21T08:00:00Z"), resolve: fakeResolver(sinkholed) });
    const changes = parseChanges(second.changes_json)!;
    expect(changes.newlyResolving.map((c) => c.name).sort()).toEqual([ads[0], ads[1]].sort());

    const alerts = db.prepare("SELECT kind, title, body, url, status FROM alerts WHERE kind = 'network'").all() as { title: string; body: string; url: string; status: string }[];
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.title).toBe("This network: 2 canaries newly resolving");
    expect(alerts[0]!.body).toContain(ads[0]!);
    expect(alerts[0]!.body).toContain("it was sinkholed yesterday");
    expect(alerts[0]!.url).toBe("https://bw.example/scan/network");
    expect(alerts[0]!.status).toBe("unconfigured"); // no transport in the test; the row is still the audit trail

    const digest = buildDigest(db, { from: at.toISOString(), to: "2026-10-21T09:00:00.000Z", baseUrl: "https://bw.example", period: "daily" }).text;
    expect(digest).toContain(`- ${ads[0]!} (ads) now resolves; it was sinkholed`);
  });

  it("records a run that found no resolver instead of failing, and reads the Pi-hole's client count when a token is saved", async () => {
    const none = await runNetworkScan(db, { now: () => at, resolve: fakeResolver(new Set()), readFile: () => null, http: fakeHttp({}) });
    expect(none.resolver).toBeNull();
    expect(none.error).toBe("no resolver found in the lease or resolv.conf");
    expect(scanCanaries(db, none.id)).toEqual([]);

    setSetting(db, netSettingKeys.piholeUrl, "http://192.0.2.10", at.toISOString());
    setSetting(db, netSettingKeys.piholeToken, "token-abc", at.toISOString());
    const http = fakeHttp({
      "http://192.0.2.10/admin/api.php?summaryRaw&auth=token-abc": { text: '{"unique_clients": 23}' },
      // No DoH route: the fake throws, which the scan reads as blocked from this LAN.
    });
    const sets = canarySets(db);
    const scan = await runNetworkScan(db, { now: () => new Date("2026-10-21T08:00:00Z"), resolve: fakeResolver(new Set(sets.flatMap((s) => s.names))), readFile: readLan, http });
    expect(scan.clients_seen).toBe(23);
    expect(scan.clients_source).toBe("pihole");
    expect(scan.doh).toBe("blocked");
    const summary = networkSummary(db)!;
    expect(summary).toMatchObject({ total: 60, sinkholed: 60, resolved: 0 });
  });

  it("is due daily once on: off until the setting is set, then once per local date", () => {
    const timeZone = "America/Chicago";
    expect(netScanDue(db, timeZone, at)).toBe(false); // not enabled
    setSetting(db, netSettingKeys.enabled, "1", at.toISOString());
    expect(netScanDue(db, timeZone, at)).toBe(true); // enabled, never run
    db.prepare("INSERT INTO net_scans (started_at, finished_at) VALUES (?, ?)").run(at.toISOString(), at.toISOString());
    expect(netScanDue(db, timeZone, new Date("2026-10-20T21:00:00Z"))).toBe(false); // same local date
    expect(netScanDue(db, timeZone, new Date("2026-10-21T02:00:00Z"))).toBe(false); // still the 20th in Chicago
    expect(netScanDue(db, timeZone, new Date("2026-10-21T08:00:00Z"))).toBe(true); // the next local date
  });
});

describe("the /scan/network page", () => {
  let app: TestApp;
  beforeEach(async () => {
    app = await startTestApp({ now: () => at });
    await seedCanaries(app.db, app.dataDir);
  });
  afterEach(async () => {
    await app.close();
  });

  it("renders the empty state, and the owner's switch is the only way a scan runs", async () => {
    const response = await fetch(`${app.base}/scan/network`);
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).toContain("This network");
    expect(text).toContain("It sends DNS queries on this network, so it waits for you to turn it on.");
    expect(text).toContain('action="/scan/network/enable"');
    expect(text).not.toContain('action="/scan/network/run"'); // not until it is on
    expect(text).not.toMatch(/<script/);

    const refused = await formPost(app.base, "/scan/network/run", {});
    expect(refused.status).toBe(400);
    expect(await refused.text()).toContain("Turn the network scan on first");
  });

  it("requires the owner for every switch", async () => {
    const closed = await startTestApp({ env: { BW_ADMIN_PASSWORD: "a-password" } });
    try {
      for (const route of ["/scan/network/enable", "/scan/network/run", "/scan/network/settings"]) {
        const response = await formPost(closed.base, route, { on: "1" });
        expect(response.status, route).toBe(403);
      }
    } finally {
      await closed.close();
    }
  });

  it("turns on, runs through the injected resolver, draws the tiles and findings, and feeds row 05 on /scan", async () => {
    const sets = canarySets(app.db);
    const sinkholed = new Set(sets.filter((s) => s.category !== "adfection").flatMap((s) => s.names));
    const withDns = await startTestApp({
      now: () => at,
      http: fakeHttp({ ...canaryRoutes(), [dohProbeUrl]: { text: "{}" } }),
      resolve: fakeResolver(sinkholed),
      readFile: readLan,
    });
    try {
      await seedCanaries(withDns.db, withDns.dataDir);
      const on = await formPost(withDns.base, "/scan/network/enable", { on: "1" });
      expect(on.status).toBe(303);
      const ran = await formPost(withDns.base, "/scan/network/run", {});
      expect(ran.status).toBe(303);

      const page = await (await fetch(`${withDns.base}/scan/network`)).text();
      expect(page).toContain(`<code>${resolverAddress}</code>`);
      expect(page).toContain("12 ad-delivered spyware canaries resolved");
      expect(page).toContain("Add the adfection list as an adlist on the resolver");
      expect(page).toContain('href="/standards/adfection-dns"');
      expect(page).toContain("reachable: a browser can bypass this resolver");
      expect(page).toContain("203.0.113.53");
      expect(page.match(/blocked network-wide/g)!.length).toBe(48);
      expect(page).not.toMatch(/<script/);

      const scanPage = await (await fetch(`${withDns.base}/scan`)).text();
      expect(scanPage).toContain("48 / 60 sinkholed");
      expect(scanPage).toContain('<span class="state warn">48 / 60 sinkholed</span>');
    } finally {
      await withDns.close();
    }
  });

  it("stores dashboard settings without ever rendering the token, and clears on a blank save", async () => {
    const saved = await formPost(app.base, "/scan/network/settings", { pihole_url: "http://192.0.2.10", pihole_token: "secret-token-xyz" });
    expect(saved.status).toBe(303);
    const page = await (await fetch(`${app.base}/scan/network`)).text();
    expect(page).toContain("Pi-hole API token (set)");
    expect(page).not.toContain("secret-token-xyz");

    const bad = await formPost(app.base, "/scan/network/settings", { adguard_url: "not a url" });
    expect(bad.status).toBe(400);

    // A whitespace-only field clears; an absent one keeps.
    await formPost(app.base, "/scan/network/settings", { pihole_token: " " });
    const cleared = await (await fetch(`${app.base}/scan/network`)).text();
    expect(cleared).toContain("Pi-hole API token (not set)");
  });
});
