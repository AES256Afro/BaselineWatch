import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { recordReading } from "../src/devices.ts";
import { buildDigest } from "../src/digest.ts";
import { exposureKeys } from "../src/exposure.ts";
import { setSetting } from "../src/netscan.ts";

/** The digest carries the Scan area's open findings: devices with something open, the exposure run, certificates logged. */

const now = new Date("2026-10-21T22:00:00Z");
const at = now.toISOString();
const from = "2026-10-20T22:00:00.000Z";

describe("the digest", () => {
  it("names devices with something open, the exposure run's findings and the certificates logged, and is silent when all is clear", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const base = { bw: 1 as const, browsers: [], packages: [], packageSource: null, os: { family: "windows" as const, name: "Windows 11 Pro", version: "24H2", build: "10.0.26100.9445", display: "24H2", id: null, versionId: null } };
    const quiet = buildDigest(db, { from, to: at, baseUrl: "https://bw.example", period: "daily" }).text;
    expect(quiet).not.toContain("Devices:");
    expect(quiet).not.toContain("Exposure:");
    expect(quiet).not.toContain("Certificates logged:");

    recordReading(db, "laptop", base, [{ id: "windows", title: "Windows updates", state: "bad", text: "3 CVE(s) fixed in KB5127648 are not on this build.", refs: [], quoted: [] }, { id: "os", title: "Windows support", state: "ok", text: "in support", refs: [], quoted: [] }], at);
    recordReading(db, "study pc", base, [{ id: "windows", title: "Windows updates", state: "ok", text: "current", refs: [], quoted: [] }], at);
    setSetting(db, exposureKeys.last, JSON.stringify({ at, publicIp: "203.0.113.9", internet: null, router: null, firmware: null, findings: [{ id: "internet", title: "What the internet sees", state: "warn", text: "2 open port(s) on record.", refs: [], quoted: [] }, { id: "public-address", title: "Public address", state: "ok", text: "ok", refs: [], quoted: [] }] }), at);
    db.prepare("INSERT INTO ct_certs (domain, id, issuer, names, not_before, not_after, seen_at) VALUES ('cybercard.net', 1, 'R13', 'login.cybercard.net', '2026-10-21T08:00:00', '2027-01-19T08:00:00', ?)").run(at);
    db.prepare("INSERT INTO ct_certs (domain, id, issuer, names, not_before, not_after, seen_at) VALUES ('cybercard.net', 2, 'R13', 'old.cybercard.net', '2026-09-01T08:00:00', '2026-12-01T08:00:00', '2026-09-01T09:00:00.000Z')").run();
    const { text, publicText } = buildDigest(db, { from, to: at, baseUrl: "https://bw.example", period: "daily" });
    expect(text).toContain("Devices: 1 with something open https://bw.example/scan/devices");
    expect(text).toContain("- laptop (exposed): Windows updates; read 2026-10-21");
    expect(text).not.toContain("study pc");
    expect(text).toContain("Exposure: 1 finding(s) on the last run https://bw.example/scan/network#exposure");
    expect(text).toContain("- What the internet sees: 2 open port(s) on record.");
    expect(text).toContain("Certificates logged: 1 for your domains https://bw.example/scan/domain");
    expect(text).toContain("- login.cybercard.net by R13, from 2026-10-21");
    expect(text).not.toContain("old.cybercard.net");
    // The half anyone who may read the site gets: none of the above. The device's name, what is
    // open on it, the exposure findings and the owner's domains' certificates are the owner's,
    // and `/digest` and `/api/v1/digest` are gated for reading rather than for the owner.
    for (const owners of ["laptop", "Devices:", "Exposure:", "Certificates logged:", "login.cybercard.net", "open port(s) on record"]) {
      expect(publicText, owners).not.toContain(owners);
    }
    // …and it is still a digest: what the instance tracks is all there.
    expect(publicText).toContain("BaselineWatch daily digest");
    expect(publicText).toContain("Triage:");
    db.close();
  });
});
