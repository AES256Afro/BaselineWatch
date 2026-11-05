import { createHash, webcrypto } from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

/**
 * The traces script (public/traces.js) driven with Blobs and Node's WebCrypto: the boundary rules
 * Zero Breach's scanner holds its matching to, each artefact's reader and grade, and the verdict.
 * No browser, no network, and no indicator is ever resolved.
 */

interface Indicator {
  value: string;
  type: string;
  tier: string;
  confidence: string | null;
  source: string | null;
}
interface IndicatorSet {
  byValue: Map<string, Indicator>;
  domains: Set<string>;
  ips: Set<string>;
  hashes: Set<string>;
  hsts: Map<string, string>;
}
interface Hit {
  value: string;
  evidence: string;
  seenAs: string;
}
interface Result {
  path: string;
  size: number;
  art: { kind: string; label: string; evidence: string };
  hits: Hit[];
  hashed: boolean;
  blocked: string[];
  error: string | null;
  note: string | null;
}
interface Finding {
  indicator: Indicator;
  places: { path: string; label: string; evidence: string; seenAs: string }[];
  evidence: string;
  action: number;
}
interface Coverage {
  files: number;
  read: number;
  unread: Result[];
  kinds: Map<string, number>;
  missing: { label: string }[];
  blocked: string[];
  notes: string[];
}
interface TracesScript {
  CHUNK: number;
  indicatorSet(list: unknown[]): IndicatorSet;
  hstsFingerprint(host: string, subtle: unknown): Promise<string>;
  prepareHsts(set: IndicatorSet, subtle: unknown): Promise<void>;
  defang(value: string): string;
  matchHost(host: string, set: IndicatorSet): Indicator | null;
  scanText(text: string, set: IndicatorSet): Map<string, { value: string; seenAs: Set<string> }>;
  artifactOf(path: string): { kind: string; label: string; evidence: string };
  sniff(sample: string): { kind: string; label: string; evidence: string } | null;
  hostsFindings(text: string, set: IndicatorSet): { configured: { value: string; seenAs: string }[]; blocked: string[] };
  readArtifact(file: Blob | { size: number; slice(): Blob; arrayBuffer(): Promise<ArrayBuffer> }, path: string, set: IndicatorSet, subtle: unknown): Promise<Result>;
  actionOf(evidence: string, tier: string): number;
  findingsOf(results: Result[], set: IndicatorSet): Finding[];
  coverageOf(results: Result[]): Coverage;
  judge(findings: Finding[], coverage: Coverage): { tone: string; title: string; text: string; action: number };
}

let t: TracesScript;
let set: IndicatorSet;
const subtle = webcrypto.subtle;
const sampleBytes = new TextEncoder().encode("MZ pretend spyware sample");
const sampleHash = createHash("sha256").update(sampleBytes).digest("hex");

beforeAll(async () => {
  t = (await import(pathToFileURL(path.join(import.meta.dirname, "..", "public", "traces.js")).href)) as TracesScript;
  const row = (value: string, tier: string, type = "domain"): Indicator => ({ value, type, tier, confidence: "primary", source: "citizenlab-adfection-2026" });
  // Real entries from the fixture list (test/fixtures/blocklists/adfection_iocs-2026-10-18b.txt), and one synthetic sample hash.
  set = t.indicatorSet([
    row("fearevolve.com", "cc"),
    row("keyadapter.com", "validator"),
    row("sharethere.net", "validator"),
    row("controlium.net", "delivery"),
    row("mtrtb.com", "delivery"),
    row("powerium.net", "delivery"),
    row("noas.powerium.net", "delivery"),
    row("qa-noas.powerium.net", "delivery"),
    row("52.174.65.77", "cc", "ip"),
    row("5.181.159.109", "candiru-ip", "ip"),
    row(sampleHash, "sample", "sha256"),
  ]);
  await t.prepareHsts(set, subtle);
});

const found = (text: string): string[] => [...t.scanText(text, set).keys()].sort();
const blob = (text: string): Blob => new Blob([text]);
const wide = (text: string): Blob => new Blob([Buffer.from(text, "utf16le")]);

describe("matching", () => {
  it("takes whole names only, as the scanner does", () => {
    expect(found("notcontrolium.net controlium.network controlium.net.evil.example a_controlium.net controlium.net_x")).toEqual([]);
    expect(found("https://cdn.controlium.net/ad.js")).toEqual(["controlium.net"]);
    expect(found("end of a sentence: controlium.net.")).toEqual(["controlium.net"]);
    expect(found("controlium.net._x")).toEqual(["controlium.net"]);
    expect(found("CONTROLIUM.NET")).toEqual(["controlium.net"]);
  });

  it("counts a child once rather than its parents again, and a parent standing alone still counts", () => {
    expect(found("cookie for qa-noas.powerium.net")).toEqual(["qa-noas.powerium.net"]);
    expect(found("qa-noas.powerium.net and later powerium.net")).toEqual(["powerium.net", "qa-noas.powerium.net"]);
  });

  it("takes whole addresses only", () => {
    expect(found("152.174.65.771 1.52.174.65.77 52.174.65.770")).toEqual([]);
    expect(found("connect 52.174.65.77:443")).toEqual(["52.174.65.77"]);
    expect(found("52.174.65.77.")).toEqual(["52.174.65.77"]);
  });

  it("reads UTF-16LE as well as single-byte text", () => {
    const text = new TextDecoder("latin1").decode(Buffer.from("\u0000x https://fearevolve.com/c and 5.181.159.109\u0000", "utf16le"));
    expect(found(text)).toEqual(["5.181.159.109", "fearevolve.com"]);
  });

  it("matches a host exactly or as a subdomain, most specific first", () => {
    expect(t.matchHost("X.KeyAdapter.com.", set)?.value).toBe("keyadapter.com");
    expect(t.matchHost("a.qa-noas.powerium.net", set)?.value).toBe("qa-noas.powerium.net");
    expect(t.matchHost("keyadapter.com.evil.example", set)).toBeNull();
    expect(t.matchHost("52.174.65.77", set)?.tier).toBe("cc");
  });

  it("hashes a host the way Chromium's HSTS state keeps it", async () => {
    const wire = Buffer.concat([Buffer.from([10]), Buffer.from("fearevolve"), Buffer.from([3]), Buffer.from("com"), Buffer.from([0])]);
    expect(await t.hstsFingerprint("FearEvolve.com.", subtle)).toBe(createHash("sha256").update(wire).digest("base64"));
  });

  it("never shows an indicator as something a click can follow", () => {
    expect(t.defang("qa-noas.powerium.net")).toBe("qa-noas[.]powerium[.]net");
  });
});

describe("artefacts", () => {
  it("grades a match by where it was found", () => {
    expect(t.artifactOf("Default/Cache/Cache_Data/f_00001a")).toMatchObject({ label: "HTTP cache", evidence: "referenced" });
    expect(t.artifactOf("User Data\\Default\\Local Storage\\leveldb\\000003.log")).toMatchObject({ label: "Site storage", evidence: "contacted" });
    expect(t.artifactOf("Profiles/abc.default/places.sqlite")).toMatchObject({ label: "History", evidence: "referenced" });
    expect(t.artifactOf("Profiles/abc.default/SiteSecurityServiceState.bin")).toMatchObject({ label: "Firefox HSTS state", evidence: "contacted" });
    expect(t.artifactOf("clsid.reg")).toMatchObject({ evidence: "persistence" });
    expect(t.artifactOf("etc/hosts")).toMatchObject({ kind: "hosts" });
    expect(t.artifactOf("notes.txt")).toMatchObject({ kind: "sniff" });
  });

  it("tells a registry export, a DNS dump and a hosts file by their first lines", () => {
    expect(t.sniff("\uFEFFWindows Registry Editor Version 5.00")?.evidence).toBe("persistence");
    expect(t.sniff("    Record Name . . . . . : example.com")?.label).toBe("DNS records");
    expect(t.sniff("Event[0]:\n  Log Name: Microsoft-Windows-DNS-Client/Operational")?.label).toBe("DNS records");
    expect(t.sniff("example.com IN A 93.184.216.34")?.label).toBe("DNS records");
    expect(t.sniff("127.0.0.1 localhost\n")?.kind).toBe("hosts");
    expect(t.sniff("just some words")).toBeNull();
  });

  it("calls a hosts line pointed at a sink a block, and one pointed at a real address a finding", () => {
    const hosts = t.hostsFindings("127.0.0.1 localhost\n0.0.0.0 controlium.net www.controlium.net\n203.0.113.5 fearevolve.com # added by someone\n# 203.0.113.6 keyadapter.com\n", set);
    expect(hosts.blocked).toEqual(["controlium.net", "controlium.net"]);
    expect(hosts.configured).toEqual([{ value: "fearevolve.com", seenAs: "fearevolve.com → 203.0.113.5" }]);
  });
});

describe("reading a file", () => {
  it("reads a cache entry as a mention, with the name as it was found", async () => {
    const r = await t.readArtifact(blob("GET https://cdn.mtrtb.com/b.gif HTTP/1.1"), "Default/Cache/Cache_Data/f_0001", set, subtle);
    expect(r.hashed).toBe(true);
    expect(r.hits).toEqual([{ value: "mtrtb.com", evidence: "referenced", seenAs: "cdn.mtrtb.com" }]);
  });

  it("reads connection records: a server entry is contact, a mention elsewhere is only a mention", async () => {
    const nps = JSON.stringify({ net: { http_server_properties: { servers: [{ server: "https://fearevolve.com:443" }, { server: "https://example.org" }], note: "keyadapter.com" } } });
    const r = await t.readArtifact(blob(nps), "User Data/Default/Network/Network Persistent State", set, subtle);
    expect(r.hits).toEqual([
      { value: "fearevolve.com", evidence: "contacted", seenAs: "fearevolve.com" },
      { value: "keyadapter.com", evidence: "referenced", seenAs: "keyadapter.com" },
    ]);
  });

  it("matches Chromium's hashed HSTS hosts and learns nothing else", async () => {
    const fp = await t.hstsFingerprint("sharethere.net", subtle);
    const other = await t.hstsFingerprint("example.org", subtle);
    const r = await t.readArtifact(blob(JSON.stringify({ sts: [{ host: other }, { host: fp }], version: 2 })), "Default/Network/TransportSecurity", set, subtle);
    expect(r.hits).toEqual([{ value: "sharethere.net", evidence: "contacted", seenAs: "an HSTS header received over HTTPS" }]);
  });

  it("reads a UTF-16 registry export as a registration to run", async () => {
    const reg = '\uFEFFWindows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{0}\\InprocServer32]\r\n@="C:\\\\Users\\\\x\\\\AppData\\\\Roaming\\\\keyadapter.com\\\\a.dll"\r\n';
    const r = await t.readArtifact(wide(reg), "clsid-export.txt", set, subtle);
    expect(r.art.label).toBe("Registry export");
    expect(r.hits).toEqual([{ value: "keyadapter.com", evidence: "persistence", seenAs: "keyadapter.com" }]);
  });

  it("reads pasted DNS-cache text as a resolver record", async () => {
    const r = await t.readArtifact(blob("Windows IP Configuration\n\n    sharethere.net\n    ----------------------------------------\n    Record Name . . . . . : sharethere.net\n"), "pasted text", set, subtle);
    expect(r.art.label).toBe("DNS records");
    expect(r.hits[0]).toMatchObject({ value: "sharethere.net", evidence: "dns-record" });
  });

  it("fingerprints a file against the sample hashes, and notes a same-named driver that is not the build", async () => {
    const sample = await t.readArtifact(new Blob([sampleBytes]), "Downloads/setup.dll", set, subtle);
    expect(sample.hits).toEqual([{ value: sampleHash, evidence: "on-disk", seenAs: sampleHash }]);
    const driver = await t.readArtifact(blob("a legitimate driver"), "Windows/System32/drivers/HW.sys", set, subtle);
    expect(driver.hits).toEqual([]);
    expect(driver.note).toContain("HW.sys");
  });

  it("finds a name that straddles the edge of a search window", async () => {
    const pad = t.CHUNK - 6;
    const bytes = new Uint8Array(pad + 64).fill(0x20);
    bytes.set(new TextEncoder().encode("fearevolve.com"), pad);
    const r = await t.readArtifact(new Blob([bytes]), "Default/Cache/Cache_Data/data_1", set, subtle);
    expect(r.hits.map((h) => h.value)).toEqual(["fearevolve.com"]);
  });

  it("reports a file it could not read as unknown, with the reason in the reader's terms", async () => {
    const locked = { size: 10, slice: () => new Blob([]), arrayBuffer: () => Promise.reject(Object.assign(new Error("locked"), { name: "NotReadableError" })) };
    const r = await t.readArtifact(locked, "Default/History", set, subtle);
    expect(r.error).toContain("in use or locked");
    expect(r.hits).toEqual([]);
  });
});

describe("the verdict", () => {
  const result = (pathName: string, hits: Hit[], extra: Partial<Result> = {}): Result => ({ path: pathName, size: 100, art: t.artifactOf(pathName), hits, hashed: true, blocked: [], error: null, note: null, ...extra });

  it("weighs evidence by tier, as the scanner's next steps do", () => {
    expect(t.actionOf("referenced", "cc")).toBe(0);
    expect(t.actionOf("on-disk", "vuln-driver")).toBe(1);
    expect(t.actionOf("on-disk", "sample")).toBe(3);
    expect(t.actionOf("persistence", "validator")).toBe(3);
    expect(t.actionOf("contacted", "delivery")).toBe(1);
    expect(t.actionOf("dns-record", "candiru-ip")).toBe(1);
    expect(t.actionOf("contacted", "cc")).toBe(2);
  });

  it("groups hits by indicator, keeps the strongest evidence, and puts the most serious first", () => {
    const results = [
      result("Default/Cache/Cache_Data/f_1", [{ value: "mtrtb.com", evidence: "referenced", seenAs: "cdn.mtrtb.com" }, { value: "fearevolve.com", evidence: "referenced", seenAs: "fearevolve.com" }]),
      result("Default/Network/Network Persistent State", [{ value: "fearevolve.com", evidence: "contacted", seenAs: "fearevolve.com" }]),
    ];
    const findings = t.findingsOf(results, set);
    expect(findings.map((f) => [f.indicator.value, f.evidence, f.action, f.places.length])).toEqual([
      ["fearevolve.com", "contacted", 2, 2],
      ["mtrtb.com", "referenced", 0, 1],
    ]);
    expect(t.judge(findings, t.coverageOf(results))).toMatchObject({ tone: "bad", title: "2 indicators found: have it looked at" });
  });

  it("says a clean reading is not a clean device, and names the places not read", () => {
    const results = [result("Default/History", []), result("Default/Cookies", [], { error: "could not be read: in use or locked", hashed: false })];
    const coverage = t.coverageOf(results);
    expect(coverage.read).toBe(1);
    expect(coverage.missing.map((m) => m.label)).toContain("HTTP cache");
    expect(coverage.missing.map((m) => m.label)).toContain("Cookies");
    const v = t.judge([], coverage);
    expect(v).toMatchObject({ tone: "ok", title: "No known indicator in what was read" });
    expect(v.text).toContain("not that the device is clean");
    expect(v.text).toContain("1 file(s) could not be read");
  });

  it("never calls nothing read clean", () => {
    expect(t.judge([], t.coverageOf([]))).toMatchObject({ tone: "warn", title: "Nothing was read" });
    const unread = t.coverageOf([result("Default/History", [], { error: "could not be read" })]);
    expect(t.judge([], unread).text).toContain("a gap is not a clean result");
  });

  it("asks for expert help on a sample's fingerprint, and only notes an ad network's", () => {
    const disk = [result("Downloads/x.dll", [{ value: sampleHash, evidence: "on-disk", seenAs: sampleHash }])];
    expect(t.judge(t.findingsOf(disk, set), t.coverageOf(disk))).toMatchObject({ tone: "bad", action: 3 });
    const storage = [result("Default/Local Storage/leveldb/1.log", [{ value: "controlium.net", evidence: "contacted", seenAs: "controlium.net" }])];
    expect(t.judge(t.findingsOf(storage, set), t.coverageOf(storage)).text).toContain("do not call for a helpline");
  });
});
