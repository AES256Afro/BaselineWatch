import { zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { baselineTarget, parsePolicyRules, parseSctListing, policyScope, sctAdapter, usDate } from "../src/adapters/sct.ts";
import type { SourceRow } from "../src/adapters/types.ts";
import { diffRequirements, summarizeChanges } from "../src/differ.ts";
import { fakeHttp, fixture } from "./helpers.ts";

const text = (name: string) => new TextDecoder().decode(fixture(name));

describe("Security Compliance Toolkit listing", () => {
  it("reads the embedded file list and picks the baseline zips with stable keys and versions", () => {
    const files = parseSctListing(text("sct-listing.html"));
    expect(files).toHaveLength(5);
    expect(files[1]).toMatchObject({ name: "Windows Server 2025 Security Baseline - 2602.zip", size: 1384114, datePublished: "2026-10-08T18:35:40.000Z" });
    const targets = files.map(baselineTarget).filter((t) => t !== null);
    expect(targets.map((t) => [t.key, t.versionLabel])).toEqual([
      ["baseline:windows-server-2025", "2602"],
      ["baseline:windows-11-v26h2", "v2"],
      ["baseline:windows-11-v25h2", "2026-02-23"],
    ]);
    expect(usDate("2/23/2026 4:12:00 PM")).toBe("2026-02-23T16:12:00.000Z");
    expect(usDate("12/1/2025 12:05:00 AM")).toBe("2025-12-01T00:05:00.000Z");
    expect(usDate("nope")).toBeNull();
    expect(() => parseSctListing("<html></html>")).toThrow(/__DLCDetails__/);
  });
});

describe("PolicyRules", () => {
  it("turns registry, security-template and audit entries into requirements with version-free refs", () => {
    const rules = parsePolicyRules(text("sct.PolicyRules"));
    expect(rules).toHaveLength(11);
    const first = rules[0]!;
    expect(first.ref).toBe("windows server 2025 - member server|computer|software\\microsoft\\windows\\currentversion\\policies\\explorer\\nodrivetypeautorun");
    expect(first.label).toBe("NoDriveTypeAutoRun");
    expect(first.title).toBe("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun");
    expect(first.statement).toBe("REG_DWORD = 255");
    expect(first.family).toBe("Windows Server 2025 - Member Server");
    expect(first.extra).toMatchObject({ kind: "registry", hive: "Computer" });
    const user = rules.find((r) => r.extra.hive === "User")!;
    expect(user.title.startsWith("HKCU\\")).toBe(true);
    const template = rules.find((r) => r.extra.kind === "security-template")!;
    expect(template.title).toBe("System Access: LSAAnonymousNameLookup");
    expect(template.statement).toBe("0");
    const audit = rules.find((r) => r.extra.kind === "audit")!;
    expect(audit.title).toBe("Audit policy: Audit Credential Validation");
    expect(audit.statement).toBe("Success and Failure");
    expect(policyScope("MSFT Windows Server 2025 v2602 - Domain Controller")).toBe("Windows Server 2025 - Domain Controller");
    expect(policyScope("MSFT Internet Explorer 11 - User")).toBe("Internet Explorer 11 - User");
  });

  it("diffs two baseline versions setting by setting", () => {
    const before = parsePolicyRules(text("sct.PolicyRules"));
    const next = text("sct.PolicyRules").replace("<RegData>255</RegData>", "<RegData>91</RegData>").replace("v2602", "v2606");
    const after = parsePolicyRules(next);
    const summary = summarizeChanges(diffRequirements(before, after));
    expect(summary.added).toEqual([]);
    expect(summary.removed).toEqual([]);
    expect(summary.substantive).toEqual([before[0]!.ref]);
  });

  it("reads a baseline zip through the adapter and lists documents from the page", async () => {
    const ctx = { db: null as never, source: null as never, http: fakeHttp({}) };
    const zip = zipSync({ "Windows Server 2025 Security Baseline - 2602/Documentation/MSFT-WS2025-v2602.PolicyRules": fixture("sct.PolicyRules"), "Windows Server 2025 Security Baseline - 2602/Documentation/x.txt": new Uint8Array(0) });
    const parsed = await sctAdapter.parseDocument!(zip, { key: "baseline:windows-server-2025", url: "u", versionLabel: "2602", publishedAt: "2026-10-08T18:35:40.000Z" }, ctx);
    expect(parsed.title).toBe("Windows Server 2025 Security Baseline - 2602");
    expect(parsed.versionLabel).toBe("2602");
    expect(parsed.requirements).toHaveLength(11);
    await expect(sctAdapter.parseDocument!(zipSync({ "a.txt": new Uint8Array([1]) }), { key: "k", url: "u" }, ctx)).rejects.toThrow(/PolicyRules/);

    // Older toolkits: several PolicyRules files per zip, encoded as UTF-16 with a byte-order mark.
    const utf16 = (s: string) => {
      const out = new Uint8Array(2 + s.length * 2);
      out[0] = 0xff;
      out[1] = 0xfe;
      for (let i = 0; i < s.length; i += 1) {
        const code = s.charCodeAt(i);
        out[2 + i * 2] = code & 0xff;
        out[3 + i * 2] = code >> 8;
      }
      return out;
    };
    const one = text("sct.PolicyRules");
    const two = one.replace(/Member Server/g, "Domain Controller");
    const old = zipSync({ "Documentation/MSFT-WS2019-MemberServer-FINAL.PolicyRules": utf16(one), "Documentation/MSFT-WS2019-DomainController-FINAL.PolicyRules": utf16(two) });
    const merged = await sctAdapter.parseDocument!(old, { key: "baseline:windows-10-version-1809-and-windows-server-2019", url: "u" }, ctx);
    expect(merged.requirements.length).toBe(11 + 11 - 2); // the two Internet Explorer user entries carry no "Member Server" and so repeat
    expect(merged.requirements.some((r) => r.family === "Windows Server 2025 - Domain Controller")).toBe(true);
    await expect(sctAdapter.parseDocument!(zipSync({ "x.PolicyRules": new TextEncoder().encode("<PolicyRules></PolicyRules>") }), { key: "k", url: "u" }, ctx)).rejects.toThrow(/no settings/);

    const source = { id: "microsoft-sct", url: "https://www.microsoft.com/en-us/download/details.aspx?id=55319" } as SourceRow;
    const http = fakeHttp({ [source.url]: { bytes: fixture("sct-listing.html") } });
    const targets = await sctAdapter.documents!(source, { db: null as never, http, now: () => new Date() });
    expect(targets).toHaveLength(3);
    expect(targets[0]?.url).toContain("Windows Server 2025 Security Baseline - 2602.zip");
  });
});
