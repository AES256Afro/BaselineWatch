import { describe, expect, it } from "vitest";
import { feedAdapter } from "../src/adapters/feed.ts";
import { hnAdapter } from "../src/adapters/hn.ts";
import { adapterFor } from "../src/adapters/index.ts";
import { kevAdapter } from "../src/adapters/kev.ts";
import { redditAdapter } from "../src/adapters/reddit.ts";
import { canonicalUrl, cveIdsIn, isoDate, plainText, type SourceRow } from "../src/adapters/types.ts";
import { ftsQuery } from "../src/wire.ts";
import { fixture } from "./helpers.ts";

const now = new Date("2026-10-14T07:00:00Z");
const source = { id: "x", format: "rss" } as SourceRow;

describe("feed adapter", () => {
  it("reads RSS with CDATA, content:encoded, entities and CVE ids", () => {
    const { items, documentKey } = feedAdapter.parse!(fixture("rss.xml"), source, now);
    expect(documentKey).toBe("feed");
    expect(items).toHaveLength(3);
    const [first, second, third] = items;
    expect(first?.externalId).toBe("news-1001");
    expect(first?.title).toBe("Vendor patches CVE-2026-31417 in SSL-VPN after in-the-wild exploitation");
    expect(first?.url).toBe("https://news.example.test/vendor-patches-ssl-vpn/?utm_source=rss&utm_medium=feed");
    expect(first?.summary).toBe("The vendor shipped 7.4.8 fixing a heap overflow & a second bug, cve-2026-31418. Read more…");
    expect(first?.publishedAt).toBe("2026-10-14T06:58:00.000Z");
    expect(first?.signals).toEqual({ cves: ["CVE-2026-31417", "CVE-2026-31418"] });
    expect(second?.externalId).toBe("https://news.example.test/ransomware-logistics/");
    expect(second?.summary).toBe("Two terabytes were listed on the leak site.");
    expect(second?.signals).toBeUndefined();
    expect(third?.externalId).toBe("No link, no guid, still a story");
    expect(third?.url).toBeNull();
    expect(third?.publishedAt).toBeNull();
  });

  it("reads Atom with alternate links, html summaries and content fallbacks", () => {
    const { items } = feedAdapter.parse!(fixture("atom.xml"), { ...source, format: "atom" }, now);
    expect(items).toHaveLength(2);
    expect(items[0]?.externalId).toBe("tag:blog.example.test,2026:post-77");
    expect(items[0]?.url).toBe("https://blog.example.test/2026/oauth-device-code");
    expect(items[0]?.summary).toBe("A walkthrough of the phishing path and the detections that catch it.");
    expect(items[0]?.publishedAt).toBe("2026-10-13T17:30:00.000Z");
    expect(items[1]?.summary).toBe("Plain text content used as the summary.");
    expect(items[1]?.publishedAt).toBe("2026-10-12T09:00:00.000Z");
  });

  it("refuses something that is not a feed", () => {
    expect(() => feedAdapter.parse!(new TextEncoder().encode("<html><body>nope</body></html>"), source, now)).toThrow(/not an RSS or Atom/);
  });
});

describe("kev adapter", () => {
  it("turns every catalog entry into a dated kev item with its due date", () => {
    const { items, documentKey, versionLabel } = kevAdapter.parse!(fixture("kev.json"), source, now);
    expect(documentKey).toBe("known_exploited_vulnerabilities.json");
    expect(versionLabel).toBe("2026.10.14");
    expect(items).toHaveLength(3);
    const ahsay = items[0]!;
    expect(ahsay.kind).toBe("kev");
    expect(ahsay.externalId).toBe("CVE-2026-105134");
    expect(ahsay.title).toBe("Ahsay AhsayCBS: Ahsay AhsayCBS Command Injection Vulnerability");
    expect(ahsay.url).toBe("https://nvd.nist.gov/vuln/detail/CVE-2026-105134");
    expect(ahsay.publishedAt).toBe("2026-10-14T00:00:00.000Z");
    expect(ahsay.signals).toMatchObject({ kev: true, cves: ["CVE-2026-105134"], dueDate: "2026-11-04", ransomware: false, cwes: ["CWE-78"] });
    expect(items[1]?.signals).toMatchObject({ ransomware: true });
  });
});

describe("reddit adapter", () => {
  it("keeps link posts and self posts, drops stickies, never stores comments", () => {
    const { items } = redditAdapter.parse!(fixture("reddit.json"), source, now);
    expect(items.map((i) => i.externalId)).toEqual(["t3_1abcde", "t3_1abcdg"]);
    expect(items[0]?.url).toBe("https://blog.example.test/2026/oauth-device-code");
    expect(items[0]?.summary).toBe("r/netsec · blog.example.test");
    expect(items[0]?.signals).toMatchObject({ score: 143, comments: 12, thread: "https://www.reddit.com/r/netsec/comments/1abcde/writeup_abusing_oauth_device_code_flow/" });
    expect(items[1]?.url).toBe("https://www.reddit.com/r/netsec/comments/1abcdg/question/");
    expect(items[1]?.signals).toMatchObject({ cves: ["CVE-2026-31417"] });
    expect(items[0]?.publishedAt).toBe(new Date(1792000000 * 1000).toISOString());
  });
});

describe("reddit adapter, Atom", () => {
  it("takes the outbound link for link posts and the thread for self posts", () => {
    const { items } = redditAdapter.parse!(fixture("reddit-atom.xml"), { ...source, format: "atom" }, now);
    expect(items.map((i) => i.externalId)).toEqual(["t3_1abcde", "t3_1abcdg"]);
    expect(items[0]?.url).toBe("https://blog.example.test/2026/oauth-device-code?utm_source=reddit");
    expect(items[0]?.summary).toBe("r/netsec · blog.example.test");
    expect(items[0]?.signals).toEqual({ thread: "https://www.reddit.com/r/netsec/comments/1abcde/writeup_abusing_oauth_device_code_flow/" });
    expect(items[0]?.publishedAt).toBe("2026-10-14T05:46:40.000Z");
    expect(items[1]?.url).toBe("https://www.reddit.com/r/netsec/comments/1abcdg/question/");
    expect(items[1]?.summary).toContain("Has anyone seen a public PoC");
    expect(items[1]?.summary).not.toContain("submitted by");
    expect(items[1]?.signals).toMatchObject({ cves: ["CVE-2026-31417"] });
  });
});

describe("hn adapter", () => {
  it("links to the story or the thread and skips hits without a title", () => {
    const { items } = hnAdapter.parse!(fixture("hn.json"), source, now);
    expect(items).toHaveLength(2);
    expect(items[0]?.url).toBe("https://eng.example.test/postmortem-ci-token");
    expect(items[0]?.summary).toBe("212 points · 87 comments");
    expect(items[1]?.url).toBe("https://news.ycombinator.com/item?id=45900002");
    expect(items[1]?.summary).toBe("Release 5.2.0 added SA-24 and I only found out by accident.");
  });
});

describe("adapter registry", () => {
  it("picks by id first, then by format", () => {
    expect(adapterFor({ id: "cisa-kev", format: "json" })?.id).toBe("kev");
    expect(adapterFor({ id: "bleeping", format: "rss" })?.id).toBe("feed");
    expect(adapterFor({ id: "schneier", format: "atom" })?.id).toBe("feed");
    expect(adapterFor({ id: "reddit-netsec", format: "json" })?.id).toBe("reddit");
    expect(adapterFor({ id: "nvd-cves", format: "json" })?.id).toBe("nvd");
    expect(adapterFor({ id: "cvelist-v5", format: "json" })?.id).toBe("cvelist");
    expect(adapterFor({ id: "disa-stigs", format: "xccdf-zip" })?.id).toBe("disa-stig");
    expect(adapterFor({ id: "cis-benchmarks", format: "pdf-upload" })?.id).toBe("cis");
    expect(adapterFor({ id: "complianceascode", format: "git" })).toBeNull();
  });
});

describe("helpers", () => {
  it("canonicalises urls for duplicate detection", () => {
    expect(canonicalUrl("http://WWW.Example.test/a/b/?utm_source=x&id=2&fbclid=y#frag")).toBe("https://example.test/a/b/?id=2");
    expect(canonicalUrl("https://example.test/a/b/")).toBe("https://example.test/a/b");
    expect(canonicalUrl("not a url")).toBeNull();
    expect(canonicalUrl(null)).toBeNull();
  });

  it("strips html and decodes entities", () => {
    expect(plainText("<p>A &amp; B&nbsp;&#8230; <b>bold</b></p>  <br>next")).toBe("A & B … bold next");
    expect(plainText("", 10)).toBeNull();
    expect(plainText("abcdefghijklmnop", 10)).toBe("abcdefghi…");
  });

  it("finds CVE ids once each, uppercased", () => {
    expect(cveIdsIn("cve-2026-1234 and CVE-2026-1234, plus CVE-2021-44228")).toEqual(["CVE-2026-1234", "CVE-2021-44228"]);
  });

  it("parses dates from strings and epoch seconds", () => {
    expect(isoDate("Tue, 14 Oct 2026 06:58:00 +0000")).toBe("2026-10-14T06:58:00.000Z");
    expect(isoDate(1792000000)).toBe(new Date(1792000000 * 1000).toISOString());
    expect(isoDate(1792000000123)).toBe(new Date(1792000000123).toISOString());
    expect(isoDate("garbage")).toBeNull();
    expect(isoDate(undefined)).toBeNull();
  });

  it("quotes every search word so FTS syntax cannot leak in", () => {
    expect(ftsQuery('fortios OR "x" AND')).toBe('"fortios" "OR" "x" "AND"');
    expect(ftsQuery("   ")).toBeNull();
  });
});
