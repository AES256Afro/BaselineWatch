import { describe, expect, it } from "vitest";
import { apiVulns } from "../src/api.ts";
import { parseCookies } from "../src/auth.ts";
import { getBlob } from "../src/blobs.ts";
import { csvCell } from "../src/csv.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { flashHeader } from "../src/flash.ts";
import { html } from "../src/html.ts";
import { privateAddress } from "../src/http.ts";
import { safeUrl } from "../src/items.ts";
import { maxMcpRequestBytes } from "../src/mcp.ts";
import { boundaryOf } from "../src/multipart.ts";
import { safeBack, safeHref } from "../src/paths.ts";
import { storeNvdRecords, type NvdCve } from "../src/adapters/nvd.ts";
import { startTestApp } from "./helpers.ts";

/**
 * The code audit of 2026-10-25 and what it changed. Every case here is one a throwaway
 * hostile-input script found against the live functions, written down so it stays found.
 */

const now = new Date("2026-10-25T12:00:00Z");

describe("an address that may be rendered", () => {
  // `new URL("/\\evil.example", "https://site/")` is "https://evil.example/": the URL parser
  // reads a backslash after the leading slash the way it reads a second slash.
  it("refuses the backslash form a browser reads as another site", () => {
    expect(new URL("/\\evil.example", "https://site.example/page").host).toBe("evil.example");
    expect(safeUrl("/\\evil.example")).toBeNull();
    expect(safeHref("/\\evil.example")).toBeNull();
    expect(safeBack("/\\evil.example", "/")).toBe("/");
  });

  it("still keeps the addresses the pages are built from", () => {
    expect(safeHref("https://example.net/a?b=c#d")).toBe("https://example.net/a?b=c#d");
    expect(safeHref("http://example.net")).toBe("http://example.net");
    expect(safeHref("/vulnerabilities?kev=1")).toBe("/vulnerabilities?kev=1");
    expect(safeHref("mailto:someone@example.net")).toBe("mailto:someone@example.net");
    expect(safeHref("#ladder")).toBe("#ladder");
    expect(safeHref("?offset=50")).toBe("?offset=50");
  });

  it("refuses the schemes that script, a protocol-relative address and a control character", () => {
    for (const bad of ["javascript:alert(1)", " JaVaScRiPt:alert(1)", "data:text/html,x", "vbscript:x", "//evil.example", "example.net/a", "", "   "]) {
      expect(safeHref(bad)).toBeNull();
    }
    expect(safeHref("https://example.net/\u0000")).toBeNull();
    expect(safeHref("https://example.net/a\r\nb")).toBeNull();
  });
});

describe("the html template", () => {
  it("puts a whole href or src through the same rule, so a page cannot forget to", () => {
    expect(html`<a href="${"javascript:alert(1)"}">x</a>`.value).toBe('<a href="#">x</a>');
    expect(html`<img src="${"javascript:alert(1)"}">`.value).toBe('<img src="#">');
    expect(html`<a href='${"/\\evil.example"}'>x</a>`.value).toBe('<a href=\'#\'>x</a>');
    expect(html`<a\nhref="${"data:text/html,x"}">x</a>`.value).toBe('<a\nhref="#">x</a>');
  });

  it("leaves an address it was given whole, and escapes it as it always did", () => {
    expect(html`<a href="${"https://example.net/a?b=1&c=2"}">x</a>`.value).toBe('<a href="https://example.net/a?b=1&amp;c=2">x</a>');
    expect(html`<a href="${"/vulnerabilities?kev=1"}">x</a>`.value).toBe('<a href="/vulnerabilities?kev=1">x</a>');
  });

  it("does not touch a hole in the middle of an address, whose literal prefix already says where it points", () => {
    const hash = "a".repeat(64);
    expect(html`<img src="/img/${hash}">`.value).toBe(`<img src="/img/${hash}">`);
    expect(html`<a href="${"https://example.net"}/a">x</a>`.value).toBe('<a href="https://example.net/a">x</a>');
  });

  it("leaves text that merely mentions one alone", () => {
    expect(html`<p>${"javascript:alert(1)"}</p>`.value).toBe("<p>javascript:alert(1)</p>");
  });
});

describe("the guard on a host the app may fetch", () => {
  it("refuses the special-purpose ranges a network can really carry a host on", () => {
    for (const ip of ["192.0.0.1", "198.18.0.1", "198.19.255.255", "2001::1", "100::1"]) {
      expect(privateAddress(ip), ip).toBe(true);
    }
  });

  it("leaves the documentation ranges public, because they are this project's own placeholder", () => {
    // They route nowhere, so refusing them stops nothing; every test, fixture and guide here
    // writes "a public address" as one of these, and a block would cost each of them a case.
    for (const ip of ["192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1"]) {
      expect(privateAddress(ip), ip).toBe(false);
    }
  });

  it("still refuses what it always did, and still allows a public host", () => {
    for (const ip of ["127.0.0.1", "0.0.0.0", "10.1.2.3", "169.254.169.254", "172.16.0.1", "192.168.1.1", "100.64.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::"]) {
      expect(privateAddress(ip), ip).toBe(true);
    }
    for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2001:4860:4860::8888", "2606:2800:220:1:248:1893:25c8:1946"]) {
      expect(privateAddress(ip), ip).toBe(false);
    }
  });
});

describe("cookies", () => {
  it("takes the first of a repeated name, which is the one this app set", () => {
    // A browser sends the host-only cookie before one a sibling host set for the shared parent
    // domain, so the neighbour cannot shadow the session, the look or the notice.
    expect(parseCookies("bw_session=ours; bw_session=theirs").bw_session).toBe("ours");
    expect(parseCookies("bw_look=console; bw_look=register").bw_look).toBe("console");
  });

  it("still reads an ordinary header, and an encoded value", () => {
    expect(parseCookies("a=1; b=two%20words")).toEqual({ a: "1", b: "two words" });
    expect(parseCookies(undefined)).toEqual({});
  });
});

describe("the one-shot notice", () => {
  it("fits in a cookie a browser will keep, whichever field ran long", () => {
    for (const payload of [
      "a".repeat(100_000),
      { sourceId: "s", status: "ok", detail: "d".repeat(100_000) },
      // No `detail` at all: the old shrink only cut that one field, so this never got smaller.
      { sourceId: "s".repeat(100_000), status: "ok" },
    ]) {
      expect(flashHeader(payload, false).length).toBeLessThan(4096);
    }
  });

  it("carries a short notice through unchanged", () => {
    expect(flashHeader("Saved.", true)).toContain(`bw_notice=${encodeURIComponent('"Saved."')}`);
    expect(flashHeader("Saved.", true)).toContain("Secure");
  });
});

describe("a CSV cell", () => {
  it("is not a formula behind a leading control character or space", () => {
    for (const value of ["\u0000=1+1", "\u000b=1+1", " =1+1", "\t=1+1", "\u0085@SUM(1)", "  -2+3+cmd|' /C calc'!A0"]) {
      const cell = csvCell(value);
      expect(cell.replace(/^"/, "").startsWith("'"), value).toBe(true);
    }
  });

  it("leaves a plain value, and a plain negative number, alone", () => {
    expect(csvCell("CVE-2026-1234")).toBe("CVE-2026-1234");
    expect(csvCell("-12.5")).toBe("-12.5");
    expect(csvCell('say "hi", twice')).toBe('"say ""hi"", twice"');
  });
});

describe("the multipart reader", () => {
  it("accepts the space a client may put before the parameter, and refuses an empty quoted boundary", () => {
    expect(boundaryOf("multipart/form-data ; boundary=abc")).toBe("abc");
    expect(boundaryOf('multipart/form-data; boundary="abc"')).toBe("abc");
    // Not the two quote characters, which no part can carry.
    expect(boundaryOf('multipart/form-data; boundary=""')).toBeNull();
    expect(boundaryOf("multipart/form-data; boundary=")).toBeNull();
    expect(boundaryOf("application/json")).toBeNull();
  });
});

describe("the blob store", () => {
  it("reads a value that is not a digest as nothing, rather than throwing out of a route", () => {
    expect(getBlob("/nowhere", "../../etc/passwd")).toBeNull();
    expect(getBlob("/nowhere", "")).toBeNull();
    expect(getBlob("/nowhere", "a".repeat(64))).toBeNull();
  });
});

describe("the MCP endpoint", () => {
  it("takes a request the size a tool call is, not the SDK's four megabytes", () => {
    expect(maxMcpRequestBytes).toBe(256 * 1024);
  });

  it("holds an anonymous caller to its allowance", async () => {
    // Single-user mode (no password) has no anonymous caller to hold: a password is what makes
    // the difference between the owner, who is not counted, and everyone else, who is.
    const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" }, now: () => now });
    try {
      const call = (): Promise<Response> =>
        fetch(`${app.base}/mcp`, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
        });
      for (let n = 0; n < 120; n += 1) expect((await call()).status).toBe(200);
      const over = await call();
      expect(over.status).toBe(429);
      expect(over.headers.get("retry-after")).toBe("60");
    } finally {
      await app.close();
    }
  });
});

describe("the CVE list over the API", () => {
  const critical = { cvssMetricV31: [{ source: "nvd@nist.gov", type: "Primary", cvssData: { version: "3.1", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", baseScore: 9.8, baseSeverity: "CRITICAL" } }] };
  const record = (cve: string, metrics: unknown = critical): { cve: NvdCve } => ({
    cve: {
      id: cve,
      sourceIdentifier: "nvd@nist.gov",
      published: "2026-10-01T00:00:00.000",
      lastModified: "2026-10-20T00:00:00.000",
      vulnStatus: "Analyzed",
      descriptions: [{ lang: "en", value: `a flaw in ${cve}` }],
      metrics,
    } as NvdCve,
  });

  it("reads severity, which only the page could filter on before", () => {
    const db = openDatabase(":memory:");
    try {
      migrate(db);
      storeNvdRecords({ db, now: () => now }, [record("CVE-2026-0001"), record("CVE-2026-0002", {})]);
      expect(apiVulns(db, {}, now).total).toBe(2);
      const onlyCritical = apiVulns(db, { severity: "critical" }, now);
      expect(onlyCritical.total).toBe(1);
      expect(onlyCritical.vulns[0]?.cve).toBe("CVE-2026-0001");
      expect(apiVulns(db, { severity: "unscored" }, now).total).toBe(1);
      // A filter this build has no such value for narrows nothing rather than erring.
      expect(apiVulns(db, { severity: "catastrophic" }, now).total).toBe(2);
    } finally {
      db.close();
    }
  });

  it("keeps limit and since, the two the API has always had of its own", () => {
    const db = openDatabase(":memory:");
    try {
      migrate(db);
      storeNvdRecords({ db, now: () => now }, [record("CVE-2026-0001"), record("CVE-2026-0002")]);
      expect(apiVulns(db, { limit: "1" }, now).vulns).toHaveLength(1);
      expect(apiVulns(db, { limit: "1" }, now).total).toBe(2);
      expect(apiVulns(db, { since: "2030-01-01" }, now).total).toBe(0);
    } finally {
      db.close();
    }
  });
});
