import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { plainText } from "../src/adapters/types.ts";
import { parseCookies, throttleKey } from "../src/auth.ts";
import { csvCell, csvLine } from "../src/csv.ts";
import { assertPublicUrl, httpGet, privateAddress } from "../src/http.ts";
import { safeUrl } from "../src/items.ts";
import { renderLatex, renderPdf } from "../src/report.ts";
import { relativeTime } from "../src/time.ts";
import { startTestApp, type TestApp } from "./helpers.ts";

/**
 * The security and bug sweep of 2026-10-19: each test pins one fix so it cannot quietly come back.
 */

describe("outbound fetching", () => {
  let server: Server | null = null;
  afterEach(async () => {
    await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
    server = null;
  });

  it("knows a private address from a public one", () => {
    for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.8.10", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "::", "fe80::1", "fc00::1", "fd12::1", "::ffff:192.168.1.1"]) {
      expect(privateAddress(ip), ip).toBe(true);
    }
    for (const ip of ["8.8.8.8", "1.1.1.1", "172.32.0.1", "2606:4700::1111", "::ffff:8.8.8.8"]) expect(privateAddress(ip), ip).toBe(false);
  });

  it("refuses a feed-supplied URL that points inside", async () => {
    await expect(assertPublicUrl("http://127.0.0.1:8790/")).rejects.toThrow(/not a public host/);
    await expect(assertPublicUrl("http://localhost/x")).rejects.toThrow(/not a public host/);
    await expect(assertPublicUrl("http://169.254.169.254/latest/meta-data")).rejects.toThrow(/not a public host/);
    await expect(assertPublicUrl("file:///etc/passwd")).rejects.toThrow(/refusing file:/);
    await expect(assertPublicUrl("javascript:alert(1)")).rejects.toThrow(/refusing/);
    // The guard holds through a redirect: the first hop is public in name only when it answers from here.
    await expect(httpGet("http://127.0.0.1:1/", { publicOnly: true, timeoutMs: 2000 })).rejects.toThrow(/not a public host/);
  });

  it("caps a streamed body that declares no length, and refuses a redirect when told to", async () => {
    server = createServer((req, res) => {
      if (req.url === "/big") {
        res.writeHead(200, { "content-type": "application/octet-stream" });
        const chunk = Buffer.alloc(64 * 1024, 1);
        let sent = 0;
        const pump = () => {
          while (sent < 4 * 1024 * 1024) {
            sent += chunk.length;
            if (!res.write(chunk)) return void res.once("drain", pump);
          }
          res.end();
        };
        pump();
      } else if (req.url === "/go") {
        res.writeHead(302, { location: "/big" });
        res.end();
      } else {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("ok");
      }
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    await expect(httpGet(`${base}/big`, { maxBytes: 256 * 1024 })).rejects.toThrow(/exceeds the 262144 byte limit/);
    await expect(httpGet(`${base}/go`, { redirect: "manual" })).rejects.toThrow(/HTTP 302/);
    const followed = await httpGet(`${base}/go`, { maxBytes: 8 * 1024 * 1024 });
    expect(followed.bytes.byteLength).toBe(4 * 1024 * 1024);
    expect((await httpGet(`${base}/small`)).bytes.byteLength).toBe(2);
  });
});

describe("text and links from feeds", () => {
  it("keeps only web links and the site's own paths", () => {
    expect(safeUrl("https://example.test/a?b=1")).toBe("https://example.test/a?b=1");
    expect(safeUrl("/vulnerabilities/CVE-2026-1")).toBe("/vulnerabilities/CVE-2026-1");
    expect(safeUrl("javascript:alert(document.cookie)")).toBeNull();
    expect(safeUrl("data:text/html,hi")).toBeNull();
    expect(safeUrl("//evil.example/")).toBeNull();
    expect(safeUrl("  ")).toBeNull();
  });

  it("does not throw on a numeric entity past the last code point", () => {
    expect(plainText("hello &#99999999; world")).toBe("hello &#99999999; world");
    expect(plainText("a &#x110000; b &#65; &amp;")).toBe("a &#x110000; b A &");
  });

  it("reads a future stamp as a date, not as just now", () => {
    const now = new Date("2026-10-19T12:00:00Z");
    expect(relativeTime("2026-10-19T11:59:30Z", now)).toBe("just now");
    expect(relativeTime("2026-10-19T12:00:20Z", now)).toBe("just now");
    expect(relativeTime("2026-10-21T12:00:00Z", now)).toBe("Wed 21 Oct");
    expect(relativeTime("2027-03-01T00:00:00Z", now)).toBe("1 Mar 2027");
    expect(relativeTime("2026-10-19T09:00:00Z", now)).toBe("3 h ago");
  });
});

describe("downloads", () => {
  it("never writes a cell a spreadsheet would run", () => {
    expect(csvCell('=HYPERLINK("https://evil","x")')).toBe(`"'=HYPERLINK(""https://evil"",""x"")"`);
    expect(csvCell("+1 (555) 0100")).toBe("'+1 (555) 0100");
    expect(csvCell("@everyone")).toBe("'@everyone");
    expect(csvCell("-cmd|' /C calc'!A0")).toBe("'-cmd|' /C calc'!A0");
    expect(csvCell("-1")).toBe("-1");
    expect(csvCell("-0.5")).toBe("-0.5");
    expect(csvCell("\t=1+1")).toBe("'=1+1");
    expect(csvCell('say "hi", twice')).toBe(`"say ""hi"", twice"`);
    expect(csvLine(["a", null, 3])).toBe("a,,3");
  });

  it("keeps a check procedure inside its Verbatim block and folds what LaTeX cannot carry", () => {
    const tex = renderLatex([
      { type: "h2", text: "Hostile → check ≥ 1 — ok… 日本" },
      { type: "code", text: "Run this.\n\\end{Verbatim}\n\\input{/etc/passwd}\n\\end {Verbatim}" },
    ]);
    expect(tex).toContain("Hostile $\\rightarrow$ check $\\geq$ 1 --- ok\\ldots{} ??");
    expect(tex).toContain("\\begin{Verbatim}[fontsize=\\small,breaklines=true]\nRun this.\n\\end {Verbatim}\n\\input{/etc/passwd}\n\\end {Verbatim}\n\\end{Verbatim}");
    expect(tex).toContain("\\usepackage{fvextra}");
    expect(tex.indexOf("\\input{/etc/passwd}")).toBeGreaterThan(tex.indexOf("\\begin{Verbatim}"));
    expect(tex.indexOf("\\input{/etc/passwd}")).toBeLessThan(tex.indexOf("\n\\end{Verbatim}"));
  });

  it("keeps the lines of a procedure in the PDF", () => {
    const pdf = Buffer.from(renderPdf([{ type: "code", text: "line one\r\nline\ttwo" }])).toString("latin1");
    expect(pdf).toContain("(line one)");
    expect(pdf).toContain("(line  two)");
    expect(pdf).not.toContain("line one?line");
  });
});

describe("requests", () => {
  it("survives a cookie it did not set, and throttles an IPv6 client by its prefix", () => {
    expect(parseCookies("x=100%; bw_session=abc")).toEqual({ x: "100%", bw_session: "abc" });
    expect(parseCookies("a=%7B%22b%22%3A1%7D")).toEqual({ a: '{"b":1}' });
    expect(throttleKey("203.0.113.9")).toBe("203.0.113.9");
    expect(throttleKey("::ffff:203.0.113.9")).toBe("203.0.113.9");
    expect(throttleKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd")).toBe("2001:0db8:0001:0002::/64");
    expect(throttleKey("2001:db8:1:2::1")).toBe(throttleKey("2001:db8:1:2:ffff::1"));
    expect(throttleKey("2001:db8:1:2::1")).not.toBe(throttleKey("2001:db8:1:3::1"));
    expect(throttleKey(undefined)).toBe("unknown");
  });

  describe("against the app", () => {
    let app: TestApp;
    afterEach(async () => {
      await app?.close();
    });

    it("answers crafted query strings and cookies with a page, not a 500", async () => {
      app = await startTestApp();
      for (const path of ["/?q=%00", "/vulnerabilities?q=%00", "/api/v1/items?q=%00", "/vulnerabilities?offset=1e300", "/api/v1/vulns?offset=1.5", "/vulnerabilities?offset=-5&changed=abc&new=999999"]) {
        expect((await fetch(`${app.base}${path}`)).status, path).toBe(200);
      }
      expect((await fetch(`${app.base}/`, { headers: { cookie: "x=100%" } })).status).toBe(200);
      expect((await fetch(`${app.base}/nope`, { headers: { cookie: "x=100%" } })).status).toBe(404);
      // A POST with no body at all (no form, no content type) is answered, not thrown at.
      expect((await fetch(`${app.base}/login`, { method: "POST", headers: { "sec-fetch-site": "same-origin", origin: app.base }, redirect: "manual" })).status).toBe(303);
      expect((await fetch(`${app.base}/look`, { method: "POST", headers: { "sec-fetch-site": "same-origin", origin: app.base }, redirect: "manual" })).status).toBe(303);
    });

    it("tells a closed instance's health to the owner alone, and keeps the data directory off the public page", async () => {
      app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2", BW_PUBLIC_READ: "false" } });
      const closed = (await (await fetch(`${app.base}/health`)).json()) as Record<string, unknown>;
      expect(closed.ok).toBe(true);
      expect(closed.database).toBeUndefined();
      const open = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" } });
      try {
        const page = await (await fetch(`${open.base}/register`)).text();
        expect(page).toContain("<dt>Data</dt><dd>set</dd>");
        expect(page).not.toContain(open.dataDir);
      } finally {
        await open.close();
      }
    });
  });
});
