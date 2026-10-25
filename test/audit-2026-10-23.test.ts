import { describe, expect, it } from "vitest";
import { storeNvdRecords, type NvdCve } from "../src/adapters/nvd.ts";
import { loadConfig } from "../src/config.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { withheldReleaseSummary } from "../src/register.ts";
import { renderLatex } from "../src/report.ts";
import { startTestApp } from "./helpers.ts";

/**
 * The code audit of 2026-10-23 and what it changed: the sign-in brake on the connection's own
 * address, the proxy trust as a setting, a malformed NVD record skipped rather than stalling the
 * stream, a licensed source's release summary withheld from the API and the feeds, and the
 * LaTeX escaper's backslash.
 */

const now = new Date("2026-10-23T12:00:00Z");

describe("the sign-in brake", () => {
  it("counts the connection's own address too, so a believed peer cannot start afresh by forging X-Forwarded-For", async () => {
    const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" }, now: () => now });
    try {
      // The test client arrives from loopback, which the default trust believes: the forged header is taken as the address.
      const attempt = (n: number): Promise<Response> =>
        fetch(`${app.base}/login`, {
          method: "POST",
          redirect: "manual",
          headers: { "content-type": "application/x-www-form-urlencoded", origin: app.base, "sec-fetch-site": "same-origin", "x-forwarded-for": `10.9.${Math.floor(n / 200)}.${(n % 200) + 1}` },
          body: new URLSearchParams({ password: "wrong", next: "/" }).toString(),
        });
      // Each forged address starts its own count of five, so the per-address brake alone never engages…
      for (let n = 0; n < 40; n += 1) expect((await attempt(n)).status).toBe(401);
      // …but the peer has now failed forty times, and the forty-first try is refused whatever it claims.
      expect((await attempt(40)).status).toBe(429);
    } finally {
      await app.close();
    }
  });

  it("reads the proxies to believe from the environment, with the former behaviour as the default", () => {
    expect(loadConfig({}).trustedProxies).toBe("loopback, linklocal, uniquelocal");
    expect(loadConfig({ BW_TRUSTED_PROXIES: "172.17.0.1" }).trustedProxies).toBe("172.17.0.1");
  });
});

describe("the NVD stream", () => {
  it("skips a malformed record and says so, rather than failing the page on every run", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const lines: string[] = [];
    const good: { cve: NvdCve } = {
      cve: { id: "CVE-2026-77001", sourceIdentifier: "cve@mitre.org", published: "2026-10-19T08:31:40.984", lastModified: "2026-10-19T17:50:00.000", vulnStatus: "Analyzed", descriptions: [{ lang: "en", value: "A flaw." }], metrics: {} },
    };
    const bad = { cve: { sourceIdentifier: "cve@mitre.org", published: "2026-10-19T08:31:40.984", lastModified: "2026-10-19T17:50:00.000", descriptions: "not a list" } };
    const stored = storeNvdRecords({ db, now: () => now, log: (l) => lines.push(l) }, [bad as never, good]);
    expect(stored).toMatchObject({ inserted: 1, skipped: 1 });
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^\[nvd\] skipped a record \(no id\): /);
    expect(db.prepare("SELECT cve_id FROM vulns").all()).toEqual([{ cve_id: "CVE-2026-77001" }]);
    db.close();
  });
});

describe("a licensed source's release entry", () => {
  it("is withheld from the API and the feeds, while the page keeps it", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      const at = now.toISOString();
      app.db
        .prepare("INSERT INTO items (source_id, kind, external_id, title, url, summary, published_at, fetched_at) VALUES ('microsoft-sct', 'release', 'sct-2026-10', 'Microsoft Security Baselines 2026-10: 1 added', '/register', ?, ?, ?)")
        .run("Added: machine|HKLM\\Software\\Policies\\Example\\Setting", at, at);
      const api = (await (await fetch(`${app.base}/api/v1/items?source=microsoft-sct`)).json()) as { items: { summary: string | null }[] };
      expect(api.items).toHaveLength(1);
      expect(api.items[0]?.summary).toBe(withheldReleaseSummary);
      const feed = await (await fetch(`${app.base}/feed.xml?source=microsoft-sct`)).text();
      expect(feed).not.toContain("HKLM");
      expect(feed).toContain("withheld under the publisher");
      const page = await (await fetch(`${app.base}/?source=microsoft-sct`)).text();
      expect(page).toContain("HKLM");
    } finally {
      await app.close();
    }
  });
});

describe("the LaTeX escaper", () => {
  it("escapes a backslash once, without escaping the braces its own replacement brings", () => {
    const tex = renderLatex([{ type: "p", runs: ["a\\b{c} and 50% of $x"] }]);
    expect(tex).toContain("a\\textbackslash{}b\\{c\\} and 50\\% of \\$x");
    expect(tex).not.toContain("\\textbackslash\\{\\}");
  });
});
