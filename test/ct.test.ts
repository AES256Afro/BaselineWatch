import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { crtshUrl, domainsKey, parseCrtsh } from "../src/adapters/crtsh.ts";
import { recentCerts } from "../src/ct.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { setSetting } from "../src/netscan.ts";
import { fakeHttp, fixture, startTestApp } from "./helpers.ts";

/** The certificate-transparency watch (Scan 2.0, S3): crt.sh's answer for cybercard.net as served on 2026-10-21, the fourteen newest. */

const now = new Date("2026-10-21T22:00:00Z");
const at = now.toISOString();
const text = () => new TextDecoder().decode(fixture("ct/cybercard.net.json"));

describe("crt.sh's answer", () => {
  it("becomes one entry per certificate, newest first, with the issuer's common name and the names on it", () => {
    const entries = parseCrtsh(text());
    expect(entries.length).toBe(14);
    expect(entries[0]).toMatchObject({ id: 29944619056, issuer: "Cloudflare TLS Issuing ECC CA 4", names: ["*.cybercard.net", "cybercard.net"], notBefore: "2026-09-29T19:33:02", notAfter: "2026-12-28T01:42:46" });
    expect(entries.some((e) => e.issuer === "WE1" && e.names.includes("www.cybercard.net"))).toBe(true);
    expect(() => parseCrtsh("<html>502</html>")).toThrow(/JSON list/);
  });
});

describe("the watch", () => {
  it("reads nothing with no domain listed, seeds a domain in silence, then makes a new certificate news", async () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-ct-"));
    try {
      const source = getSource(db, "crtsh")!;
      expect(source.enabled).toBe(1);
      const none = await ingestSource(db, dataDir, source, { http: fakeHttp({}), now: () => now });
      expect(none.status).toBe("ok");
      expect(none.detail).toContain("no domain listed");

      setSetting(db, domainsKey, "cybercard.net, example.org", at);
      const http = fakeHttp({ [crtshUrl("cybercard.net")]: { bytes: fixture("ct/cybercard.net.json") }, [crtshUrl("example.org")]: { status: 502 } });
      const first = await ingestSource(db, dataDir, source, { http, now: () => now });
      expect(first.status).toBe("ok");
      expect(first.items).toBe(14);
      // The first read seeds; the newest certificate is three weeks old, so nothing is news. The domain crt.sh refused is named.
      expect(first.detail).toBe("1 of 2 domain(s) read, 0 new certificate(s); crt.sh did not answer for 1 of them");
      expect(recentCerts(db, "cybercard.net").length).toBe(8);
      expect((db.prepare("SELECT COUNT(*) AS n FROM items WHERE source_id = 'crtsh'").get() as { n: number }).n).toBe(0);

      // A certificate logged since: one item, linking to crt.sh, saying what to make of it.
      const added = JSON.parse(text()) as Record<string, unknown>[];
      added.unshift({ issuer_ca_id: 1, issuer_name: "C=US, O=Let's Encrypt, CN=R13", common_name: "login.cybercard.net", name_value: "login.cybercard.net", id: 30000000001, not_before: "2026-10-21T08:00:00", not_after: "2027-01-19T08:00:00", serial_number: "01", result_count: 1 });
      const second = await ingestSource(db, dataDir, source, { http: fakeHttp({ [crtshUrl("cybercard.net")]: { text: JSON.stringify(added) }, [crtshUrl("example.org")]: { status: 502 } }), now: () => now });
      expect(second.inserted).toBe(1);
      const item = db.prepare("SELECT external_id, title, url, summary, published_at FROM items WHERE source_id = 'crtsh'").get() as { external_id: string; title: string; url: string; summary: string; published_at: string };
      expect(item).toMatchObject({ external_id: "cybercard.net:30000000001", title: "New certificate for login.cybercard.net (R13)", url: "https://crt.sh/?id=30000000001", published_at: "2026-10-21T08:00:00.000Z" });
      expect(item.summary).toContain("issued by R13. Expected?");
      // Read again: nothing new.
      const third = await ingestSource(db, dataDir, source, { http: fakeHttp({ [crtshUrl("cybercard.net")]: { text: JSON.stringify(added) }, [crtshUrl("example.org")]: { status: 502 } }), now: () => now });
      expect(third.inserted).toBe(0);
    } finally {
      db.close();
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it("is on the domain page for a listed domain", async () => {
    const app = await startTestApp({ now: () => now, dns: async () => ({ records: [], code: "nodata" }), tls: async () => ({ error: "ECONNREFUSED" }), http: fakeHttp({ [crtshUrl("cybercard.net")]: { bytes: fixture("ct/cybercard.net.json") } }) });
    try {
      setSetting(app.db, domainsKey, "cybercard.net", at);
      await ingestSource(app.db, app.dataDir, getSource(app.db, "crtsh")!, { http: fakeHttp({ [crtshUrl("cybercard.net")]: { bytes: fixture("ct/cybercard.net.json") } }), now: () => now });
      const page = await (await fetch(`${app.base}/scan/domain?name=cybercard.net`)).text();
      expect(page).toContain("Certificates in the transparency logs");
      expect(page).toContain('<a href="https://crt.sh/?id=29944619056" target="_blank" rel="noopener">*.cybercard.net, cybercard.net</a> <span class="small">Cloudflare TLS Issuing ECC CA 4 · from 2026-09-29 to 2026-12-28</span>');
      const other = await (await fetch(`${app.base}/scan/domain?name=other.example`)).text();
      expect(other).not.toContain("Certificates in the transparency logs");
    } finally {
      await app.close();
    }
  });
});
