import { afterEach, describe, expect, it } from "vitest";
import { cisKey, cisRequirements, parseCisText } from "../src/adapters/cis.ts";
import { nistCatalogAdapter } from "../src/adapters/oscal-nist.ts";
import { storeNvdRecords, type NvdResponse } from "../src/adapters/nvd.ts";
import { getSource, ingestDocumentTarget, ingestSource } from "../src/ingest.ts";
import { boundaryOf, parseMultipart } from "../src/multipart.ts";
import { latestDocument, releaseChanges } from "../src/register.ts";
import { setTriage } from "../src/triage.ts";
import { cookieFrom, fakeHttp, fixture, formPost, startTestApp, type TestApp } from "./helpers.ts";
import { simplePdf } from "./pdf-helper.ts";

const at = new Date("2026-10-15T08:00:00Z");

const benchmarkV1 = [
  "CIS Ubuntu Linux 24.04 LTS Benchmark",
  "v1.0.0 - 08-30-2024",
  "Table of Contents",
  "1.1.1 (L1) Ensure cramfs kernel module is not available (Automated) ........ 23",
  "1 Initial Setup",
  "1.1.1 (L1) Ensure cramfs kernel module is not available (Automated)",
  "Profile Applicability:",
  "Level 1 - Server",
  "Description:",
  "The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small",
  "footprint systems.",
  "Rationale:",
  "Removing support for unneeded filesystem types reduces the local attack surface of the server.",
  "Audit:",
  "Run the following script to verify cramfs is not loaded.",
  "Remediation:",
  "Run the following script to disable cramfs.",
  "Default Value:",
  "cramfs is available.",
  "CIS Controls:",
  "v8 4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
  "Page 24",
  "1.1.2 (L1) Ensure /tmp is a separate partition (Automated)",
  "Profile Applicability:",
  "Level 1 - Server",
  "Description:",
  "The /tmp directory is a world-writable directory used for temporary storage by all users.",
  "Rationale:",
  "Making /tmp its own file system allows an administrator to set noexec on it.",
  "Audit:",
  "Run findmnt --kernel /tmp.",
  "Remediation:",
  "Create or update an entry for /tmp in /etc/fstab.",
  "Page 27",
];

describe("CIS Benchmarks", () => {
  it("reads recommendations out of a benchmark's text, ignoring the table of contents", () => {
    const parsed = parseCisText(benchmarkV1.join("\n"));
    expect(parsed.title).toBe("CIS Ubuntu Linux 24.04 LTS Benchmark");
    expect(parsed.version).toBe("1.0.0");
    expect(parsed.recommendations.map((r) => r.number)).toEqual(["1.1.1", "1.1.2"]);
    const first = parsed.recommendations[0]!;
    expect(first).toMatchObject({ level: "L1", title: "Ensure cramfs kernel module is not available", assessment: "Automated" });
    expect(first.sections.Description).toBe("The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems.");
    expect(first.sections["Default Value"]).toBe("cramfs is available.");
    const reqs = cisRequirements(parsed);
    expect(reqs[0]).toMatchObject({ ref: "1.1.1", parentRef: "1.1", family: "1", label: "1.1.1", statement: "Run the following script to disable cramfs.", sortKey: "001.001.001" });
    expect(reqs[0]?.guidance).toContain("Removing support for unneeded filesystem types");
    expect(reqs[0]?.related).toEqual(["v8 4.8"]);
    expect(reqs[0]?.extra).toMatchObject({ level: "L1", assessment: "Automated", profiles: "Level 1 - Server" });
    expect(cisKey("CIS Ubuntu Linux 24.04 LTS Benchmark", "x.pdf")).toBe("cis:ubuntu-linux-24-04-lts");
    expect(cisKey(null, "CIS_Microsoft_Windows_11_Benchmark_v3.pdf")).toBe("cis:cis-microsoft-windows-11-benchmark-v3");
    expect(parseCisText("nothing here").recommendations).toEqual([]);
  });

  it("parses a multipart form with a file and fields", () => {
    const boundary = "----bw";
    const body = new TextEncoder().encode(
      `--${boundary}\r\nContent-Disposition: form-data; name="version"\r\n\r\nv1.0.0\r\n--${boundary}\r\nContent-Disposition: form-data; name="pdf"; filename="C:\\Users\\x\\CIS.pdf"\r\nContent-Type: application/pdf\r\n\r\n%PDF-1.4 bytes\r\n--${boundary}--\r\n`,
    );
    const form = parseMultipart(body, boundary);
    expect(form.fields).toEqual({ version: "v1.0.0" });
    expect(form.files).toHaveLength(1);
    expect(form.files[0]).toMatchObject({ field: "pdf", filename: "CIS.pdf", contentType: "application/pdf" });
    expect(new TextDecoder().decode(form.files[0]!.bytes)).toBe("%PDF-1.4 bytes");
    expect(boundaryOf('multipart/form-data; boundary="abc"')).toBe("abc");
    expect(boundaryOf("multipart/form-data; boundary=abc")).toBe("abc");
    expect(boundaryOf("application/json")).toBeNull();
  });
});

describe("uploads and the API over HTTP", () => {
  let app: TestApp;
  afterEach(async () => {
    await app?.close();
  });

  async function upload(base: string, cookie: string | undefined, pdf: Uint8Array, filename: string, fields: Record<string, string> = {}): Promise<Response> {
    const boundary = "----bwtest";
    const parts: Uint8Array[] = [];
    const enc = new TextEncoder();
    for (const [k, v] of Object.entries(fields)) parts.push(enc.encode(`--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`));
    parts.push(enc.encode(`--${boundary}\r\nContent-Disposition: form-data; name="pdf"; filename="${filename}"\r\nContent-Type: application/pdf\r\n\r\n`));
    parts.push(pdf);
    parts.push(enc.encode(`\r\n--${boundary}--\r\n`));
    const total = parts.reduce((n, p) => n + p.length, 0);
    const body = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
      body.set(p, offset);
      offset += p.length;
    }
    const headers: Record<string, string> = { "content-type": `multipart/form-data; boundary=${boundary}`, origin: base, "sec-fetch-site": "same-origin" };
    if (cookie) headers.cookie = cookie;
    return fetch(`${base}/uploads/cis`, { method: "POST", headers, body, redirect: "manual" });
  }

  it("loads a CIS benchmark by upload and diffs the next upload against it", async () => {
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2", BW_BASE_URL: "https://cybercard.net" }, now: () => at });
    const v1 = simplePdf(benchmarkV1);
    expect((await upload(app.base, undefined, v1, "cis-v1.pdf")).status).toBe(403);
    const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
    const first = await upload(app.base, cookie, v1, "cis-v1.pdf", { published: "2024-08-30" });
    expect(first.status).toBe(303);
    expect(decodeURIComponent(first.headers.get("location") ?? "")).toContain("loaded as cis:ubuntu-linux-24-04-lts 1.0.0: first version, 2 requirements");
    const doc = latestDocument(app.db, "cis-benchmarks", "cis:ubuntu-linux-24-04-lts")!;
    expect(doc).toMatchObject({ version_label: "1.0.0", requirement_count: 2, published_at: "2024-08-30T00:00:00.000Z" });

    const again = await upload(app.base, cookie, v1, "cis-v1.pdf");
    expect(decodeURIComponent(again.headers.get("location") ?? "")).toContain("was already loaded");

    const v2Text = benchmarkV1.map((l) => l.replace("v1.0.0 - 08-30-2024", "v1.1.0 - 03-01-2025").replace("Run the following script to disable cramfs.", "Run the following script to disable and blacklist cramfs."));
    v2Text.push("1.1.3 (L2) Ensure nodev option set on /tmp partition (Automated)", "Description:", "The nodev mount option specifies that the filesystem cannot contain special devices.", "Remediation:", "Edit /etc/fstab.");
    const second = await upload(app.base, cookie, simplePdf(v2Text), "cis-v2.pdf");
    expect(decodeURIComponent(second.headers.get("location") ?? "")).toContain("1.1.0: 1 added, 1 revised");
    const latest = latestDocument(app.db, "cis-benchmarks", "cis:ubuntu-linux-24-04-lts")!;
    expect(releaseChanges(app.db, latest.id).map((c) => [c.ref, c.kind, c.field])).toEqual(expect.arrayContaining([["1.1.3", "added", null], ["1.1.1", "modified", "statement"]]));
    const page = await (await fetch(`${app.base}/standards/cis-benchmarks/${latest.id}/1.1.1`)).text();
    expect(page).toContain("<ins>");
    expect(page).toContain("blacklist");
    const standard = await (await fetch(`${app.base}${second.headers.get("location")}`, { headers: { cookie } })).text();
    expect(standard).toContain("Upload a benchmark PDF");
    expect(standard).toContain("cis-v2.pdf loaded");
    expect(standard).toContain("1.1.0");

    const bad = await upload(app.base, cookie, simplePdf(["Not a benchmark at all."]), "x.pdf");
    expect(bad.status).toBe(422);
    expect(await bad.text()).toContain("no CIS recommendations found");
    const sources = await (await fetch(`${app.base}/sources`, { headers: { cookie } })).text();
    expect(sources).toContain('href="/standards/cis-benchmarks">Upload</a>');
    const fetched = await ingestSource(app.db, app.dataDir, getSource(app.db, "cis-benchmarks")!, { http: fakeHttp({}), now: () => at });
    expect(fetched.status).toBe("skipped");
  });

  it("serves the read-only API with the same shapes the pages use", async () => {
    app = await startTestApp({ env: { BW_BASE_URL: "https://cybercard.net" }, now: () => at });
    const kev = getSource(app.db, "cisa-kev")!;
    await ingestSource(app.db, app.dataDir, kev, { http: fakeHttp({ [kev.url]: { bytes: fixture("kev.json") } }), now: () => at });
    storeNvdRecords({ db: app.db, now: () => at }, (JSON.parse(new TextDecoder().decode(fixture("nvd-window.json"))) as NvdResponse).vulnerabilities!);
    const nist = getSource(app.db, "nist-sp-800-53")!;
    const http = fakeHttp({ "https://c/511.json": { bytes: fixture("oscal-catalog-5.1.1.json") }, "https://c/520.json": { bytes: fixture("oscal-catalog-5.2.0.json") } });
    await ingestDocumentTarget(app.db, app.dataDir, nist, nistCatalogAdapter, { key: "catalog", url: "https://c/511.json" }, { http, now: () => at });
    await ingestDocumentTarget(app.db, app.dataDir, nist, nistCatalogAdapter, { key: "catalog", url: "https://c/520.json" }, { http, now: () => at });
    const vulnId = (app.db.prepare("SELECT id FROM vulns WHERE cve_id = 'CVE-2021-44228'").get() as { id: number }).id;
    setTriage(app.db, { kind: "vuln", id: vulnId }, { state: "affects", note: "Patched." }, at.toISOString());

    const items = (await (await fetch(`${app.base}/api/v1/items?kind=kev&limit=2`)).json()) as { items: { kind: string; title: string; signals: { dueDate?: string } }[] };
    expect(items.items).toHaveLength(2);
    expect(items.items[0]).toMatchObject({ kind: "kev" });
    expect(items.items[0]?.signals.dueDate).toBeTruthy();

    const vulns = (await (await fetch(`${app.base}/api/v1/vulns?kev=1`)).json()) as { total: number; vulns: { cve: string; kev: unknown; cvss: { score: number } }[] };
    expect(vulns.total).toBe(1);
    expect(vulns.vulns[0]).toMatchObject({ cve: "CVE-2021-44228", cvss: { score: 10 } });
    const one = (await (await fetch(`${app.base}/api/v1/vulns/cve-2021-44228`)).json()) as { cve: string; cpes: string[]; history: { field: string }[] };
    expect(one.cve).toBe("CVE-2021-44228");
    expect(one.cpes.length).toBeGreaterThan(0);
    expect(one.history[0]?.field).toBe("new");
    expect((await fetch(`${app.base}/api/v1/vulns/CVE-2026-0`)).status).toBe(404);

    const standards = (await (await fetch(`${app.base}/api/v1/standards`)).json()) as { standards: { id: string; versions: { version: string | null; url: string }[] }[] };
    const catalog = standards.standards.find((s) => s.id === "nist-sp-800-53")!;
    expect(catalog.versions.map((v) => v.version)).toEqual(["5.2.0", "5.1.1+u4"]);
    expect(catalog.versions[0]?.url).toMatch(/^https:\/\/cybercard\.net\/standards\/nist-sp-800-53\/\d+$/);

    const changes = (await (await fetch(`${app.base}/api/v1/changes?source=nist-sp-800-53`)).json()) as { changes: { ref: string; kind: string; label: string | null; url: string }[] };
    expect(changes.changes.some((c) => c.ref === "sa-24" && c.kind === "added" && c.label === "SA-24")).toBe(true);
    expect(changes.changes[0]?.url).toContain("https://cybercard.net/standards/nist-sp-800-53/");

    const triage = (await (await fetch(`${app.base}/api/v1/triage?state=affects`)).json()) as { triage: { kind: string; state: string; note: string | null; url: string }[] };
    expect(triage.triage).toEqual([expect.objectContaining({ kind: "vuln", state: "affects", note: "Patched.", url: "https://cybercard.net/vulnerabilities/CVE-2021-44228" })]);
    const digest = (await (await fetch(`${app.base}/api/v1/digest`)).json()) as { digest: null };
    expect(digest.digest).toBeNull();
    const response = await fetch(`${app.base}/api/v1/items`);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("closes the API with the pages when reading is owner-only, and serves the typefaces", async () => {
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2", BW_PUBLIC_READ: "false" } });
    expect((await fetch(`${app.base}/api/v1/items`)).status).toBe(401);
    const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
    expect((await fetch(`${app.base}/api/v1/items`, { headers: { cookie } })).status).toBe(200);
    const font = await fetch(`${app.base}/assets/fonts/newsreader/newsreader-latin-wght-normal.woff2`);
    expect(font.status).toBe(200);
    expect(font.headers.get("content-type")).toMatch(/font\/woff2/);
    const css = await (await fetch(`${app.base}/assets/app.css`)).text();
    expect(css).toContain('font-family: "Newsreader Variable"');
  });
});
