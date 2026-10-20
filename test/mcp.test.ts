import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { nistCatalogAdapter } from "../src/adapters/oscal-nist.ts";
import type { HttpGet } from "../src/http.ts";
import { getSource, ingestDocumentTarget } from "../src/ingest.ts";
import { fixture, startTestApp, type TestApp } from "./helpers.ts";

const at = new Date("2026-10-15T01:00:00Z");

function nistHttp(): HttpGet {
  return async (url) => {
    const name = url.includes("941c978d14") ? "oscal-catalog-5.1.1.json" : "oscal-catalog-5.2.0.json";
    return { url, status: 200, notModified: false, bytes: fixture(name), etag: null, lastModified: null, contentType: "application/json" };
  };
}

async function connect(base: string): Promise<Client> {
  const client = new Client({ name: "test", version: "0" });
  // The SDK's Transport type lacks `| undefined` on optional members; see handleMcpRequest.
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`)) as unknown as Parameters<Client["connect"]>[0]);
  return client;
}

const textOf = (result: Awaited<ReturnType<Client["callTool"]>>): unknown => {
  const content = result.content as { type: string; text?: string }[];
  return JSON.parse(content[0]?.text ?? "null");
};

describe("the MCP server", () => {
  let app: TestApp | null = null;
  let client: Client | null = null;
  afterEach(async () => {
    await client?.close();
    await app?.close();
    client = null;
    app = null;
  });

  it("lists read-only tools and answers from the live database", async () => {
    app = await startTestApp({ now: () => at });
    const dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-mcp-"));
    try {
      const catalog = getSource(app.db, "nist-sp-800-53")!;
      for (const target of nistCatalogAdapter.history!(catalog)) await ingestDocumentTarget(app.db, dataDir, catalog, nistCatalogAdapter, target, { http: nistHttp(), now: () => at });
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
    client = await connect(app.base);
    const tools = await client.listTools();
    const names = tools.tools.map((t) => t.name).sort();
    expect(names).toEqual(["digest", "list_standards", "release", "requirement", "search_wire", "standard_changes", "triage", "vulnerabilities", "vulnerability"]);
    expect(tools.tools.every((t) => t.annotations?.readOnlyHint === true)).toBe(true);

    const standards = textOf(await client.callTool({ name: "list_standards", arguments: {} })) as { standards: { id: string; versions: { version: string | null }[] }[] };
    const nist = standards.standards.find((s) => s.id === "nist-sp-800-53")!;
    expect(nist.versions.map((v) => v.version)).toEqual(["5.2.0", "5.1.1+u4"]);

    const release = textOf(await client.callTool({ name: "release", arguments: { source: "nist-sp-800-53" } })) as { version: string; summary: string; counts: { added: number }; changes: { ref: string; kind: string }[]; reasons: { kind: string }[]; url: string };
    expect(release.version).toBe("5.2.0");
    expect(release.summary).toMatch(/^3 added/);
    expect(release.counts.added).toBe(3);
    expect(release.changes.some((c) => c.ref === "sa-24" && c.kind === "added")).toBe(true);
    expect(release.reasons.map((r) => r.kind)).toEqual(["publisher"]);
    expect(release.url).toMatch(/\/standards\/nist-sp-800-53\/\d+$/);

    const requirement = textOf(await client.callTool({ name: "requirement", arguments: { source: "nist-sp-800-53", ref: "SA-24" } })) as { label: string; title: string; changedIn: { kind: string; version: string | null }[] };
    expect(requirement.label).toBe("SA-24");
    expect(requirement.changedIn).toEqual([expect.objectContaining({ kind: "added", version: "5.2.0" })]);

    const changes = textOf(await client.callTool({ name: "standard_changes", arguments: { source: "nist-sp-800-53", limit: 5 } })) as { changes: unknown[] };
    expect(changes.changes).toHaveLength(5);
    // The owner's licensed copies (CIS, Microsoft) are quoted on screen only, never through a tool.
    for (const source of ["cis-benchmarks", "microsoft-sct"]) {
      const held = await client.callTool({ name: "requirement", arguments: { source, ref: "1.1.1" } });
      expect(held.isError).toBe(true);
      expect((held.content as { text: string }[])[0]?.text).toContain("licensed copy");
      expect((await client.callTool({ name: "release", arguments: { source } })).isError).toBe(true);
    }

    const wire = textOf(await client.callTool({ name: "search_wire", arguments: { kind: "release" } })) as { items: { title: string }[] };
    expect(wire.items.some((i) => /5\.2\.0: 3 added/.test(i.title))).toBe(true);

    const vulns = textOf(await client.callTool({ name: "vulnerabilities", arguments: { kev: true, limit: 10 } })) as { total: number; vulns: unknown[] };
    expect(vulns).toEqual({ total: 0, vulns: [] });
    const missing = await client.callTool({ name: "vulnerability", arguments: { id: "CVE-1999-0001" } });
    expect(missing.isError).toBe(true);

    expect(textOf(await client.callTool({ name: "digest", arguments: {} }))).toEqual({ digest: null });
    expect(textOf(await client.callTool({ name: "triage", arguments: {} }))).toEqual({ triage: [] });
  });

  it("is closed when reading is not public, and refuses the other verbs", async () => {
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2", BW_PUBLIC_READ: "false" } });
    await expect(connect(app.base)).rejects.toThrow(/Reading is not public/);
    const get = await fetch(`${app.base}/mcp`, { headers: { accept: "text/event-stream" } });
    expect(get.status).toBe(405);
    const del = await fetch(`${app.base}/mcp`, { method: "DELETE" });
    expect(del.status).toBe(405);
  });
});
