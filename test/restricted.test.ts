import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterEach, describe, expect, it } from "vitest";
import { canaryCount } from "../src/adapters/blocklists.ts";
import { getSource } from "../src/ingest.ts";
import { changeSummaryFor, explanationsFor, latestDocument, loadRequirements, withheldReleaseSummary, type DocumentRow } from "../src/register.ts";
import { cookieFrom, fakeHttp, fixture, formPost, startTestApp, type TestApp } from "./helpers.ts";

/**
 * A licence-restricted source (sources.restricted): the OpenPhish canary set, whose Community
 * Feed terms forbid showing any part of the feed to third parties. The owner sees its entries on
 * the Register; a visitor sees versions and counts; the API and MCP tools return neither names
 * nor text to anyone. Everything keys off the column, so the same holds for any source so marked.
 */
const sourceId = "canary-phishing";
const feedUrl = "https://openphish.com/feed.txt";
const llmUrl = "http://ollama:11434";
const feed = new TextDecoder().decode(fixture("blocklists/openphish-feed.txt"));
const password = "hunter2hunter2";
const at = new Date("2026-10-19T12:00:00Z");

/** The one-shot notice cookie a POST sets for the page it redirects to. */
const flashOf = (response: Response): string => (response.headers.get("set-cookie") ?? "").split(";")[0] ?? "";

/** The feed without every URL on one host, so the set loses that name and gains the next lowest hash. */
function without(text: string, name: string): string {
  return text
    .split("\n")
    .filter((line) => {
      try {
        return new URL(line.trim()).hostname.toLowerCase().replace(/^www\./, "") !== name;
      } catch {
        return true;
      }
    })
    .join("\n");
}

interface Loaded {
  app: TestApp;
  cookie: string;
  v1: DocumentRow;
  v2: DocumentRow;
  /** Every name either version holds: thirteen, none of which may reach a visitor. */
  names: string[];
  removed: string;
  added: string;
}

/**
 * The owner signs in, turns the source on and fetches it twice: the real feed, then the feed
 * with one of the twelve hosts gone, so the second version is a release with one removal and one
 * addition. A local model is configured and would happily name the entries in a summary.
 */
async function loadTwoVersions(): Promise<Loaded> {
  const served = { text: feed };
  const http = fakeHttp({
    [feedUrl]: {
      get bytes() {
        return new TextEncoder().encode(served.text);
      },
      contentType: "text/plain",
    },
    [`${llmUrl}/api/generate`]: { text: JSON.stringify({ response: `The feed dropped ${feed.split("\n")[0]} and the set moved.` }), contentType: "application/json" },
  });
  let clock = at;
  const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: password, BW_LLM_URL: llmUrl }, http, now: () => clock });
  const cookie = cookieFrom(await formPost(app.base, "/login", { password, next: "/sources" }));
  expect((await formPost(app.base, `/sources/${sourceId}/enable`, {}, cookie)).status).toBe(303);

  const first = await formPost(app.base, `/sources/${sourceId}/fetch`, {}, cookie);
  expect(first.headers.get("location")).toBe(`/sources#src-${sourceId}`);
  expect(decodeURIComponent(flashOf(first))).toContain('"status":"ok"');
  const v1 = latestDocument(app.db, sourceId, "canaries")!;
  const before = loadRequirements(app.db, v1.id).map((r) => r.ref);
  expect(before).toHaveLength(canaryCount);

  served.text = without(feed, before[0]!);
  clock = new Date("2026-10-20T12:00:00Z");
  const second = await formPost(app.base, `/sources/${sourceId}/fetch`, {}, cookie);
  expect(decodeURIComponent(flashOf(second))).toContain('"status":"ok"');
  const v2 = latestDocument(app.db, sourceId, "canaries")!;
  expect(v2.id).not.toBe(v1.id);
  expect(v2.previous_document_id).toBe(v1.id);
  const after = loadRequirements(app.db, v2.id).map((r) => r.ref);
  const summary = changeSummaryFor(app.db, v2.id);
  expect(summary.removed).toEqual([before[0]]);
  expect(summary.added).toHaveLength(1);
  expect(before).not.toContain(summary.added[0]);
  return { app, cookie, v1, v2, names: [...new Set([...before, ...after])], removed: before[0]!, added: summary.added[0]! };
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

describe("a licence-restricted source", () => {
  let app: TestApp | null = null;
  let client: Client | null = null;
  afterEach(async () => {
    await client?.close();
    await app?.close();
    client = null;
    app = null;
  });

  it("ships restricted and off, and the owner alone turns a source on or off from the Sources page", async () => {
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: password }, now: () => at });
    const source = getSource(app.db, sourceId)!;
    expect(source).toMatchObject({ enabled: 0, restricted: 1 });
    expect(source.notes).toContain("Sources page");
    expect(source.notes).not.toMatch(/no switch|by hand/);
    expect((app.db.prepare("SELECT COUNT(*) AS n FROM sources WHERE restricted = 1").get() as { n: number }).n).toBe(1);

    // A visitor sees the rule on the row and no control; a post without the owner's session is refused.
    const visitorSources = await (await fetch(`${app.base}/sources`)).text();
    expect(visitorSources).toContain("Restricted: the entries are shown to the signed-in owner only");
    expect(visitorSources).not.toContain(`/sources/${sourceId}/enable`);
    expect(visitorSources).toContain("or turn one off or on");
    expect((await formPost(app.base, `/sources/${sourceId}/enable`, {})).status).toBe(403);

    const cookie = cookieFrom(await formPost(app.base, "/login", { password, next: "/sources" }));
    const ownerSources = await (await fetch(`${app.base}/sources`, { headers: { cookie } })).text();
    expect(ownerSources).toContain(`action="/sources/${sourceId}/enable"`);
    expect(ownerSources).toContain('action="/sources/cisa-kev/disable"');
    expect(ownerSources).not.toContain('action="/sources/cis-benchmarks/disable"');

    const crossSite = await fetch(`${app.base}/sources/${sourceId}/enable`, {
      method: "POST",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded", origin: "https://evil.example", "sec-fetch-site": "cross-site" },
      body: "",
      redirect: "manual",
    });
    expect(crossSite.status).toBe(403);
    expect(getSource(app.db, sourceId)!.enabled).toBe(0);

    // The outcome rides to the Sources page in the one-shot notice cookie, like a fetch's, and the redirect lands on the row.
    const on = await formPost(app.base, `/sources/${sourceId}/enable`, {}, cookie);
    expect(on.status).toBe(303);
    expect(on.headers.get("location")).toBe(`/sources#src-${sourceId}`);
    expect(decodeURIComponent(flashOf(on))).toContain('"status":"enabled"');
    expect(getSource(app.db, sourceId)!.enabled).toBe(1);
    const afterOn = await (await fetch(`${app.base}/sources`, { headers: { cookie: `${cookie}; ${flashOf(on)}` } })).text();
    expect(afterOn).toContain(`<b>${sourceId}</b>: enabled · checked daily`);
    expect(afterOn).toContain(`action="/sources/${sourceId}/disable"`);
    expect(afterOn).toContain(`<tr id="src-${sourceId}" class="">`);

    const off = await formPost(app.base, `/sources/${sourceId}/disable`, {}, cookie);
    expect(off.headers.get("location")).toBe(`/sources#src-${sourceId}`);
    expect(decodeURIComponent(flashOf(off))).toContain('"status":"disabled"');
    expect(getSource(app.db, sourceId)!.enabled).toBe(0);
    const afterOff = await (await fetch(`${app.base}/sources`, { headers: { cookie: `${cookie}; ${flashOf(off)}` } })).text();
    expect(afterOff).toContain(`<b>${sourceId}</b>: disabled · no longer fetched`);
    expect(afterOff).toContain(`<tr id="src-${sourceId}" class="off">`);
    expect((await formPost(app.base, "/sources/no-such-source/enable", {}, cookie)).status).toBe(404);
  });

  it("shows a visitor the versions and counts of a restricted list and the owner its entries", async () => {
    const loaded = await loadTwoVersions();
    app = loaded.app;
    const { cookie, v2, names, removed, added } = loaded;
    const get = async (path: string, asOwner = false): Promise<string> => (await fetch(`${app!.base}${path}`, asOwner ? { headers: { cookie } } : {})).text();
    const none = (text: string, where: string): void => {
      for (const name of names) expect(text, `${where} names ${name}`).not.toContain(name);
    };

    // No generated summary was asked for, although a model is configured and answers.
    expect(explanationsFor(app.db, v2.id).map((e) => e.kind)).toEqual(["none"]);

    const standard = await get(`/standards/${sourceId}`);
    expect(standard).toContain("2 versions");
    expect(standard).toContain("1 added, 1 removed");
    expect(standard).toContain("Entries shown to the owner only.");
    expect(standard).toContain("OpenPhish Community Feed terms");
    expect(standard).toContain('<a href="/login">Owner sign-in</a>');
    none(standard, "the standard page");

    const release = await get(`/standards/${sourceId}/${v2.id}`);
    expect(release).toContain("+ 1 added<");
    expect(release).toContain("− 1 removed<");
    expect(release).toContain("Entries shown to the owner only.");
    expect(release).toContain("No stated reason was captured");
    expect(release).not.toContain(`/standards/${sourceId}/${v2.id}/`);
    expect(release).not.toContain("Generated");
    none(release, "the release page");

    const browse = await get(`/standards/${sourceId}/${v2.id}/browse?q=${encodeURIComponent(names[1]!)}`);
    expect(browse).toContain(`${canaryCount} entries`);
    expect(browse).toContain("Entries shown to the owner only.");
    expect(browse).not.toContain('class="browse"');
    // The browse page's own search box is withheld; the masthead's box, which searches nothing restricted, stays.
    expect(browse).not.toContain('class="search"');
    none(browse, "the browse page");

    // An entry page draws the same thing for every ref, looked up or not: the URL is no oracle for what is on the list.
    const entry = await fetch(`${app.base}/standards/${sourceId}/${v2.id}/${names[1]}`);
    expect(entry.status).toBe(200);
    const entryText = await entry.text();
    expect(entryText).toContain("withheld (licence)");
    expect(entryText).toContain("Entry shown to the owner only");
    none(entryText, "the entry page");
    const stranger = await fetch(`${app.base}/standards/${sourceId}/${v2.id}/not-on-any-list.example`);
    expect(stranger.status).toBe(200);
    expect(await stranger.text()).toBe(entryText);
    expect((await fetch(`${app.base}/standards/${sourceId}/999999/${names[1]}`)).status).toBe(404);

    // Everywhere else the list is counted, never named: the Register home, the Wire's release item, Today, the Atlas, Sources.
    const register = await get("/register");
    expect(register).toContain("entries shown to the owner only (licence)");
    const wire = await get("/?kind=release");
    expect(wire).toContain("Phishing canaries (OpenPhish) feed");
    expect(wire).toContain("1 added, 1 removed");
    expect(wire).toContain("Entries withheld under the publisher"); // the apostrophe is escaped on the page; the API test checks the text whole
    for (const [path, text] of [
      ["/register", register],
      ["/?kind=release", wire],
      ["/today", await get("/today")],
      ["/atlas", await get("/atlas")],
      ["/sources", await get("/sources")],
    ]) {
      none(text!, path!);
    }
    // Searching the Wire for a name finds nothing: the release item never carried it.
    expect(await get(`/?q=${encodeURIComponent(added)}`)).toContain("No items match these filters");

    // The owner sees the entries as for any other list.
    const ownerRelease = await get(`/standards/${sourceId}/${v2.id}`, true);
    expect(ownerRelease).toContain(removed);
    expect(ownerRelease).toContain(added);
    expect(ownerRelease).toContain(`− 1 removed: ${removed}`);
    expect(ownerRelease).not.toContain("Entries shown to the owner only.");
    expect(ownerRelease).toContain(`/standards/${sourceId}/${v2.id}/browse`);
    const ownerBrowse = await get(`/standards/${sourceId}/${v2.id}/browse`, true);
    for (const r of loadRequirements(app.db, v2.id)) expect(ownerBrowse).toContain(r.ref);
    expect(ownerBrowse).toContain(`${canaryCount} of ${canaryCount}`);
    const ownerEntry = await get(`/standards/${sourceId}/${v2.id}/${added}`, true);
    expect(ownerEntry).toContain(added);
    expect(ownerEntry).toContain("Phishing canary");
    expect(ownerEntry).toContain(">added<");
    expect((await fetch(`${app.base}/standards/${sourceId}/${v2.id}/not-on-any-list.example`, { headers: { cookie } })).status).toBe(404);

    // A triaged entry is named on the board for the owner alone; a visitor's card leads to the release.
    expect((await formPost(app.base, "/triage", { kind: "control", id: String(v2.id), key: added, state: "reviewing", back: "/triage" }, cookie)).status).toBe(303);
    const board = await get("/triage");
    expect(board).toContain("withheld (licence) (Phishing canaries (OpenPhish) feed");
    expect(board).toContain(`href="/standards/${sourceId}/${v2.id}"`);
    none(board, "the triage board");
    const ownerBoard = await get("/triage", true);
    expect(ownerBoard).toContain(`${added} Phishing canary (Phishing canaries (OpenPhish) feed`);
    expect(ownerBoard).toContain(`href="/standards/${sourceId}/${v2.id}/${added}"`);
    const csv = await get("/triage.csv", true);
    expect(csv).toContain(added);
  });

  it("never hands the entries to the API or the MCP tools, owner or not", async () => {
    const loaded = await loadTwoVersions();
    app = loaded.app;
    const { cookie, v2, names, added } = loaded;
    const none = (text: string, where: string): void => {
      for (const name of names) expect(text, `${where} names ${name}`).not.toContain(name);
    };
    expect((await formPost(app.base, "/triage", { kind: "control", id: String(v2.id), key: added, state: "affects", back: "/triage" }, cookie)).status).toBe(303);

    for (const asOwner of [false, true]) {
      const who = asOwner ? "the owner" : "a visitor";
      const json = async (path: string): Promise<unknown> => (await fetch(`${app!.base}${path}`, asOwner ? { headers: { cookie } } : {})).json();

      const standards = (await json("/api/v1/standards")) as { standards: { id: string; restricted: boolean; versions: { requirements: number }[] }[] };
      const phishing = standards.standards.find((s) => s.id === sourceId)!;
      expect(phishing.restricted).toBe(true);
      expect(phishing.versions.map((v) => v.requirements)).toEqual([canaryCount, canaryCount]);
      expect(standards.standards.filter((s) => s.restricted).map((s) => s.id)).toEqual([sourceId]);
      none(JSON.stringify(standards), `/api/v1/standards for ${who}`);

      expect(await json(`/api/v1/changes?source=${sourceId}`)).toEqual({ changes: [] });
      none(JSON.stringify(await json("/api/v1/changes")), `/api/v1/changes for ${who}`);

      const items = (await json("/api/v1/items?kind=release")) as { items: { source: string; title: string; summary: string | null }[] };
      const item = items.items.find((i) => i.source === sourceId && /1 added, 1 removed/.test(i.title))!;
      expect(item.summary).toBe(withheldReleaseSummary);
      none(JSON.stringify(items), `/api/v1/items for ${who}`);

      const triage = (await json("/api/v1/triage")) as { triage: { title: string; url: string }[] };
      expect(triage.triage).toHaveLength(1);
      expect(triage.triage[0]!.title).toMatch(/^withheld \(licence\)/);
      expect(triage.triage[0]!.url).toBe(`${app.config.baseUrl}/standards/${sourceId}/${v2.id}`);
      none(JSON.stringify(triage), `/api/v1/triage for ${who}`);
    }

    client = await connect(app.base);
    const standards = textOf(await client.callTool({ name: "list_standards", arguments: {} })) as { standards: { id: string; restricted: boolean }[] };
    expect(standards.standards.find((s) => s.id === sourceId)?.restricted).toBe(true);
    none(JSON.stringify(standards), "list_standards");

    expect(textOf(await client.callTool({ name: "standard_changes", arguments: { source: sourceId } }))).toEqual({ changes: [] });
    none(JSON.stringify(textOf(await client.callTool({ name: "standard_changes", arguments: {} }))), "standard_changes");

    const release = textOf(await client.callTool({ name: "release", arguments: { source: sourceId } })) as {
      version: string;
      summary: string;
      counts: Record<string, number>;
      changes: unknown[];
      reasons: { kind: string }[];
      restricted: boolean;
      withheld: string;
    };
    expect(release.version).toMatch(/^feed [0-9a-f]{7}$/);
    expect(release.summary).toBe("1 added, 1 removed");
    expect(release.counts).toEqual({ added: 1, removed: 1, revised: 0, editorial: 0 });
    expect(release.changes).toEqual([]);
    expect(release.reasons.map((r) => r.kind)).toEqual(["none"]);
    expect(release.restricted).toBe(true);
    expect(release.withheld).toContain("withheld under the publisher's licence");
    none(JSON.stringify(release), "release");

    // The requirement tool refuses before looking the ref up, so it answers the same for a name on the list and one that is not.
    const requirement = await client.callTool({ name: "requirement", arguments: { source: sourceId, ref: added } });
    expect(requirement.isError).toBe(true);
    const refusal = (requirement.content as { text: string }[])[0]!.text;
    expect(refusal).toContain("withheld under the publisher's licence");
    none(refusal, "requirement");
    const stranger = await client.callTool({ name: "requirement", arguments: { source: sourceId, ref: "not-on-any-list.example" } });
    expect(stranger.content).toEqual(requirement.content);

    none(JSON.stringify(textOf(await client.callTool({ name: "search_wire", arguments: { kind: "release" } }))), "search_wire");
    none(JSON.stringify(textOf(await client.callTool({ name: "search_wire", arguments: { q: added } }))), "search_wire by name");
    none(JSON.stringify(textOf(await client.callTool({ name: "triage", arguments: {} }))), "triage");
  });
});
