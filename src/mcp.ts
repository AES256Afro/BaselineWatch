/**
 * The read-only MCP server: the JSON API's reads as tools, so an agent (BoxPilot's, Claude's, a
 * script) can ask "what changed in 800-53 this quarter?" or "is anything on my watchlist in KEV?"
 * and get the engine's answer with links back. Stateless Streamable HTTP at /mcp, one server per
 * request, no sessions, no writes: nothing here can triage, upload, fetch or change a setting.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { apiChanges, apiDigest, apiItems, apiStandards, apiTriage, apiVuln, apiVulns, isLicensedSource } from "./api.ts";
import { getSource } from "./ingest.ts";
import { changeSummaryFor, changeSummaryText, explanationsFor, getDocument, latestDocument, licenceOf, notesFor, releaseChanges, requirementIn } from "./register.ts";
import { productName, productVersion } from "./version.ts";

const readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;

function asText(value: unknown): { content: { type: "text"; text: string }[] } {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 1) }] };
}

function failure(message: string): { content: { type: "text"; text: string }[]; isError: true } {
  return { content: [{ type: "text", text: message }], isError: true };
}

/** CIS and Microsoft text is the owner's own licensed copy: on screen only, never through a tool. */
const licensed = (source: string) => failure(`${source} is the owner's own licensed copy; it is quoted on the pages and not served through the API or this tool.`);

const since = z.string().max(40).optional().describe("ISO 8601 date or timestamp; only things at or after it");
const limit = z.number().int().min(1).max(200).optional().describe("How many rows at most (default 50, max 200)");

/** The API's readers take query strings; a tool's numbers go over as the strings they would be in a URL. */
const s = (v: string | number | boolean | undefined): string | undefined => (v === undefined || v === false ? undefined : v === true ? "1" : String(v));

/** Why a restricted source's entries are not in a tool's answer: said the same way in every tool that would have carried them. */
const withheldBy = (source: { name: string; licence: string | null }): string => `The entries of ${source.name} are withheld under the publisher's licence (${licenceOf(source)}); the instance's owner sees them on its pages. Versions and counts are in list_standards.`;

/** A fresh server for one request: tools over the live database, nothing kept between calls. */
function buildMcpServer(db: DatabaseSync, baseUrl: string): McpServer {
  const server = new McpServer(
    { name: "baselinewatch", title: productName, version: productVersion },
    {
      instructions:
        `${productName} tracks security news, CVEs and the standards themselves (NIST SP 800-53 and its baselines, FedRAMP's rules, DISA STIGs, Microsoft baselines, CIS by upload). ` +
        "Every tool reads; none writes. Figures come from the instance's own database. Standards changes carry the publisher's stated reason when one was captured; a summary marked generated came from a model and is labelled so. " +
        "A standard flagged restricted is tracked under a licence that forbids showing its entries to third parties: its versions, counts and reasons are here, its entries' names and text are not, in any tool. " +
        `Links point at ${baseUrl}.`,
    },
  );

  server.registerTool(
    "list_standards",
    {
      title: "Tracked standards",
      description: "Every standard the Register tracks, with its loaded versions (id, version, publication date, requirement count, predecessor) and links. One flagged restricted yields versions and counts only: no tool returns its entries.",
      inputSchema: {},
      annotations: readOnly,
    },
    async () => asText({ standards: apiStandards(db, baseUrl) }),
  );

  server.registerTool(
    "standard_changes",
    {
      title: "Changes to standards",
      description: "Control- or rule-level changes across releases: ref, kind (added, removed, modified), the field, before and after text, and the publisher's note when one exists. Filter by source id and date. A restricted source's changes are left out.",
      inputSchema: { source: z.string().max(60).optional().describe("A source id from list_standards, such as nist-sp-800-53 or fedramp-rules"), since, limit },
      annotations: readOnly,
    },
    async (args) => asText({ changes: apiChanges(db, { source: args.source, since: args.since, limit: s(args.limit) }, baseUrl) }),
  );

  server.registerTool(
    "release",
    {
      title: "One release of a standard",
      description: "A loaded version of a standard: what it is, what changed against the version before it (summary and the first 200 changes with the publisher's notes), and the release's stated reason. Without document_id, the latest version of the source's first document key. For a restricted source the changes are counted, not listed.",
      inputSchema: { source: z.string().max(60).describe("Source id"), document_id: z.number().int().optional().describe("A version id from list_standards; the latest when omitted") },
      annotations: readOnly,
    },
    async (args) => {
      if (isLicensedSource(args.source)) return licensed(args.source);
      let doc = args.document_id !== undefined ? getDocument(db, args.document_id) : null;
      if (!doc) {
        const first = db.prepare("SELECT document_key FROM documents WHERE source_id = ? ORDER BY document_key LIMIT 1").get(args.source) as { document_key: string } | undefined;
        doc = first ? latestDocument(db, args.source, first.document_key) : null;
      }
      if (!doc || doc.source_id !== args.source) return failure(`No loaded version for ${args.source}${args.document_id !== undefined ? ` with id ${args.document_id}` : ""}.`);
      const source = getSource(db, doc.source_id);
      const restricted = source?.restricted === 1;
      const summary = changeSummaryFor(db, doc.id);
      const previous = doc.previous_document_id ? getDocument(db, doc.previous_document_id) : null;
      const changes = restricted ? [] : releaseChanges(db, doc.id).slice(0, 200);
      return asText({
        id: doc.id,
        source: doc.source_id,
        key: doc.document_key,
        version: doc.version_label,
        title: doc.title,
        published: doc.published_at,
        requirements: doc.requirement_count,
        previous: previous ? { id: previous.id, version: previous.version_label, published: previous.published_at } : null,
        summary: previous ? changeSummaryText(summary) : "loaded as the first version",
        counts: { added: summary.added.length, removed: summary.removed.length, revised: summary.substantive.length, editorial: summary.editorial.length },
        // The publisher's words and the "no reason" marker travel; a generated summary of a restricted release would quote its entries, and none is ever made.
        reasons: explanationsFor(db, doc.id)
          .filter((e) => !restricted || e.kind !== "generated")
          .map((e) => ({ kind: e.kind, text: e.text, url: e.source_url })),
        changes: changes.map((c) => ({ ref: c.ref, kind: c.kind, field: c.field, before: c.before_text, after: c.after_text, notes: notesFor(db, doc.id, c.ref).map((n) => n.text) })),
        ...(restricted && source ? { restricted: true, withheld: withheldBy(source) } : {}),
        url: `${baseUrl}/standards/${doc.source_id}/${doc.id}`,
      });
    },
  );

  server.registerTool(
    "requirement",
    {
      title: "One control or rule",
      description: "The current text of a requirement in a standard (statement, guidance, parameters, related controls) and the releases that changed it. Not for a restricted source, whose entries are withheld.",
      inputSchema: { source: z.string().max(60).describe("Source id"), ref: z.string().max(80).describe("The requirement's ref, lower case, such as ac-2.1, sa-24, afc-frp-vre or ksi-ced-rat") },
      annotations: readOnly,
    },
    async (args) => {
      if (isLicensedSource(args.source)) return licensed(args.source);
      // Refused before the ref is looked up, so the answer says nothing about whether it is on the list.
      const source = getSource(db, args.source);
      if (source?.restricted === 1) return failure(withheldBy(source));
      const ref = args.ref.trim().toLowerCase();
      const rows = db.prepare("SELECT DISTINCT document_key FROM documents WHERE source_id = ? ORDER BY document_key").all(args.source) as { document_key: string }[];
      for (const { document_key } of rows) {
        const doc = latestDocument(db, args.source, document_key);
        const r = doc ? requirementIn(db, doc.id, ref) : null;
        if (!doc || !r) continue;
        const history = db
          .prepare(
            `SELECT c.to_document_id AS document_id, d.version_label AS version, d.published_at AS published, c.kind, c.field
             FROM changes c JOIN documents d ON d.id = c.to_document_id WHERE c.source_id = ? AND c.ref = ? ORDER BY d.published_at DESC, c.field`,
          )
          .all(args.source, ref) as { document_id: number; version: string | null; published: string | null; kind: string; field: string | null }[];
        return asText({
          source: args.source,
          document: { id: doc.id, key: doc.document_key, version: doc.version_label },
          ref: r.ref,
          label: r.label,
          title: r.title,
          family: r.family,
          statement: r.statement,
          guidance: r.guidance,
          params: r.params,
          related: r.related,
          status: r.status,
          extra: r.extra,
          changedIn: history,
          url: `${baseUrl}/standards/${args.source}/${doc.id}/${r.ref}`,
        });
      }
      return failure(`No requirement ${ref} in the latest versions of ${args.source}.`);
    },
  );

  server.registerTool(
    "search_wire",
    {
      title: "The News",
      description: "Timeline items: news and advisories, notable CVEs, KEV additions and standard releases, newest first. Full-text search with q.",
      inputSchema: {
        q: z.string().max(200).optional().describe("Full-text search"),
        kind: z.enum(["article", "vulnerability", "kev", "release"]).optional(),
        source: z.string().max(60).optional().describe("A source id"),
        since,
        limit,
      },
      annotations: readOnly,
    },
    async (args) => asText({ items: apiItems(db, { q: args.q, kind: args.kind, source: args.source, since: args.since, limit: s(args.limit) }, baseUrl) }),
  );

  server.registerTool(
    "vulnerabilities",
    {
      title: "CVEs and advisories",
      description: "Vulnerabilities with CVSS, EPSS, KEV, SSVC, vendors, products and the platforms they affect. Filter by platform (windows, apple, linux, browsers, android, network), to the most dangerous (exploited, a public exploit, or EPSS at least 50%), to KEV, by score or likelihood, by change date, or search.",
      inputSchema: {
        q: z.string().max(200).optional().describe("Search in ids and descriptions"),
        platform: z.enum(["windows", "apple", "linux", "browsers", "android", "network", "chrome", "firefox", "edge"]).optional().describe("Only vulnerabilities affecting this platform"),
        dangerous: z.boolean().optional().describe("Only the most dangerous: exploited, a public exploit, or likely to be (EPSS at least 50%)"),
        kev: z.boolean().optional().describe("Only CISA KEV entries"),
        min_cvss: z.number().min(0).max(10).optional(),
        min_epss: z.number().min(0).max(1).optional(),
        since,
        sort: z.enum(["modified", "published", "cvss", "epss"]).optional(),
        limit,
        offset: z.number().int().min(0).max(100_000).optional(),
      },
      annotations: readOnly,
    },
    async (args) =>
      asText(
        apiVulns(db, {
          q: args.q,
          platform: args.platform,
          danger: s(args.dangerous),
          kev: s(args.kev),
          min_cvss: s(args.min_cvss),
          min_epss: s(args.min_epss),
          since: args.since,
          sort: args.sort,
          limit: s(args.limit),
          offset: s(args.offset),
        }),
      ),
  );

  server.registerTool(
    "vulnerability",
    { title: "One CVE or advisory", description: "A vulnerability by id (CVE-..., or a GHSA id for an advisory NVD has not analysed) with its CPEs, references and change history.", inputSchema: { id: z.string().max(60).describe("CVE-2026-12345 or GHSA-xxxx-xxxx-xxxx") }, annotations: readOnly },
    async (args) => {
      const v = apiVuln(db, args.id.trim().toUpperCase());
      return v ? asText(v) : failure(`No vulnerability ${args.id} in this instance.`);
    },
  );

  server.registerTool(
    "triage",
    { title: "The triage board", description: "What the owner has placed on the board, by state: new, reviewing, affects, done, dismissed.", inputSchema: { state: z.enum(["new", "reviewing", "affects", "done", "dismissed"]).optional(), limit }, annotations: readOnly },
    async (args) => asText({ triage: apiTriage(db, { state: args.state, limit: s(args.limit) }, baseUrl) }),
  );

  server.registerTool("digest", { title: "The latest digest", description: "The most recent daily or weekly digest as written.", inputSchema: {}, annotations: readOnly }, async () => asText({ digest: apiDigest(db) }));

  return server;
}

/**
 * What a tool call can be. Every input this server takes is a source id, a date, a CVE or a
 * number, so the longest honest request is a few hundred bytes; the SDK's own default is four
 * megabytes, which is four megabytes of JSON this endpoint would parse before refusing it.
 */
export const maxMcpRequestBytes = 256 * 1024;

/**
 * Answers one POST to /mcp: a fresh server and a stateless transport, torn down when the response
 * closes. The SDK's types leave `| undefined` off their optional members, which this project's
 * `exactOptionalPropertyTypes` insists on, so the transport is handed over through one cast here.
 */
export async function handleMcpRequest(db: DatabaseSync, baseUrl: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const server = buildMcpServer(db, baseUrl);
  const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true, maxRequestBodySize: maxMcpRequestBytes });
  res.on("close", () => {
    void transport.close();
    void server.close();
  });
  await server.connect(transport as unknown as Parameters<McpServer["connect"]>[0]);
  await transport.handleRequest(req, res);
}
