import type { DatabaseSync } from "node:sqlite";
import { publicSummary } from "./api.ts";
import { fleetPlatforms } from "./fleet.ts";
import { guideArticles } from "./pages/guides/index.ts";
import { html, type Html } from "./html.ts";
import { parseJson } from "./json.ts";
import { productName } from "./version.ts";
import { listVulns, type VulnFilters } from "./vulns.ts";
import { listWire, type WireFilters } from "./wire.ts";

/**
 * What a reader, a calendar or a crawler can take away (N6): the News and the Vulnerabilities
 * table as RSS under the same filters their pages take, every source as OPML, CISA's KEV due
 * dates as a calendar, and robots.txt and a sitemap that tell a crawler the truth about an
 * instance that is open or closed. Everything here is a different shape of what the pages show;
 * nothing is computed that a page does not already compute.
 */

export interface FeedEntry {
  title: string;
  link: string;
  guid: string;
  date: string | null;
  description: string | null;
  category?: string | null;
}

const rfc822 = (iso: string): string => new Date(iso).toUTCString();

/** An RSS 2.0 document; the html helper's escaping is XML's, so it draws this too. */
export function rssDocument(channel: { title: string; link: string; description: string; self: string }, entries: FeedEntry[]): string {
  const body: Html = html`<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>${channel.title}</title>
<link>${channel.link}</link>
<description>${channel.description}</description>
<atom:link href="${channel.self}" rel="self" type="application/rss+xml"/>
${entries.map(
  (e) => html`<item>
<title>${e.title}</title>
<link>${e.link}</link>
<guid isPermaLink="false">${e.guid}</guid>
${e.date ? html`<pubDate>${rfc822(e.date)}</pubDate>` : ""}
${e.description ? html`<description>${e.description}</description>` : ""}
${e.category ? html`<category>${e.category}</category>` : ""}
</item>
`,
)}</channel>
</rss>
`;
  return `<?xml version="1.0" encoding="UTF-8"?>\n${body.value}`;
}

const feedLimit = 50;

/** The News under the Wire's own filters: group, source, kind, q. */
export function wireFeed(db: DatabaseSync, baseUrl: string, filters: WireFilters, self: string): string {
  const items = listWire(db, { ...filters, unread: false, before: undefined, limit: feedLimit });
  const words = [filters.group, filters.source, filters.kind, filters.q ? `“${filters.q}”` : null].filter((w) => w);
  return rssDocument(
    { title: `${productName} · News${words.length ? ` · ${words.join(" · ")}` : ""}`, link: `${baseUrl}/`, description: "News, advisories and CVEs that matter, as BaselineWatch reads them.", self },
    items.map((i) => ({ title: i.title, link: i.url ?? `${baseUrl}/`, guid: `${i.source_id}:${i.external_id}`, date: i.published_at ?? i.fetched_at, description: publicSummary(i), category: i.source_name })),
  );
}

/** The Vulnerabilities table under its own filters; a CVE that changes comes round again, because the change is the news. */
export function vulnFeed(db: DatabaseSync, baseUrl: string, filters: VulnFilters, self: string): string {
  const { rows } = listVulns(db, { ...filters, offset: 0, limit: feedLimit });
  const words = [filters.kev ? "KEV" : null, filters.exploit ? "public exploit" : null, filters.watch ? "your stack" : null, filters.platform, filters.severity, filters.minCvss !== undefined ? `CVSS ≥ ${filters.minCvss}` : null, filters.q ? `“${filters.q}”` : null].filter((w) => w);
  return rssDocument(
    { title: `${productName} · Vulnerabilities${words.length ? ` · ${words.join(" · ")}` : ""}`, link: `${baseUrl}/vulnerabilities`, description: "CVEs as NVD, CISA and FIRST describe them, newest change first.", self },
    rows.map((r) => {
      const vendors = parseJson<string[]>(r.vendors_json, []).slice(0, 3);
      const products = parseJson<string[]>(r.products_json, []).slice(0, 3);
      const who = [...new Set([...vendors, ...products])].join(", ");
      const severity = r.cvss_score === null ? "unscored" : `CVSS ${r.cvss_score.toFixed(1)} ${(r.cvss_severity ?? "").toLowerCase()}`.trim();
      return {
        title: `${r.cve_id} · ${severity}${r.kev ? " · KEV" : ""}${r.watch_hit ? " · your stack" : ""}`,
        link: `${baseUrl}/vulnerabilities/${r.cve_id}`,
        guid: `${r.cve_id}@${r.last_modified_at}`,
        date: r.last_modified_at,
        description: `${who ? `${who}. ` : ""}${r.description ?? ""}`.trim() || null,
        category: r.kev ? "KEV" : null,
      };
    }),
  );
}

/** Every enabled feed source as an OPML outline, grouped, with this instance's own feeds first. */
export function opmlDocument(db: DatabaseSync, baseUrl: string): string {
  const sources = db.prepare("SELECT id, name, group_name, url FROM sources WHERE enabled = 1 AND format IN ('rss', 'atom') ORDER BY group_name, name").all() as { id: string; name: string; group_name: string; url: string }[];
  const groups = new Map<string, typeof sources>();
  for (const s of sources) groups.set(s.group_name, [...(groups.get(s.group_name) ?? []), s]);
  const own = [
    { name: `${productName} · News`, url: `${baseUrl}/feed.xml` },
    { name: `${productName} · Vendor advisories`, url: `${baseUrl}/feed.xml?group=vulnerabilities` },
    { name: `${productName} · Vulnerabilities`, url: `${baseUrl}/vulnerabilities/feed.xml` },
    { name: `${productName} · Known exploited`, url: `${baseUrl}/vulnerabilities/feed.xml?kev=1` },
  ];
  const body = html`<opml version="2.0">
<head><title>${productName} sources</title></head>
<body>
<outline text="${productName}">
${own.map((o) => html`<outline text="${o.name}" type="rss" xmlUrl="${o.url}" htmlUrl="${baseUrl}/"/>
`)}</outline>
${[...groups.entries()].map(
  ([group, list]) => html`<outline text="${group}">
${list.map((s) => html`<outline text="${s.name}" type="rss" xmlUrl="${s.url}" htmlUrl="${baseUrl}/?source=${s.id}"/>
`)}</outline>
`,
)}</body>
</opml>
`;
  return `<?xml version="1.0" encoding="UTF-8"?>\n${body.value}`;
}

/**
 * iCalendar text: backslashes, semicolons and commas escaped as RFC 5545 asks, and every kind of
 * line break folded into `\n` — a lone CR as well as CRLF and LF, since a stored description
 * holding one would otherwise end the line and the calendar with it.
 */
function icsText(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/;/g, "\\;")
    .replace(/,/g, "\\,")
    .replace(/\r\n|[\r\n]/g, "\\n")
    // Nothing else below a space belongs in a calendar property value.
    .replace(/\p{Cc}/gu, " ");
}

/**
 * Lines of at most 75 **octets**, continued with CRLF and a space (RFC 5545 §3.1).
 *
 * Octets, not characters: a KEV summary of multi-byte text folded at 74 characters came out at
 * 140 octets, and slicing by character can cut a surrogate pair in half and put invalid UTF-8 in
 * the calendar. This walks code points, counts their encoded length, and never splits one.
 */
export function foldIcsLine(line: string): string {
  const octets = (s: string): number => Buffer.byteLength(s, "utf8");
  if (octets(line) <= 75) return line;
  const out: string[] = [];
  // A continuation line starts with one space, which is itself one of the 75 octets.
  let current = "";
  for (const point of line) {
    if (octets(current) + octets(point) > 75) {
      out.push(current);
      current = " ";
    }
    current += point;
  }
  if (current !== "" && current !== " ") out.push(current);
  return out.join("\r\n");
}

const icsDate = (iso: string): string => iso.slice(0, 10).replace(/-/g, "");

/** CISA KEV due dates as all-day events, from a month ago on, so a calendar shows what is due and what just was. */
export function kevCalendar(db: DatabaseSync, baseUrl: string, options: { watch: boolean; now: Date }): string {
  const since = new Date(options.now.getTime() - 30 * 86_400_000).toISOString().slice(0, 10);
  const rows = db
    .prepare(`SELECT cve_id, kev_due_date, kev_date_added, description, watch_hit FROM vulns WHERE kev = 1 AND kev_due_date IS NOT NULL AND kev_due_date >= ?${options.watch ? " AND watch_hit = 1" : ""} ORDER BY kev_due_date, cve_id LIMIT 500`)
    .all(since) as { cve_id: string; kev_due_date: string; kev_date_added: string | null; description: string | null; watch_hit: number }[];
  const stamp = options.now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const lines = ["BEGIN:VCALENDAR", "VERSION:2.0", `PRODID:-//${productName}//KEV due dates//EN`, "CALSCALE:GREGORIAN", "METHOD:PUBLISH", `X-WR-CALNAME:${icsText(`${productName} · KEV due dates${options.watch ? " (your stack)" : ""}`)}`];
  for (const r of rows) {
    const due = r.kev_due_date.slice(0, 10);
    const next = new Date(new Date(`${due}T00:00:00Z`).getTime() + 86_400_000).toISOString();
    const what = (r.description ?? "").replace(/\s+/g, " ").trim();
    lines.push(
      "BEGIN:VEVENT",
      `UID:kev-${r.cve_id}@baselinewatch`,
      `DTSTAMP:${stamp}`,
      `DTSTART;VALUE=DATE:${icsDate(due)}`,
      `DTEND;VALUE=DATE:${icsDate(next)}`,
      `SUMMARY:${icsText(`KEV due: ${r.cve_id}${r.watch_hit ? " (your stack)" : ""}${what ? ` — ${what.length > 80 ? `${what.slice(0, 79)}…` : what}` : ""}`)}`,
      `DESCRIPTION:${icsText(`${what}${r.kev_date_added ? ` Added to CISA's catalog ${r.kev_date_added.slice(0, 10)}.` : ""} ${baseUrl}/vulnerabilities/${r.cve_id}`.trim())}`,
      `URL:${baseUrl}/vulnerabilities/${r.cve_id}`,
      "END:VEVENT",
    );
  }
  lines.push("END:VCALENDAR");
  return `${lines.map(foldIcsLine).join("\r\n")}\r\n`;
}

/** The owner's pages, the API and the images: nothing a crawler should index or a search result should land on. */
const notForCrawlers = [
  "/login", "/triage", "/watchlist", "/digest", "/saved", "/sources", "/fleet", "/appearance", "/branding",
  // The Scan area's own pages: each hides the owner's facts from a visitor, so what a crawler
  // would index is the hedged version — noise in a search result and nothing gained.
  "/scan/network", "/scan/history", "/scan/devices", "/scan/echo",
  "/api/", "/mcp", "/img/", "/health", "/metrics", "/items/", "/wire/",
];

/** A closed instance says so; an open one names what is not for indexing and where the sitemap is. */
export function robotsText(publicRead: boolean, baseUrl: string): string {
  if (!publicRead) return "User-agent: *\nDisallow: /\n";
  return `User-agent: *\n${notForCrawlers.map((p) => `Disallow: ${p}`).join("\n")}\nAllow: /\nSitemap: ${baseUrl}/sitemap.xml\n`;
}

/** The pages worth a crawler's visit: the areas, each standard, each platform's baseline and guide. Not the CVEs; NVD has those. */
export function sitemapDocument(db: DatabaseSync, baseUrl: string): string {
  const standards = (db.prepare("SELECT id FROM sources WHERE group_name = 'standards' AND enabled = 1 ORDER BY id").all() as { id: string }[]).map((s) => `/standards/${s.id}`);
  const paths = [
    "/", "/today", "/standards", "/baselines", "/controls", "/stigs", "/register", "/atlas", "/learn", "/vulnerabilities", "/vulnerabilities/microsoft", "/scan", "/scan/guide", "/guide", "/feeds",
    ...standards,
    ...guideArticles.map((a) => `/guide/${a.slug}`),
    ...fleetPlatforms.map((p) => `/baselines/${p.id}`),
    ...["windows", "macos", "linux", "ios", "android"].map((os) => `/scan/guide/${os}`),
  ];
  const body = html`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${paths.map((p) => html`<url><loc>${baseUrl}${p}</loc></url>
`)}</urlset>
`;
  return `<?xml version="1.0" encoding="UTF-8"?>\n${body.value}`;
}
