import { createHash, randomBytes } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import type { DatabaseSync, StatementSync } from "node:sqlite";
import { publicRecordName, type DnsLookup } from "./domaincheck.ts";
import { registrableDomain } from "./fix.ts";
import { privateAddress } from "./http.ts";

/**
 * Who reads this site: every page, feed and API answer given to anyone but the owner, counted on
 * the server as it is sent. Nothing runs in the reader's browser and no cookie is set, so the
 * strict CSP holds and a reader who blocks every tracker is counted the same as one who blocks
 * none.
 *
 * What is kept of a request: the day and minute, the host it asked for (cybercard.net and any
 * other name routed here), the path without its query, the status, what kind of program asked
 * (a person's browser, an AI assistant fetching for a person, a crawler, a feed reader, a tool),
 * the country Cloudflare's edge read from the address (CF-IPCountry), the site the reader came
 * from (its host only), and the domain the address's reverse DNS names, with whether that name
 * resolves back to the address. The address itself is never stored: a visitor is a hash of the
 * address and the User-Agent under the day's salt, and the salt is deleted when the next day's is
 * made, so two days' hashes cannot be joined and no hash can be traced back once its day is over.
 * A request that sends Sec-GPC or DNT is counted, and its address's name is not looked up.
 */

export type VisitKind = "page" | "feed" | "api";
export type AgentKind = "person" | "assistant" | "crawler" | "reader" | "tool" | "unknown";

export interface Agent {
  kind: AgentKind;
  name: string | null;
  os: string | null;
  device: "desktop" | "phone" | "tablet" | null;
}

/**
 * Programs that name themselves in the User-Agent, by the name each publishes; the first match
 * wins, so an assistant acting for a person comes before its company's crawler. A hand-kept list
 * (src/curated.ts): a program not on it is still named when its User-Agent says bot, crawler or
 * spider, and otherwise falls through to the browser and tool readings below.
 */
export const agents: readonly (readonly [RegExp, string, AgentKind])[] = [
  // A person asked an AI assistant to read the page; the fetch is theirs.
  [/ChatGPT-User/i, "ChatGPT-User", "assistant"],
  [/Claude-User/i, "Claude-User", "assistant"],
  [/Perplexity-User/i, "Perplexity-User", "assistant"],
  [/MistralAI-User/i, "MistralAI-User", "assistant"],
  [/Meta-ExternalFetcher/i, "Meta-ExternalFetcher", "assistant"],
  [/DuckAssistBot/i, "DuckAssistBot", "assistant"],
  // AI crawlers, gathering for a model or an answer index.
  [/GPTBot/i, "GPTBot", "crawler"],
  [/OAI-SearchBot/i, "OAI-SearchBot", "crawler"],
  [/Claude-SearchBot/i, "Claude-SearchBot", "crawler"],
  [/ClaudeBot|anthropic-ai/i, "ClaudeBot", "crawler"],
  [/PerplexityBot/i, "PerplexityBot", "crawler"],
  [/CCBot/i, "CCBot", "crawler"],
  [/Bytespider/i, "Bytespider", "crawler"],
  [/meta-externalagent/i, "meta-externalagent", "crawler"],
  [/cohere-ai/i, "cohere-ai", "crawler"],
  [/Amazonbot/i, "Amazonbot", "crawler"],
  [/Applebot/i, "Applebot", "crawler"],
  // Search engines.
  [/Googlebot/i, "Googlebot", "crawler"],
  [/Google-InspectionTool|GoogleOther|AdsBot-Google|Storebot-Google|Mediapartners-Google|APIs-Google/i, "Google, other", "crawler"],
  [/bingbot|BingPreview|msnbot/i, "Bingbot", "crawler"],
  [/DuckDuckBot/i, "DuckDuckBot", "crawler"],
  [/YandexBot|YandexMobileBot/i, "YandexBot", "crawler"],
  [/Baiduspider/i, "Baiduspider", "crawler"],
  [/PetalBot/i, "PetalBot", "crawler"],
  [/SeznamBot/i, "SeznamBot", "crawler"],
  [/Qwantbot/i, "Qwantbot", "crawler"],
  [/MojeekBot/i, "MojeekBot", "crawler"],
  // A link shared somewhere that draws a preview card.
  [/facebookexternalhit|facebookcatalog/i, "Facebook preview", "crawler"],
  [/Twitterbot/i, "Twitterbot", "crawler"],
  [/LinkedInBot/i, "LinkedInBot", "crawler"],
  [/Slackbot|Slack-ImgProxy/i, "Slackbot", "crawler"],
  [/Discordbot/i, "Discordbot", "crawler"],
  [/TelegramBot/i, "TelegramBot", "crawler"],
  [/WhatsApp/i, "WhatsApp preview", "crawler"],
  [/redditbot/i, "redditbot", "crawler"],
  [/Mastodon|Akkoma|Pleroma|Misskey/i, "Fediverse preview", "crawler"],
  [/Bluesky|Cardyb/i, "Bluesky preview", "crawler"],
  [/SkypeUriPreview|MicrosoftPreview/i, "Microsoft preview", "crawler"],
  // Search-engine optimisers, internet-wide scanners and uptime monitors.
  [/AhrefsBot|SemrushBot|MJ12bot|DotBot|DataForSeoBot|BLEXBot|serpstatbot|Barkrowler/i, "SEO crawler", "crawler"],
  [/CensysInspect|Expanse|zgrab|Nuclei|Nmap|masscan|InternetMeasurement|ModatScanner/i, "Internet scanner", "crawler"],
  [/UptimeRobot|Pingdom|StatusCake|Better ?Uptime|BetterStack|Site24x7|Uptime-Kuma/i, "Uptime monitor", "crawler"],
  // Feed readers, polling the RSS on a reader's behalf.
  [/Feedly/i, "Feedly", "reader"],
  [/Inoreader/i, "Inoreader", "reader"],
  [/NewsBlur/i, "NewsBlur", "reader"],
  [/Feedbin/i, "Feedbin", "reader"],
  [/theoldreader|The Old Reader/i, "The Old Reader", "reader"],
  [/Miniflux/i, "Miniflux", "reader"],
  [/FreshRSS/i, "FreshRSS", "reader"],
  [/Tiny Tiny RSS/i, "Tiny Tiny RSS", "reader"],
  [/NetNewsWire/i, "NetNewsWire", "reader"],
  [/Reeder/i, "Reeder", "reader"],
  [/Feedspot|BazQux|Blogtrottr|rss2email|FeedFetcher-Google|Feeder|Akregator|Liferea|NextCloud-News/i, "Other feed reader", "reader"],
  // Libraries and command-line tools, named by their own token.
  [/HeadlessChrome/i, "Headless Chrome", "tool"],
];

/** Browser families by their own User-Agent token, most specific first; one not here reads as "Other browser". */
export const browsers: readonly (readonly [RegExp, string])[] = [
  [/Edg(?:e|A|iOS)?\//, "Edge"],
  [/OPR\/|Opera/, "Opera"],
  [/SamsungBrowser\//, "Samsung Internet"],
  [/Vivaldi\//, "Vivaldi"],
  [/YaBrowser\//, "Yandex Browser"],
  [/DuckDuckGo\//, "DuckDuckGo"],
  [/Firefox\/|FxiOS\//, "Firefox"],
  [/CriOS\/|Chrome\//, "Chrome"],
  [/Version\/[\d.]+.*Safari\//, "Safari"],
];

function osOf(ua: string): string | null {
  if (/iPhone|iPod/.test(ua)) return "iOS";
  if (/iPad/.test(ua)) return "iPadOS";
  if (/Android/.test(ua)) return "Android";
  if (/CrOS/.test(ua)) return "ChromeOS";
  if (/Windows/.test(ua)) return "Windows";
  if (/Macintosh|Mac OS X/.test(ua)) return "macOS";
  if (/Linux|X11/.test(ua)) return "Linux";
  return null;
}

function deviceOf(ua: string): Agent["device"] {
  if (/iPad|Tablet/.test(ua) || (/Android/.test(ua) && !/Mobile/.test(ua))) return "tablet";
  if (/Mobi|iPhone|iPod/.test(ua)) return "phone";
  return "desktop";
}

/**
 * What kind of program sent a request, from its User-Agent and whether it sent Accept-Language.
 * Every browser a person uses sends Accept-Language; a script that borrows a browser's name often
 * does not, so a browser's name without it is not counted as a person.
 */
export function classifyAgent(userAgent: string, acceptLanguage: boolean): Agent {
  const ua = userAgent.slice(0, 512).trim();
  if (!ua) return { kind: "unknown", name: "no User-Agent", os: null, device: null };
  for (const [pattern, name, kind] of agents) if (pattern.test(ua)) return { kind, name, os: null, device: null };
  const named = /([\w.-]*(?:bot|crawler|spider)[\w.-]*)/i.exec(ua);
  if (named) return { kind: "crawler", name: named[1]!.slice(0, 40), os: null, device: null };
  if (/^Mozilla\/5\.0 /.test(ua)) {
    const browser = browsers.find(([pattern]) => pattern.test(ua))?.[1] ?? "Other browser";
    const os = osOf(ua);
    const device = deviceOf(ua);
    if (!acceptLanguage) return { kind: "unknown", name: `${browser}, no Accept-Language`, os, device };
    return { kind: "person", name: browser, os, device };
  }
  return { kind: "tool", name: /^([\w.-]{1,40})/.exec(ua)?.[1] ?? "unnamed", os: null, device: null };
}

const feedPaths = /^\/(feed\.xml|vulnerabilities\/feed\.xml|vulnerabilities\/kev\.ics|sources\.opml)$/i;
const notPages = /^\/(assets|img|branding|fonts)\/|^\/(favicon\.ico|robots\.txt|sitemap\.xml|health|api\/v1\/health|metrics|login|logout|look)$/i;
const fileLike = /\.(csv|json|zip|docx|pdf|tex|xml|ics|js|css|png|svg|jpe?g|webp|gif|ico|woff2?)$/i;

/**
 * Whether a finished request is a visit, and of what: the API and the MCP endpoint, the feeds, or
 * a page. A page is an HTML answer, a 304 (a browser that has the page already and asked whether
 * it changed) or a 404 (a broken link, or a scanner trying paths). Assets, images, health and the
 * sign-in are not visits; neither is a redirect, a refusal or an error.
 */
export function visitKind(method: string, path: string, status: number, contentType: string): VisitKind | null {
  if (!((status >= 200 && status < 300) || status === 304 || status === 404)) return null;
  if (notPages.test(path)) return null;
  if (/^\/api\//i.test(path) || path === "/mcp") return method === "GET" || method === "HEAD" || method === "POST" ? "api" : null;
  if (method !== "GET" && method !== "HEAD") return null;
  if (feedPaths.test(path)) return "feed";
  if (status === 404) return "page";
  if (status === 304) return fileLike.test(path) ? null : "page";
  return /^text\/html/i.test(contentType) ? "page" : null;
}

/** The calendar day of an instant where the owner is, as YYYY-MM-DD. */
export function localDay(at: Date, timeZone: string): string {
  return new Intl.DateTimeFormat("en-CA", { timeZone, year: "numeric", month: "2-digit", day: "2-digit" }).format(at);
}

/** The site a reader came from, as its host without www, or null when they came from this site or said nothing. */
export function referrerHost(referer: string | null, host: string): string | null {
  if (!referer) return null;
  let url: URL;
  try {
    url = new URL(referer);
  } catch {
    return null;
  }
  const name = url.hostname.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
  if (!name || (host && registrableDomain(name) === registrableDomain(host))) return null;
  return name.slice(0, 100);
}

function canonicalAddress(ip: string): string {
  if (isIP(ip) !== 6) return ip;
  try {
    return new URL(`http://[${ip}]`).hostname.replace(/^\[|\]$/g, "");
  } catch {
    return ip;
  }
}

/** A public address as given, or null for none, a malformed one, or one on this side of the router. */
export function publicAddress(ip: string | null | undefined): string | null {
  if (!ip) return null;
  const bare = ip.replace(/^::ffff:/, "");
  const kind = isIP(bare);
  if (kind === 0 || bare === "::1" || privateAddress(bare)) return null;
  if (kind === 6 && /^f[cd]|^fe[89ab]/i.test(bare)) return null;
  return canonicalAddress(bare);
}

export type ReverseLookup = (ip: string) => Promise<string[]>;

/** The host's resolver, three seconds a question; an address with no PTR record throws, which reads as no name. */
export function nodeReverse(): ReverseLookup {
  const resolver = new Resolver({ timeout: 3000, tries: 1 });
  return (ip) => resolver.reverse(ip);
}

export interface Network {
  /** The registered domain the PTR name sits under ("comcast.net", "googlebot.com"); the PTR itself often spells the address, so it is not kept. */
  name: string;
  /** The PTR name resolves back to the address, so the network's owner set it and it is not a borrowed name. */
  confirmed: boolean;
}

/** The domain an address's reverse DNS names, checked forward: anyone can write any PTR for their own addresses. */
export async function networkOf(ip: string, reverse: ReverseLookup, forward: DnsLookup): Promise<Network | null> {
  let names: string[];
  try {
    names = await reverse(ip);
  } catch {
    return null;
  }
  const ptr = names.map((n) => publicRecordName(n)).find((n): n is string => n !== null);
  if (!ptr) return null;
  const answer = await forward(ptr, isIP(ip) === 6 ? "AAAA" : "A");
  const confirmed = answer.records.some((record) => canonicalAddress(record) === ip);
  return { name: registrableDomain(ptr), confirmed };
}

export interface VisitFacts {
  at: Date;
  ip: string | null | undefined;
  host: string;
  path: string;
  kind: VisitKind;
  status: number;
  userAgent: string;
  acceptLanguage: boolean;
  /** Cloudflare's CF-IPCountry: two letters, XX for unknown, T1 for Tor. */
  country: string | null | undefined;
  referer: string | null | undefined;
  /** Sec-GPC or DNT was sent: the visit is counted, and the address's name is not looked up. */
  optOut: boolean;
}

export interface VisitDeps {
  reverse: ReverseLookup;
  forward: DnsLookup;
  timeZone: string;
  log?: (line: string) => void;
}

/** Lookups in flight at once; a burst past this is counted without a network name rather than queued. */
const maxLookups = 6;
/** Addresses whose names are remembered for the day before the memory is cleared. */
const maxNames = 20_000;

/** Records visits, holding the day's salt and the day's address-to-network answers in memory only. */
export class VisitRecorder {
  readonly #db: DatabaseSync;
  readonly #deps: VisitDeps;
  #day = "";
  #salt = "";
  readonly #names = new Map<string, Network | null>();
  readonly #pending = new Map<string, number[]>();
  readonly #lookups = new Set<Promise<void>>();
  #insert: StatementSync | undefined;

  constructor(db: DatabaseSync, deps: VisitDeps) {
    this.#db = db;
    this.#deps = deps;
  }

  /** Records one visit; the row's id, or null when the request came from no public address. */
  record(facts: VisitFacts): number | null {
    const ip = publicAddress(facts.ip);
    if (!ip) return null;
    const day = localDay(facts.at, this.#deps.timeZone);
    if (day !== this.#day) this.#turnDay(day);
    const agent = classifyAgent(facts.userAgent, facts.acceptLanguage);
    const visitor = createHash("sha256").update(`${this.#salt}\n${ip}\n${facts.userAgent}`).digest("hex").slice(0, 16);
    const host = facts.host.toLowerCase().replace(/\.$/, "");
    const country = facts.country && /^[A-Za-z][A-Za-z0-9]$/.test(facts.country) ? facts.country.toUpperCase() : null;
    const known = this.#names.get(ip);
    this.#insert ??= this.#db.prepare(
      `INSERT INTO visits (at, day, host, path, kind, status, visitor, agent, agent_name, os, device, country, referrer, network, network_confirmed)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const result = this.#insert.run(
        facts.at.toISOString(),
        day,
        /^[a-z0-9.-]{1,100}$/.test(host) ? host : "other",
        facts.path.slice(0, 200) || "/",
        facts.kind,
        facts.status,
        visitor,
        agent.kind,
        agent.name,
        agent.os,
        agent.device,
        country,
        referrerHost(facts.referer ?? null, host),
        known?.name ?? null,
        known?.confirmed ? 1 : 0,
      );
    const id = Number(result.lastInsertRowid);
    if (known === undefined && !facts.optOut) this.#lookUp(ip, id);
    return id;
  }

  /** Resolves once every network lookup started so far has written its answer; for tests and shutdown. */
  async settled(): Promise<void> {
    while (this.#lookups.size > 0) await Promise.all([...this.#lookups]);
  }

  #turnDay(day: string): void {
    this.#day = day;
    this.#names.clear();
    this.#pending.clear();
    const row = this.#db.prepare("SELECT salt FROM visit_salts WHERE day = ?").get(day) as { salt: string } | undefined;
    this.#salt = row?.salt ?? randomBytes(16).toString("hex");
    if (!row) this.#db.prepare("INSERT INTO visit_salts (day, salt) VALUES (?, ?)").run(day, this.#salt);
    // Yesterday's salt goes the moment today's exists: its hashes can no longer be recomputed.
    this.#db.prepare("DELETE FROM visit_salts WHERE day <> ?").run(day);
  }

  #lookUp(ip: string, id: number): void {
    const waiting = this.#pending.get(ip);
    if (waiting) {
      waiting.push(id);
      return;
    }
    if (this.#pending.size >= maxLookups) return;
    this.#pending.set(ip, [id]);
    const day = this.#day;
    const lookup = networkOf(ip, this.#deps.reverse, this.#deps.forward)
      .catch(() => null)
      .then((network) => {
        const ids = this.#pending.get(ip) ?? [];
        this.#pending.delete(ip);
        // A day that turned while the question was out has cleared its memory; its rows stay unnamed.
        if (day !== this.#day) return;
        if (this.#names.size >= maxNames) this.#names.clear();
        this.#names.set(ip, network);
        if (!network || ids.length === 0) return;
        try {
          const update = this.#db.prepare("UPDATE visits SET network = ?, network_confirmed = ? WHERE id = ?");
          for (const rowId of ids) update.run(network.name, network.confirmed ? 1 : 0, rowId);
        } catch (error) {
          this.#deps.log?.(`[visits] the network name was not written: ${error instanceof Error ? error.message : String(error)}`);
        }
      })
      .finally(() => this.#lookups.delete(lookup));
    this.#lookups.add(lookup);
  }
}

// ---------------------------------------------------------------------------------------------
// The owner's report.

export const visitWindows = [1, 7, 30, 90] as const;
export type VisitWindow = (typeof visitWindows)[number];

export interface Counted {
  name: string;
  visits: number;
}

export interface VisitReport {
  from: string;
  to: string;
  days: VisitWindow;
  host: string | null;
  /** Every host asked for in the window, for the filter. */
  hosts: { host: string; visits: number; requests: number }[];
  totals: { visits: number; views: number; assistants: number; crawlers: number; readers: number; tools: number; unknown: number; missing: number; api: number };
  byDay: { day: string; visits: number; views: number; assistants: number; crawlers: number; others: number }[];
  pages: { path: string; visits: number; views: number }[];
  referrers: Counted[];
  countries: Counted[];
  networks: (Counted & { confirmed: boolean })[];
  browsers: Counted[];
  systems: Counted[];
  devices: Counted[];
  automated: { kind: AgentKind; name: string; network: string | null; confirmed: boolean; requests: number; last: string }[];
  missing: { path: string; requests: number; last: string }[];
  recent: { at: string; host: string; path: string; country: string | null; network: string | null; confirmed: boolean; browser: string | null; os: string | null; device: string | null; referrer: string | null }[];
  /** The newest visit of any kind, for the page's meta line. */
  lastAt: string | null;
}

/** A person's page: a browser that sent Accept-Language, given a page that exists. */
const personPage = "agent = 'person' AND kind = 'page' AND status <> 404";

export function visitReport(db: DatabaseSync, options: { now: Date; timeZone: string; days: VisitWindow; host: string | null }): VisitReport {
  const to = localDay(options.now, options.timeZone);
  // Days are counted back on the calendar, not in 24-hour steps, so a change of clocks never skips one.
  const back = (n: number): string => new Date(Date.parse(`${to}T12:00:00Z`) - n * 86_400_000).toISOString().slice(0, 10);
  const from = back(options.days - 1);
  const scope = "day >= ? AND day <= ? AND (? IS NULL OR host = ?)";
  const args = [from, to, options.host, options.host] as const;
  const all = <T>(sql: string, ...more: (string | number | null)[]): T[] => db.prepare(sql).all(...args, ...more) as T[];
  const one = <T>(sql: string): T => db.prepare(sql).get(...args) as T;

  const totals = one<VisitReport["totals"]>(
    `SELECT COUNT(DISTINCT CASE WHEN ${personPage} THEN day || visitor END) AS visits,
            COALESCE(SUM(CASE WHEN ${personPage} THEN 1 ELSE 0 END), 0) AS views,
            COALESCE(SUM(agent = 'assistant'), 0) AS assistants,
            COALESCE(SUM(agent = 'crawler'), 0) AS crawlers,
            COALESCE(SUM(agent = 'reader'), 0) AS readers,
            COALESCE(SUM(agent = 'tool'), 0) AS tools,
            COALESCE(SUM(agent = 'unknown'), 0) AS unknown,
            COALESCE(SUM(status = 404), 0) AS missing,
            COALESCE(SUM(kind = 'api'), 0) AS api
     FROM visits WHERE ${scope}`,
  );
  const days = new Map(
    all<VisitReport["byDay"][number]>(
      `SELECT day, COUNT(DISTINCT CASE WHEN ${personPage} THEN visitor END) AS visits,
              COALESCE(SUM(CASE WHEN ${personPage} THEN 1 ELSE 0 END), 0) AS views,
              COALESCE(SUM(agent = 'assistant'), 0) AS assistants,
              COALESCE(SUM(agent = 'crawler'), 0) AS crawlers,
              COALESCE(SUM(agent IN ('reader', 'tool', 'unknown')), 0) AS others
       FROM visits WHERE ${scope} GROUP BY day`,
    ).map((d) => [d.day, d]),
  );
  // Every day of the window, newest first, a quiet one included as zeros.
  const byDay: VisitReport["byDay"] = [];
  for (let i = 0; i < options.days; i += 1) {
    const day = back(i);
    byDay.push(days.get(day) ?? { day, visits: 0, views: 0, assistants: 0, crawlers: 0, others: 0 });
  }
  const counted = (column: string, limit = 40): Counted[] =>
    all<Counted>(`SELECT ${column} AS name, COUNT(DISTINCT day || visitor) AS visits FROM visits WHERE ${scope} AND ${personPage} AND ${column} IS NOT NULL GROUP BY ${column} ORDER BY visits DESC, name LIMIT ${limit}`);

  return {
    from,
    to,
    days: options.days,
    host: options.host,
    hosts: db
      .prepare(
        `SELECT host, COUNT(DISTINCT CASE WHEN ${personPage} THEN day || visitor END) AS visits, COUNT(*) AS requests
         FROM visits WHERE day >= ? AND day <= ? GROUP BY host ORDER BY requests DESC LIMIT 20`,
      )
      .all(from, to) as VisitReport["hosts"],
    totals,
    byDay,
    pages: all<VisitReport["pages"][number]>(`SELECT path, COUNT(DISTINCT day || visitor) AS visits, COUNT(*) AS views FROM visits WHERE ${scope} AND ${personPage} GROUP BY path ORDER BY visits DESC, views DESC, path LIMIT 50`),
    referrers: counted("referrer"),
    countries: counted("country", 60),
    networks: all<{ name: string; confirmed: number; visits: number }>(
      `SELECT network AS name, MAX(network_confirmed) AS confirmed, COUNT(DISTINCT day || visitor) AS visits FROM visits
       WHERE ${scope} AND ${personPage} AND network IS NOT NULL GROUP BY network ORDER BY visits DESC, name LIMIT 50`,
    ).map((n) => ({ ...n, confirmed: n.confirmed === 1 })),
    browsers: counted("agent_name", 20),
    systems: counted("os", 20),
    devices: counted("device", 5),
    automated: all<{ kind: AgentKind; name: string; network: string | null; confirmed: number; requests: number; last: string }>(
      `SELECT agent AS kind, COALESCE(agent_name, 'unnamed') AS name, network, network_confirmed AS confirmed, COUNT(*) AS requests, MAX(at) AS last
       FROM visits WHERE ${scope} AND agent <> 'person'
       GROUP BY agent, agent_name, network, network_confirmed ORDER BY requests DESC, name LIMIT 120`,
    ).map((a) => ({ ...a, confirmed: a.confirmed === 1 })),
    missing: all<VisitReport["missing"][number]>(`SELECT path, COUNT(*) AS requests, MAX(at) AS last FROM visits WHERE ${scope} AND status = 404 GROUP BY path ORDER BY requests DESC, path LIMIT 50`),
    recent: all<{ at: string; host: string; path: string; country: string | null; network: string | null; confirmed: number; browser: string | null; os: string | null; device: string | null; referrer: string | null }>(
      `SELECT at, host, path, country, network, network_confirmed AS confirmed, agent_name AS browser, os, device, referrer
       FROM visits WHERE ${scope} AND ${personPage} ORDER BY at DESC, id DESC LIMIT 50`,
    ).map((r) => ({ ...r, confirmed: r.confirmed === 1 })),
    lastAt: (db.prepare("SELECT MAX(at) AS at FROM visits").get() as { at: string | null }).at,
  };
}

/** Visits older than `days` days: the weekly housekeeping pass deletes them. */
export function sweepVisits(db: DatabaseSync, now: Date, days: number): number {
  const before = new Date(now.getTime() - days * 86_400_000).toISOString();
  return Number(db.prepare("DELETE FROM visits WHERE at < ?").run(before).changes);
}
