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
 * Two stores, because most requests are not people. A person's page view is a row in `visits`:
 * the day and minute, the host it asked for, the path without its query, the browser family,
 * system and device, the country Cloudflare's edge read from the address (CF-IPCountry), the site
 * the reader came from (its host only), and the domain the address's reverse DNS names, with
 * whether that name resolves back to the address. Everything else (crawlers, AI assistants, feed
 * readers, tools, a person's 404 or feed request) is a count per day in `visit_counts`, keyed by
 * host, kind, status, the program's name, country and network, and the path only for a 404:
 * a crawler walking every filter of a list on one day is one row, not hundreds of thousands.
 *
 * The address itself is never stored: a visitor is a hash of the address and the User-Agent under
 * the day's salt, and the salt is deleted when the next day's is made, so two days' hashes cannot
 * be joined and no hash can be traced back once its day is over. A request that sends Sec-GPC or
 * DNT is counted, and its address's name is not looked up.
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

/** What a request carried besides its User-Agent that only a real browser sends together. */
export interface BrowserSignals {
  acceptLanguage: boolean;
  /** Sec-Fetch-Mode: every current browser sends it (Chrome 76, Firefox 90, Safari 16.4). */
  fetchMetadata: boolean;
}

/**
 * What kind of program sent a request, from its User-Agent and the headers only browsers send.
 * Every browser a person uses sends Accept-Language and Sec-Fetch-Mode; a script that borrows a
 * browser's name usually leaves one out, so a browser's name without both is not counted as a person.
 */
export function classifyAgent(userAgent: string, signals: BrowserSignals): Agent {
  const ua = userAgent.slice(0, 512).trim();
  if (!ua) return { kind: "unknown", name: "no User-Agent", os: null, device: null };
  for (const [pattern, name, kind] of agents) if (pattern.test(ua)) return { kind, name, os: null, device: null };
  const named = /([\w.-]*(?:bot|crawler|spider)[\w.-]*)/i.exec(ua);
  if (named) return { kind: "crawler", name: named[1]!.slice(0, 40), os: null, device: null };
  if (/^Mozilla\/5\.0 /.test(ua)) {
    const browser = browsers.find(([pattern]) => pattern.test(ua))?.[1] ?? "Other browser";
    const os = osOf(ua);
    const device = deviceOf(ua);
    if (!signals.acceptLanguage) return { kind: "unknown", name: `${browser}, no Accept-Language`, os, device };
    if (!signals.fetchMetadata) return { kind: "unknown", name: `${browser}, no Sec-Fetch headers`, os, device };
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
  /** Sec-Fetch-Mode was sent. */
  fetchMetadata: boolean;
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
/** Addresses looked up per program name per day: enough to say where a crawler comes from, not one question per address of a fleet. */
const lookupsPerProgram = 20;
/** A browser past this many pages in a day is a program wearing a browser's name, and is counted as one from then on. */
export const maxPagesPerPerson = 300;

type Write = (network: Network | null) => void;

/**
 * Records visits, holding in memory only what the day needs: its salt, the network each address
 * resolved to, how many pages each person has read, and how many addresses each program has had
 * looked up. Writes wait for the network lookup when one is asked, so a row is written once, whole.
 */
export class VisitRecorder {
  readonly #db: DatabaseSync;
  readonly #deps: VisitDeps;
  #day = "";
  #salt = "";
  readonly #names = new Map<string, Network | null>();
  readonly #waiting = new Map<string, Write[]>();
  readonly #pages = new Map<string, number>();
  readonly #programLookups = new Map<string, number>();
  readonly #lookups = new Set<Promise<void>>();
  #insertVisit: StatementSync | undefined;
  #countVisit: StatementSync | undefined;

  constructor(db: DatabaseSync, deps: VisitDeps) {
    this.#db = db;
    this.#deps = deps;
  }

  /** Counts one answer; false when the request came from no public address and is not a visit. */
  record(facts: VisitFacts): boolean {
    const ip = publicAddress(facts.ip);
    if (!ip) return false;
    const day = localDay(facts.at, this.#deps.timeZone);
    if (day !== this.#day) this.#turnDay(day);
    let agent = classifyAgent(facts.userAgent, { acceptLanguage: facts.acceptLanguage, fetchMetadata: facts.fetchMetadata });
    const host = facts.host.toLowerCase().replace(/\.$/, "");
    const fields = {
      at: facts.at.toISOString(),
      day,
      host: /^[a-z0-9.-]{1,100}$/.test(host) ? host : "other",
      path: facts.path.slice(0, 200) || "/",
      kind: facts.kind,
      status: facts.status,
      country: facts.country && /^[A-Za-z][A-Za-z0-9]$/.test(facts.country) ? facts.country.toUpperCase() : null,
    };
    let person = agent.kind === "person" && facts.kind === "page" && facts.status !== 404;
    const visitor = createHash("sha256").update(`${this.#salt}\n${ip}\n${facts.userAgent}`).digest("hex").slice(0, 16);
    if (person) {
      const read = (this.#pages.get(visitor) ?? 0) + 1;
      if (this.#pages.size < maxNames) this.#pages.set(visitor, read);
      if (read > maxPagesPerPerson) {
        agent = { ...agent, kind: "unknown", name: `${agent.name}, over ${maxPagesPerPerson} pages a day` };
        person = false;
      }
    }
    const referrer = person ? referrerHost(facts.referer ?? null, host) : null;
    const write: Write = person
      ? (network) => {
          this.#insertVisit ??= this.#db.prepare(
            `INSERT INTO visits (at, day, host, path, kind, status, visitor, agent, agent_name, os, device, country, referrer, network, network_confirmed)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'person', ?, ?, ?, ?, ?, ?, ?)`,
          );
          this.#insertVisit.run(fields.at, fields.day, fields.host, fields.path, fields.kind, fields.status, visitor, agent.name, agent.os, agent.device, fields.country, referrer, network?.name ?? null, network?.confirmed ? 1 : 0);
        }
      : (network) => {
          this.#countVisit ??= this.#db.prepare(
            `INSERT INTO visit_counts (day, host, path, kind, status, agent, agent_name, country, network, network_confirmed, requests, last_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
             ON CONFLICT (day, host, path, kind, status, agent, agent_name, country, network, network_confirmed)
             DO UPDATE SET requests = requests + 1, last_at = MAX(last_at, excluded.last_at)`,
          );
          // The path is kept for a 404 alone: it is how a scanner's probes are told from a broken link.
          this.#countVisit.run(fields.day, fields.host, fields.status === 404 ? fields.path : "", fields.kind, fields.status, agent.kind, agent.name ?? "", fields.country ?? "", network?.name ?? "", network?.confirmed ? 1 : 0, fields.at);
        };
    const wanted = (): boolean => {
      if (facts.optOut) return false;
      if (person || agent.kind === "assistant") return true;
      const key = `${agent.kind}\n${agent.name ?? ""}`;
      const asked = this.#programLookups.get(key) ?? 0;
      if (asked >= lookupsPerProgram) return false;
      this.#programLookups.set(key, asked + 1);
      return true;
    };
    this.#withNetwork(ip, wanted, write);
    return true;
  }

  /** Resolves once every lookup started so far has written what waited on it; for tests and shutdown. */
  async settled(): Promise<void> {
    while (this.#lookups.size > 0) await Promise.all([...this.#lookups]);
  }

  #turnDay(day: string): void {
    this.#day = day;
    this.#names.clear();
    this.#pages.clear();
    this.#programLookups.clear();
    const row = this.#db.prepare("SELECT salt FROM visit_salts WHERE day = ?").get(day) as { salt: string } | undefined;
    this.#salt = row?.salt ?? randomBytes(16).toString("hex");
    if (!row) this.#db.prepare("INSERT INTO visit_salts (day, salt) VALUES (?, ?)").run(day, this.#salt);
    // Yesterday's salt goes the moment today's exists: its hashes can no longer be recomputed.
    this.#db.prepare("DELETE FROM visit_salts WHERE day <> ?").run(day);
  }

  #write(write: Write, network: Network | null): void {
    try {
      write(network);
    } catch (error) {
      this.#deps.log?.(`[visits] not written: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /** Writes at once when the address's network is known or not wanted, or once its lookup answers. */
  #withNetwork(ip: string, wanted: () => boolean, write: Write): void {
    const known = this.#names.get(ip);
    if (known !== undefined) return this.#write(write, known);
    const waiting = this.#waiting.get(ip);
    if (waiting) {
      waiting.push(write);
      return;
    }
    if (this.#waiting.size >= maxLookups || !wanted()) return this.#write(write, null);
    this.#waiting.set(ip, [write]);
    const day = this.#day;
    const lookup = networkOf(ip, this.#deps.reverse, this.#deps.forward)
      .catch(() => null)
      .then((network) => {
        const writes = this.#waiting.get(ip) ?? [];
        this.#waiting.delete(ip);
        // Remembered for the day it was asked in; the rows carry their own day either way.
        if (day === this.#day) {
          if (this.#names.size >= maxNames) this.#names.clear();
          this.#names.set(ip, network);
        }
        for (const w of writes) this.#write(w, network);
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

/** A person's page: a browser that sent the headers only browsers send, given a page that exists. */
const personPage = "agent = 'person' AND kind = 'page' AND status <> 404";

export function visitReport(db: DatabaseSync, options: { now: Date; timeZone: string; days: VisitWindow; host: string | null }): VisitReport {
  const to = localDay(options.now, options.timeZone);
  // Days are counted back on the calendar, not in 24-hour steps, so a change of clocks never skips one.
  const back = (n: number): string => new Date(Date.parse(`${to}T12:00:00Z`) - n * 86_400_000).toISOString().slice(0, 10);
  const from = back(options.days - 1);
  const scope = "day >= ? AND day <= ? AND (? IS NULL OR host = ?)";
  const args = [from, to, options.host, options.host] as const;
  const all = <T>(sql: string): T[] => db.prepare(sql).all(...args) as T[];
  const one = <T>(sql: string): T => db.prepare(sql).get(...args) as T;

  const people = one<{ visits: number; views: number }>(`SELECT COUNT(DISTINCT day || visitor) AS visits, COUNT(*) AS views FROM visits WHERE ${scope} AND ${personPage}`);
  const sumOf = (condition: string): string => `COALESCE(SUM(CASE WHEN ${condition} THEN requests ELSE 0 END), 0)`;
  const programs = one<Omit<VisitReport["totals"], "visits" | "views">>(
    `SELECT ${sumOf("agent = 'assistant'")} AS assistants, ${sumOf("agent = 'crawler'")} AS crawlers, ${sumOf("agent = 'reader'")} AS readers,
            ${sumOf("agent = 'tool'")} AS tools, ${sumOf("agent = 'unknown'")} AS unknown, ${sumOf("status = 404")} AS missing, ${sumOf("kind = 'api'")} AS api
     FROM visit_counts WHERE ${scope}`,
  );
  const peopleDays = new Map(all<{ day: string; visits: number; views: number }>(`SELECT day, COUNT(DISTINCT visitor) AS visits, COUNT(*) AS views FROM visits WHERE ${scope} AND ${personPage} GROUP BY day`).map((d) => [d.day, d]));
  const programDays = new Map(
    all<{ day: string; assistants: number; crawlers: number; others: number }>(
      `SELECT day, ${sumOf("agent = 'assistant'")} AS assistants, ${sumOf("agent = 'crawler'")} AS crawlers, ${sumOf("agent IN ('reader', 'tool', 'unknown')")} AS others
       FROM visit_counts WHERE ${scope} GROUP BY day`,
    ).map((d) => [d.day, d]),
  );
  // Every day of the window, newest first, a quiet one included as zeros.
  const byDay: VisitReport["byDay"] = [];
  for (let i = 0; i < options.days; i += 1) {
    const day = back(i);
    const p = peopleDays.get(day);
    const q = programDays.get(day);
    byDay.push({ day, visits: p?.visits ?? 0, views: p?.views ?? 0, assistants: q?.assistants ?? 0, crawlers: q?.crawlers ?? 0, others: q?.others ?? 0 });
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
        `SELECT host, SUM(visits) AS visits, SUM(requests) AS requests FROM (
           SELECT host, COUNT(DISTINCT day || visitor) AS visits, COUNT(*) AS requests FROM visits WHERE day >= ? AND day <= ? GROUP BY host
           UNION ALL
           SELECT host, 0 AS visits, SUM(requests) AS requests FROM visit_counts WHERE day >= ? AND day <= ? GROUP BY host
         ) GROUP BY host ORDER BY requests DESC, host LIMIT 20`,
      )
      .all(from, to, from, to) as VisitReport["hosts"],
    totals: { visits: people.visits, views: people.views, ...programs },
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
    automated: all<{ kind: AgentKind; name: string; network: string; confirmed: number; requests: number; last: string }>(
      `SELECT agent AS kind, agent_name AS name, network, network_confirmed AS confirmed, SUM(requests) AS requests, MAX(last_at) AS last
       FROM visit_counts WHERE ${scope} AND agent <> 'person'
       GROUP BY agent, agent_name, network, network_confirmed ORDER BY requests DESC, name LIMIT 120`,
    ).map((a) => ({ ...a, name: a.name || "unnamed", network: a.network || null, confirmed: a.confirmed === 1 })),
    missing: all<VisitReport["missing"][number]>(`SELECT path, SUM(requests) AS requests, MAX(last_at) AS last FROM visit_counts WHERE ${scope} AND status = 404 GROUP BY path ORDER BY requests DESC, path LIMIT 50`),
    recent: all<{ at: string; host: string; path: string; country: string | null; network: string | null; confirmed: number; browser: string | null; os: string | null; device: string | null; referrer: string | null }>(
      `SELECT at, host, path, country, network, network_confirmed AS confirmed, agent_name AS browser, os, device, referrer
       FROM visits WHERE ${scope} AND ${personPage} ORDER BY at DESC, id DESC LIMIT 50`,
    ).map((r) => ({ ...r, confirmed: r.confirmed === 1 })),
    lastAt: (db.prepare("SELECT MAX(at) AS at FROM (SELECT MAX(at) AS at FROM visits UNION ALL SELECT MAX(last_at) FROM visit_counts)").get() as { at: string | null }).at,
  };
}

/** Visits and counts older than `days` days: the weekly housekeeping pass deletes them. */
export function sweepVisits(db: DatabaseSync, now: Date, days: number): number {
  const before = new Date(now.getTime() - days * 86_400_000).toISOString();
  const rows = Number(db.prepare("DELETE FROM visits WHERE at < ?").run(before).changes);
  return rows + Number(db.prepare("DELETE FROM visit_counts WHERE day < ?").run(before.slice(0, 10)).changes);
}
