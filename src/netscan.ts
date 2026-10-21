/**
 * The network check (M12.3, "This network"): the eye no web page can have, because this server
 * sits on the LAN. It discovers the resolver the network hands out (the server's own DHCP lease,
 * then resolv.conf), resolves the canary names from the Register's blocklist sources through it,
 * and classifies each answer: resolved (a real address came back), sinkholed (0.0.0.0, loopback,
 * the resolver's own address, or NXDOMAIN) or timeout. A control name that always resolves names
 * the upstream the resolver forwards to, a DoH request to a public endpoint says whether a browser
 * could bypass the resolver from this LAN, and a Pi-hole or AdGuard Home names its client count
 * when the owner has saved a token. Canaries are resolved only: nothing is ever fetched from one.
 *
 * The scan is opt-in (it sends packets on the owner's network) and runs daily once on. Every
 * run is stored; what moved since the last one (a canary newly resolving, the resolver changed)
 * is an alert through the notifier and a line in the digest. DNS, the clock, the filesystem and
 * HTTP are all injected so tests replay real answers without a network.
 */
import { readFileSync } from "node:fs";
import { Resolver } from "node:dns/promises";
import type { DatabaseSync } from "node:sqlite";
import { pickCanaries } from "./adapters/blocklists.ts";
import { localClock } from "./digest.ts";
import { HttpError, httpGet, type HttpGet } from "./http.ts";
import { notify, type Transport } from "./notify.ts";
import { latestDocument, loadRequirements } from "./register.ts";

export type NetOutcome = "resolved" | "sinkholed" | "timeout";

/**
 * One lookup through one resolver: the A addresses, or a throw whose `code` is node's
 * ('ENOTFOUND' for NXDOMAIN, 'ENODATA', 'ETIMEOUT', ...). Injected so fixture tests replay
 * real answers without the network.
 */
export type Resolve = (name: string, server: string) => Promise<string[]>;

/** Five seconds then one retryless failure: a canary that gets no answer is a timeout, not a hang. */
const resolveTimeoutMs = 5000;

const defaultResolve: Resolve = async (name, server) => {
  const resolver = new Resolver({ timeout: resolveTimeoutMs, tries: 1 });
  resolver.setServers([server]);
  return resolver.resolve4(name);
};

// ---------------------------------------------------------------------------------------------
// Resolver discovery: the server's own lease, then resolv.conf (behind the systemd stub if need be).

export interface DiscoveredResolver {
  address: string;
  /** Where the address was read: 'dhcp lease', 'resolv.conf' or 'systemd-resolved'. */
  source: string;
}

/** Reads a file or says it is not there; injected so discovery is testable without the host's files. */
export type ReadText = (path: string) => string | null;

const defaultReadText: ReadText = (path) => {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
};

/** Where dhclient keeps the lease the router answered with; the newest lease wins. */
export const leasePaths = ["/var/lib/dhcp/dhclient.leases", "/var/db/dhclient.leases"] as const;
export const resolvConfPath = "/etc/resolv.conf";
/** The real upstreams behind systemd-resolved's 127.0.0.53 stub. */
export const systemdResolvConfPath = "/run/systemd/resolve/resolv.conf";

/** The last `option domain-name-servers a, b;` in a dhclient lease file: the first server named. */
export function leaseNameserver(text: string): string | null {
  let found: string | null = null;
  for (const m of text.matchAll(/option\s+domain-name-servers\s+([^;]+);/g)) {
    const first = m[1]?.split(",")[0]?.trim();
    if (first) found = first;
  }
  return found;
}

/** The first `nameserver` line of a resolv.conf. */
export function resolvConfNameserver(text: string): string | null {
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*nameserver\s+(\S+)/.exec(line);
    if (m?.[1]) return m[1];
  }
  return null;
}

const loopback = (address: string): boolean => /^127\./.test(address) || address === "::1";

/**
 * The resolver the network hands out: the server's own DHCP lease first (that is the router's
 * answer, whatever a local stub rewrote), then resolv.conf. A loopback nameserver that is
 * systemd-resolved's stub is followed through to the real upstream; a loopback address with no
 * stub file behind it is kept, because a Pi-hole on this very host answers at 127.0.0.1.
 */
export function discoverResolver(read: ReadText = defaultReadText): DiscoveredResolver | null {
  for (const path of leasePaths) {
    const text = read(path);
    const address = text ? leaseNameserver(text) : null;
    if (address) return { address, source: "dhcp lease" };
  }
  const conf = read(resolvConfPath);
  const address = conf ? resolvConfNameserver(conf) : null;
  if (!address) return null;
  if (loopback(address)) {
    const real = read(systemdResolvConfPath);
    const upstream = real ? resolvConfNameserver(real) : null;
    if (upstream && !loopback(upstream)) return { address: upstream, source: "systemd-resolved" };
  }
  return { address, source: "resolv.conf" };
}

// ---------------------------------------------------------------------------------------------
// Classification.

/** What a Pi-hole or AdGuard Home answers for a blocked name, besides NXDOMAIN. */
const sinkholeAddresses = new Set(["0.0.0.0", "::", "::1"]);

function isSinkholeAddress(address: string, resolver: string): boolean {
  // A resolver in IP-blocking mode answers with its own address; that is a block, not a resolution.
  return sinkholeAddresses.has(address) || /^127\./.test(address) || address === resolver;
}

export interface Classified {
  outcome: NetOutcome;
  /** The addresses or the error code, verbatim, for the page's Answer column. */
  answer: string;
}

export function classifyAnswer(addresses: string[], resolver: string): Classified {
  if (addresses.length === 0) return { outcome: "sinkholed", answer: "no address" };
  const outcome = addresses.every((a) => isSinkholeAddress(a, resolver)) ? "sinkholed" : "resolved";
  return { outcome, answer: addresses.join(", ") };
}

export function classifyError(error: unknown): Classified {
  const code = typeof (error as { code?: unknown })?.code === "string" ? (error as { code: string }).code : "";
  if (code === "ENOTFOUND" || code === "ENODATA") return { outcome: "sinkholed", answer: "NXDOMAIN" };
  return { outcome: "timeout", answer: code || "no answer" };
}

async function resolveCanary(resolve: Resolve, name: string, server: string): Promise<Classified> {
  try {
    return classifyAnswer(await resolve(name, server), server);
  } catch (error) {
    return classifyError(error);
  }
}

// ---------------------------------------------------------------------------------------------
// The canary sets, read from the Register at scan time.

export interface CanaryCategory {
  category: string;
  label: string;
  sourceId: string;
}

/** The four canary sets and the adfection list's domains, the mockup's fifth tile. */
const canaryCategories: readonly (CanaryCategory & { key: string })[] = [
  { category: "ads", label: "Ads", sourceId: "canary-ads", key: "canaries" },
  { category: "trackers", label: "Trackers", sourceId: "canary-trackers", key: "canaries" },
  { category: "malware", label: "Malware", sourceId: "canary-malware", key: "canaries" },
  { category: "phishing", label: "Phishing", sourceId: "canary-phishing", key: "canaries" },
  { category: "adfection", label: "Ad-delivered spyware", sourceId: "adfection-dns", key: "domains" },
];

const categoryLabel = (category: string): string => canaryCategories.find((c) => c.category === category)?.label ?? category;

export interface CanarySet extends CanaryCategory {
  names: string[];
}

/**
 * The names to resolve: each canary set's twelve as its latest Register document holds them, and
 * twelve of the adfection list's domains picked by the same lowest-hash rule, so the pick is
 * deterministic and moves only with the list. A source with no document yet (never fetched, or
 * registered off like OpenPhish on a public instance) contributes nothing.
 */
export function canarySets(db: DatabaseSync): CanarySet[] {
  const sets: CanarySet[] = [];
  for (const { category, label, sourceId, key } of canaryCategories) {
    const document = latestDocument(db, sourceId, key);
    if (!document) continue;
    const refs = loadRequirements(db, document.id).map((r) => r.ref);
    const names = category === "adfection" ? pickCanaries(refs.map((name) => ({ name, line: name }))).map((c) => c.name) : refs;
    if (names.length > 0) sets.push({ category, label, sourceId, names });
  }
  return sets;
}

/** A name that always resolves; the answer is the address the resolver's upstream path presents. */
export const controlName = "whoami.akamai.net";

/** One public DoH endpoint, asked for a harmless name: reachable means a browser on this LAN can bypass the resolver. */
export const dohProbeUrl = "https://cloudflare-dns.com/dns-query?name=example.com&type=A";

// ---------------------------------------------------------------------------------------------
// Settings: the opt-in flag and the dashboard tokens, in app_settings. Tokens are never rendered.

export const netSettingKeys = {
  enabled: "netscan.enabled",
  piholeUrl: "netscan.pihole_url",
  piholeToken: "netscan.pihole_token",
  adguardUrl: "netscan.adguard_url",
  adguardToken: "netscan.adguard_token",
} as const;

export function getSetting(db: DatabaseSync, key: string): string | null {
  return (db.prepare("SELECT value FROM app_settings WHERE key = ?").get(key) as { value: string } | undefined)?.value ?? null;
}

export function setSetting(db: DatabaseSync, key: string, value: string | null, at: string): void {
  if (value === null || value === "") db.prepare("DELETE FROM app_settings WHERE key = ?").run(key);
  else db.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").run(key, value, at);
}

export function netScanEnabled(db: DatabaseSync): boolean {
  return getSetting(db, netSettingKeys.enabled) === "1";
}

// ---------------------------------------------------------------------------------------------
// Stored scans.

export interface NetScanRow {
  id: number;
  started_at: string;
  finished_at: string | null;
  resolver: string | null;
  resolver_source: string | null;
  upstream: string | null;
  doh: "reachable" | "blocked" | "not-tested" | null;
  clients_seen: number | null;
  clients_source: string | null;
  changes_json: string | null;
  error: string | null;
}

export interface NetCanaryRow {
  id: number;
  scan_id: number;
  category: string;
  source_id: string;
  name: string;
  outcome: NetOutcome;
  answer: string | null;
}

export interface NetScanChanges {
  resolverChanged: { from: string | null; to: string | null } | null;
  newlyResolving: { category: string; name: string }[];
  newlySinkholed: { category: string; name: string }[];
}

export function latestNetScan(db: DatabaseSync): NetScanRow | null {
  return (db.prepare("SELECT * FROM net_scans ORDER BY id DESC LIMIT 1").get() as unknown as NetScanRow | undefined) ?? null;
}

export function scanCanaries(db: DatabaseSync, scanId: number): NetCanaryRow[] {
  return db.prepare("SELECT * FROM net_canaries WHERE scan_id = ? ORDER BY category, name").all(scanId) as unknown as NetCanaryRow[];
}

export function parseChanges(text: string | null): NetScanChanges | null {
  if (!text) return null;
  try {
    return JSON.parse(text) as NetScanChanges;
  } catch {
    return null;
  }
}

export interface CategoryTally {
  category: string;
  label: string;
  total: number;
  sinkholed: number;
  resolved: number;
  timeout: number;
}

export function categoryTallies(rows: NetCanaryRow[]): CategoryTally[] {
  const byCategory = new Map<string, CategoryTally>();
  for (const row of rows) {
    const tally = byCategory.get(row.category) ?? { category: row.category, label: categoryLabel(row.category), total: 0, sinkholed: 0, resolved: 0, timeout: 0 };
    tally.total += 1;
    tally[row.outcome] += 1;
    byCategory.set(row.category, tally);
  }
  // In the tiles' order, not the map's.
  return canaryCategories.map((c) => byCategory.get(c.category)).filter((t): t is CategoryTally => t !== undefined);
}

/** What the /scan row and the Today view need in one glance. */
export interface NetworkSummary {
  scan: NetScanRow;
  total: number;
  sinkholed: number;
  resolved: number;
}

export function networkSummary(db: DatabaseSync): NetworkSummary | null {
  const scan = latestNetScan(db);
  if (!scan) return null;
  const counts = db.prepare("SELECT outcome, COUNT(*) AS n FROM net_canaries WHERE scan_id = ? GROUP BY outcome").all(scan.id) as { outcome: NetOutcome; n: number }[];
  const of = (outcome: NetOutcome): number => counts.find((c) => c.outcome === outcome)?.n ?? 0;
  return { scan, total: counts.reduce((sum, c) => sum + c.n, 0), sinkholed: of("sinkholed"), resolved: of("resolved") };
}

/** Due once per local date, the digest's rule: enabled, and no scan has run on today's date yet. */
export function netScanDue(db: DatabaseSync, timeZone: string, now: Date): boolean {
  if (!netScanEnabled(db)) return false;
  const last = latestNetScan(db);
  if (!last) return true;
  return localClock(new Date(last.started_at), timeZone).dateKey !== localClock(now, timeZone).dateKey;
}

// ---------------------------------------------------------------------------------------------
// The dashboards' client counts, when the owner saved a token. Errors are kept as a status word,
// never the message: the URL and the token are the credential.

interface ClientCount {
  clients: number;
  source: "pihole" | "adguard";
}

function countFailure(error: unknown): string {
  if (error instanceof HttpError) return `HTTP ${error.status}`;
  if (error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")) return "timed out";
  return "unreadable";
}

async function clientCount(db: DatabaseSync, http: HttpGet): Promise<{ count: ClientCount | null; note: string | null }> {
  const piholeUrl = getSetting(db, netSettingKeys.piholeUrl);
  const piholeToken = getSetting(db, netSettingKeys.piholeToken);
  if (piholeUrl && piholeToken) {
    try {
      const response = await http(`${piholeUrl.replace(/\/+$/, "")}/admin/api.php?summaryRaw&auth=${encodeURIComponent(piholeToken)}`, { timeoutMs: 10_000 });
      const summary = JSON.parse(new TextDecoder().decode(response.bytes)) as { unique_clients?: unknown };
      const clients = Number(summary.unique_clients);
      if (Number.isFinite(clients)) return { count: { clients, source: "pihole" }, note: null };
      return { count: null, note: "pihole: no client count in the answer" };
    } catch (error) {
      return { count: null, note: `pihole: ${countFailure(error)}` };
    }
  }
  const adguardUrl = getSetting(db, netSettingKeys.adguardUrl);
  const adguardToken = getSetting(db, netSettingKeys.adguardToken);
  if (adguardUrl && adguardToken) {
    try {
      const auth = Buffer.from(adguardToken, "utf8").toString("base64");
      const response = await http(`${adguardUrl.replace(/\/+$/, "")}/control/stats`, { timeoutMs: 10_000, headers: { authorization: `Basic ${auth}` } });
      const stats = JSON.parse(new TextDecoder().decode(response.bytes)) as { top_clients?: unknown };
      if (Array.isArray(stats.top_clients)) return { count: { clients: stats.top_clients.length, source: "adguard" }, note: null };
      return { count: null, note: "adguard: no client list in the answer" };
    } catch (error) {
      return { count: null, note: `adguard: ${countFailure(error)}` };
    }
  }
  return { count: null, note: null };
}

// ---------------------------------------------------------------------------------------------
// The scan itself.

export interface NetScanDeps {
  now?: () => Date;
  resolve?: Resolve;
  readFile?: ReadText;
  http?: HttpGet;
  transport?: Transport | null;
  baseUrl?: string;
  log?: (line: string) => void;
}

/** Runs the lookups a few at a time; sixty names at one five-second timeout each must not take five minutes. */
async function resolveAll(sets: CanarySet[], resolve: Resolve, server: string): Promise<Omit<NetCanaryRow, "id" | "scan_id">[]> {
  const jobs = sets.flatMap((set) => set.names.map((name) => ({ category: set.category, sourceId: set.sourceId, name })));
  const results: Omit<NetCanaryRow, "id" | "scan_id">[] = [];
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(4, jobs.length) }, async () => {
      while (next < jobs.length) {
        const job = jobs[next]!;
        next += 1;
        const { outcome, answer } = await resolveCanary(resolve, job.name, server);
        results.push({ category: job.category, source_id: job.sourceId, name: job.name, outcome, answer });
      }
    }),
  );
  return results;
}

function diffScans(db: DatabaseSync, previous: NetScanRow | null, resolver: string | null, rows: Omit<NetCanaryRow, "id" | "scan_id">[]): NetScanChanges | null {
  if (!previous) return null;
  const before = new Map(scanCanaries(db, previous.id).map((r) => [`${r.category}\u0000${r.name}`, r.outcome]));
  const newlyResolving: NetScanChanges["newlyResolving"] = [];
  const newlySinkholed: NetScanChanges["newlySinkholed"] = [];
  for (const row of rows) {
    const was = before.get(`${row.category}\u0000${row.name}`);
    if (was === "sinkholed" && row.outcome === "resolved") newlyResolving.push({ category: row.category, name: row.name });
    if (was === "resolved" && row.outcome === "sinkholed") newlySinkholed.push({ category: row.category, name: row.name });
  }
  const resolverChanged = previous.resolver !== resolver ? { from: previous.resolver, to: resolver } : null;
  return { resolverChanged, newlyResolving, newlySinkholed };
}

function insertScan(db: DatabaseSync, scan: Omit<NetScanRow, "id">, rows: Omit<NetCanaryRow, "id" | "scan_id">[]): NetScanRow {
  db.exec("BEGIN IMMEDIATE");
  try {
    const id = Number(
      db
        .prepare("INSERT INTO net_scans (started_at, finished_at, resolver, resolver_source, upstream, doh, clients_seen, clients_source, changes_json, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .run(scan.started_at, scan.finished_at, scan.resolver, scan.resolver_source, scan.upstream, scan.doh, scan.clients_seen, scan.clients_source, scan.changes_json, scan.error).lastInsertRowid,
    );
    const insert = db.prepare("INSERT INTO net_canaries (scan_id, category, source_id, name, outcome, answer) VALUES (?, ?, ?, ?, ?, ?)");
    for (const row of rows) insert.run(id, row.category, row.source_id, row.name, row.outcome, row.answer);
    db.exec("COMMIT");
    return db.prepare("SELECT * FROM net_scans WHERE id = ?").get(id) as unknown as NetScanRow;
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

/**
 * One scan, stored. Day-over-day changes against the previous scan ride the row as JSON; a canary
 * newly resolving or a changed resolver is an alert through the notifier right away, like a KEV
 * addition, and the digest reads the same JSON for its line.
 */
export async function runNetworkScan(db: DatabaseSync, deps: NetScanDeps = {}): Promise<NetScanRow> {
  const now = deps.now ?? (() => new Date());
  const resolve = deps.resolve ?? defaultResolve;
  const http = deps.http ?? httpGet;
  const log = deps.log ?? (() => {});
  const startedAt = now().toISOString();
  const previous = latestNetScan(db);

  const discovered = discoverResolver(deps.readFile ?? defaultReadText);
  if (!discovered) {
    log("[netscan] no resolver found in the lease or resolv.conf; nothing resolved");
    return insertScan(db, { started_at: startedAt, finished_at: now().toISOString(), resolver: null, resolver_source: null, upstream: null, doh: null, clients_seen: null, clients_source: null, changes_json: null, error: "no resolver found in the lease or resolv.conf" }, []);
  }

  const sets = canarySets(db);
  const rows = await resolveAll(sets, resolve, discovered.address);

  let upstream: string | null = null;
  try {
    upstream = (await resolve(controlName, discovered.address)).join(", ") || null;
  } catch {
    // The control not answering is itself a finding the page shows as "unknown"; the scan goes on.
  }

  let doh: NetScanRow["doh"] = "not-tested";
  try {
    await http(dohProbeUrl, { timeoutMs: 10_000, headers: { accept: "application/dns-json" } });
    doh = "reachable";
  } catch {
    doh = "blocked";
  }

  const { count, note } = await clientCount(db, http);
  const changes = diffScans(db, previous, discovered.address, rows);
  const scan = insertScan(db, {
    started_at: startedAt,
    finished_at: now().toISOString(),
    resolver: discovered.address,
    resolver_source: discovered.source,
    upstream,
    doh,
    clients_seen: count?.clients ?? null,
    clients_source: count?.source ?? null,
    changes_json: changes ? JSON.stringify(changes) : null,
    error: note,
  }, rows);
  log(`[netscan] resolved ${rows.length} canaries through ${discovered.address} (${discovered.source}): ${rows.filter((r) => r.outcome === "sinkholed").length} sinkholed, ${rows.filter((r) => r.outcome === "resolved").length} resolved`);

  if (changes && (changes.newlyResolving.length > 0 || changes.resolverChanged)) {
    const lines: string[] = [];
    if (changes.resolverChanged) lines.push(`The resolver changed: ${changes.resolverChanged.from ?? "none"} → ${changes.resolverChanged.to ?? "none"}.`);
    for (const c of changes.newlyResolving.slice(0, 10)) lines.push(`${c.name} (${categoryLabel(c.category).toLowerCase()}) now resolves; it was sinkholed yesterday.`);
    if (changes.newlyResolving.length > 10) lines.push(`…and ${changes.newlyResolving.length - 10} more.`);
    const title = changes.newlyResolving.length > 0 ? `This network: ${changes.newlyResolving.length} canar${changes.newlyResolving.length === 1 ? "y" : "ies"} newly resolving` : "This network: the resolver changed";
    await notify(db, deps.transport ?? null, { kind: "network", title, body: lines.join("\n"), url: deps.baseUrl ? `${deps.baseUrl}/scan/network` : null }, http, now);
  }
  return scan;
}

/** The scheduler's thunk: runs a scan when one is due, and says whether it did. */
export async function maybeRunNetworkScan(db: DatabaseSync, options: NetScanDeps & { timeZone: string }): Promise<boolean> {
  if (!netScanDue(db, options.timeZone, (options.now ?? (() => new Date()))())) return false;
  await runNetworkScan(db, options);
  return true;
}
