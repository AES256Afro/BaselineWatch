/**
 * BaselineWatch · traces (/scan/traces).
 *
 * The browser's half of Zero Breach's local scanner (adint-scan): the files a person picks — a
 * browser profile, its cache, the hosts file, a DNS-cache dump, a registry export, the Downloads
 * folder — read in this tab against the AdFection / Candiru indicator list the Register holds.
 * Nothing is uploaded and nothing is stored, and no indicator is ever resolved, fetched or linked:
 * this is text comparison only, the one rule the scanner is held to.
 *
 *  1. Names and addresses. Every file's bytes are searched for the list's domains and addresses,
 *     as single-byte text and as UTF-16LE (Chromium's storage and Windows' exports use both), with
 *     the scanner's boundary rules: notcontrolium.net and controlium.network are not
 *     controlium.net, 152.174.65.771 is not 52.174.65.77, a subdomain is its parent's match, and
 *     the most specific indicator wins so one contact is not counted twice.
 *  2. Fingerprints. Each file up to 256 MB is hashed (SHA-256) against the list's sample hashes.
 *  3. Where it was found decides what it means. A name in a cache file was mentioned; a name in
 *     Chromium's connection records, its HSTS state (matched by the same one-way hash Chromium
 *     keeps, so no other host is learned) or Firefox's was contacted; a DNS dump is a resolver
 *     record; a registry export is a registration to run; the hosts file maps it or blocks it.
 *  4. A file that could not be read is unknown, never clean, and the report says which of the
 *     places worth reading were not in what was picked.
 *
 * Plain ES2020 module, no dependencies, served from /assets/traces.js under the page's own policy
 * (script-src 'self', connect-src 'self'). The readers take the browser as arguments, so
 * test/traces-script.test.ts drives them with Blobs and Node's WebCrypto.
 */

/** Files are searched in windows this size, overlapping by enough to hold the longest name twice over in UTF-16. */
export const CHUNK = 16 * 1024 * 1024;
const OVERLAP = 1024;

/** Larger files are searched but not fingerprinted; the skip is reported. */
export const HASH_LIMIT = 256 * 1024 * 1024;

/** What a match in each tier means, in the order of how seriously to take it. */
export const TIERS = Object.freeze({
  sample: { label: "Spyware sample", meaning: "The fingerprint of a published Candiru sample. A file with this fingerprint is that sample: conclusive, not circumstantial." },
  cc: { label: "Command-and-control", meaning: "A Candiru command-and-control server, the address an implant talks to. The most serious kind of network indicator." },
  validator: { label: "Validator server", meaning: "A Candiru validator: it profiled a device and decided whether to deliver an exploit to it. Contact suggests the device was being assessed as a target." },
  candiru: { label: "Candiru infrastructure", meaning: "A server Recorded Future attributes to Candiru without saying which role it played. Serious, but unspecified." },
  historical: { label: "Earlier Candiru infrastructure", meaning: "Infrastructure from older, separate Candiru campaigns. Read a dated record against the cited report; who runs it now is not established." },
  "candiru-ip": { label: "Candiru address", meaning: "An address attributed to Candiru infrastructure in 2025. Weak on its own: cloud addresses pass to unrelated customers within months, so only a dated record from that period means much." },
  delivery: { label: "Ad delivery", meaning: "Advertising infrastructure of the network that delivered the spyware. An ad from it is not evidence of infection; it says an ad reached this browser, or that its name was saved." },
  "vuln-driver": { label: "Abused signed driver", meaning: "A legitimate, signed driver this actor brings along to switch protections off. It ships with real products and sits on clean machines for honest reasons: a lead to check, not proof of spyware." },
});

/** Evidence grades, strongest first, with the words a row and its reader use. */
export const EVIDENCE = Object.freeze({
  "on-disk": { label: "On disk", meaning: "a file here has the fingerprint" },
  persistence: { label: "Registered to run", meaning: "named in a registration that loads code" },
  contacted: { label: "Contacted", meaning: "the browser kept a record of connecting to it" },
  "dns-record": { label: "In DNS records", meaning: "a resolver record names it; a lookup is not a connection, and it may have failed" },
  configured: { label: "Mapped in hosts", meaning: "the hosts file points the name at a real address" },
  referenced: { label: "Mentioned", meaning: "the name appears in saved content; that alone is not a connection" },
});
const evidenceOrder = Object.keys(EVIDENCE);

/** Addresses a hosts line points a name at to block it: protective, never a finding. */
export const SINKS = Object.freeze(["0.0.0.0", "127.0.0.1", "::1", "::", "0:0:0:0:0:0:0:1"]);

// ---------------------------------------------------------------- the list

/** The list as served by /scan/traces/indicators.json, indexed for matching. */
export function indicatorSet(list) {
  const byValue = new Map();
  const domains = new Set();
  const ips = new Set();
  const hashes = new Set();
  for (const raw of list ?? []) {
    const value = String(raw.value ?? "").trim().toLowerCase();
    if (!value) continue;
    const indicator = { value, type: raw.type, tier: raw.tier, confidence: raw.confidence ?? null, source: raw.source ?? null };
    byValue.set(value, indicator);
    if (raw.type === "domain") domains.add(value);
    else if (raw.type === "ip") ips.add(value);
    else if (raw.type === "sha256") hashes.add(value);
  }
  return { byValue, domains, ips, hashes, hsts: new Map() };
}

/** Chromium keeps HSTS hosts as base64(SHA-256(DNS wire form)); hashing the list's domains the same way matches a host exactly and learns nothing else. */
export async function hstsFingerprint(host, subtle) {
  const parts = [];
  for (const label of host.replace(/^\.+|\.+$/g, "").toLowerCase().split(".")) {
    parts.push(label.length);
    for (let i = 0; i < label.length; i++) parts.push(label.charCodeAt(i) & 0x7f);
  }
  parts.push(0);
  const digest = new Uint8Array(await subtle.digest("SHA-256", new Uint8Array(parts)));
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Fills set.hsts with each domain's fingerprint, once per run. */
export async function prepareHsts(set, subtle) {
  for (const domain of set.domains) set.hsts.set(await hstsFingerprint(domain, subtle), domain);
}

/** `controlium.net` → `controlium[.]net`: an indicator shown on a page must never be a link a click can follow. */
export function defang(value) {
  return String(value).replace(/\./g, "[.]");
}

// ---------------------------------------------------------------- matching

const LABEL = /[a-z0-9-]/;
const NARROW = /[a-z0-9_.-]{4,}/gi;
/** UTF-16LE text read as Latin-1 is each character followed by a NUL. */
const NUL = String.fromCharCode(0);
const WIDE = new RegExp(`(?:[a-z0-9_.-]${NUL}){4,}`, "gi");
const stripNul = (text) => text.split(NUL).join("");
const IPV4 = /(?<![0-9.])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9]|\.[0-9])/g;

/** The host an exact name or one of its subdomains belongs to, most specific indicator first; null when none. */
export function matchHost(host, set) {
  const name = String(host).toLowerCase().replace(/^\.+|\.+$/g, "");
  if (set.ips.has(name)) return set.byValue.get(name);
  for (let p = 0; p < name.length; p = name.indexOf(".", p) + 1) {
    if (set.domains.has(name.slice(p))) return set.byValue.get(name.slice(p));
    if (name.indexOf(".", p) === -1) break;
  }
  return null;
}

/**
 * The places a run of name characters may end: its own end, and every dot not followed by a
 * label character (`controlium.net.` ends a name; `controlium.net.evil.example` does not).
 */
function nameEnds(token) {
  const ends = [token.length];
  for (let i = token.indexOf("."); i !== -1; i = token.indexOf(".", i + 1)) {
    if (i + 1 < token.length && !LABEL.test(token[i + 1])) ends.push(i);
  }
  return ends;
}

/** Each domain indicator a run of name characters holds as a whole name, the most specific one per name. */
function domainsIn(token, set, found) {
  if (token.indexOf(".") === -1) return;
  const lower = token.toLowerCase();
  for (const end of nameEnds(lower)) {
    const name = lower.slice(0, end).replace(/\.+$/, "");
    // Left boundary: the start of the run, or a dot (a subdomain). `_` and label characters are not boundaries.
    for (let p = 0; p < name.length; p = name.indexOf(".", p) + 1) {
      const tail = name.slice(p);
      if (LABEL.test(tail[0] ?? "") && set.domains.has(tail)) {
        note(found, tail, name);
        break;
      }
      if (name.indexOf(".", p) === -1) break;
    }
  }
}

function ipsIn(text, set, found) {
  IPV4.lastIndex = 0;
  for (let m = IPV4.exec(text); m; m = IPV4.exec(text)) if (set.ips.has(m[1])) note(found, m[1], m[1]);
}

function note(found, value, seenAs) {
  const entry = found.get(value) ?? { value, seenAs: new Set() };
  if (entry.seenAs.size < 5) entry.seenAs.add(seenAs);
  found.set(value, entry);
}

/**
 * Every network indicator in a piece of text — a file's bytes read as Latin-1, or text pasted in
 * — as single-byte and UTF-16LE. Adds to `found` (value → { value, seenAs }) and returns it.
 */
export function scanText(text, set, found = new Map()) {
  NARROW.lastIndex = 0;
  for (let m = NARROW.exec(text); m; m = NARROW.exec(text)) domainsIn(m[0], set, found);
  ipsIn(text, set, found);
  WIDE.lastIndex = 0;
  for (let m = WIDE.exec(text); m; m = WIDE.exec(text)) {
    const narrow = stripNul(m[0]);
    domainsIn(narrow, set, found);
    ipsIn(narrow, set, found);
  }
  return found;
}

// ---------------------------------------------------------------- what a file is

/**
 * What a picked file is, from its path: which artefact, and the grade a match in it earns. A
 * byte match proves only that the name is there, so most stores are `referenced`; the stores
 * that hold nothing but hosts the browser connected to, and the origin stores the scanner treats
 * as contact, are `contacted`. `kind` names the reader for the stores read specially.
 */
export function artifactOf(path) {
  const p = String(path).replace(/\\/g, "/").toLowerCase();
  const name = p.slice(p.lastIndexOf("/") + 1);
  if (name === "network persistent state") return { kind: "connections", label: "Chromium connection records", evidence: "referenced" };
  if (name === "transportsecurity") return { kind: "hsts", label: "Chromium HSTS state", evidence: "contacted" };
  if (name.startsWith("sitesecurityservicestate")) return { kind: "plain", label: "Firefox HSTS state", evidence: "contacted" };
  if (name === "history" || name === "places.sqlite") return { kind: "plain", label: "History", evidence: "referenced" };
  if (name === "cookies" || name === "cookies.sqlite") return { kind: "plain", label: "Cookies", evidence: "referenced" };
  if (name === "favicons" || name === "favicons.sqlite") return { kind: "plain", label: "Favicons", evidence: "referenced" };
  if (/\/(local storage|session storage)\//.test(p)) return { kind: "plain", label: "Site storage", evidence: "contacted" };
  if (/\/service worker\//.test(p)) return { kind: "plain", label: "Service worker cache", evidence: "contacted" };
  if (p.includes("/indexeddb/")) return { kind: "plain", label: "IndexedDB", evidence: "referenced" };
  if (/\/(cache_data|cache2|code cache|cache)\//.test(p)) return { kind: "plain", label: "HTTP cache", evidence: "referenced" };
  if (name === "hosts") return { kind: "hosts", label: "Hosts file", evidence: "configured" };
  if (name.endsWith(".reg")) return { kind: "plain", label: "Registry export", evidence: "persistence" };
  return { kind: "sniff", label: "File", evidence: "referenced" };
}

/** A file with no telling name, judged by its first lines: a registry export, a DNS dump or log, a hosts file. */
export function sniff(sample) {
  const text = stripNul(sample);
  // A byte-order mark read as Latin-1 is ÿþ (UTF-16LE) or ï»¿ (UTF-8).
  if (/^(?:\uFEFF|\u00FF\u00FE|\u00EF\u00BB\u00BF)?\s*(windows registry editor|regedit4)/i.test(text)) return { kind: "plain", label: "Registry export", evidence: "persistence" };
  if (/record name[ .]*:|\bentry\s+recordname\b|microsoft-windows-dns-client|^\s*\S+\s+IN\s+(A|AAAA|CNAME|HTTPS)\s/im.test(text)) return { kind: "plain", label: "DNS records", evidence: "dns-record" };
  if (/^\s*(127\.0\.0\.1|0\.0\.0\.0|::1)\s+localhost\b/m.test(text)) return { kind: "hosts", label: "Hosts file", evidence: "configured" };
  return null;
}

/** The hosts file: a name pointed at a sink is a block, counted; pointed anywhere else, a finding. */
export function hostsFindings(text, set) {
  const configured = [];
  const blocked = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const [address, ...names] = line.split(/\s+/);
    for (const name of names) {
      const indicator = matchHost(name, set);
      if (!indicator) continue;
      if (SINKS.includes(address ?? "")) blocked.push(indicator.value);
      else configured.push({ value: indicator.value, seenAs: `${name} → ${address}` });
    }
  }
  return { configured, blocked };
}

/** The hosts in Chromium's Network Persistent State: the servers it held connection details for. */
export function serverHosts(text) {
  const hosts = [];
  const pattern = /"server"\s*:\s*"(?:https?:\/\/)?\[?([^"\]/:]+)/g;
  for (let m = pattern.exec(text); m; m = pattern.exec(text)) hosts.push(m[1].toLowerCase());
  return hosts;
}

/** The hashed hosts in Chromium's TransportSecurity: every 44-character base64 string in it. */
export function stsHashes(text) {
  const hashes = new Set();
  const pattern = /"([A-Za-z0-9+/]{43}=)"/g;
  for (let m = pattern.exec(text); m; m = pattern.exec(text)) hashes.add(m[1]);
  return hashes;
}

// ---------------------------------------------------------------- reading a file

const latin1 = () => new TextDecoder("latin1");

function hex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function reason(error) {
  const name = error && error.name ? error.name : "";
  if (name === "NotReadableError") return "could not be read: in use or locked. Close the program that owns it, or read it from another browser";
  if (name === "NotFoundError") return "was moved or removed after it was picked";
  if (name === "SecurityError" || name === "NotAllowedError") return "the system refused this browser access to it";
  return `could not be read (${error && error.message ? error.message : String(error)})`;
}

/**
 * One picked file, read against the list. `file` is anything with size, slice() and
 * arrayBuffer() (a File, a Blob). Returns the artefact, the hits with their evidence, the
 * fingerprint, and the error that kept it from being read.
 */
export async function readArtifact(file, path, set, subtle) {
  let art = artifactOf(path);
  const result = { path, size: file.size, art, hits: [], hashed: false, blocked: [], error: null, note: null };
  try {
    const decoder = latin1();
    const whole = file.size <= HASH_LIMIT ? new Uint8Array(await file.arrayBuffer()) : null;
    if (whole && file.size > 0) {
      const digest = hex(await subtle.digest("SHA-256", whole));
      result.hashed = true;
      if (set.hashes.has(digest)) result.hits.push({ value: digest, evidence: "on-disk", seenAs: digest });
      else if (/(^|[\\/])hw\.sys$/i.test(path)) result.note = "A file named HW.sys is here and its fingerprint is not the abused driver's build: most likely a legitimate same-named driver, but given the name worth knowing who installed it.";
    }
    const bytesOf = async (start, end) => (whole ? whole.subarray(start, end) : new Uint8Array(await file.slice(start, end).arrayBuffer()));
    if (art.kind === "sniff") {
      const head = decoder.decode(await bytesOf(0, Math.min(file.size, 65536)));
      art = sniff(head) ?? art;
      result.art = art;
    }
    if (art.kind === "hosts" || art.kind === "connections" || art.kind === "hsts") {
      const text = decoder.decode(await bytesOf(0, Math.min(file.size, 64 * 1024 * 1024)));
      if (art.kind === "hosts") {
        const { configured, blocked } = hostsFindings(stripNul(text), set);
        for (const c of configured) result.hits.push({ value: c.value, evidence: "configured", seenAs: c.seenAs });
        result.blocked = blocked;
        return result;
      }
      if (art.kind === "hsts") {
        for (const hash of stsHashes(text)) {
          const domain = set.hsts.get(hash);
          if (domain) result.hits.push({ value: domain, evidence: "contacted", seenAs: "an HSTS header received over HTTPS" });
        }
        return result;
      }
      // Connection records: a server entry is contact; any other mention of the name is only a mention.
      const contacted = new Set();
      for (const host of serverHosts(text)) {
        const indicator = matchHost(host, set);
        if (indicator && !contacted.has(indicator.value)) {
          contacted.add(indicator.value);
          result.hits.push({ value: indicator.value, evidence: "contacted", seenAs: host });
        }
      }
      for (const entry of scanText(text, set).values()) if (!contacted.has(entry.value)) result.hits.push({ value: entry.value, evidence: "referenced", seenAs: [...entry.seenAs].join(", ") });
      return result;
    }
    const found = new Map();
    for (let start = 0; start < file.size; start += CHUNK) {
      const end = Math.min(file.size, start + CHUNK + OVERLAP);
      scanText(decoder.decode(await bytesOf(start, end)), set, found);
    }
    for (const entry of found.values()) result.hits.push({ value: entry.value, evidence: art.evidence, seenAs: [...entry.seenAs].join(", ") });
  } catch (error) {
    result.error = reason(error);
  }
  return result;
}

// ---------------------------------------------------------------- judging

/**
 * How much a hit asks of the person, after the scanner's own scale: 0 saved context only, 1 look
 * yourself, 2 qualified interpretation, 3 expert help promptly.
 */
export function actionOf(evidence, tier) {
  if (evidence === "referenced") return 0;
  if (evidence === "on-disk" && tier === "vuln-driver") return 1;
  if (evidence === "on-disk" || evidence === "persistence") return 3;
  if (tier === "delivery" || tier === "candiru-ip") return 1;
  return 2;
}

/** The hits of a run grouped by indicator, each with its places, strongest evidence and action, most serious first. */
export function findingsOf(results, set) {
  const by = new Map();
  for (const r of results) {
    for (const hit of r.hits) {
      const indicator = set.byValue.get(hit.value) ?? { value: hit.value, tier: "candiru", type: "domain", confidence: null, source: null };
      const f = by.get(hit.value) ?? { indicator, places: [], evidence: hit.evidence, action: 0 };
      f.places.push({ path: r.path, label: r.art.label, evidence: hit.evidence, seenAs: hit.seenAs });
      if (evidenceOrder.indexOf(hit.evidence) < evidenceOrder.indexOf(f.evidence)) f.evidence = hit.evidence;
      f.action = Math.max(f.action, actionOf(hit.evidence, indicator.tier));
      by.set(hit.value, f);
    }
  }
  return [...by.values()].sort((a, b) => b.action - a.action || evidenceOrder.indexOf(a.evidence) - evidenceOrder.indexOf(b.evidence) || a.indicator.value.localeCompare(b.indicator.value));
}

/** The places worth reading, by label, and the one line that says where each lives. */
export const PLACES = Object.freeze([
  { label: "History", hint: "History (Chromium) or places.sqlite (Firefox)" },
  { label: "Cookies", hint: "Network/Cookies (Chromium) or cookies.sqlite (Firefox)" },
  { label: "HTTP cache", hint: "Cache/Cache_Data, or Firefox's cache2 — on macOS and Linux under the caches folder, not the profile" },
  { label: "Site storage", hint: "Local Storage and Session Storage in a Chromium profile" },
  { label: "Chromium connection records", hint: "Network/Network Persistent State in a Chromium profile" },
  { label: "Chromium HSTS state", hint: "Network/TransportSecurity in a Chromium profile" },
  { label: "Hosts file", hint: "C:\\Windows\\System32\\drivers\\etc\\hosts, or /etc/hosts" },
  { label: "DNS records", hint: "a DNS-cache or DNS-log dump, pasted or picked" },
]);

/** Counts what the run read, could not read, and which places worth reading were not among the files. */
export function coverageOf(results) {
  const read = results.filter((r) => !r.error);
  const unread = results.filter((r) => r.error);
  const kinds = new Map();
  for (const r of read) kinds.set(r.art.label, (kinds.get(r.art.label) ?? 0) + 1);
  return {
    files: results.length,
    read: read.length,
    bytes: read.reduce((n, r) => n + r.size, 0),
    hashed: read.filter((r) => r.hashed).length,
    unread,
    kinds,
    missing: PLACES.filter((p) => !kinds.has(p.label)),
    blocked: [...new Set(read.flatMap((r) => r.blocked))],
    notes: read.map((r) => r.note).filter(Boolean),
  };
}

/** The sentence at the top: what was found and what to do, or what was read and what a clean read is not. */
export function judge(findings, coverage) {
  if (coverage.read === 0) return { tone: "warn", title: "Nothing was read", text: coverage.files === 0 ? "Pick a folder or files, or paste text, then run the check." : "None of the files could be read, so nothing is known: a gap is not a clean result. The list below says why for each.", action: -1 };
  if (findings.length === 0) {
    const gap = coverage.unread.length ? ` ${coverage.unread.length} file(s) could not be read; for those nothing is known.` : "";
    return { tone: "ok", title: "No known indicator in what was read", text: `That means no published indicator was found in these ${coverage.read} file(s) — not that the device is clean. Spyware of this grade is built to defeat exactly this kind of check, and caches and logs are short-lived.${gap}`, action: -1 };
  }
  const action = Math.max(...findings.map((f) => f.action));
  const n = findings.length;
  const what = `${n} indicator${n === 1 ? "" : "s"} found`;
  if (action === 3) return { tone: "bad", title: `${what}: seek expert help`, text: "A file has a spyware sample's fingerprint, or a registration to run names an indicator. Keep the file and this page's findings; do not open, run, move or delete anything. A helpline below can help, and you do not need to finish investigating first.", action };
  if (action === 2) return { tone: "bad", title: `${what}: have it looked at`, text: "A record names spyware infrastructure, not just advertising. A DNS record may be a failed lookup and a connection record is not proof of infection, but this warrants a qualified person's reading. Keep the files; do not clean them while arranging it.", action };
  if (action === 1) return { tone: "warn", title: `${what}: worth a look`, text: "Records of the ad network that delivered the spyware, or of a reassigned address. An ordinary ad can put these here; they do not show this device was selected or infected, and on their own they do not call for a helpline.", action };
  return { tone: "warn", title: `${what}, mentioned only`, text: "The names appear in saved content — a cache entry, a history row's text, a cookie store — which shows the string was stored, not that the browser connected to it.", action };
}

// ---------------------------------------------------------------- the page

function el(doc, tag, attrs, ...children) {
  const node = doc.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) node.setAttribute(k, v);
  for (const child of children) if (child !== null && child !== undefined) node.append(typeof child === "string" ? doc.createTextNode(child) : child);
  return node;
}

function size(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

const stateClass = (action) => (action >= 2 ? "bad" : action === 1 ? "warn" : "na");

function findingRow(doc, n, f) {
  const tier = TIERS[f.indicator.tier] ?? { label: f.indicator.tier, meaning: "" };
  const places = el(doc, "ul", { class: "ev" });
  for (const p of f.places.slice(0, 12)) {
    places.append(el(doc, "li", {}, el(doc, "code", {}, p.path), ` — ${p.label}: ${EVIDENCE[p.evidence]?.meaning ?? p.evidence}`, p.seenAs && p.seenAs !== f.indicator.value ? ` (as ${defang(p.seenAs)})` : ""));
  }
  if (f.places.length > 12) places.append(el(doc, "li", {}, `and ${f.places.length - 12} more files`));
  const provenance = [f.indicator.source ? `source: ${f.indicator.source}` : null, f.indicator.confidence ? `${f.indicator.confidence} source` : null].filter(Boolean).join(" · ");
  return el(
    doc,
    "article",
    { class: "check" },
    el(doc, "span", { class: "n" }, String(n).padStart(2, "0")),
    el(doc, "div", {}, el(doc, "div", { class: "t" }, `${defang(f.indicator.value)} — ${tier.label}`), el(doc, "p", { class: "d" }, tier.meaning), places, provenance ? el(doc, "p", { class: "small" }, provenance) : null),
    el(doc, "span", { class: `state ${stateClass(f.action)}` }, EVIDENCE[f.evidence]?.label ?? f.evidence),
  );
}

/** Draws the verdict, the findings and the coverage into the page. */
export function render(doc, findings, coverage) {
  const v = judge(findings, coverage);
  const banner = doc.getElementById("traces-verdict");
  if (banner) {
    doc.getElementById("traces-verdict-count").textContent = String(findings.length);
    doc.getElementById("traces-verdict-title").textContent = v.title;
    doc.getElementById("traces-verdict-text").textContent = v.text;
    banner.setAttribute("data-tone", v.tone);
    banner.hidden = false;
  }
  const help = doc.getElementById("traces-help");
  if (help) help.hidden = v.action < 2;
  const list = doc.getElementById("traces-findings");
  if (list) {
    list.replaceChildren(...findings.map((f, i) => findingRow(doc, i + 1, f)));
    list.hidden = findings.length === 0;
  }
  const cov = doc.getElementById("traces-coverage");
  if (cov) {
    const lines = [el(doc, "li", {}, `Read ${coverage.read} of ${coverage.files} file(s), ${size(coverage.bytes)}; ${coverage.hashed} fingerprinted.`)];
    if (coverage.kinds.size) lines.push(el(doc, "li", {}, `Among them: ${[...coverage.kinds].map(([k, n]) => `${k} ${n}`).join(" · ")}.`));
    if (coverage.missing.length) lines.push(el(doc, "li", {}, "Not in what was read, so unknown: ", ...coverage.missing.flatMap((m, i) => [i ? "; " : "", el(doc, "b", {}, m.label), ` (${m.hint})`]), "."));
    if (coverage.blocked.length) lines.push(el(doc, "li", {}, `Blocked in the hosts file, which is protective and not a finding: ${coverage.blocked.map(defang).join(", ")}.`));
    for (const n of coverage.notes) lines.push(el(doc, "li", {}, n));
    for (const r of coverage.unread.slice(0, 20)) lines.push(el(doc, "li", {}, el(doc, "code", {}, r.path), ` ${r.error}.`));
    if (coverage.unread.length > 20) lines.push(el(doc, "li", {}, `and ${coverage.unread.length - 20} more not read.`));
    cov.replaceChildren(el(doc, "h2", {}, "What was read"), el(doc, "ul", { class: "small plan" }, ...lines));
    cov.hidden = false;
  }
}

/** A dropped folder's files, walked through the entries API; a dropped file is itself. */
async function droppedFiles(items) {
  const out = [];
  const walk = async (entry, prefix) => {
    if (!entry) return;
    if (entry.isFile) {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      out.push({ file, path: prefix + entry.name });
      return;
    }
    const reader = entry.createReader();
    for (;;) {
      const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
      if (batch.length === 0) break;
      for (const child of batch) await walk(child, `${prefix}${entry.name}/`);
    }
  };
  for (const item of items) await walk(item.webkitGetAsEntry ? item.webkitGetAsEntry() : null, "");
  return out;
}

export function wire(doc, view) {
  const root = doc.getElementById("traces");
  const button = doc.getElementById("traces-run");
  const status = doc.getElementById("traces-status");
  const folder = doc.getElementById("traces-folder");
  const files = doc.getElementById("traces-files");
  const paste = doc.getElementById("traces-paste");
  const drop = doc.getElementById("traces-drop");
  const picked = doc.getElementById("traces-picked");
  if (!root || !button || !status) return;
  let dropped = [];
  let set = null;

  const chosen = () => [
    ...[...(folder?.files ?? [])].map((file) => ({ file, path: file.webkitRelativePath || file.name })),
    ...[...(files?.files ?? [])].map((file) => ({ file, path: file.name })),
    ...dropped,
  ];
  const tell = () => {
    const n = chosen().length;
    const text = paste && paste.value.trim() ? " and pasted text" : "";
    if (picked) picked.textContent = n || text ? `${n} file(s)${text} ready.` : "Nothing picked yet.";
  };
  folder?.addEventListener("change", tell);
  files?.addEventListener("change", tell);
  paste?.addEventListener("input", tell);
  drop?.addEventListener("dragover", (event) => {
    event.preventDefault();
    drop.classList.add("over");
  });
  drop?.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop?.addEventListener("drop", (event) => {
    event.preventDefault();
    drop.classList.remove("over");
    droppedFiles([...(event.dataTransfer?.items ?? [])])
      .then((list) => {
        dropped = dropped.concat(list);
        tell();
      })
      .catch((error) => {
        status.textContent = `The drop could not be read: ${error && error.message ? error.message : String(error)}`;
      });
  });

  async function run() {
    button.disabled = true;
    const subtle = view.crypto && view.crypto.subtle;
    if (!subtle) throw new Error("this page needs a secure (https) connection to fingerprint files");
    if (!set) {
      status.textContent = "Fetching the indicator list from this site…";
      const response = await view.fetch("/scan/traces/indicators.json", { credentials: "omit" });
      if (!response.ok) throw new Error(`the indicator list did not load (${response.status})`);
      const body = await response.json();
      set = indicatorSet(body.indicators);
      if (set.byValue.size === 0) throw new Error("this instance holds no indicator list yet; the Register fetches it daily");
      await prepareHsts(set, subtle);
    }
    const work = chosen();
    if (paste && paste.value.trim()) work.push({ file: new view.Blob([paste.value]), path: "pasted text" });
    const results = [];
    const started = view.performance.now();
    let last = 0;
    for (const [i, { file, path }] of work.entries()) {
      const now = view.performance.now();
      if (now - last > 200) {
        status.textContent = `Reading ${i + 1} of ${work.length}: ${path}`;
        last = now;
        await new Promise((resolve) => view.setTimeout(resolve, 0));
      }
      results.push(await readArtifact(file, path, set, subtle));
    }
    render(doc, findingsOf(results, set), coverageOf(results));
    root.classList.add("ran");
    const seconds = ((view.performance.now() - started) / 1000).toFixed(1);
    status.textContent = work.length ? `Read in ${seconds} s in this tab against ${set.byValue.size} indicators; nothing left this page.` : "Nothing to read yet.";
    button.textContent = "Read again";
    button.disabled = false;
  }

  button.addEventListener("click", () => {
    run().catch((error) => {
      status.textContent = `The check stopped: ${error && error.message ? error.message : String(error)}`;
      button.disabled = false;
    });
  });
  button.disabled = false;
  status.textContent = "Pick what to read, then run. Nothing is uploaded.";
}

if (typeof document !== "undefined" && typeof window !== "undefined" && document.getElementById("traces")) {
  wire(document, window);
}
