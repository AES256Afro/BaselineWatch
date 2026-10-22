/**
 * BaselineWatch · the browser check (/scan).
 *
 * The one script this site serves. It runs three checks in this tab and writes what it saw into
 * the page's rows; nothing is uploaded and nothing is stored. The technique follows a public scan
 * page's, as summarised in docs/PLAN.md under M12:
 *
 *  1. Ad hiding. Twenty elements named the way ad slots are named and two with neutral names are
 *     planted off-screen; after two frames, and once more half a second later for blockers that
 *     apply their rules on a timer, the script reads which were hidden. Hidden baits beside visible
 *     controls mean a filter list's generic cosmetic rules are at work in this browser.
 *  2. Ad requests. Images on paths EasyList's request rules match (/ad_images/, /adsbanner-,
 *     /ad_skyscraper.gif) are loaded one after another between control images with identical
 *     bytes, from this origin and, when the page names one, from a second origin for the
 *     cross-site case. No cookies (crossOrigin "anonymous"), no referrer, never displayed. A load
 *     difference is the signal; a timeout is unknown; a failure the page's own policy caused is
 *     reported as such; a failed test image is tried once more before it counts.
 *  3. Filtering DNS. AdGuard's self-check (a fresh random name under -dnscheck.adguard-dns.com
 *     resolves only through AdGuard's resolvers and answers JSON naming the server group) and
 *     NextDNS's (a fresh random name under test.nextdns.io answers with the profile only through
 *     NextDNS). Those two are the only outside hosts contacted; no advertising domain ever is.
 *
 * Plain ES2020 module, no dependencies, served from /assets/scan.js under the page's own policy
 * (script-src 'self'). Every function that touches the browser takes it as an argument, so
 * test/scan-script.test.ts drives them with fakes and none of them needs a browser.
 */

/** The twenty bait names: fourteen classes and six ids. */
export const BAITS = Object.freeze([
  ...["adsbox", "ad-banner", "advertisement", "adsbygoogle", "textads", "ad-container", "ad_box", "ads-banner", "google-ad", "sponsored-link", "ad-unit", "banner_ad", "sponsored_ad", "ad-placement"].map((name) => ({ kind: "class", name })),
  ...["ad", "ads", "adsense", "ad_banner", "banner-ad", "advertisement"].map((name) => ({ kind: "id", name })),
]);

/** Two neutral names no filter list has a reason to touch; a hidden control voids the read. */
export const CONTROLS = Object.freeze([
  { kind: "class", name: "note-card" },
  { kind: "id", name: "reading-pane" },
]);

/** The control image and the three test images this server serves (src/scan.ts holds the same list). */
export const CONTROL_PATH = "/scan/probe/control.gif";
export const TEST_PATHS = Object.freeze(["/scan/probe/ad_images/1.gif", "/scan/probe/adsbanner-1.gif", "/scan/probe/ad_skyscraper.gif"]);

/**
 * The resolvers' self-checks, each asked at a fresh random name so no cache answers. AdGuard's
 * name takes the label in front. NextDNS's bare test.nextdns.io redirects to a random name under
 * itself without CORS headers, which a page's fetch may not follow, so the script picks the name.
 */
export const ADGUARD_SUFFIX = "-dnscheck.adguard-dns.com";
export const NEXTDNS_SUFFIX = ".test.nextdns.io";

/** Every request gives up after this long and is reported as unknown, never as blocked. */
export const TIMEOUT_MS = 4000;

/** How long after the second frame the baits are read once more. */
export const SETTLE_MS = 600;

// ---------------------------------------------------------------- ad hiding

/** `.adsbox` or `#ad`: how a bait is named in the results. */
export function label(spec) {
  return spec.kind === "id" ? `#${spec.name}` : `.${spec.name}`;
}

/** One element per spec, carrying the bait name and the `bw-bait` class the stylesheet sizes. */
export function plant(doc, specs) {
  return specs.map((spec) => {
    const el = doc.createElement("div");
    el.className = spec.kind === "class" ? `${spec.name} bw-bait` : "bw-bait";
    if (spec.kind === "id") el.id = spec.name;
    el.setAttribute("aria-hidden", "true");
    return { spec, el };
  });
}

/** True when a planted element is not drawn: a blocker's display:none, or anything else that leaves it without a box. */
export function isHidden(el, view) {
  const style = view.getComputedStyle(el);
  if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") return true;
  return el.offsetParent === null || el.offsetHeight === 0 || el.offsetWidth === 0;
}

function frames(view, count) {
  return new Promise((resolve) => {
    const step = (left) => (left === 0 ? resolve() : view.requestAnimationFrame(() => step(left - 1)));
    step(count);
  });
}

function sleep(view, ms) {
  return new Promise((resolve) => view.setTimeout(resolve, ms));
}

/**
 * Plants the baits and the controls, reads them after two frames and again after `settleMs`, and
 * takes them away. Returns the hidden and visible bait labels and any control that was hidden.
 */
export async function checkHiding(doc, view, options = {}) {
  const settleMs = options.settleMs === undefined ? SETTLE_MS : options.settleMs;
  const holder = doc.createElement("div");
  holder.className = "bw-baits";
  holder.setAttribute("aria-hidden", "true");
  const baits = plant(doc, BAITS);
  const controls = plant(doc, CONTROLS);
  for (const { el } of [...baits, ...controls]) holder.appendChild(el);
  doc.body.appendChild(holder);
  try {
    const read = () => ({
      hidden: baits.filter(({ el }) => isHidden(el, view)).map(({ spec }) => label(spec)),
      controlsHidden: controls.filter(({ el }) => isHidden(el, view)).map(({ spec }) => label(spec)),
    });
    await frames(view, 2);
    let seen = read();
    if (settleMs > 0) {
      await sleep(view, settleMs);
      seen = read();
    }
    const all = baits.map(({ spec }) => label(spec));
    return { total: all.length, hidden: seen.hidden, visible: all.filter((name) => !seen.hidden.includes(name)), controlsHidden: seen.controlsHidden };
  } finally {
    doc.body.removeChild(holder);
  }
}

// ------------------------------------------------------------- ad requests

/** The probe URL: a path under an origin ("" for this one) with a fresh query so no cache answers. */
export function probeUrl(origin, path, nonce) {
  return `${origin}${path}?r=${nonce}`;
}

/**
 * Loads one image without cookies, without a referrer and without showing it, and says how it
 * ended: loaded, failed, timeout, or policy when the page's own policy refused it. `deps` holds
 * `createImage` (a fresh Image), `now` (a clock in milliseconds), `timeoutMs` and `policyBlocked`
 * (whether a securitypolicyviolation named this URL).
 */
export function probeImage(url, deps) {
  const timeoutMs = deps.timeoutMs === undefined ? TIMEOUT_MS : deps.timeoutMs;
  const policyBlocked = deps.policyBlocked || (() => false);
  return new Promise((resolve) => {
    const img = deps.createImage();
    img.crossOrigin = "anonymous";
    img.referrerPolicy = "no-referrer";
    const started = deps.now();
    let settled = false;
    let timer = null;
    const finish = (reason) => {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      img.onload = null;
      img.onerror = null;
      resolve({ url, reason, ms: Math.round(deps.now() - started) });
    };
    timer = setTimeout(() => finish("timeout"), timeoutMs);
    img.onload = () => finish("loaded");
    // The policy-violation event is dispatched before the error event is queued; one turn of the
    // loop lets it land before the reason is read.
    img.onerror = () => setTimeout(() => finish(policyBlocked(url) ? "policy" : "failed"), 0);
    img.src = url;
  });
}

/** Reads one origin's sequence: control, the three tests (each retried once on failure), control. */
export async function probeFrom(origin, deps) {
  const before = await probeImage(probeUrl(origin, CONTROL_PATH, deps.nonce()), deps);
  const tests = [];
  for (const path of TEST_PATHS) {
    const first = await probeImage(probeUrl(origin, path, deps.nonce()), deps);
    const retry = first.reason === "failed" ? await probeImage(probeUrl(origin, path, deps.nonce()), deps) : null;
    tests.push({ path, first, retry, final: retry || first });
  }
  const after = await probeImage(probeUrl(origin, CONTROL_PATH, deps.nonce()), deps);
  return { origin, before, tests, after, ...judgeRequests(before, tests, after) };
}

/**
 * What one origin's loads say: `difference` (a test image failed while both controls loaded),
 * `none` (everything loaded), `policy` (the page's own policy refused a test image) or `unknown`
 * (a control failed or something timed out). Never a verdict from a timeout.
 */
export function judgeRequests(before, tests, after) {
  const finals = tests.map((t) => t.final);
  if (before.reason !== "loaded" || after.reason !== "loaded") {
    const timedOut = before.reason === "timeout" || after.reason === "timeout";
    return {
      verdict: "unknown",
      blocked: 0,
      note: timedOut ? "a control image timed out, so nothing can be read from this origin" : "a control image did not load, so this origin is unreachable or everything from it is blocked",
    };
  }
  if (finals.some((r) => r.reason === "policy")) {
    return { verdict: "policy", blocked: 0, note: "this page's own policy refused a test image, so the probe origin is not in it" };
  }
  const blocked = finals.filter((r) => r.reason === "failed").length;
  const timeouts = finals.filter((r) => r.reason === "timeout").length;
  if (blocked > 0) return { verdict: "difference", blocked, note: `${blocked} of ${finals.length} test images did not load; both controls loaded` };
  if (timeouts > 0) return { verdict: "unknown", blocked: 0, note: `${timeouts} of ${finals.length} test images timed out` };
  return { verdict: "none", blocked: 0, note: `all ${finals.length} test images loaded, as the controls did` };
}

/** The median of a list of numbers, or null for none. */
export function median(values) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[middle] : Math.round((sorted[middle - 1] + sorted[middle]) / 2);
}

// ----------------------------------------------------------- filtering DNS

/** Sixteen hex characters from the browser's random source, for AdGuard's name and the probes' queries. */
export function randomLabel(cryptoLike) {
  const bytes = new Uint8Array(8);
  cryptoLike.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function fetchJson(fetchFn, url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchFn(url, { mode: "cors", credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer", redirect: "follow", signal: controller.signal });
    if (!response.ok) return { kind: "status", status: response.status };
    return { kind: "json", body: await response.json() };
  } catch (error) {
    return { kind: error && error.name === "AbortError" ? "timeout" : "unreachable" };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * AdGuard's self-check: the name resolves only through AdGuard's resolvers, so an answer with a
 * `server_group_name` means this browser uses AdGuard DNS and no answer at all means it does not.
 */
export async function checkAdGuard(fetchFn, randomName, timeoutMs = TIMEOUT_MS) {
  const provider = "AdGuard DNS";
  const answer = await fetchJson(fetchFn, `https://a${randomName}${ADGUARD_SUFFIX}/dnscheck/test`, timeoutMs);
  if (answer.kind === "json" && answer.body && typeof answer.body.server_group_name === "string") {
    const protocol = typeof answer.body.protocol === "string" ? answer.body.protocol.split("-")[0] : "";
    return { provider, state: "yes", detail: `server group ${answer.body.server_group_name}${protocol ? `, ${protocol}` : ""}` };
  }
  if (answer.kind === "unreachable") return { provider, state: "no", detail: "no answer: this browser's resolver is not AdGuard DNS" };
  if (answer.kind === "timeout") return { provider, state: "unknown", detail: "timed out" };
  return { provider, state: "unknown", detail: "answered, but not with the self-check's fields" };
}

/**
 * NextDNS's self-check: any name under test.nextdns.io answers for every resolver (the names are
 * public) and names the profile only when NextDNS answered the query. Two shapes are known: a
 * `status` of ok or unconfigured, and, to a page's cross-origin fetch, a `profile` string that is
 * empty when NextDNS is not the resolver.
 */
export async function checkNextDns(fetchFn, randomName, timeoutMs = TIMEOUT_MS) {
  const provider = "NextDNS";
  const answer = await fetchJson(fetchFn, `https://${randomName}${NEXTDNS_SUFFIX}/`, timeoutMs);
  if (answer.kind === "json" && answer.body && typeof answer.body === "object") {
    const body = answer.body;
    const profile = typeof body.profile === "string" ? body.profile : "";
    const protocol = typeof body.protocol === "string" ? body.protocol : "";
    if (body.status === "ok" || profile !== "") return { provider, state: "yes", detail: `profile ${profile || "set"}${protocol ? `, ${protocol}` : ""}` };
    if (body.status === "unconfigured" || "profile" in body) return { provider, state: "no", detail: "answered without a profile: this browser's resolver is not NextDNS" };
    return { provider, state: "unknown", detail: "answered, but not with the self-check's fields" };
  }
  if (answer.kind === "timeout") return { provider, state: "unknown", detail: "timed out" };
  return { provider, state: "unknown", detail: "no answer from test.nextdns.io (blocked, or offline)" };
}

/** The row's state from the two resolvers: ok when one named itself, none when both said no, else unknown. */
export function judgeDns(results) {
  if (results.some((r) => r.state === "yes")) return "ok";
  if (results.every((r) => r.state === "no")) return "none";
  return "unknown";
}

// ------------------------------------------------------------- environment

const browserTokens = [
  ["Edge", /Edg\/(\d+)/],
  ["Opera", /OPR\/(\d+)/],
  ["Samsung Internet", /SamsungBrowser\/(\d+)/],
  ["Firefox", /(?:Firefox|FxiOS)\/(\d+)/],
  ["Chrome", /(?:Chrome|CriOS)\/(\d+)/],
  ["Safari", /Version\/(\d+)[^)]*Safari\//],
];

/**
 * What the user agent says about where this runs: the browser family and version, the platform,
 * and whether this is an app's in-app view (which has no blocker and cannot install a DNS
 * profile). Read from the string alone; nothing is sent anywhere.
 */
export function environment(nav) {
  const ua = String(nav.userAgent || "");
  const has = (re) => re.test(ua);
  let browser = "unknown";
  for (const [name, re] of browserTokens) {
    const match = ua.match(re);
    if (match) {
      browser = `${name} ${match[1]}`;
      break;
    }
  }
  const inApp = has(/FBAN|FBAV|FB_IAB/) ? "Facebook" : has(/Instagram/) ? "Instagram" : has(/TikTok|BytedanceWebview|musical_ly/) ? "TikTok" : has(/Snapchat/) ? "Snapchat" : has(/\bLine\//) ? "LINE" : has(/; wv\)/) ? "an Android app's web view" : null;
  const touch = Number(nav.maxTouchPoints || 0);
  const platform = has(/iPhone/)
    ? "iOS"
    : has(/iPad/) || (has(/Macintosh/) && touch > 1)
      ? "iPadOS"
      : has(/Android/)
        ? "Android"
        : has(/Windows/)
          ? "Windows"
          : has(/Macintosh|Mac OS X/)
            ? "macOS"
            : has(/CrOS/)
              ? "ChromeOS"
              : has(/Linux/)
                ? "Linux"
                : "unknown";
  return { browser, platform, inApp };
}

/** Brave says so through navigator.brave.isBrave(); anything else answers false. */
export async function isBrave(nav) {
  try {
    return nav.brave && typeof nav.brave.isBrave === "function" ? Boolean(await nav.brave.isBrave()) : false;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- the page

function setRow(doc, root, id, state, text, lines) {
  const row = root.querySelector(`[data-check="${id}"]`);
  if (!row) return;
  const badge = row.querySelector(".state");
  badge.className = `state ${state}`;
  badge.textContent = text;
  const list = row.querySelector(".ev");
  while (list.firstChild) list.removeChild(list.firstChild);
  for (const line of lines) {
    const item = doc.createElement("li");
    item.textContent = line;
    list.appendChild(item);
  }
  list.hidden = lines.length === 0;
}

function setEnv(root, key, text) {
  const cell = root.querySelector(`[data-env="${key}"]`);
  if (cell) cell.textContent = text;
}

/** The ad-hiding row from a `checkHiding` result. */
export function describeHiding(result) {
  if (result.controlsHidden.length > 0) {
    return { state: "warn", text: "Unreadable", lines: [`A control was hidden too (${result.controlsHidden.join(", ")}), so the read says nothing about ad rules.`] };
  }
  if (result.hidden.length === 0) {
    return { state: "na", text: "Not observed", lines: [`0 of ${result.total} baits hidden; both controls visible.`, "No generic cosmetic rule acted on this page. Some blockers hide nothing and block everything; the next row is the better eye."] };
  }
  const lines = [`${result.hidden.length} of ${result.total} baits hidden; both controls visible.`, `Hidden: ${result.hidden.join(", ")}.`];
  lines.push(result.visible.length > 0 ? `Visible: ${result.visible.join(", ")}.` : "Every bait was hidden.");
  return { state: "ok", text: "Detected", lines };
}

/** The ad-requests row from the same-site read and, when there was one, the cross-site read. */
export function describeRequests(same, cross) {
  const reads = cross ? [same, cross] : [same];
  const line = (name, r) => {
    const image = (p) => (p.reason === "loaded" ? "loaded" : p.reason === "timeout" ? "timed out" : p.reason === "policy" ? "refused by this page's policy" : "did not load");
    return `${name}: control before ${image(r.before)}, ${r.blocked} of ${r.tests.length} test images did not load, control after ${image(r.after)}.`;
  };
  const lines = [line("Same-site", same)];
  if (cross) lines.push(line("Cross-site", cross));
  const retries = reads.reduce((n, r) => n + r.tests.filter((t) => t.retry !== null).length, 0);
  const times = reads.flatMap((r) => [r.before, ...r.tests.map((t) => t.final), r.after]).filter((p) => p.reason === "loaded").map((p) => p.ms);
  const mid = median(times);
  const policy = reads.some((r) => r.verdict === "policy");
  lines.push(`${policy ? "A page-policy failure" : "No page-policy failures"}; ${retries === 0 ? "no retries needed" : `${retries} ${retries === 1 ? "retry" : "retries"}`}${mid === null ? "" : `; ${mid} ms median`}.`);
  if (policy) return { state: "warn", text: "Policy failure", lines };
  if (reads.some((r) => r.verdict === "difference")) return { state: "ok", text: "Load difference", lines };
  if (reads.every((r) => r.verdict === "none")) {
    lines.push("Every test image loaded: no request filter acted on these paths in this browser.");
    return { state: "na", text: "No difference", lines };
  }
  return { state: "na", text: "Unknown", lines: [...lines, ...reads.filter((r) => r.verdict === "unknown").map((r) => `${r.origin ? "Cross-site" : "Same-site"}: ${r.note}.`)] };
}

/** The filtering-DNS row from the two self-checks. */
export function describeDns(results) {
  const lines = results.map((r) => `${r.provider}: ${r.detail}.`);
  const state = judgeDns(results);
  if (state === "ok") return { state: "ok", text: results.filter((r) => r.state === "yes").map((r) => r.provider).join(", "), lines };
  if (state === "none") {
    lines.push("Neither named itself for this browser. Cloudflare, Quad9 and a Pi-hole have no self-check; the network check is the eye for those.");
    return { state: "na", text: "None seen", lines };
  }
  return { state: "na", text: "Unknown", lines };
}

// ------------------------------------------------- what this browser gives away (S1)

/** Global Privacy Control and Do Not Track as this browser sends them. */
export function describeSignals(nav) {
  const gpc = nav.globalPrivacyControl === true;
  const dnt = nav.doNotTrack === "1" || nav.doNotTrack === "yes";
  const lines = [
    gpc ? "Sec-GPC: 1 is sent: a legal opt-out of sale and sharing where the law reads it (California, Colorado, Connecticut and more)." : "No Global Privacy Control: sites get no opt-out signal. Firefox, Brave and DuckDuckGo can send it; Chrome and Safari cannot yet.",
    dnt ? "DNT: 1 is sent. Almost no site honours it, but it is harmless." : "Do Not Track is off, which is the default everywhere now.",
  ];
  return { state: gpc ? "ok" : "na", text: gpc ? "GPC sent" : "No GPC", lines };
}

/** ICE candidates gathered with no STUN server at all: what WebRTC gives away without asking anyone outside. */
export async function gatherCandidates(view, ms = 1500) {
  if (typeof view.RTCPeerConnection !== "function") return { supported: false, candidates: [] };
  const candidates = [];
  const pc = new view.RTCPeerConnection({ iceServers: [] });
  try {
    pc.createDataChannel("probe");
    pc.onicecandidate = (event) => {
      if (event.candidate && event.candidate.candidate) candidates.push(String(event.candidate.candidate));
    };
    await pc.setLocalDescription(await pc.createOffer());
    await sleep(view, ms);
  } catch (error) {
    return { supported: true, candidates, error: error && error.message ? error.message : String(error) };
  } finally {
    pc.close();
  }
  return { supported: true, candidates };
}

const privateIp = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fd[0-9a-f]{2}:|fc[0-9a-f]{2}:)/i;

/** The addresses in the candidate lines, sorted into mDNS names (hidden), private and public. */
export function judgeWebRtc(result) {
  if (!result.supported) return { state: "ok", text: "No WebRTC", lines: ["This browser has no RTCPeerConnection, or it is disabled: nothing to give away."] };
  const addresses = [...new Set(result.candidates.map((c) => c.split(" ")[4]).filter(Boolean))];
  const mdns = addresses.filter((a) => /\.local$/i.test(a));
  const ips = addresses.filter((a) => !/\.local$/i.test(a) && !/^(127\.|::1$)/.test(a));
  const priv = ips.filter((a) => privateIp.test(a));
  const pub = ips.filter((a) => !privateIp.test(a));
  if (pub.length) return { state: "bad", text: "Public address exposed", lines: [`A public address is in the candidates: ${pub.join(", ")}. With a VPN on, this is the address the VPN was meant to hide.`] };
  if (priv.length) return { state: "warn", text: "LAN address exposed", lines: [`A private address is in the candidates: ${priv.join(", ")}. Any site can read it; current browsers hide it behind an mDNS name.`] };
  if (mdns.length) return { state: "ok", text: "Hidden (mDNS)", lines: [`${mdns.length} candidate(s), each an mDNS name rather than an address: the modern default, and the right one.`] };
  return { state: "ok", text: "Nothing exposed", lines: [`No host candidate was offered${result.error ? ` (${result.error})` : ""}.`] };
}

const sampleFonts = ["Arial", "Helvetica Neue", "Times New Roman", "Courier New", "Georgia", "Verdana", "Segoe UI", "Roboto", "Ubuntu", "SF Pro Text", "Calibri", "Noto Sans"];

async function hashOf(view, text) {
  const digest = await view.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].slice(0, 6).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** A canvas drawn the way fingerprinters draw one, hashed; two draws that differ mean the browser randomises it. */
async function canvasHash(doc, view) {
  const canvas = doc.createElement("canvas");
  canvas.width = 220;
  canvas.height = 40;
  const ctx = canvas.getContext("2d");
  if (!ctx || typeof canvas.toDataURL !== "function") return null;
  ctx.textBaseline = "top";
  ctx.font = "16px Arial";
  ctx.fillStyle = "#f60";
  ctx.fillRect(10, 5, 80, 20);
  ctx.fillStyle = "#069";
  ctx.fillText("BaselineWatch ✓ 2026", 2, 15);
  ctx.strokeStyle = "rgba(102,204,0,0.7)";
  ctx.beginPath();
  ctx.arc(150, 20, 15, 0, Math.PI * 2);
  ctx.stroke();
  return hashOf(view, canvas.toDataURL());
}

/** Which of a dozen common fonts are installed, by whether a line of text changes width against the generic family. */
function fontSurface(doc) {
  const span = doc.createElement("span");
  span.textContent = "mmmmmmmmmmlli";
  span.style.cssText = "position:absolute;left:-9999px;top:0;font-size:48px;white-space:nowrap";
  doc.body.appendChild(span);
  const generic = ["monospace", "serif", "sans-serif"];
  const base = {};
  for (const g of generic) {
    span.style.fontFamily = g;
    base[g] = span.offsetWidth;
  }
  const present = sampleFonts.filter((f) =>
    generic.some((g) => {
      span.style.fontFamily = `'${f}',${g}`;
      return span.offsetWidth !== base[g];
    }),
  );
  span.remove();
  return present;
}

/** The surface a fingerprinter reads, as this page can read it, each part named. */
export async function fingerprintSurface(doc, view) {
  const nav = view.navigator;
  const screen = view.screen || {};
  let timezone = null;
  try {
    timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || null;
  } catch {
    timezone = null;
  }
  return {
    screen: `${screen.width || "?"}×${screen.height || "?"}×${screen.colorDepth || "?"}`,
    dpr: view.devicePixelRatio || 1,
    timezone,
    languages: (nav.languages || []).join(","),
    cores: nav.hardwareConcurrency || null,
    memory: nav.deviceMemory || null,
    touch: Number(nav.maxTouchPoints || 0),
    canvas: await canvasHash(doc, view),
    canvasAgain: await canvasHash(doc, view),
    fonts: fontSurface(doc),
  };
}

export function describeFingerprint(s) {
  const randomised = Boolean(s.canvas && s.canvasAgain && s.canvas !== s.canvasAgain);
  const lines = [
    `Screen ${s.screen} at ${s.dpr}×; ${s.timezone || "no time zone read"}; languages ${s.languages || "?"}; ${s.cores || "?"} cores${s.memory ? `, ${s.memory} GB` : ""}; ${s.touch} touch points.`,
    randomised ? "Canvas randomised: two draws gave two hashes (Brave's farbling, or a resist-fingerprinting setting)." : s.canvas ? `Canvas stable: the same drawing hashes to ${s.canvas} every time.` : "Canvas unavailable.",
    `${s.fonts.length} of ${sampleFonts.length} common fonts detectable${s.fonts.length ? `: ${s.fonts.join(", ")}` : ""}.`,
  ];
  if (randomised) return { state: "ok", text: "Randomised", lines };
  lines.push("A surface this stable and this wide lets a site recognise this browser again without a cookie. Brave, Firefox with resistFingerprinting, and the Tor Browser blur it.");
  return { state: "warn", text: "Stable surface", lines };
}

/** What the server at `origin` saw of a request from this page: the Referer, and the transport. */
export async function echoFrom(fetchFn, origin) {
  const response = await fetchFn(`${origin}/scan/echo`, { credentials: "omit", cache: "no-store", mode: origin ? "cors" : "same-origin" });
  if (!response.ok) throw new Error(`echo answered ${response.status}`);
  return response.json();
}

/** The Referer as this site and (when there is one) another site received it, against this page's policy. */
export function describeReferrer(same, cross, policy, pageUrl) {
  let origin = "";
  try {
    origin = new URL(pageUrl).origin;
  } catch {
    origin = "";
  }
  const word = (ref) => (!ref ? "nothing" : ref === pageUrl ? "the full address of this page" : ref.replace(/\/$/, "") === origin ? "the origin only" : ref);
  const lines = [`To this site: ${word(same ? same.referer : null)}.`];
  if (cross) lines.push(`To another site: ${word(cross.referer)}.`);
  else lines.push("No second origin is configured for a cross-site read; the policy line below says what would be sent.");
  lines.push(`This page's policy: ${policy || "the browser's default"}. Every current browser defaults to strict-origin-when-cross-origin: the origin only across sites, nothing to plain HTTP.`);
  const crossLeak = Boolean(cross && cross.referer && cross.referer.replace(/\/$/, "") !== origin);
  if (crossLeak) return { state: "warn", text: "Full URL cross-site", lines };
  if (!same) return { state: "na", text: "Unreadable", lines };
  return { state: "ok", text: cross ? (cross.referer ? "Origin only" : "Nothing cross-site") : "Policy as set", lines };
}

/** How this page reached the site, from the server's echo and the browser's own connection object. */
export function describeTransport(echo, nav) {
  if (!echo) return { state: "na", text: "Unreadable", lines: ["The echo did not answer, so nothing is known about the transport."] };
  const lines = [`Reached this site over ${echo.family || "an unknown family"}, HTTP/${echo.httpVersion || "?"}${echo.tls ? ` on ${echo.tls}` : echo.protocol === "https" ? " (TLS ended at the edge in front of the server)" : ""}.`];
  if (echo.family === "IPv4") lines.push("No IPv6 on this path: either the network has none or the browser preferred IPv4.");
  const conn = nav.connection;
  if (conn && conn.effectiveType) lines.push(`The browser rates the connection ${conn.effectiveType}${conn.saveData ? ", with Save-Data on" : ""}.`);
  return { state: echo.protocol === "https" ? "ok" : "warn", text: `${echo.family || "?"} · HTTP/${echo.httpVersion || "?"}`, lines };
}

/** The privacy tally: GPC, WebRTC hidden, fingerprint randomised, referrer trimmed. */
export function privacyLine(sig, rtc, fp, ref) {
  const marks = [
    [sig.state === "ok", "GPC sent"],
    [rtc.state === "ok", "WebRTC hidden"],
    [fp.state === "ok", "fingerprint randomised"],
    [ref.state === "ok", "referrer trimmed"],
  ];
  const seen = marks.filter(([on]) => on).length;
  return { seen, text: `Privacy: ${seen} of ${marks.length} — ${marks.map(([on, name]) => `${name} ${on ? "✓" : "✗"}`).join(", ")}.` };
}

// --------------------------------------------------------- this browser's version (S1)

/** Dotted versions compared as numbers, a missing part counting as zero. */
export function compareDotted(a, b) {
  const parts = (v) => (String(v || "").match(/^\d+(\.\d+)*/) || [""])[0].split(".").filter((p) => p !== "").map(Number);
  const x = parts(a);
  const y = parts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i += 1) {
    const d = (x[i] || 0) - (y[i] || 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** The browser family the vendor feeds know, and the fullest version this browser will say: client hints where they exist, else the user agent. */
export async function browserVersion(nav) {
  const ua = String(nav.userAgent || "");
  const family = /Edg\//.test(ua) ? "edge" : /OPR\/|SamsungBrowser\//.test(ua) ? null : /(?:Firefox|FxiOS)\//.test(ua) ? "firefox" : /(?:Chrome|CriOS)\//.test(ua) ? "chrome" : /Version\/\d+[^)]*Safari\//.test(ua) ? "safari" : null;
  let version = null;
  try {
    if (nav.userAgentData && typeof nav.userAgentData.getHighEntropyValues === "function") {
      const hints = await nav.userAgentData.getHighEntropyValues(["fullVersionList"]);
      const brands = (hints && hints.fullVersionList) || [];
      const want = family === "edge" ? /Microsoft Edge/i : family === "chrome" ? /Google Chrome|Chromium/i : null;
      const hit = want ? brands.find((b) => want.test(String(b.brand))) : null;
      if (hit && hit.version) version = String(hit.version);
    }
  } catch {
    version = null;
  }
  if (!version) {
    const m = family === "edge" ? /Edg\/(\d+(?:\.\d+)*)/.exec(ua) : family === "firefox" ? /(?:Firefox|FxiOS)\/(\d+(?:\.\d+)*)/.exec(ua) : family === "chrome" ? /(?:Chrome|CriOS)\/(\d+(?:\.\d+)*)/.exec(ua) : family === "safari" ? /Version\/(\d+(?:\.\d+)*)/.exec(ua) : null;
    version = m ? m[1] : null;
  }
  // An iPhone says its iOS version plainly ("CPU iPhone OS 26_7_1"); an iPad has called itself a Mac since iPadOS 13, so its line is unread.
  const ios = /iPhone OS (\d+(?:_\d+)*)/.exec(ua);
  return { family, version, os: ios ? { line: "ios", version: ios[1].replace(/_/g, ".") } : null };
}

/** The phone's iOS against Apple's releases: within its own line, and told when a newer line exists. */
export function describeOs(os, answer) {
  if (!os) return null;
  const name = os.line === "ios" ? "iOS" : os.line;
  if (!answer || !answer.latest) return { state: "na", text: `${name} ${os.version}: the sources hold no release of it yet.` };
  const behind = compareDotted(os.version, answer.latest) < 0;
  const line = answer.newerLine ? ` ${name} ${answer.newerLine} exists for devices that support it.` : "";
  if (!behind) return { state: "ok", text: `${name} ${os.version} is the newest of its line (${answer.latest}).${line}` };
  const n = (answer.newer || []).length;
  return { state: n >= 2 ? "bad" : "warn", text: `${name} ${os.version} is behind ${answer.latest}: ${n} newer release${n === 1 ? "" : "s"} with security content. Settings → General → Software Update.${line}` };
}

/** This browser's version against what the server says the vendor has announced. */
export function describeVersion(who, answer) {
  const name = who.family ? who.family.charAt(0).toUpperCase() + who.family.slice(1) : "This browser";
  if (!who.family) return { state: "na", text: "Not judged", lines: ["No vendor feed for this browser is read here, so its version is not judged."] };
  if (!who.version) return { state: "na", text: "Unreadable", lines: [`${name} did not say its version.`] };
  if (!answer || !answer.latest) return { state: "na", text: "Unknown", lines: [`${name} ${who.version}: the sources hold no release of ${name} yet.`] };
  const behind = compareDotted(who.version, answer.latest) < 0;
  const lines = [`Running ${name} ${who.version}; the newest the vendor has announced is ${answer.latest}.`];
  if (!behind) return { state: "ok", text: "Current", lines };
  for (const n of (answer.newer || []).slice(0, 4)) lines.push(`${n.version}: ${n.title}${n.published ? ` (${String(n.published).slice(0, 10)})` : ""}.`);
  lines.push("Update the browser, then relaunch it: the fixes are not in effect until the new version is the one running.");
  const count = (answer.newer || []).length;
  return { state: count >= 2 ? "bad" : "warn", text: `Behind by ${count}`, lines };
}

// ------------------------------------------------------- verdict and fixes

/**
 * Which fix-panel lines fit where the check ran: a browser key for the requests panel and a
 * platform key for the DNS panel, each falling back to "other" when nothing matched. An in-app
 * view outranks the browser family (it has no blocker at all), and Brave outranks Chrome (its
 * shields are the fix, not an extension).
 */
export function fixKeys(env, brave) {
  const family = String(env.browser || "").split(" ")[0].toLowerCase();
  const browser = env.inApp ? "inapp" : brave ? "brave" : ["firefox", "chrome", "edge", "safari"].includes(family) ? family : "other";
  const platforms = { iOS: "ios", iPadOS: "ios", Android: "android", Windows: "windows", macOS: "macos", Linux: "linux" };
  return { browser, platform: platforms[env.platform] || "other" };
}

/**
 * One sentence that says where this browser stands, from the three rows' described results, and
 * which fix panels to unfold. "Open" is only a definite negative (every test image loaded; both
 * resolvers said no); an unknown row is named but never grows a fix, because a fix for a row that
 * could not be read would be guessing.
 */
export function verdictOf(h, r, d) {
  const hidingSeen = h.state === "ok";
  const requestsSeen = r.state === "ok";
  const dnsSeen = d.state === "ok";
  const openRequests = r.text === "No difference";
  const openDns = d.text === "None seen";
  const unknowns = (requestsSeen || openRequests ? 0 : 1) + (dnsSeen || openDns ? 0 : 1) + (h.state === "warn" ? 1 : 0);
  const seen = [hidingSeen, requestsSeen, dnsSeen].filter(Boolean).length;
  const fixes = [...(openRequests ? ["requests"] : []), ...(openDns ? ["dns"] : [])];

  let title;
  let text;
  if (openRequests && openDns) {
    title = hidingSeen ? "Partly protected: ads are hidden here, not stopped." : "No protection seen in this browser.";
    text = hidingSeen
      ? "Something hides ad slots in this browser, but the requests underneath still left this tab, and no filtering resolver answered. The two fixes below close the gap; re-run after each and watch the row turn."
      : "Nothing hid the baits, every test image loaded, and no filtering resolver answered for this browser. The two fixes below are about two minutes each; re-run after each and watch the row turn.";
  } else if (openRequests) {
    title = dnsSeen ? "A resolver filters for this browser, but it still fetches ads." : "This browser fetches ads: nothing stopped the test requests.";
    text = `${dnsSeen ? "The filtering resolver below answers for this browser, yet every" : "Every"} test image loaded: requests on ad paths still go out. The fix below closes that; re-run after to see the row turn.`;
  } else if (openDns) {
    title = requestsSeen ? "This browser blocks ads; every other app is on its own." : "No filtering resolver answered for this browser.";
    text = `${requestsSeen ? "Requests on ad paths are stopped in this tab. " : ""}No filtering resolver answered, and a resolver is what covers every app on this device, not one browser. The fix below closes that — unless a Pi-hole or a VPN's filter already does, which this page cannot see.`;
  } else if (fixes.length === 0 && unknowns === 0) {
    title = seen === 3 ? "Protected: hidden, blocked, and a filtering resolver answering." : "Nothing left to fix that this page can see.";
    text = "Every row this page can read came back covered. Still signals, not a certificate: this is one browser, and ads served from a site's own domain pass every blocker.";
  }
  if (unknowns > 0) {
    title = title || "Some rows could not be read.";
    text = (text || "") + ` ${unknowns} row${unknowns === 1 ? "" : "s"} could not be read this run; an unreadable row gets no fix, because it would be a guess. Re-running usually settles it.`;
    text = text.trim();
  }
  return { seen, fixes, title, text };
}

/**
 * Unfolds the fix panels the verdict named, shows the one line that fits this browser or
 * platform ("other" when none does), and points each panel's guide link at the detected
 * platform's page and the panel's own section.
 */
export function applyFixes(root, fixes, keys) {
  const panels = [
    { id: "fix-requests", open: fixes.includes("requests"), key: keys.browser },
    { id: "fix-dns", open: fixes.includes("dns"), key: keys.platform },
  ];
  for (const panel of panels) {
    const el = root.querySelector(`#${panel.id}`);
    if (!el) continue;
    el.hidden = !panel.open;
    if (!panel.open) continue;
    let matched = false;
    for (const line of el.querySelectorAll("[data-for]")) {
      const hit = line.getAttribute("data-for") === panel.key;
      line.hidden = !hit;
      matched = matched || hit;
    }
    if (!matched) {
      const fallback = el.querySelector('[data-for="other"]');
      if (fallback) fallback.hidden = false;
    }
    for (const link of el.querySelectorAll("[data-guide]")) {
      const anchor = link.getAttribute("data-anchor") || "";
      const platform = keys.platform === "other" ? "" : `/${keys.platform}`;
      link.setAttribute("href", `/scan/guide${platform}${platform && anchor ? `#${anchor}` : ""}`);
    }
  }
}

/** Finds the page's parts, arms the button, and runs the three checks when it is pressed. */
export function wire(doc, view) {
  const root = doc.getElementById("scan");
  const button = doc.getElementById("scan-run");
  const status = doc.getElementById("scan-status");
  if (!root || !button || !status) return;

  const violations = new Set();
  doc.addEventListener("securitypolicyviolation", (event) => {
    if (event.blockedURI) violations.add(String(event.blockedURI));
  });
  // A violation names the full URL (CSP 3) or, from an older engine, the origin alone.
  const policyBlocked = (url) => [...violations].some((v) => v === url || url.split("?")[0] === v.split("?")[0] || (v.length > 0 && url.startsWith(v)));

  const crossOrigin = (root.getAttribute("data-probe-origin") || "").replace(/\/+$/, "");
  const nav = view.navigator;

  async function run() {
    button.disabled = true;
    const started = view.performance.now();
    for (const id of ["hiding", "requests", "dns", "signals", "webrtc", "fingerprint", "referrer", "transport", "version"]) setRow(doc, root, id, "run", "Running", []);

    const env = environment(nav);
    const brave = await isBrave(nav);
    setEnv(root, "browser", env.browser);
    setEnv(root, "platform", env.platform);
    setEnv(root, "inapp", env.inApp ? `${env.inApp}: no blocker here, and no DNS profile can be installed` : "not an in-app view");
    setEnv(root, "brave", brave ? "Brave: shields block requests without hiding by class names" : "not Brave");

    status.textContent = "Running: ad hiding…";
    const hiding = await checkHiding(doc, view);
    const h = describeHiding(hiding);
    setRow(doc, root, "hiding", h.state, h.text, h.lines);

    status.textContent = "Running: ad requests…";
    const deps = { createImage: () => new view.Image(), now: () => view.performance.now(), nonce: () => randomLabel(view.crypto), policyBlocked };
    const same = await probeFrom("", deps);
    const cross = crossOrigin ? await probeFrom(crossOrigin, deps) : null;
    const r = describeRequests(same, cross);
    setRow(doc, root, "requests", r.state, r.text, r.lines);

    status.textContent = "Running: filtering DNS…";
    const fetchFn = (url, init) => view.fetch(url, init);
    const results = await Promise.all([checkAdGuard(fetchFn, randomLabel(view.crypto)), checkNextDns(fetchFn, randomLabel(view.crypto))]);
    const d = describeDns(results);
    setRow(doc, root, "dns", d.state, d.text, d.lines);

    status.textContent = "Running: privacy signals…";
    const sig = describeSignals(nav);
    setRow(doc, root, "signals", sig.state, sig.text, sig.lines);
    status.textContent = "Running: WebRTC…";
    const rtc = judgeWebRtc(await gatherCandidates(view));
    setRow(doc, root, "webrtc", rtc.state, rtc.text, rtc.lines);
    status.textContent = "Running: fingerprint surface…";
    let fp;
    try {
      fp = describeFingerprint(await fingerprintSurface(doc, view));
    } catch (error) {
      fp = { state: "na", text: "Unreadable", lines: [`The surface could not be read: ${error && error.message ? error.message : String(error)}`] };
    }
    setRow(doc, root, "fingerprint", fp.state, fp.text, fp.lines);
    status.textContent = "Running: referrer and transport…";
    let echoSame = null;
    let echoCross = null;
    try {
      echoSame = await echoFrom(fetchFn, "");
    } catch {
      echoSame = null;
    }
    if (crossOrigin) {
      try {
        echoCross = await echoFrom(fetchFn, crossOrigin);
      } catch {
        echoCross = null;
      }
    }
    const ref = describeReferrer(echoSame, echoCross, doc.referrerPolicy, view.location.href);
    setRow(doc, root, "referrer", ref.state, ref.text, ref.lines);
    const tr = describeTransport(echoSame, nav);
    setRow(doc, root, "transport", tr.state, tr.text, tr.lines);
    status.textContent = "Running: browser version…";
    const who = await browserVersion(nav);
    let answer = null;
    if (who.family && who.version) {
      try {
        const r = await fetchFn(`/scan/browser-check?browser=${who.family}&version=${encodeURIComponent(who.version)}`, { cache: "no-store" });
        if (r.ok) answer = await r.json();
      } catch {
        answer = null;
      }
    }
    const ver = describeVersion(who, answer);
    if (who.os) {
      let osAnswer = null;
      try {
        const r = await fetchFn(`/scan/browser-check?browser=${who.os.line}&version=${encodeURIComponent(who.os.version)}`, { cache: "no-store" });
        if (r.ok) osAnswer = await r.json();
      } catch {
        osAnswer = null;
      }
      const os = describeOs(who.os, osAnswer);
      if (os) {
        ver.lines.push(os.text);
        const worse = { ok: 0, na: 0, warn: 1, bad: 2 };
        if (worse[os.state] > worse[ver.state]) {
          ver.state = os.state;
          ver.text = os.state === "bad" ? "Behind on iOS" : "iOS behind";
        }
      }
    }
    setRow(doc, root, "version", ver.state, ver.text, ver.lines);
    const privacy = doc.getElementById("scan-privacy");
    if (privacy) {
      privacy.textContent = privacyLine(sig, rtc, fp, ref).text;
      privacy.hidden = false;
    }

    const v = verdictOf(h, r, d);
    const banner = doc.getElementById("scan-verdict");
    if (banner) {
      const count = doc.getElementById("scan-verdict-count");
      const title = doc.getElementById("scan-verdict-title");
      const text = doc.getElementById("scan-verdict-text");
      if (count) count.textContent = String(v.seen);
      if (title) title.textContent = v.title;
      if (text) text.textContent = v.text;
      banner.setAttribute("data-tone", v.fixes.length === 0 ? "ok" : "warn");
      banner.hidden = false;
    }
    applyFixes(root, v.fixes, fixKeys(env, brave));
    const open = doc.getElementById("scan-open");
    if (open) {
      open.textContent = v.fixes.length === 0 ? "" : `${v.fixes.length} ${v.fixes.length === 1 ? "fix" : "fixes"} open above`;
      open.hidden = v.fixes.length === 0;
    }
    root.classList.add("ran");

    const seconds = ((view.performance.now() - started) / 1000).toFixed(1);
    status.textContent = `Ran in ${seconds} s in this tab. Signals, not a certificate; after changing a blocker's settings, reload first.`;
    button.textContent = "Run the check again";
    button.disabled = false;
  }

  button.addEventListener("click", () => {
    run().catch((error) => {
      status.textContent = `The check stopped: ${error && error.message ? error.message : String(error)}`;
      button.disabled = false;
    });
  });
  button.disabled = false;
  status.textContent = "Not run yet. About four seconds in this tab; nothing is uploaded.";
}

if (typeof document !== "undefined" && typeof window !== "undefined" && document.getElementById("scan")) {
  wire(document, window);
}
