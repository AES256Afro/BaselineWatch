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
    for (const id of ["hiding", "requests", "dns"]) setRow(doc, root, id, "run", "Running", []);

    const env = environment(nav);
    setEnv(root, "browser", env.browser);
    setEnv(root, "platform", env.platform);
    setEnv(root, "inapp", env.inApp ? `${env.inApp}: no blocker here, and no DNS profile can be installed` : "not an in-app view");
    setEnv(root, "brave", (await isBrave(nav)) ? "Brave: shields block requests without hiding by class names" : "not Brave");

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
