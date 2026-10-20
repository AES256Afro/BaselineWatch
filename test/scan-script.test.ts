import path from "node:path";
import { pathToFileURL } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { probeControlPath, probeTestPaths } from "../src/scan.ts";

/**
 * The browser script (public/scan.js) driven with fakes: a document and view that hide whatever
 * names a pretend blocker hides, an Image that loads or fails by URL, and a fetch that answers the
 * two resolvers' shapes. No browser, no network.
 */

interface BaitSpec {
  kind: "class" | "id";
  name: string;
}
interface Probe {
  url: string;
  reason: "loaded" | "failed" | "timeout" | "policy";
  ms: number;
}
interface Read {
  origin: string;
  before: Probe;
  tests: { path: string; first: Probe; retry: Probe | null; final: Probe }[];
  after: Probe;
  verdict: "difference" | "none" | "policy" | "unknown";
  blocked: number;
  note: string;
}
interface Resolver {
  provider: string;
  state: "yes" | "no" | "unknown";
  detail: string;
}
interface ScanScript {
  BAITS: readonly BaitSpec[];
  CONTROLS: readonly BaitSpec[];
  CONTROL_PATH: string;
  TEST_PATHS: readonly string[];
  label(spec: BaitSpec): string;
  checkHiding(doc: unknown, view: unknown, options?: { settleMs?: number }): Promise<{ total: number; hidden: string[]; visible: string[]; controlsHidden: string[] }>;
  probeFrom(origin: string, deps: unknown): Promise<Read>;
  judgeRequests(before: Probe, tests: { final: Probe }[], after: Probe): { verdict: string; blocked: number; note: string };
  median(values: number[]): number | null;
  randomLabel(cryptoLike: { getRandomValues(bytes: Uint8Array): void }): string;
  checkAdGuard(fetchFn: unknown, randomName: string, timeoutMs?: number): Promise<Resolver>;
  checkNextDns(fetchFn: unknown, randomName: string, timeoutMs?: number): Promise<Resolver>;
  judgeDns(results: Resolver[]): string;
  environment(nav: { userAgent: string; maxTouchPoints?: number }): { browser: string; platform: string; inApp: string | null };
  isBrave(nav: unknown): Promise<boolean>;
  describeHiding(result: { total: number; hidden: string[]; visible: string[]; controlsHidden: string[] }): { state: string; text: string; lines: string[] };
  describeRequests(same: Read, cross: Read | null): { state: string; text: string; lines: string[] };
  describeDns(results: Resolver[]): { state: string; text: string; lines: string[] };
}

let scan: ScanScript;

beforeAll(async () => {
  // The script is plain JavaScript outside the TypeScript program; a file URL keeps the import untyped.
  scan = (await import(pathToFileURL(path.join(import.meta.dirname, "..", "public", "scan.js")).href)) as ScanScript;
});

/** A document whose elements are hidden when a pretend blocker's rule set names their class or id. */
function fakeDom(hiddenNames: Set<string>) {
  interface El {
    tag: string;
    className: string;
    id: string;
    attrs: Record<string, string>;
    children: El[];
    parent: El | null;
    setAttribute(key: string, value: string): void;
    appendChild(child: El): El;
    removeChild(child: El): El;
    readonly offsetHeight: number;
    readonly offsetWidth: number;
    readonly offsetParent: El | null;
  }
  const hidden = (el: El): boolean => el.className.split(" ").some((c) => c && hiddenNames.has(`.${c}`)) || (el.id !== "" && hiddenNames.has(`#${el.id}`));
  const make = (tag: string): El => ({
    tag,
    className: "",
    id: "",
    attrs: {},
    children: [],
    parent: null,
    setAttribute(key, value) {
      this.attrs[key] = value;
    },
    appendChild(child) {
      this.children.push(child);
      child.parent = this;
      return child;
    },
    removeChild(child) {
      this.children = this.children.filter((c) => c !== child);
      child.parent = null;
      return child;
    },
    get offsetHeight() {
      return hidden(this) ? 0 : 1;
    },
    get offsetWidth() {
      return hidden(this) ? 0 : 1;
    },
    get offsetParent() {
      return hidden(this) ? null : this.parent;
    },
  });
  const body = make("body");
  const doc = { body, createElement: make };
  const view = {
    getComputedStyle: (el: El) => ({ display: hidden(el) ? "none" : "block", visibility: "visible", opacity: "1" }),
    requestAnimationFrame: (cb: () => void) => setTimeout(cb, 0),
    setTimeout,
  };
  return { doc, view, body };
}

describe("ad hiding", () => {
  it("plants twenty baits and two controls", () => {
    expect(scan.BAITS).toHaveLength(20);
    expect(scan.BAITS.filter((b) => b.kind === "class")).toHaveLength(14);
    expect(scan.BAITS.filter((b) => b.kind === "id")).toHaveLength(6);
    expect(scan.CONTROLS).toHaveLength(2);
    expect(scan.BAITS.map(scan.label)).toContain(".adsbygoogle");
    expect(scan.BAITS.map(scan.label)).toContain("#ad");
    expect(new Set(scan.BAITS.map(scan.label)).size).toBe(20);
  });

  it("reads back which baits a blocker hid, leaves the controls alone, and tidies up", async () => {
    const { doc, view, body } = fakeDom(new Set([".adsbox", ".ad-banner", ".adsbygoogle", "#ad", "#ads"]));
    const result = await scan.checkHiding(doc, view, { settleMs: 1 });
    expect(result.total).toBe(20);
    expect(result.hidden).toEqual([".adsbox", ".ad-banner", ".adsbygoogle", "#ad", "#ads"]);
    expect(result.visible).toHaveLength(15);
    expect(result.controlsHidden).toEqual([]);
    expect(body.children).toHaveLength(0);
    expect(scan.describeHiding(result)).toMatchObject({ state: "ok", text: "Detected" });
    expect(scan.describeHiding(result).lines[0]).toBe("5 of 20 baits hidden; both controls visible.");
  });

  it("reports nothing hidden as not observed, never as unprotected", async () => {
    const { doc, view } = fakeDom(new Set());
    const result = await scan.checkHiding(doc, view, { settleMs: 0 });
    expect(result.hidden).toEqual([]);
    const drawn = scan.describeHiding(result);
    expect(drawn.state).toBe("na");
    expect(drawn.text).toBe("Not observed");
    expect(drawn.lines.join(" ")).toContain("Some blockers hide nothing and block everything");
  });

  it("voids the read when a control is hidden too", async () => {
    const { doc, view } = fakeDom(new Set([".adsbox", ".note-card"]));
    const result = await scan.checkHiding(doc, view, { settleMs: 0 });
    expect(result.controlsHidden).toEqual([".note-card"]);
    expect(scan.describeHiding(result)).toMatchObject({ state: "warn", text: "Unreadable" });
  });

  it("gives every bait the bw-bait class the stylesheet sizes and keeps the bait name on it", async () => {
    const seen: { className: string; id: string; attrs: Record<string, string> }[] = [];
    const { doc, view, body } = fakeDom(new Set());
    const original = body.appendChild.bind(body);
    body.appendChild = (holder) => {
      for (const child of holder.children) seen.push({ className: child.className, id: child.id, attrs: child.attrs });
      return original(holder);
    };
    await scan.checkHiding(doc, view, { settleMs: 0 });
    expect(seen).toHaveLength(22);
    expect(seen.every((s) => s.className.split(" ").includes("bw-bait") && s.attrs["aria-hidden"] === "true")).toBe(true);
    expect(seen.find((s) => s.className.startsWith("adsbox "))).toBeTruthy();
    expect(seen.find((s) => s.id === "adsense")?.className).toBe("bw-bait");
  });
});

/** Image fakes: `fails` says which paths never load; `hangs` which never answer; `policy` which the page policy refused. */
function imageDeps(options: { fails?: RegExp; hangs?: RegExp; policy?: RegExp; failOnce?: RegExp; timeoutMs?: number } = {}) {
  let clock = 0;
  let nonces = 0;
  const failed = new Set<string>();
  const loads: string[] = [];
  const deps = {
    createImage() {
      const img: { src: string; onload: (() => void) | null; onerror: (() => void) | null; crossOrigin?: string; referrerPolicy?: string } = { src: "", onload: null, onerror: null };
      let src = "";
      Object.defineProperty(img, "src", {
        get: () => src,
        set: (url: string) => {
          src = url;
          loads.push(url);
          const bare = url.split("?")[0] ?? url;
          clock += 10;
          if (options.hangs?.test(bare)) return;
          const once = options.failOnce?.test(bare) && !failed.has(bare);
          if (once) failed.add(bare);
          const fails = options.fails?.test(bare) || options.policy?.test(bare) || once;
          setTimeout(() => (fails ? img.onerror?.() : img.onload?.()), 0);
        },
      });
      return img;
    },
    now: () => clock,
    nonce: () => `n${(nonces += 1)}`,
    timeoutMs: options.timeoutMs ?? 50,
    policyBlocked: (url: string) => options.policy?.test(url.split("?")[0] ?? url) === true,
    loads,
  };
  return deps;
}

describe("ad requests", () => {
  it("uses the paths the server serves, in the order control, tests, control, each with a fresh query", async () => {
    expect(scan.CONTROL_PATH).toBe(probeControlPath);
    expect([...scan.TEST_PATHS]).toEqual([...probeTestPaths]);
    const deps = imageDeps();
    const read = await scan.probeFrom("", deps);
    expect(deps.loads.map((u) => u.split("?")[0])).toEqual([probeControlPath, ...probeTestPaths, probeControlPath]);
    expect(new Set(deps.loads.map((u) => u.split("?")[1])).size).toBe(5);
    expect(read.verdict).toBe("none");
    expect(read.blocked).toBe(0);
    expect(read.tests.every((t) => t.retry === null)).toBe(true);
  });

  it("sets anonymous and no-referrer on every image", async () => {
    const deps = imageDeps();
    const made: { crossOrigin?: string; referrerPolicy?: string }[] = [];
    const create = deps.createImage;
    deps.createImage = () => {
      const img = create();
      made.push(img);
      return img;
    };
    await scan.probeFrom("", deps);
    expect(made).toHaveLength(5);
    expect(made.every((img) => img.crossOrigin === "anonymous" && img.referrerPolicy === "no-referrer")).toBe(true);
  });

  it("reads a load difference when test images fail between controls that loaded, after one retry each", async () => {
    const deps = imageDeps({ fails: /ad_images|ad_skyscraper/ });
    const read = await scan.probeFrom("https://probe.example.net", deps);
    expect(read.verdict).toBe("difference");
    expect(read.blocked).toBe(2);
    expect(read.tests.map((t) => t.final.reason)).toEqual(["failed", "loaded", "failed"]);
    expect(read.tests.filter((t) => t.retry !== null)).toHaveLength(2);
    expect(deps.loads).toHaveLength(7);
    expect(deps.loads.every((u) => u.startsWith("https://probe.example.net/scan/probe/"))).toBe(true);
    expect(read.note).toBe("2 of 3 test images did not load; both controls loaded");
  });

  it("does not count a failure that the retry recovers from", async () => {
    const read = await scan.probeFrom("", imageDeps({ failOnce: /adsbanner/ }));
    expect(read.verdict).toBe("none");
    expect(read.tests[1]?.retry?.reason).toBe("loaded");
  });

  it("reports a timeout as unknown, never as blocked", async () => {
    const read = await scan.probeFrom("", imageDeps({ hangs: /adsbanner/, timeoutMs: 5 }));
    expect(read.verdict).toBe("unknown");
    expect(read.blocked).toBe(0);
    expect(read.tests[1]?.final.reason).toBe("timeout");
    expect(read.note).toBe("1 of 3 test images timed out");
  });

  it("reads nothing from an origin whose control did not load", async () => {
    const read = await scan.probeFrom("https://down.example.net", imageDeps({ fails: /control/ }));
    expect(read.verdict).toBe("unknown");
    expect(read.note).toMatch(/control image did not load/);
    const slow = await scan.probeFrom("", imageDeps({ hangs: /control/, timeoutMs: 5 }));
    expect(slow.note).toMatch(/control image timed out/);
  });

  it("names a failure the page's own policy caused", async () => {
    const read = await scan.probeFrom("https://probe.example.net", imageDeps({ policy: /probe\.example\.net/ }));
    expect(read.before.reason).toBe("policy");
    expect(read.verdict).toBe("unknown");
    const tests = await scan.probeFrom("", imageDeps({ policy: /ad_images/ }));
    expect(tests.tests[0]?.final.reason).toBe("policy");
    expect(tests.verdict).toBe("policy");
  });

  it("draws the row from the same-site read and the cross-site one", async () => {
    const same = await scan.probeFrom("", imageDeps({ fails: /ad_/ }));
    const cross = await scan.probeFrom("https://probe.example.net", imageDeps({ fails: /adsbanner/ }));
    const drawn = scan.describeRequests(same, cross);
    expect(drawn).toMatchObject({ state: "ok", text: "Load difference" });
    expect(drawn.lines[0]).toBe("Same-site: control before loaded, 2 of 3 test images did not load, control after loaded.");
    expect(drawn.lines[1]).toBe("Cross-site: control before loaded, 1 of 3 test images did not load, control after loaded.");
    expect(drawn.lines[2]).toMatch(/^No page-policy failures; 3 retries; \d+ ms median\.$/);
    const quiet = scan.describeRequests(await scan.probeFrom("", imageDeps()), null);
    expect(quiet).toMatchObject({ state: "na", text: "No difference" });
    expect(quiet.lines).toHaveLength(3);
    expect(scan.median([3, 1, 2])).toBe(2);
    expect(scan.median([4, 1, 2, 3])).toBe(3);
    expect(scan.median([])).toBeNull();
  });
});

type FetchInit = { signal: AbortSignal; credentials: string; referrerPolicy: string; mode: string; cache: string };
function fakeFetch(answer: (url: string) => unknown | Promise<unknown>) {
  const calls: { url: string; init: FetchInit }[] = [];
  const fetchFn = async (url: string, init: FetchInit) => {
    calls.push({ url, init });
    const body = await answer(url);
    return { ok: true, status: 200, json: async () => body };
  };
  return Object.assign(fetchFn, { calls });
}

describe("filtering DNS", () => {
  it("asks AdGuard with a fresh random name and reads the server group", async () => {
    const fetchFn = fakeFetch(() => ({ device_id: "", protocol: "DOH-ADGUARD", server_group_name: "family", node_location: "x", node_name: "y" }));
    const result = await scan.checkAdGuard(fetchFn, "0123456789abcdef");
    expect(fetchFn.calls[0]?.url).toBe("https://a0123456789abcdef-dnscheck.adguard-dns.com/dnscheck/test");
    expect(fetchFn.calls[0]?.init).toMatchObject({ credentials: "omit", referrerPolicy: "no-referrer", mode: "cors", cache: "no-store" });
    expect(result).toEqual({ provider: "AdGuard DNS", state: "yes", detail: "server group family, DOH" });
  });

  it("reads no answer from AdGuard's name as not AdGuard, and a timeout as unknown", async () => {
    const down = async () => {
      throw new TypeError("Failed to fetch");
    };
    expect(await scan.checkAdGuard(down, "abc")).toMatchObject({ state: "no" });
    const slow = (_url: string, init: FetchInit) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
      });
    expect(await scan.checkAdGuard(slow, "abc", 5)).toMatchObject({ state: "unknown", detail: "timed out" });
  });

  it("asks NextDNS at a fresh random name, not the bare host whose redirect a page cannot follow", async () => {
    const fetchFn = fakeFetch(() => ({ status: "ok", protocol: "DOH", profile: "abc123" }));
    expect(await scan.checkNextDns(fetchFn, "fedcba9876543210")).toEqual({ provider: "NextDNS", state: "yes", detail: "profile abc123, DOH" });
    expect(fetchFn.calls[0]?.url).toBe("https://fedcba9876543210.test.nextdns.io/");
    expect(fetchFn.calls[0]?.init).toMatchObject({ credentials: "omit", referrerPolicy: "no-referrer", mode: "cors", cache: "no-store" });
  });

  it("reads NextDNS's two answer shapes", async () => {
    expect(await scan.checkNextDns(fakeFetch(() => ({ type: "", matchedName: "", profile: "9f8e7d", lists: null })), "abc")).toMatchObject({ state: "yes", detail: "profile 9f8e7d" });
    expect(await scan.checkNextDns(fakeFetch(() => ({ status: "unconfigured", resolver: "192.0.2.1" })), "abc")).toMatchObject({ state: "no" });
    expect(await scan.checkNextDns(fakeFetch(() => ({ type: "", matchedName: "", profile: "", lists: null })), "abc")).toMatchObject({ state: "no" });
    expect(await scan.checkNextDns(fakeFetch(() => ({ something: "else" })), "abc")).toMatchObject({ state: "unknown" });
    const down = async () => {
      throw new TypeError("Failed to fetch");
    };
    expect(await scan.checkNextDns(down, "abc")).toMatchObject({ state: "unknown" });
  });

  it("names the resolver that answered, or says none seen", () => {
    const yes = { provider: "NextDNS", state: "yes" as const, detail: "profile abc" };
    const no = { provider: "AdGuard DNS", state: "no" as const, detail: "no answer" };
    const unknown = { provider: "AdGuard DNS", state: "unknown" as const, detail: "timed out" };
    expect(scan.judgeDns([no, yes])).toBe("ok");
    expect(scan.judgeDns([no, { ...no, provider: "NextDNS" }])).toBe("none");
    expect(scan.judgeDns([unknown, { ...no, provider: "NextDNS" }])).toBe("unknown");
    expect(scan.describeDns([no, yes])).toMatchObject({ state: "ok", text: "NextDNS" });
    const none = scan.describeDns([no, { ...no, provider: "NextDNS" }]);
    expect(none).toMatchObject({ state: "na", text: "None seen" });
    expect(none.lines.at(-1)).toContain("Pi-hole");
  });

  it("draws sixteen hex characters from the random source", () => {
    const label = scan.randomLabel({ getRandomValues: (bytes) => bytes.fill(171) });
    expect(label).toBe("abababababababab");
  });
});

describe("environment", () => {
  it("names the browser, the platform and an in-app view from the user agent", () => {
    expect(scan.environment({ userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36" })).toEqual({ browser: "Chrome 141", platform: "Windows", inApp: null });
    expect(scan.environment({ userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0" }).browser).toBe("Edge 141");
    expect(scan.environment({ userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15" })).toEqual({ browser: "Safari 26", platform: "macOS", inApp: null });
    expect(scan.environment({ userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15", maxTouchPoints: 5 }).platform).toBe("iPadOS");
    expect(scan.environment({ userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 400.0.0.0" })).toEqual({ browser: "unknown", platform: "iOS", inApp: "Instagram" });
    expect(scan.environment({ userAgent: "Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.0.0 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/500.0.0.0;]" })).toMatchObject({ platform: "Android", inApp: "Facebook" });
    expect(scan.environment({ userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0" })).toEqual({ browser: "Firefox 144", platform: "Linux", inApp: null });
  });

  it("asks Brave and takes anything else as not Brave", async () => {
    expect(await scan.isBrave({ brave: { isBrave: async () => true } })).toBe(true);
    expect(await scan.isBrave({})).toBe(false);
    expect(
      await scan.isBrave({
        brave: {
          isBrave: async () => {
            throw new Error("no");
          },
        },
      }),
    ).toBe(false);
  });
});
