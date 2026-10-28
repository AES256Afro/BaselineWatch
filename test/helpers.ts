import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { createApp } from "../src/app.ts";
import { loadConfig, type Config } from "../src/config.ts";
import { migrate, openDatabase } from "../src/db.ts";
import type { DnsLookup, TlsProbe } from "../src/domaincheck.ts";
import { HttpError, type HttpGet, type HttpResponse } from "../src/http.ts";
import type { ReadText, Resolve } from "../src/netscan.ts";

export const fixturesDir = path.join(import.meta.dirname, "fixtures");

export function fixture(name: string): Uint8Array {
  return new Uint8Array(readFileSync(path.join(fixturesDir, name)));
}

export interface FakeRoute {
  bytes?: Uint8Array;
  text?: string;
  status?: number;
  etag?: string | null;
  lastModified?: string | null;
  contentType?: string | null;
  /** Answer 304 when the request carries this etag. */
  notModifiedFor?: string;
  /** Response headers, as the client lowercases them. */
  headers?: Record<string, string>;
}

/** An HttpGet that answers from a table of URLs and records every request it saw. */
export function fakeHttp(routes: Record<string, FakeRoute>): HttpGet & { calls: { url: string; etag: string | null | undefined }[] } {
  const calls: { url: string; etag: string | null | undefined }[] = [];
  const get: HttpGet = async (url, options = {}) => {
    calls.push({ url, etag: options.etag });
    const route = routes[url];
    if (!route) throw new Error(`fake http: no route for ${url}`);
    // A 3xx under manual redirects and every 4xx or 5xx fail the way the client fails, headers attached.
    if (route.status && (route.status >= 400 || (route.status >= 300 && options.redirect === "manual"))) throw new HttpError(url, route.status, route.headers ?? {});
    const base: HttpResponse = {
      url,
      status: 200,
      notModified: false,
      bytes: route.bytes ?? new TextEncoder().encode(route.text ?? ""),
      etag: route.etag ?? null,
      lastModified: route.lastModified ?? null,
      contentType: route.contentType ?? null,
      headers: route.headers ?? {},
    };
    if (route.notModifiedFor && options.etag === route.notModifiedFor) {
      return { ...base, status: 304, notModified: true, bytes: new Uint8Array(0) };
    }
    return base;
  };
  return Object.assign(get, { calls });
}

/**
 * The commit each pinned release of the SP 800-53 catalog is loaded from, against the fixture that
 * holds that release's slice of it. Every fixture carries the same controls — AC-1, the SA-15 and
 * SI-2 and SI-7 families, and SA-24 where it exists — so a diff between two of them is the
 * publisher's change and not a difference in how the fixture was cut.
 */
const nistReleaseFixtures: [sha: string, catalog: string, profile: string][] = [
  ["601b282bee", "oscal-catalog-5.1.2.json", "oscal-profile-moderate-5.1.2.json"],
  ["bae69b5a53", "oscal-catalog-5.1.1-patch.json", "oscal-profile-moderate-5.1.1-patch.json"],
  ["1763607deb", "oscal-catalog-5.1.1-u2.json", "oscal-profile-moderate-5.1.1-u2.json"],
  ["b517381112", "oscal-catalog-5.1.1-u3.json", "oscal-profile-moderate-5.1.1-u3.json"],
  ["941c978d14", "oscal-catalog-5.1.1.json", "oscal-profile-moderate-5.1.1.json"],
  ["bc8a528770", "oscal-catalog-5.2.0-first.json", "oscal-profile-moderate-5.2.0-first.json"],
];

/**
 * An HttpGet that answers the whole NIST history: Revision 4 under its own key, every pinned
 * release of Revision 5, and the live URL — which carries no commit — as the current release, the
 * way a scheduled fetch sees it.
 */
export function nistFixtureHttp(): HttpGet {
  return async (url) => {
    const release = nistReleaseFixtures.find(([sha]) => url.includes(sha));
    let name: string;
    if (url.includes("rev4")) name = "oscal-catalog-rev4.json";
    else if (url.includes("_catalog.json")) name = release ? release[1] : "oscal-catalog-5.2.0.json";
    else if (url.includes("baseline_profile.json")) name = release ? release[2] : "oscal-profile-moderate-5.2.0.json";
    else throw new Error(`no fixture for ${url}`);
    return { url, status: 200, notModified: false, bytes: fixture(name), etag: null, lastModified: null, contentType: "application/json" };
  };
}

/**
 * Most tests want one diff rather than the whole back catalogue: the 5.1.1+u4 release and the
 * 5.2.0 release after it. Walking every pinned release has its own test in register.test.ts.
 */
export function nistOneDiff(target: { url: string }): boolean {
  return target.url.includes("941c978d14") || target.url.includes("bc8a528770");
}

/** The release the current catalog's bytes belong to, for a test that wants only that one. */
export function nistCurrentRelease<T extends { url: string }>(targets: T[]): T {
  const target = targets.find((t) => t.url.includes("bc8a528770"));
  if (!target) throw new Error("the 5.2.0 release is no longer pinned in the adapter");
  return target;
}

export interface TestApp {
  base: string;
  db: DatabaseSync;
  dataDir: string;
  config: Config;
  close(): Promise<void>;
}

export async function startTestApp(options: { env?: Record<string, string>; http?: HttpGet; now?: () => Date; resolve?: Resolve; readFile?: ReadText; dns?: DnsLookup; tls?: TlsProbe } = {}): Promise<TestApp> {
  const dataDir = mkdtempSync(path.join(os.tmpdir(), "bw-app-"));
  const db = openDatabase(":memory:");
  const migration = migrate(db);
  const config = loadConfig({ BW_DATA_DIR: dataDir, BW_SCHEDULER: "false", ...options.env });
  const app = createApp({
    config,
    db,
    migrations: migration.known,
    startedAt: Date.now() - 5000,
    ...(options.http ? { http: options.http } : {}),
    ...(options.now ? { now: options.now } : {}),
    ...(options.resolve ? { resolve: options.resolve } : {}),
    ...(options.readFile ? { readFile: options.readFile } : {}),
    ...(options.dns ? { dns: options.dns } : {}),
    ...(options.tls ? { tls: options.tls } : {}),
  });
  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    base,
    db,
    dataDir,
    config,
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      db.close();
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

/** A same-origin form post, the way a browser sends one from the app's own page. */
export function formPost(base: string, path: string, fields: Record<string, string>, cookie?: string): Promise<Response> {
  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded",
    origin: base,
    "sec-fetch-site": "same-origin",
  };
  if (cookie) headers.cookie = cookie;
  return fetch(`${base}${path}`, { method: "POST", headers, body: new URLSearchParams(fields).toString(), redirect: "manual" });
}

export function cookieFrom(response: Response): string {
  const header = response.headers.get("set-cookie") ?? "";
  return header.split(";")[0] ?? "";
}
