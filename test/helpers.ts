import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { createApp } from "../src/app.ts";
import { loadConfig, type Config } from "../src/config.ts";
import { migrate, openDatabase } from "../src/db.ts";
import type { HttpGet, HttpResponse } from "../src/http.ts";
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
}

/** An HttpGet that answers from a table of URLs and records every request it saw. */
export function fakeHttp(routes: Record<string, FakeRoute>): HttpGet & { calls: { url: string; etag: string | null | undefined }[] } {
  const calls: { url: string; etag: string | null | undefined }[] = [];
  const get: HttpGet = async (url, options = {}) => {
    calls.push({ url, etag: options.etag });
    const route = routes[url];
    if (!route) throw new Error(`fake http: no route for ${url}`);
    if (route.status && route.status >= 400) throw new Error(`HTTP ${route.status} from ${url}`);
    const base: HttpResponse = {
      url,
      status: 200,
      notModified: false,
      bytes: route.bytes ?? new TextEncoder().encode(route.text ?? ""),
      etag: route.etag ?? null,
      lastModified: route.lastModified ?? null,
      contentType: route.contentType ?? null,
    };
    if (route.notModifiedFor && options.etag === route.notModifiedFor) {
      return { ...base, status: 304, notModified: true, bytes: new Uint8Array(0) };
    }
    return base;
  };
  return Object.assign(get, { calls });
}

export interface TestApp {
  base: string;
  db: DatabaseSync;
  dataDir: string;
  config: Config;
  close(): Promise<void>;
}

export async function startTestApp(options: { env?: Record<string, string>; http?: HttpGet; now?: () => Date; resolve?: Resolve; readFile?: ReadText } = {}): Promise<TestApp> {
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
