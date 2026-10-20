import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { brandImageType, readBrandMarks } from "../src/branding.ts";
import { cookieFrom, formPost, startTestApp, type TestApp } from "./helpers.ts";

const marksDir = path.join(import.meta.dirname, "..", "docs", "mockups", "logo");

// Only the magic numbers matter to the type check, so a stub body is enough.
const pngBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 73, 72, 68, 82]);
const icoBytes = new Uint8Array([0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 16, 16, 0, 0, 1, 0, 32, 0, 0, 0]);
const svgBytes = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');

describe("brand image types", () => {
  it("reads the type from the bytes and lets ICO in for the favicon alone", () => {
    expect(brandImageType("logo", pngBytes)).toBe("image/png");
    expect(brandImageType("favicon", icoBytes)).toBe("image/x-icon");
    expect(brandImageType("logo", icoBytes)).toBeNull();
    expect(brandImageType("logo", svgBytes)).toBeNull();
    expect(brandImageType("favicon", svgBytes)).toBeNull();
  });
});

describe("the repo's marks", () => {
  it("reads the design sheets' SVGs with their titles", () => {
    const marks = readBrandMarks(marksDir);
    expect(marks.length).toBeGreaterThan(20);
    const diff = marks.find((m) => m.id === "09-diff");
    expect(diff?.title).toBe("Diff");
    expect(marks.some((m) => m.id.startsWith("refined-"))).toBe(true);
    expect(new Set(marks.map((m) => m.id)).size).toBe(marks.length);
  });

  it("offers no marks on a checkout without the folder", () => {
    expect(readBrandMarks(path.join(marksDir, "no-such-folder"))).toEqual([]);
  });
});

describe("branding over HTTP", () => {
  let app: TestApp;
  afterEach(async () => {
    await app?.close();
  });

  async function upload(base: string, cookie: string | undefined, kind: string, bytes: Uint8Array, filename: string): Promise<Response> {
    const boundary = "----bwbrand";
    const enc = new TextEncoder();
    const head = enc.encode(`--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`);
    const tail = enc.encode(`\r\n--${boundary}--\r\n`);
    const body = new Uint8Array(head.length + bytes.length + tail.length);
    body.set(head, 0);
    body.set(bytes, head.length);
    body.set(tail, head.length + bytes.length);
    const headers: Record<string, string> = { "content-type": `multipart/form-data; boundary=${boundary}`, origin: base, "sec-fetch-site": "same-origin" };
    if (cookie) headers.cookie = cookie;
    return fetch(`${base}/branding/${kind}`, { method: "POST", headers, body, redirect: "manual" });
  }

  async function signIn(base: string): Promise<string> {
    return cookieFrom(await formPost(base, "/login", { password: "hunter2hunter2", next: "/" }));
  }

  it("lets the owner apply a repo mark as the logo, and readers see it everywhere", async () => {
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" } });
    expect((await formPost(app.base, "/branding/mark", { mark: "09-diff", kind: "logo" })).status).toBe(403);

    const before = await (await fetch(`${app.base}/`)).text();
    expect(before).not.toContain("brand-logo");

    const cookie = await signIn(app.base);
    const applied = await formPost(app.base, "/branding/mark", { mark: "09-diff", kind: "logo" }, cookie);
    expect(applied.status).toBe(303);
    expect(applied.headers.get("location")).toBe("/branding");

    const home = await (await fetch(`${app.base}/`)).text();
    expect(home).toContain('class="brand-logo" src="/branding/logo?v=');
    const served = await fetch(`${app.base}/branding/logo`);
    expect(served.status).toBe(200);
    expect(served.headers.get("content-type")).toContain("image/svg+xml");
    expect(await served.text()).toContain("BaselineWatch mark 09");

    // The Branding page names the mark and marks its card.
    const pageHtml = await (await fetch(`${app.base}/branding`, { headers: { cookie } })).text();
    expect(pageHtml).toContain('class="mark on"');

    const removed = await formPost(app.base, "/branding/logo/remove", {}, cookie);
    expect(removed.status).toBe(303);
    expect(await (await fetch(`${app.base}/`)).text()).not.toContain("brand-logo");
    expect((await fetch(`${app.base}/branding/logo`)).status).toBe(404);
  });

  it("takes an uploaded favicon, answers /favicon.ico and links it from the layout", async () => {
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" } });
    expect((await fetch(`${app.base}/favicon.ico`)).status).toBe(404);
    const cookie = await signIn(app.base);
    expect((await upload(app.base, undefined, "favicon", icoBytes, "fav.ico")).status).toBe(403);
    const uploaded = await upload(app.base, cookie, "favicon", icoBytes, "fav.ico");
    expect(uploaded.status).toBe(303);

    const home = await (await fetch(`${app.base}/`)).text();
    expect(home).toContain('<link rel="icon" href="/branding/favicon?v=');
    const ico = await fetch(`${app.base}/favicon.ico`);
    expect(ico.status).toBe(200);
    expect(ico.headers.get("content-type")).toContain("image/x-icon");
    expect(new Uint8Array(await ico.arrayBuffer())).toEqual(icoBytes);
  });

  it("refuses an uploaded SVG, an ICO logo and an unknown mark", async () => {
    app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" } });
    const cookie = await signIn(app.base);
    expect((await upload(app.base, cookie, "logo", svgBytes, "mark.svg")).status).toBe(422);
    expect((await upload(app.base, cookie, "logo", icoBytes, "fav.ico")).status).toBe(422);
    expect((await formPost(app.base, "/branding/mark", { mark: "no-such-mark", kind: "logo" }, cookie)).status).toBe(400);
    expect((await formPost(app.base, "/branding/mark", { mark: "09-diff", kind: "banner" }, cookie)).status).toBe(400);
  });
});
