import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { addSaved, deleteSaved, listSaved, savablePath } from "../src/saved.ts";
import { cookieFrom, formPost, startTestApp } from "./helpers.ts";

/** Saved searches (N6): a named list page with its filters, kept on the desk and on Today. */

const now = new Date("2026-10-21T22:00:00Z");

describe("a savable path", () => {
  it("is one of the list pages with a query string, on this site, and nothing else", () => {
    expect(savablePath("/vulnerabilities?kev=1&platform=windows")).toBe("/vulnerabilities?kev=1&platform=windows");
    expect(savablePath("/?group=news&q=router")).toBe("/?group=news&q=router");
    expect(savablePath("/search?q=ac-2")).toBe("/search?q=ac-2");
    expect(savablePath("/vulnerabilities/microsoft?family=Windows+Kernel")).toBe("/vulnerabilities/microsoft?family=Windows+Kernel");
    expect(savablePath("/vulnerabilities")).toBeNull();
    expect(savablePath("/scan/domain?name=x")).toBeNull();
    expect(savablePath("//evil.example/?q=1")).toBeNull();
    expect(savablePath("https://evil.example/?q=1")).toBeNull();
    expect(savablePath('/vulnerabilities?q="<script>')).toBeNull();
  });
});

describe("the desk", () => {
  it("keeps a list once by its path, and lets it go", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    expect(addSaved(db, "Windows KEV", "/vulnerabilities?kev=1&platform=windows", now.toISOString())).toBe(true);
    expect(addSaved(db, "Again", "/vulnerabilities?kev=1&platform=windows", now.toISOString())).toBe(false);
    expect(listSaved(db).map((s) => s.name)).toEqual(["Windows KEV"]);
    expect(deleteSaved(db, listSaved(db)[0]!.id)).toBe(true);
    expect(listSaved(db)).toEqual([]);
    db.close();
  });

  it("shows the owner a Save box on a filtered list, keeps it, and lists it on Today and the menu", async () => {
    const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" }, now: () => now });
    try {
      const visitor = await (await fetch(`${app.base}/vulnerabilities?kev=1`)).text();
      expect(visitor).not.toContain('action="/saved"');
      expect((await formPost(app.base, "/saved", { name: "x", path: "/vulnerabilities?kev=1" })).status).toBe(403);
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
      const unfiltered = await (await fetch(`${app.base}/vulnerabilities`, { headers: { cookie } })).text();
      expect(unfiltered).not.toContain('action="/saved"');
      const filtered = await (await fetch(`${app.base}/vulnerabilities?kev=1`, { headers: { cookie } })).text();
      expect(filtered).toContain('<input type="hidden" name="path" value="/vulnerabilities?kev=1">');
      expect((await formPost(app.base, "/saved", { name: "x", path: "https://evil.example/?q=1" }, cookie)).status).toBe(400);
      const saved = await formPost(app.base, "/saved", { name: "In the KEV", path: "/vulnerabilities?kev=1" }, cookie);
      expect(saved.status).toBe(303);
      expect(saved.headers.get("location")).toBe("/vulnerabilities?kev=1");
      const again = await (await fetch(`${app.base}/vulnerabilities?kev=1`, { headers: { cookie } })).text();
      expect(again).toContain('This list is <a href="/saved">saved</a>.');
      const list = await (await fetch(`${app.base}/saved`, { headers: { cookie } })).text();
      expect(list).toContain('<a href="/vulnerabilities?kev=1"><b>In the KEV</b></a>');
      expect(list).toContain('aria-current="page"><b>Saved searches</b>');
      const today = await (await fetch(`${app.base}/today`, { headers: { cookie } })).text();
      expect(today).toContain('<h2><a href="/saved">Saved searches</a></h2>');
      expect(today).toContain('<li><a href="/vulnerabilities?kev=1">In the KEV</a></li>');
      // The News and a search carry the form too; a visitor's Today has no box.
      expect(await (await fetch(`${app.base}/?group=news`, { headers: { cookie } })).text()).toContain('name="path" value="/?group=news"');
      expect(await (await fetch(`${app.base}/search?q=widget`, { headers: { cookie } })).text()).toContain('name="path" value="/search?q=widget"');
      expect(await (await fetch(`${app.base}/today`)).text()).not.toContain("Saved searches</a></h2>");
      const id = (app.db.prepare("SELECT id FROM saved_searches").get() as { id: number }).id;
      expect((await formPost(app.base, `/saved/${id}/delete`, {}, cookie)).status).toBe(303);
      expect((await formPost(app.base, `/saved/${id}/delete`, {}, cookie)).status).toBe(404);
    } finally {
      await app.close();
    }
  });
});
