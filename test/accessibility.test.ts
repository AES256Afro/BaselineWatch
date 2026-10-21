import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startTestApp, type TestApp } from "./helpers.ts";

/**
 * The usability sweep's invariants (N8), checked on every page a reader lands on: a skip link
 * and one main landmark, a language on the root, a description and OpenGraph tags, a caption
 * and header scopes on every table, a label for every input, alt on every image, a text
 * alternative or hidden mark on every SVG, and no empty button. A page that breaks one fails here
 * before it reaches anyone.
 */

const pages = ["/", "/today", "/standards", "/baselines", "/controls", "/stigs", "/register", "/atlas", "/fleet", "/vulnerabilities", "/vulnerabilities/microsoft", "/feeds", "/search?q=x", "/scan", "/scan/why", "/scan/domain", "/scan/network", "/scan/history", "/scan/guide", "/scan/guide/windows", "/triage", "/watchlist", "/saved", "/digest", "/sources", "/appearance", "/branding", "/guide", "/login"];

let app: TestApp;
beforeAll(async () => {
  app = await startTestApp({ env: { BW_BASE_URL: "https://site.example" } });
});
afterAll(async () => {
  await app.close();
});

/** Every table on the page: its caption and its header cells. */
function tables(html: string): { caption: boolean; headersWithoutScope: number; headRow: boolean }[] {
  return [...html.matchAll(/<table[^>]*>([\s\S]*?)<\/table>/g)].map((m) => ({
    caption: /<caption/.test(m[1]!),
    headersWithoutScope: [...m[1]!.matchAll(/<th(\s[^>]*)?>/g)].filter((th) => !/scope="(col|row)"/.test(th[1] ?? "")).length,
    // Column headers belong in a thead; a table of row headers alone (the storage table) has none.
    headRow: !/<th scope="col"/.test(m[1]!) || /<thead>[\s\S]*?<th scope="col"[\s\S]*?<\/thead>/.test(m[1]!),
  }));
}

describe.each(pages)("%s", (path) => {
  it("keeps the invariants", async () => {
    const response = await fetch(`${app.base}${path}`);
    expect(response.status, path).toBe(200);
    const html = await response.text();
    expect(html, "lang").toMatch(/^<!doctype html>\n<html lang="en"/);
    expect(html, "skip link").toContain('<a class="skip" href="#main">Skip to content</a>');
    expect(html.match(/<main /g), "one main").toHaveLength(1);
    expect(html, "main id").toContain('<main class="wrap" id="main" tabindex="-1">');
    expect(html, "description").toMatch(/<meta name="description" content="[^"]{20,}">/);
    expect(html, "og:title").toMatch(/<meta property="og:title" content="[^"]+">/);
    for (const [i, t] of tables(html).entries()) {
      expect(t.caption, `${path} table ${i + 1} caption`).toBe(true);
      expect(t.headersWithoutScope, `${path} table ${i + 1} header scope`).toBe(0);
      expect(t.headRow, `${path} table ${i + 1} has its header cells inside a thead`).toBe(true);
    }
    // A tag that is not one: the mark of a header regex that once caught <thead> as <th>.
    expect(html, "a well-formed thead").not.toMatch(/<th [^>]*ead>/);
    // Every input has a label: one wrapping it, one pointing at its id, or an aria-label of its own; hidden inputs need none.
    const outsideLabels = html.replace(/<label[^>]*>[\s\S]*?<\/label>/g, "");
    for (const input of outsideLabels.matchAll(/<input([^>]*)>/g)) {
      const attrs = input[1]!;
      if (/type="hidden"/.test(attrs)) continue;
      const id = /\sid="([^"]+)"/.exec(attrs)?.[1];
      const labelled = (id && html.includes(`for="${id}"`)) || /aria-label=/.test(attrs);
      expect(labelled, `${path}: input ${id ?? attrs.slice(0, 60)} has no label`).toBe(true);
    }
    for (const img of html.matchAll(/<img([^>]*)>/g)) expect(/\salt=/.test(img[1]!), `${path}: an img without alt`).toBe(true);
    for (const svg of html.matchAll(/<svg([^>]*)>/g)) expect(/aria-hidden="true"|role="img"|aria-label=/.test(svg[1]!), `${path}: an svg without a text alternative or aria-hidden`).toBe(true);
    for (const button of html.matchAll(/<button[^>]*>([\s\S]*?)<\/button>/g)) expect(button[1]!.replace(/<[^>]+>/g, "").trim().length > 0 || /aria-label=/.test(button[0]), `${path}: an empty button`).toBe(true);
  });
});

describe("canonical and OpenGraph", () => {
  it("name the instance's own address, and a filtered page names its unfiltered self", async () => {
    const list = await (await fetch(`${app.base}/vulnerabilities?kev=1`)).text();
    expect(list).toContain('<link rel="canonical" href="https://site.example/vulnerabilities">');
    expect(list).toContain('<meta property="og:url" content="https://site.example/vulnerabilities">');
    const home = await (await fetch(`${app.base}/?group=news`)).text();
    expect(home).toContain('<link rel="canonical" href="https://site.example/">');
    expect(home).toContain('<meta property="og:description" content="Security news, vendor advisories and the CVEs that matter');
    // A page without a canonical of its own carries none rather than a wrong one.
    const search = await (await fetch(`${app.base}/search?q=x`)).text();
    expect(search).not.toContain('rel="canonical"');
  });
});
