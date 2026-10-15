import { describe, expect, it } from "vitest";
import { escapeHtml, formatBytes, html, newTab, newTabIf, raw } from "../src/html.ts";

describe("html", () => {
  it("escapes interpolated text", () => {
    expect(html`<p>${"<script>alert(1)</script>"}</p>`.value).toBe("<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>");
    expect(escapeHtml(`"quoted" & 'single'`)).toBe("&quot;quoted&quot; &amp; &#39;single&#39;");
  });

  it("passes nested html and raw through, joins arrays, drops null and false", () => {
    const inner = html`<b>${"x < y"}</b>`;
    const out = html`<div>${inner}${raw("<hr>")}${[1, 2, 3].map((n) => html`<i>${n}</i>`)}${null}${false}${undefined}</div>`.value;
    expect(out).toBe("<div><b>x &lt; y</b><hr><i>1</i><i>2</i><i>3</i></div>");
  });

  it("formats bytes for people", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(4096)).toBe("4.0 KB");
    expect(formatBytes(432_013_312)).toBe("412 MB");
  });
  it("sends off-site links to a new tab, and leaves paths on this site alone", () => {
    expect(html`<a href="https://example.org" ${newTab}>x</a>`.value).toBe('<a href="https://example.org" target="_blank" rel="noopener">x</a>');
    expect(newTabIf("https://nvd.nist.gov/vuln/detail/CVE-2026-0001").value).toBe(newTab.value);
    expect(newTabIf("HTTP://EXAMPLE.ORG").value).toBe(newTab.value);
    expect(newTabIf("/wire?kind=kev").value).toBe("");
    expect(newTabIf(null).value).toBe("");
    expect(newTabIf(undefined).value).toBe("");
  });
});
