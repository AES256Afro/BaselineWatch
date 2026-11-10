import { html } from "../html.ts";
import type { LookState } from "../look.ts";
import { page } from "./layout.ts";

/**
 * The 404 page, which shows the path it was asked for, escaped, and offers the two ways on: a
 * search for what the reader was after, and the main areas by name.
 */
export function renderNotFound(path: string, look: LookState): string {
  // The last segment of the path is usually the thing being looked for: a control, a CVE, a KB.
  const guess = path.split("/").filter(Boolean).pop() ?? "";
  return page({
    title: "Not found",
    active: "search",
    look,
    content: html`<h1>Nothing at ${path}</h1>
      <p class="lede">No page has that address. It may have moved, or the link that brought you here may be mistyped.</p>
      <form class="search-again" method="get" action="/search" role="search">
        <label for="nf-q">Search for it</label>
        <input type="search" id="nf-q" name="q" value="${guess.slice(0, 120)}">
        <button type="submit">Search</button>
      </form>
      <p>Or go to <a href="/">the News</a>, <a href="/vulnerabilities">Vulnerabilities</a>, <a href="/standards">Standards</a> or <a href="/register">the change register</a>.</p>`,
  });
}
