import { html } from "../html.ts";
import type { LookState } from "../look.ts";
import { page } from "./layout.ts";

/**
 * The 404 page, which shows the path it was asked for, escaped.
 */
export function renderNotFound(path: string, look: LookState): string {
  return page({
    title: "Not found",
    active: "register",
    look,
    content: html`<h1>Nothing at ${path}</h1><p class="lede">That page does not exist in this build. The <a href="/">Register</a> and <a href="/sources">Sources</a> do.</p>`,
  });
}
