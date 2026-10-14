import { html } from "../html.ts";
import { page } from "./layout.ts";

export function renderNotFound(path: string): string {
  return page({
    title: "Not found",
    active: "register",
    content: html`<h1>Nothing at ${path}</h1><p class="lede">That page does not exist in this build. The <a href="/">Register</a> and <a href="/sources">Sources</a> do.</p>`,
  });
}
