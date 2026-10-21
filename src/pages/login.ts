import { html } from "../html.ts";
import type { LookState } from "../look.ts";
import { page } from "./layout.ts";

/**
 * The sign-in page, reachable even when reading is closed, drawn in the look the browser chose.
 */
export function renderLogin(options: { error?: string | undefined; next: string; open: boolean; look: LookState }): string {
  const content = html`
    <section class="login">
      <h1>Owner sign-in</h1>
      ${options.open
        ? html`<p class="lede">No owner password is configured, so this instance is in single-user mode and nothing needs a sign-in. Set <code>BW_ADMIN_PASSWORD</code> to require one.</p>`
        : html`<p class="lede">Reading BaselineWatch is open. Marking items, changing sources and the watchlist need the owner.</p>
          <form method="post" action="/login" class="stack">
            <input type="hidden" name="next" value="${options.next}">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" autocomplete="current-password" required autofocus>
            ${options.error ? html`<p class="form-error" role="alert">${options.error}</p>` : ""}
            <button type="submit" class="primary">Sign in</button>
          </form>`}
    </section>`;
  return page({ title: "Sign in", active: "register", content, look: options.look });
}
