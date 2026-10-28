import { html, type Html } from "../html.ts";
import { platformChoices, type PlatformChoice } from "../platforms.ts";

/** Which platform a list is narrowed to, and whether to only the dangerous: the same pair on News, Today and Vulnerabilities. */
export interface PlatformScope {
  platform?: PlatformChoice | undefined;
  danger?: boolean | undefined;
}

/**
 * The row of platform chips the three pages share: All, each platform as people ask about it,
 * and Most dangerous. `href` writes the page's own address for a scope, keeping its other filters.
 * A chip that is on turns itself off.
 */
export function platformPicker(current: PlatformScope, href: (next: PlatformScope) => string): Html {
  return html`<div class="filters platform-pick" role="group" aria-label="Platform">
    <span class="lab">Platform</span>
    <a class="${!current.platform ? "on" : ""}" href="${href({ platform: undefined, danger: current.danger })}">All</a>
    ${platformChoices.map((c) => html`<a class="${current.platform === c.id ? "on" : ""}" href="${href({ platform: current.platform === c.id ? undefined : c.id, danger: current.danger })}" title="${c.blurb}">${c.label}</a>`)}
    <a class="danger${current.danger ? " on" : ""}" href="${href({ platform: current.platform, danger: !current.danger })}" title="Exploited, a public exploit, or EPSS at or over 50%">Most dangerous</a>
  </div>`;
}
