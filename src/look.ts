import { parseCookies } from "./auth.ts";
import type { Brand } from "./branding.ts";
import { html, type Html } from "./html.ts";
import { safeBack } from "./paths.ts";

/**
 * How the pages are drawn: a look and a colour scheme.
 *
 * The look is the whole face of the site. "register" is the paper one BaselineWatch began with:
 * a serif masthead, one column with an aside, a green accent. "console" is the dense dashboard
 * look of a security console: panels with uppercase mono titles, thin large numerals, charts and
 * hexagon severity marks. The scheme is light, dark, or "system", which lets the device decide
 * through prefers-color-scheme as it always has.
 *
 * Both are chosen per browser with two cookies set by the switch in the masthead, and default to
 * the instance's own settings (BW_LOOK, BW_SCHEME). The cookies hold one of a few fixed words
 * each; anything else is ignored, so nothing a browser sends reaches the page. The whole thing
 * is server-side: the stylesheet reads data-look and data-scheme on <html>, and the page needs no
 * script for it, which the content security policy forbids anyway.
 */

export const looks = ["register", "console"] as const;
export type Look = (typeof looks)[number];
export const schemes = ["system", "light", "dark"] as const;
export type Scheme = (typeof schemes)[number];

const lookCookie = "bw_look";
const schemeCookie = "bw_scheme";
/** A preference, kept for a year. */
const cookieSeconds = 365 * 24 * 60 * 60;

export function isLook(value: unknown): value is Look {
  return typeof value === "string" && (looks as readonly string[]).includes(value);
}

export function isScheme(value: unknown): value is Scheme {
  return typeof value === "string" && (schemes as readonly string[]).includes(value);
}

export interface LookChoice {
  look: Look;
  scheme: Scheme;
}

/** The choice as the page draws it, with the path the switch returns the browser to. */
export interface LookState extends LookChoice {
  back: string;
  /**
   * The instance's uploaded logo and favicon (branding.ts). It rides with the look because every
   * page already hands the look to the layout, which is the one place that wears it.
   */
  brand?: Brand;
}

/** The browser's choice from its cookies, or the instance's defaults for whatever is missing or not a known word. */
export function readLook(cookieHeader: string | undefined, defaults: LookChoice): LookChoice {
  const cookies = parseCookies(cookieHeader);
  const look = cookies[lookCookie];
  const scheme = cookies[schemeCookie];
  return { look: isLook(look) ? look : defaults.look, scheme: isScheme(scheme) ? scheme : defaults.scheme };
}

/** The state for one request: its cookies against the instance's defaults, and where its switch leads back to. */
export function lookState(request: { headers: { cookie?: string | undefined }; originalUrl?: string | undefined }, defaults: LookChoice): LookState {
  return { ...readLook(request.headers.cookie, defaults), back: safeBack(request.originalUrl, "/") };
}

/**
 * The two Set-Cookie headers for a choice. Lax rather than Strict: the cookies carry a drawing
 * preference and nothing else, and Strict would draw the first page reached from a link elsewhere
 * in the defaults. HttpOnly because no script needs them; Secure behind TLS.
 */
export function lookCookieHeaders(choice: LookChoice, secure: boolean): string[] {
  const attributes = `Path=/; Max-Age=${cookieSeconds}; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
  return [`${lookCookie}=${choice.look}; ${attributes}`, `${schemeCookie}=${choice.scheme}; ${attributes}`];
}

/** The attributes on <html> the stylesheet reads. "system" sets no scheme, so prefers-color-scheme decides. */
export function lookAttributes(choice: LookChoice): Html {
  return html` data-look="${choice.look}"${choice.scheme === "system" ? "" : html` data-scheme="${choice.scheme}"`}`;
}

export const schemeLabels: Record<Scheme, { label: string; title: string }> = {
  system: { label: "Auto", title: "Follow the device's light or dark setting" },
  light: { label: "Light", title: "Always light" },
  dark: { label: "Dark", title: "Always dark" },
};
export const lookLabels: Record<Look, { label: string; title: string }> = {
  register: { label: "Paper", title: "The Register look: paper, serif headings, one column" },
  console: { label: "Console", title: "The Console look: dense panels, charts and large figures" },
};

/**
 * The switch, now on the Appearance page under the Desk rather than in the masthead: two small
 * forms, one for the scheme and one for the look, each a row of buttons of which the current one
 * is pressed. One click applies, no script involved: the button's own name and value are the
 * whole request, and the page comes back where it was.
 */
export function lookSwitch(state: LookState): Html {
  const button = (name: "look" | "scheme", value: string, current: boolean, text: { label: string; title: string }): Html =>
    html`<button type="submit" name="${name}" value="${value}" aria-pressed="${current ? "true" : "false"}" title="${text.title}">${text.label}</button>`;
  return html`<div class="look">
    <form method="post" action="/look" class="look-group" aria-label="Colours">
      <input type="hidden" name="back" value="${state.back}">
      ${schemes.map((scheme) => button("scheme", scheme, scheme === state.scheme, schemeLabels[scheme]))}
    </form>
    <form method="post" action="/look" class="look-group" aria-label="Look">
      <input type="hidden" name="back" value="${state.back}">
      ${looks.map((look) => button("look", look, look === state.look, lookLabels[look]))}
    </form>
  </div>`;
}
