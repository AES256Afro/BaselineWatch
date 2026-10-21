import { html } from "../html.ts";
import { lookLabels, lookSwitch, looks, schemeLabels, schemes, type LookState } from "../look.ts";
import { page } from "./layout.ts";

/**
 * Appearance, on the Desk: the look and the colour scheme, which used to sit in the masthead
 * beside the menus and took room from them on every page for a choice a person makes once.
 * The controls are the same two forms the masthead carried, so the cookies and the POST are
 * unchanged; what is new is the room to say what each look is for.
 */
export function renderAppearance(options: { owner: boolean; open: boolean; look: LookState }): string {
  const { look } = options;
  const content = html`
    <h1>Appearance</h1>
    <p class="lede">
      How this browser draws the site. The choice is kept in two cookies on this device alone —
      it is not an account setting, nothing is stored on the server, and a visitor who has chosen
      nothing gets the instance's own default.
    </p>
    <div class="guide">
      <section class="box" id="scheme">
        <h2>Colour scheme <span class="count">${schemeLabels[look.scheme].label}</span></h2>
        <p>
          <b>${schemeLabels.system.label}</b> follows the device's own light or dark setting, and
          changes with it through the day. <b>${schemeLabels.light.label}</b> and
          <b>${schemeLabels.dark.label}</b> override it for this browser.
        </p>
      </section>
      <section class="box" id="look">
        <h2>Look <span class="count">${lookLabels[look.look].label}</span></h2>
        <p>
          The same pages, drawn to different habits. ${looks.map((l, i) => html`${i > 0 ? " " : ""}<b>${lookLabels[l].label}</b> — ${lookLabels[l].title}.`)}
        </p>
      </section>
      <section class="box wide" id="choose">
        <h2>Choose</h2>
        ${lookSwitch(look)}
        <p class="small">
          Every look and both schemes carry the same content and the same contrast rules; nothing
          is hidden in one and shown in another. A change applies on the next page the browser
          draws, which is this one.
        </p>
      </section>
      <section class="box" id="more">
        <h2>The mark, and the printed page</h2>
        <p>
          The logo and favicon this instance wears are the owner's, under
          <a href="/branding">Branding</a>. A baseline or a test plan carries its own look when it
          is exported to Word, PDF or LaTeX, chosen beside the export buttons on
          <a href="/baselines">the builder</a> rather than here, because a document's look is
          part of the document and not of this browser.
        </p>
      </section>
    </div>`;

  return page({ title: "Appearance", active: "appearance", content, meta: html`${lookLabels[look.look].label} · ${schemeLabels[look.scheme].label}`, ...options });
}

/** The schemes and looks this page documents, for the test that keeps the list honest. */
export const appearanceChoices = { looks, schemes };
