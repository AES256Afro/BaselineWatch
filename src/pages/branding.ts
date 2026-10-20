import { brandKinds, type Brand, type BrandKind, type BrandMark } from "../branding.ts";
import { html, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { productName } from "../version.ts";
import { page } from "./layout.ts";

const copy: Record<BrandKind, { title: string; where: string; formats: string }> = {
  logo: { title: "Logo", where: "Drawn in the masthead beside the site's name on every page.", formats: "PNG, JPEG, GIF, WebP or AVIF" },
  favicon: { title: "Favicon", where: "The browser-tab icon, linked from every page and answered at /favicon.ico. Safari ignores SVG favicons, so beside a mark an uploaded ICO or PNG covers it.", formats: "ICO, PNG, JPEG, GIF, WebP or AVIF" },
};

export function renderBranding(options: { brand: Brand; marks: BrandMark[]; owner: boolean; open: boolean; notice?: string | undefined; look: LookState }): string {
  const { brand, marks, owner, open, notice, look } = options;

  const section = (kind: BrandKind): Html => {
    const image = brand[kind];
    const text = copy[kind];
    return html`<section class="box" id="${kind}">
      <h2><a href="#${kind}">${text.title}</a></h2>
      <p class="small">${text.where}</p>
      <div class="brand-preview">
        ${image ? html`<img src="/branding/${kind}?v=${image.sha256.slice(0, 12)}" alt="The current ${kind}"><span class="small">${marks.find((m) => m.sha256 === image.sha256)?.title ?? image.type}</span>` : html`<span class="small">None set${kind === "logo" ? html`; the masthead shows “${productName}” alone` : ""}.</span>`}
      </div>
      ${owner
        ? html`<form method="post" action="/branding/${kind}" enctype="multipart/form-data" class="stack">
            <label for="${kind}-file">${image ? "Replace it with an upload" : "Upload your own"} (${text.formats}, up to 2 MB; an uploaded SVG is never served)</label>
            <input type="file" id="${kind}-file" name="image" accept="image/*${kind === "favicon" ? ",.ico" : ""}" required>
            <button type="submit" class="primary">Apply</button>
          </form>
          ${image ? html`<form method="post" action="/branding/${kind}/remove" class="inline"><button type="submit">Remove</button></form>` : ""}`
        : ""}
    </section>`;
  };

  const markCard = (mark: BrandMark): Html => {
    const uses = brandKinds.filter((kind) => brand[kind]?.sha256 === mark.sha256);
    return html`<figure class="mark${uses.length ? " on" : ""}">
      <img src="/branding/marks/${mark.id}" alt="${mark.title}" width="48" height="48" loading="lazy">
      <figcaption>${mark.title}${uses.length ? html` <span class="small">· the ${uses.join(" and ")}</span>` : ""}</figcaption>
      ${owner
        ? html`<form method="post" action="/branding/mark" class="inline">
            <input type="hidden" name="mark" value="${mark.id}">
            <button type="submit" name="kind" value="logo">Logo</button>
            <button type="submit" name="kind" value="favicon">Favicon</button>
          </form>`
        : ""}
    </figure>`;
  };

  const content = html`
    <h1>Branding</h1>
    <p class="lede">This instance's own face: a logo for the masthead and a favicon for the tab. The marks below are the repo's own (docs/mockups/logo), drawn for both colour schemes and ready at 16 px; applying one needs a click, or upload your own image. Without either, the pages carry the plain ${productName} wordmark.</p>
    ${notice ? html`<div class="notice ok">${notice}</div>` : ""}
    <div class="cols">
      <section class="main">
        ${section("logo")}
        ${section("favicon")}
        ${marks.length
          ? html`<section class="box" id="marks">
              <h2><a href="#marks">The repo's marks</a></h2>
              <p class="small">From the design sheets: the twenty, the refinements and the detail passes. Each swaps ink and accent for dark mode on its own.${owner ? " Pick where a mark goes:" : ""}</p>
              <div class="mark-grid">${marks.map((mark) => markCard(mark))}</div>
            </section>`
          : ""}
      </section>
      <aside class="side">
        ${owner
          ? html`<section class="box"><h2>How it is stored</h2><p class="small">A chosen mark or an upload lands in the same content-addressed blob store as article images and applies at once on every page, the sign-in page included. The served type is read from the bytes, never from the upload. Removing one puts the wordmark back; the bytes stay in the store like any snapshot.</p></section>`
          : html`<section class="box"><h2><a href="/login">Owner only</a></h2><p class="small"><a href="/login">Sign in</a> to change the branding.</p></section>`}
      </aside>
    </div>`;

  return page({ title: "Branding", active: "branding", content, owner, open, look });
}
