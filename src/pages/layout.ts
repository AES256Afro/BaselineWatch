import { html, newTab, type Html } from "../html.ts";
import { lookAttributes, lookSwitch, type LookState } from "../look.ts";
import { productName, productVersion, repositoryUrl } from "../version.ts";

export type Area = "today" | "register" | "stigs" | "wire" | "vulnerabilities" | "triage" | "atlas" | "watchlist" | "digest" | "sources";

/** Areas that have a page in this build. The rest are drawn as "soon", so the shape of the app is visible from day one. */
const built: Record<Area, { label: string; path: string; milestone: string }> = {
  today: { label: "Today", path: "/today", milestone: "" },
  register: { label: "Register", path: "/", milestone: "" },
  stigs: { label: "STIGs", path: "/stigs", milestone: "" },
  wire: { label: "Wire", path: "/wire", milestone: "" },
  vulnerabilities: { label: "Vulnerabilities", path: "/vulnerabilities", milestone: "" },
  triage: { label: "Triage", path: "/triage", milestone: "" },
  atlas: { label: "Atlas", path: "/atlas", milestone: "" },
  watchlist: { label: "Watchlist", path: "/watchlist", milestone: "" },
  digest: { label: "Digest", path: "/digest", milestone: "" },
  sources: { label: "Sources", path: "/sources", milestone: "" },
};
const order: Area[] = ["today", "register", "stigs", "wire", "vulnerabilities", "triage", "atlas", "watchlist", "digest", "sources"];

export interface PageOptions {
  title: string;
  active: Area;
  content: Html;
  meta?: Html;
  /** Draws the sign-in or sign-out control. Omit on pages that do not know. */
  owner?: boolean | undefined;
  open?: boolean | undefined;
  /** The look and scheme this browser chose, and where its switch leads back to. */
  look: LookState;
}

export function page({ title, active, content, meta, owner, open, look }: PageOptions): string {
  const nav = order.map((area) => {
    const item = built[area];
    const current = area === active;
    if (item.milestone) {
      return html`<span class="soon" title="Arrives in ${item.milestone}">${item.label}</span>`;
    }
    return html`<a href="${item.path}"${current ? html` aria-current="page"` : ""}>${item.label}</a>`;
  });
  const session =
    owner === undefined || open
      ? ""
      : owner
        ? html`<form method="post" action="/logout" class="inline"><button type="submit" class="link">Sign out</button></form>`
        : html`<a href="/login">Owner sign-in</a>`;
  // The look and the scheme are attributes on the root, read by the stylesheet alone: no script
  // decides anything, and a page arrives drawn right rather than flashing from one look to another.
  return (
    "<!doctype html>\n" +
    html`<html lang="en"${lookAttributes(look)}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title === productName ? title : `${title} · ${productName}`}</title>
<link rel="stylesheet" href="/assets/app.css?v=${productVersion}">
<meta name="color-scheme" content="${look.scheme === "light" ? "light" : look.scheme === "dark" ? "dark" : "light dark"}">
</head>
<body>
<header class="mast">
  <div class="mast-inner">
    <a class="name" href="/">${productName} <small>Standards change register</small></a>
    <nav aria-label="Areas">${nav}</nav>
    <div class="meta">${meta ?? ""}${session ? html` <span class="sep">·</span> ${session}` : ""}</div>
    ${lookSwitch(look)}
  </div>
</header>
<main class="wrap">${content}</main>
<footer class="foot">
  <div class="wrap">
    <p>${productName} ${productVersion} · <a href="${repositoryUrl}" ${newTab}>source</a> · <a href="/health">health</a></p>
    <p class="attrib">This product uses the NVD API but is not endorsed or certified by the NVD. CVE is a registered trademark of The MITRE Corporation. Known Exploited Vulnerabilities Catalog provided by CISA. EPSS scores provided by FIRST. Package advisories from OSV.dev and the GitHub Advisory Database (CC-BY 4.0). CIS and Microsoft content is shown from your own copy under your own licence and is never redistributed.</p>
  </div>
</footer>
</body>
</html>`.value
  );
}
