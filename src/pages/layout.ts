import type { DatabaseSync } from "node:sqlite";
import { html, newTab, type Html } from "../html.ts";
import { lookAttributes, type LookState } from "../look.ts";
import { relativeTime } from "../time.ts";
import { productName, productVersion, repositoryUrl } from "../version.ts";

/**
 * The page frame every page is drawn in: the masthead and its two menus built from the ladder, the
 * Register ribbon, the footer with the attributions, and the look attributes the stylesheet reads.
 */
export type Area =
  | "today"
  | "register"
  | "catalog"
  | "controls"
  | "stigs"
  | "baselines"
  | "learn"
  | "fleet"
  | "wire"
  | "vulnerabilities"
  | "patch-tuesday"
  | "feeds"
  | "search"
  | "scan-domain"
  | "scan-network"
  | "scan-guide"
  | "scan-history"
  | "scan-devices"
  | "saved"
  | "triage"
  | "atlas"
  | "watchlist"
  | "digest"
  | "sources"
  | "branding"
  | "appearance"
  | "guide"
  | "scan";

/**
 * The top, built from the ladder the guide teaches: a **standard** is the rulebook, a
 * **baseline** is the set of its rules chosen for a kind of system, a **control** is one rule,
 * and a setting is how that rule is enforced on a device. The Standards menu is those three
 * words in that order, each with the line that says what it is, and the tools that cut across
 * them (STIGs, Atlas) sit below a rule. The owner's desk is one cluster on the right: their own
 * fleet and work, then the instance, then how it looks. Both groups are plain <details> menus:
 * no script, CSP intact.
 */
const areas: Record<Area, { label: string; path: string; blurb?: string }> = {
  wire: { label: "News", path: "/" },
  today: { label: "Today", path: "/today" },
  catalog: { label: "Standards", path: "/standards", blurb: "the rulebooks this instance tracks" },
  baselines: { label: "Baselines", path: "/baselines", blurb: "the set of rules chosen for a platform" },
  controls: { label: "Controls", path: "/controls", blurb: "one rule at a time, and what changed" },
  stigs: { label: "STIGs", path: "/stigs", blurb: "a platform's rules, with check and fix" },
  atlas: { label: "Atlas", path: "/atlas", blurb: "the rhythm of releases, and what is due" },
  learn: { label: "Learn", path: "/learn", blurb: "where every rule comes from, and who derived it from whom" },
  register: { label: "Change register", path: "/register", blurb: "every release, control by control" },
  fleet: { label: "Fleet", path: "/fleet", blurb: "your releases and the hardware they run on" },
  saved: { label: "Saved searches", path: "/saved", blurb: "the lists you come back to" },
  vulnerabilities: { label: "Vulnerabilities", path: "/vulnerabilities", blurb: "every CVE, scored and marked: KEV, EPSS, exploits" },
  "patch-tuesday": { label: "Patch Tuesday", path: "/vulnerabilities/microsoft", blurb: "Microsoft's monthly release, by update and product" },
  feeds: { label: "Feeds", path: "/feeds", blurb: "RSS, OPML and a KEV calendar for your reader" },
  scan: { label: "This browser", path: "/scan", blurb: "ads, trackers and filtering DNS, seen from this tab" },
  "scan-domain": { label: "A domain", path: "/scan/domain", blurb: "mail, DNS and web posture, each record quoted" },
  "scan-devices": { label: "A device", path: "/scan/devices", blurb: "paste what it runs, see which CVEs apply" },
  "scan-network": { label: "Your network", path: "/scan/network", blurb: "the LAN resolver, from this server, daily" },
  "scan-guide": { label: "By hand", path: "/scan/guide", blurb: "the same checks done yourself, per platform" },
  "scan-history": { label: "History", path: "/scan/history", blurb: "every run, and what changed between them" },
  triage: { label: "Triage", path: "/triage", blurb: "what needs a decision" },
  watchlist: { label: "Watchlist", path: "/watchlist", blurb: "the products and platforms you run" },
  digest: { label: "Digest", path: "/digest", blurb: "the daily or weekly summary, and alerts" },
  sources: { label: "Sources", path: "/sources", blurb: "what is read, how often, under what terms" },
  appearance: { label: "Appearance", path: "/appearance", blurb: "the look and the colour scheme" },
  branding: { label: "Branding", path: "/branding", blurb: "the mark this instance wears" },
  guide: { label: "Guide", path: "/guide" },
  search: { label: "Search", path: "/search" },
};

/** The ladder, in order, then the tools that cut across it, then where it all comes from. */
const standardsGroup: Area[] = ["catalog", "baselines", "controls"];
const standardsTools: Area[] = ["stigs", "register", "atlas"];
const standardsLearn: Area[] = ["learn"];
/** The owner's own work, then the instance, then how it is drawn. */
const vulnGroup: Area[] = ["vulnerabilities", "patch-tuesday", "feeds"];
const scanGroup: Area[] = ["scan", "scan-domain", "scan-devices", "scan-network", "scan-history", "scan-guide"];
const deskGroup: Area[] = ["fleet", "triage", "watchlist", "saved"];
const deskInstance: Area[] = ["sources", "digest"];
const deskLook: Area[] = ["appearance", "branding"];

export interface PageOptions {
  title: string;
  active: Area;
  content: Html;
  meta?: Html;
  /** Draws the sign-in or sign-out control. Omit on pages that do not know. */
  owner?: boolean | undefined;
  open?: boolean | undefined;
  /** A ribbon under the masthead, such as the Register's latest changes on News and Today. */
  strip?: Html;
  /** The look and scheme this browser chose, and where its switch leads back to. */
  look: LookState;
  /** The RSS address that carries this page's list, for a reader's autodiscovery. */
  feed?: { href: string; title: string } | undefined;
  /** One sentence for search results and link previews; the product's own when a page has none. */
  description?: string | undefined;
  /** The page's canonical path, for the tag that tells a crawler which address is the one; pages with filters name their unfiltered self. */
  canonical?: string | undefined;
  /**
   * The one self-hosted module script a page may carry, as a path under /assets. Only the Scan
   * page passes one, under its own policy; every other page is served with script-src 'none'.
   */
  script?: string | undefined;
}

/** The Register's newest changes, for the ribbon under the masthead and anywhere else that glances at it. */
export function latestRegisterChanges(db: DatabaseSync, limit = 3): { documentId: number; sourceId: string; name: string; versionLabel: string | null; at: string; changeCount: number }[] {
  const rows = db
    .prepare(
      `SELECT d.id AS documentId, d.source_id AS sourceId, s.name, d.version_label AS versionLabel,
              COALESCE(d.published_at, d.parsed_at) AS at,
              (SELECT COUNT(*) FROM changes c WHERE c.to_document_id = d.id) AS changeCount
       FROM documents d JOIN sources s ON s.id = d.source_id
       WHERE s.group_name = 'standards'
       ORDER BY at DESC, d.id DESC LIMIT ?`,
    )
    .all(limit) as { documentId: number; sourceId: string; name: string; versionLabel: string | null; at: string; changeCount: number }[];
  return rows;
}

/** The amber Register ribbon: the latest standards changes ride the page, each linking into its diff. */
export function registerStrip(db: DatabaseSync, now: Date): Html {
  const rows = latestRegisterChanges(db, 3);
  if (rows.length === 0) return html``;
  const entries = rows.map(
    (r, i) =>
      html`${i > 0 ? html`<span class="dot">·</span>` : ""}<a href="/standards/${r.sourceId}/${r.documentId}">${r.name}${r.versionLabel ? html` ${r.versionLabel}` : ""}: ${r.changeCount === 0 ? "first version" : html`${r.changeCount} changed`}</a> <span class="when">${relativeTime(r.at, now)}</span>`,
  );
  return html`<div class="strip"><div class="strip-inner"><a class="lab" href="/register">Register</a> ${entries}</div></div>`;
}

/** The instance's public address, set once by createApp, so canonical and OpenGraph tags can be absolute. */
let siteBase = "";
export function setSiteBase(baseUrl: string): void {
  siteBase = baseUrl.replace(/\/+$/, "");
}

export const productDescription = "News, advisories and CVEs in one timeline, and a change register for the security standards themselves: what each control said before and after, and why.";

export function page({ title, active, content, meta, owner, open, strip, look, script, feed, description, canonical }: PageOptions): string {
  const link = (area: Area, cls?: string): Html => {
    const item = areas[area];
    return html`<a href="${item.path}"${area === active ? html` aria-current="page"` : ""}${cls ? html` class="${cls}"` : ""}>${item.label}</a>`;
  };
  // Inside a menu a label alone teaches nothing, so each entry carries the line that says what it is.
  const entry = (area: Area): Html => {
    const item = areas[area];
    return html`<a class="entry" href="${item.path}"${area === active ? html` aria-current="page"` : ""}><b>${item.label}</b>${item.blurb ? html`<small>${item.blurb}</small>` : ""}</a>`;
  };
  const session =
    owner === undefined || open
      ? ""
      : owner
        ? html`<hr><form method="post" action="/logout" class="inline"><button type="submit" class="link">Sign out</button></form>`
        : html`<hr><a href="/login">Owner sign-in</a>`;
  // The look and the scheme are attributes on the root, read by the stylesheet alone: no script
  // decides anything, and a page arrives drawn right rather than flashing from one look to another.
  return (
    "<!doctype html>\n" +
    html`<html lang="en"${lookAttributes(look)}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title === productName ? title : `${title} · ${productName}`}</title>
<meta name="description" content="${description ?? productDescription}">
<meta property="og:site_name" content="${productName}">
<meta property="og:type" content="website">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${description ?? productDescription}">
${canonical && siteBase ? html`<link rel="canonical" href="${siteBase}${canonical}">
<meta property="og:url" content="${siteBase}${canonical}">
` : ""}${look.brand?.favicon ? html`<link rel="icon" href="/branding/favicon?v=${look.brand.favicon.sha256.slice(0, 12)}">` : ""}
<link rel="stylesheet" href="/assets/app.css?v=${productVersion}">
${feed ? html`<link rel="alternate" type="application/rss+xml" title="${feed.title}" href="${feed.href}">
` : ""}<meta name="color-scheme" content="${look.scheme === "light" ? "light" : look.scheme === "dark" ? "dark" : "light dark"}">
${script ? html`<script type="module" src="${script}?v=${productVersion}"></script>` : ""}
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="mast">
  <div class="mast-inner">
    <a class="name" href="/">${look.brand?.logo ? html`<img class="brand-logo" src="/branding/logo?v=${look.brand.logo.sha256.slice(0, 12)}" alt="">` : ""}${productName}</a>
    <nav aria-label="Areas">
      ${link("wire")}${link("today")}<details class="group${[...standardsGroup, ...standardsTools, ...standardsLearn].includes(active) ? " on" : ""}">
        <summary>Standards</summary>
        <div class="menu wide">
          <a class="cap" href="/guide#ladder">A standard is the rulebook · a baseline picks its rules for a system · a control is one rule</a>
          ${standardsGroup.map((a) => entry(a))}
          <hr>
          ${standardsTools.map((a) => entry(a))}
          <hr>
          <span class="cap">Where it all comes from</span>
          ${standardsLearn.map((a) => entry(a))}
        </div>
      </details><details class="group${vulnGroup.includes(active) ? " on" : ""}">
        <summary>Vulnerabilities</summary>
        <div class="menu wide">
          ${vulnGroup.map((a) => entry(a))}
        </div>
      </details><details class="group${scanGroup.includes(active) ? " on" : ""}">
        <summary>Scan</summary>
        <div class="menu wide">
          ${scanGroup.map((a) => entry(a))}
        </div>
      </details>
    </nav>
    <form class="mast-search" method="get" action="/search" role="search"><label class="visually-hidden" for="mast-q">Search</label><input type="search" id="mast-q" name="q" placeholder="Search" aria-label="Search CVEs, controls and news"></form>
    <div class="meta">${meta ?? ""}</div>
    <details class="group desk${deskGroup.includes(active) ? " on" : ""}">
      <summary>Desk</summary>
      <div class="menu right wide">
        <span class="cap">Your fleet and your work</span>
        ${deskGroup.map((a) => entry(a))}
        <hr>
        <span class="cap">This instance</span>
        ${deskInstance.map((a) => entry(a))}
        <hr>
        <span class="cap">How it is drawn</span>
        ${deskLook.map((a) => entry(a))}
        ${session}
      </div>
    </details>
  </div>
</header>
${strip ?? ""}
<main class="wrap" id="main" tabindex="-1">${content}</main>
<footer class="foot">
  <div class="wrap">
    <p>${productName} ${productVersion} · a change register for the security standards themselves · <a href="/guide">how to read this site</a> · <a href="${repositoryUrl}" ${newTab}>source</a> · <a href="/health">health</a></p>
    <p class="attrib">This product uses the NVD API but is not endorsed or certified by the NVD. CVE is a registered trademark of The MITRE Corporation. Known Exploited Vulnerabilities Catalog provided by CISA. EPSS scores provided by FIRST. Package advisories from OSV.dev and the GitHub Advisory Database (CC-BY 4.0). CIS and Microsoft content is shown from your own copy under your own licence and is never redistributed. Article images belong to their publishers and link to the original story. AdFection / Candiru indicators are the Zero Breach project's (CC0), which is not affiliated with the researchers it cites. Canary names are quoted from EasyList and EasyPrivacy (GPLv3 or CC BY-SA 3.0) and from URLhaus by abuse.ch; they are only ever resolved, never loaded, and nothing here links to them. A source whose licence restricts display shows its entries to this instance's owner only.</p>
  </div>
</footer>
</body>
</html>`.value
  );
}
