import type { DatabaseSync } from "node:sqlite";
import { html, newTab, type Html } from "../html.ts";
import { lookAttributes, lookSwitch, type LookState } from "../look.ts";
import { relativeTime } from "../time.ts";
import { productName, productVersion, repositoryUrl } from "../version.ts";

export type Area = "today" | "register" | "stigs" | "baselines" | "platforms" | "wire" | "vulnerabilities" | "triage" | "atlas" | "watchlist" | "digest" | "sources" | "guide" | "scan";

/**
 * The top, reorganised the way the leading aggregators organise theirs (docs/mockups): News is
 * home, the reading areas sit flat, the standards library is one labelled group, and the owner's
 * desk is one cluster on the right. Both groups are plain <details> menus: no script, CSP intact.
 */
const areas: Record<Area, { label: string; path: string }> = {
  wire: { label: "News", path: "/" },
  today: { label: "Today", path: "/today" },
  register: { label: "Register", path: "/register" },
  stigs: { label: "STIGs", path: "/stigs" },
  baselines: { label: "Baselines", path: "/baselines" },
  platforms: { label: "Platforms", path: "/platforms" },
  atlas: { label: "Atlas", path: "/atlas" },
  vulnerabilities: { label: "Vulnerabilities", path: "/vulnerabilities" },
  scan: { label: "Scan", path: "/scan" },
  triage: { label: "Triage", path: "/triage" },
  watchlist: { label: "Watchlist", path: "/watchlist" },
  digest: { label: "Digest", path: "/digest" },
  sources: { label: "Sources", path: "/sources" },
  guide: { label: "Guide", path: "/guide" },
};

export function areaPath(area: Area): string {
  return areas[area].path;
}

const standardsGroup: Area[] = ["register", "stigs", "baselines", "platforms", "atlas"];
const deskGroup: Area[] = ["triage", "watchlist", "digest", "sources"];

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

export function page({ title, active, content, meta, owner, open, strip, look, script }: PageOptions): string {
  const link = (area: Area, cls?: string): Html => {
    const item = areas[area];
    return html`<a href="${item.path}"${area === active ? html` aria-current="page"` : ""}${cls ? html` class="${cls}"` : ""}>${item.label}</a>`;
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
<link rel="stylesheet" href="/assets/app.css?v=${productVersion}">
<meta name="color-scheme" content="${look.scheme === "light" ? "light" : look.scheme === "dark" ? "dark" : "light dark"}">
${script ? html`<script type="module" src="${script}?v=${productVersion}"></script>` : ""}
</head>
<body>
<header class="mast">
  <div class="mast-inner">
    <a class="name" href="/">${productName}</a>
    <nav aria-label="Areas">
      ${link("wire")}${link("today")}<details class="group${standardsGroup.includes(active) ? " on" : ""}">
        <summary>Standards</summary>
        <div class="menu">
          <a class="cap" href="/guide">The standards change register — how to read it</a>
          ${standardsGroup.map((a) => link(a))}
        </div>
      </details>${link("vulnerabilities")}${link("scan")}
    </nav>
    <div class="meta">${meta ?? ""}</div>
    <details class="group desk${deskGroup.includes(active) ? " on" : ""}">
      <summary>Desk</summary>
      <div class="menu right">
        <span class="cap">Owner's desk</span>
        ${deskGroup.map((a) => link(a))}
        ${session}
      </div>
    </details>
    ${lookSwitch(look)}
  </div>
</header>
${strip ?? ""}
<main class="wrap">${content}</main>
<footer class="foot">
  <div class="wrap">
    <p>${productName} ${productVersion} · a change register for the security standards themselves · <a href="/guide">how to read this site</a> · <a href="${repositoryUrl}" ${newTab}>source</a> · <a href="/health">health</a></p>
    <p class="attrib">This product uses the NVD API but is not endorsed or certified by the NVD. CVE is a registered trademark of The MITRE Corporation. Known Exploited Vulnerabilities Catalog provided by CISA. EPSS scores provided by FIRST. Package advisories from OSV.dev and the GitHub Advisory Database (CC-BY 4.0). CIS and Microsoft content is shown from your own copy under your own licence and is never redistributed. Article images belong to their publishers and link to the original story. AdFection / Candiru indicators are the Zero Breach project's (CC0), which is not affiliated with the researchers it cites. Canary names are quoted from EasyList and EasyPrivacy (GPLv3 or CC BY-SA 3.0) and from URLhaus by abuse.ch; they are only ever resolved, never loaded, and nothing here links to them.</p>
  </div>
</footer>
</body>
</html>`.value
  );
}
