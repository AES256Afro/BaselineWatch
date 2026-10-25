import type { DatabaseSync } from "node:sqlite";
import { digestTextFor, latestDigest, listDigests, type DigestRow } from "../digest.ts";
import { html, newTabIf, type Html } from "../html.ts";
import { recentAlerts } from "../notify.ts";
import { relativeTime, shortStamp } from "../time.ts";
import type { LookState } from "../look.ts";
import { page } from "./layout.ts";

/**
 * The Digest page: the digests written so far, each with its links drawn as links, and the alert log
 * beneath them.
 */
const urlPattern = /https?:\/\/\S+/g;

/**
 * This instance's own URL as a path, so a digest written under another base — localhost before
 * BW_BASE_URL was set — still leads somewhere on the page that shows it.
 */
function localPath(url: string, baseUrl: string): string | null {
  if (url.startsWith(`${baseUrl}/`)) return url.slice(baseUrl.length);
  try {
    const u = new URL(url);
    if (u.hostname === "localhost" || u.hostname === "127.0.0.1") return `${u.pathname}${u.search}`;
  } catch {
    // Not a URL after all; it stays text.
  }
  return null;
}

/** The digest is stored as the plain text that was sent; on the page its URLs become links. */
export function linkified(line: string, baseUrl: string): Html {
  const parts: Html[] = [];
  let last = 0;
  for (const m of line.matchAll(urlPattern)) {
    parts.push(html`${line.slice(last, m.index)}`);
    const url = m[0]!;
    const local = localPath(url, baseUrl);
    parts.push(local ? html`<a href="${local}">${local}</a>` : html`<a href="${url}" ${newTabIf(url)}>${url}</a>`);
    last = m.index + url.length;
  }
  parts.push(html`${line.slice(last)}`);
  return html`${parts}`;
}

function body(d: DigestRow, baseUrl: string, owner: boolean) {
  return html`${digestTextFor(d, owner).split("\n").map((line) => (line.startsWith("- ") ? html`<li>${linkified(line.slice(2), baseUrl)}</li>` : line === "" ? html`` : html`<p>${linkified(line, baseUrl)}</p>`))}`;
}

export function renderDigest(options: { db: DatabaseSync; owner: boolean; open: boolean; now: Date; period: string; hour: number; timeZone: string; notifyConfigured: boolean; baseUrl: string; look: LookState }): string {
  const { db, owner, open, now, baseUrl, look } = options;
  const latest = latestDigest(db);
  const older = listDigests(db, 20).filter((d) => d.id !== latest?.id);
  const alerts = recentAlerts(db, 25);

  const content = html`
    <div class="wire-top">
      <h1>Digest</h1>
      ${owner ? html`<form method="post" action="/digest/run" class="inline"><button type="submit">Write one now</button></form>` : ""}
    </div>
    <p class="lede">${options.period === "off" ? "The digest is switched off (BW_DIGEST)." : `Written ${options.period} at ${String(options.hour).padStart(2, "0")}:00 ${options.timeZone}`}${options.notifyConfigured ? ", and sent to your notifier." : ". No notifier is configured (BW_NOTIFY_URL), so it only appears here."}</p>
    <div class="cols">
      <section class="main">
        ${latest
          ? html`<section class="box digest" id="latest"><h2><a href="#latest">${latest.period.charAt(0).toUpperCase()}${latest.period.slice(1)} digest</a> <span class="count"><a href="#latest">${shortStamp(latest.generated_at)}</a></span></h2><div class="digest-body">${body(latest, baseUrl, owner)}</div></section>`
          : html`<div class="empty"><b>No digest yet.</b><p>The first one is written at the scheduled hour${owner ? ", or now with the button above" : ""}.</p></div>`}
        ${older.length ? html`<h2 class="later" id="earlier"><a href="#earlier">Earlier</a></h2>${older.map((d) => html`<details class="box"><summary>${d.period} digest, ${shortStamp(d.generated_at)}</summary><div class="digest-body">${body(d, baseUrl, owner)}</div></details>`)}` : ""}
      </section>
      <aside class="side">
        <section class="box" id="alerts">
          <h2><a href="#alerts">Alerts sent</a> <span class="count"><a href="#alerts">${alerts.length}</a></span></h2>
          ${alerts.length
            ? html`<ul class="alerts">${alerts.map((a) => html`<li class="${a.status}"><span class="when">${relativeTime(a.sent_at, now)} · ${a.kind} · ${a.status}${a.error ? html` <span class="small">${a.error}</span>` : ""}</span>${a.url ? html`<a href="${a.url}" ${newTabIf(a.url)}>${a.title}</a>` : a.title}</li>`)}</ul>`
            : html`<p class="small">None yet. KEV additions, watched CVE changes and standard releases are sent as they arrive, after a source's first load.</p>`}
        </section>
      </aside>
    </div>`;

  return page({ title: "Digest", active: "digest", content, meta: latest ? html`last ${relativeTime(latest.generated_at, now)}` : html`none yet`, owner, open, look });
}
