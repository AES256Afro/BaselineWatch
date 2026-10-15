import type { DatabaseSync } from "node:sqlite";
import { latestDigest, listDigests, type DigestRow } from "../digest.ts";
import { html, newTabIf } from "../html.ts";
import { recentAlerts } from "../notify.ts";
import { relativeTime, shortStamp } from "../time.ts";
import type { LookState } from "../look.ts";
import { page } from "./layout.ts";

function body(d: DigestRow) {
  return html`${d.text.split("\n").map((line) => (line.startsWith("- ") ? html`<li>${line.slice(2)}</li>` : line === "" ? html`` : html`<p>${line}</p>`))}`;
}

export function renderDigest(options: { db: DatabaseSync; owner: boolean; open: boolean; now: Date; period: string; hour: number; timeZone: string; notifyConfigured: boolean; look: LookState }): string {
  const { db, owner, open, now, look } = options;
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
          ? html`<section class="box digest"><h2>${latest.period.charAt(0).toUpperCase()}${latest.period.slice(1)} digest <span class="count">${shortStamp(latest.generated_at)}</span></h2><div class="digest-body">${body(latest)}</div></section>`
          : html`<div class="empty"><b>No digest yet.</b><p>The first one is written at the scheduled hour${owner ? ", or now with the button above" : ""}.</p></div>`}
        ${older.length ? html`<h2 class="later">Earlier</h2>${older.map((d) => html`<details class="box"><summary>${d.period} digest, ${shortStamp(d.generated_at)}</summary><div class="digest-body">${body(d)}</div></details>`)}` : ""}
      </section>
      <aside class="side">
        <section class="box">
          <h2>Alerts sent <span class="count">${alerts.length}</span></h2>
          ${alerts.length
            ? html`<ul class="alerts">${alerts.map((a) => html`<li class="${a.status}"><span class="when">${relativeTime(a.sent_at, now)} · ${a.kind} · ${a.status}${a.error ? html` <span class="small">${a.error}</span>` : ""}</span>${a.url ? html`<a href="${a.url}" ${newTabIf(a.url)}>${a.title}</a>` : a.title}</li>`)}</ul>`
            : html`<p class="small">None yet. KEV additions, watched CVE changes and standard releases are sent as they arrive, after a source's first load.</p>`}
        </section>
      </aside>
    </div>`;

  return page({ title: "Digest", active: "digest", content, meta: latest ? html`last ${relativeTime(latest.generated_at, now)}` : html`none yet`, owner, open, look });
}
