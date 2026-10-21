import type { DatabaseSync } from "node:sqlite";
import type { Config } from "../config.ts";
import { countRows, databaseBytes } from "../db.ts";
import { latestDigest } from "../digest.ts";
import { figure, formatBytes, html, newTab, newTabIf } from "../html.ts";
import { recentAlerts } from "../notify.ts";
import { relativeTime } from "../time.ts";
import { triageCounts, triageInbox } from "../triage.ts";
import type { LookState } from "../look.ts";
import { repositoryUrl } from "../version.ts";
import { page } from "./layout.ts";

/**
 * The Register's home at /register: every standard tracked, its latest version, and the newest
 * changes, which is where the product began before News became the front page.
 */
interface StandardRow {
  id: string;
  name: string;
  format: string;
  schedule: string;
  enabled: number;
  restricted: number;
  notes: string | null;
  snapshot_count: number;
  change_count: number;
  latest_version: string | null;
  latest_published: string | null;
}

interface KevRow {
  id: number;
  title: string;
  url: string | null;
  published_at: string | null;
  signals_json: string | null;
}

const formatLabel: Record<string, string> = {
  "oscal-json": "OSCAL JSON",
  "cprt-json": "CPRT JSON",
  "xccdf-zip": "XCCDF in zips",
  "xml-zip": "XML in a zip",
  "yaml-zip": "YAML rules in a zip",
  "intune-zip": "Intune JSON in a zip",
  "ckl-zip": "Checklists in a zip",
  "sct-zip": "GPO backups and Excel",
  "pdf-upload": "PDF you upload",
  "csrc-pdf": "PDFs from CSRC pages",
  docx: "Word document listing",
  git: "git history",
  rss: "RSS",
  atom: "Atom",
  json: "JSON",
  text: "plain text list",
  adblock: "Adblock Plus list",
  csv: "CSV",
  html: "HTML listing",
};

export interface HomeOptions {
  config: Config;
  db: DatabaseSync;
  migrations: string[];
  owner: boolean;
  now: Date;
  look: LookState;
}

export function renderHome({ config, db, migrations, owner, now, look }: HomeOptions): string {
  const standards = db
    .prepare(
      `SELECT s.id, s.name, s.format, s.schedule, s.enabled, s.restricted, s.notes,
              (SELECT COUNT(*) FROM snapshots sn WHERE sn.source_id = s.id) AS snapshot_count,
              (SELECT COUNT(*) FROM changes c WHERE c.source_id = s.id) AS change_count,
              (SELECT d.version_label FROM documents d WHERE d.source_id = s.id ORDER BY d.published_at DESC, d.id DESC LIMIT 1) AS latest_version,
              (SELECT d.published_at FROM documents d WHERE d.source_id = s.id ORDER BY d.published_at DESC, d.id DESC LIMIT 1) AS latest_published
       FROM sources s
       WHERE s.group_name = 'standards' AND s.kind <> 'article'
       ORDER BY s.name`,
    )
    .all() as unknown as StandardRow[];

  const stats = {
    standards: standards.filter((s) => s.enabled === 1).length,
    sources: countRows(db, "sources", "WHERE enabled = 1"),
    snapshots: countRows(db, "snapshots"),
    changes: countRows(db, "changes"),
    items: countRows(db, "items"),
    unread: countRows(db, "items", "WHERE read = 0"),
    bytes: databaseBytes(db),
  };

  const kev = db
    .prepare("SELECT id, title, url, published_at, signals_json FROM items WHERE kind = 'kev' ORDER BY published_at DESC, id DESC LIMIT 6")
    .all() as unknown as KevRow[];
  const kevVersion = (db.prepare("SELECT version_label FROM documents WHERE source_id = 'cisa-kev' ORDER BY id DESC LIMIT 1").get() as { version_label: string } | undefined)
    ?.version_label;
  const lastFetch = (db.prepare("SELECT MAX(last_fetch_at) AS at FROM sources").get() as { at: string | null }).at;
  const counts = triageCounts(db);
  const inboxCount = triageInbox(db, 500).length;
  const digest = latestDigest(db);
  const alerts = recentAlerts(db, 1);

  const standardCards = standards.map((s) => {
    const state =
      s.snapshot_count === 0
        ? s.format === "pdf-upload"
          ? html`<span class="state wait">Waiting for your first upload</span>`
          : html`<span class="state wait">No snapshot yet</span>`
        : html`<span class="state ok">${s.latest_version ?? "latest"}${s.latest_published ? html` · ${s.latest_published.slice(0, 10)}` : ""}</span>`;
    return html`<li class="std">
      <div class="std-head"><b><a href="/standards/${s.id}">${s.name}</a></b>${state}</div>
      <div class="std-meta"><span>${formatLabel[s.format] ?? s.format}</span><a href="/sources#src-${s.id}">${s.schedule === "manual" ? "manual" : `checked ${s.schedule}`}</a><a class="n" href="/standards/${s.id}">${s.snapshot_count} snapshots · ${s.change_count} changes</a>${s.restricted ? html`<a href="/sources#src-${s.id}">entries shown to the owner only (licence)</a>` : ""}</div>
      ${s.notes ? html`<p class="std-note">${s.notes}</p>` : ""}
    </li>`;
  });

  const kevList = kev.map((k) => {
    let due = "";
    try {
      due = (JSON.parse(k.signals_json ?? "{}") as { dueDate?: string }).dueDate ?? "";
    } catch {
      due = "";
    }
    return html`<li><a href="${k.url ?? "/?kind=kev"}" ${newTabIf(k.url ?? "/?kind=kev")}>${k.title}</a><span class="when">${relativeTime(k.published_at, now)}${due ? html` · due ${due}` : ""}</span></li>`;
  });

  const content = html`
    <div class="stats" aria-label="Totals">
      <a href="/sources#standards"><small>Standards tracked</small><b>${stats.standards}</b></a>
      <a href="/sources"><small>Sources enabled</small><b>${stats.sources}</b></a>
      <a href="#tracked"><small>Snapshots</small><b>${figure(stats.snapshots)}</b></a>
      <a href="/?kind=release"><small>Changes</small><b>${figure(stats.changes)}</b></a>
      <a href="/?unread=1"><small>News, unread</small><b>${figure(stats.unread)}</b></a>
      <a href="#instance"><small>Database</small><b>${formatBytes(stats.bytes)}</b></a>
    </div>

    <div class="cols">
      <section class="main" id="tracked">
        <h1>Tracked standards</h1>
        <p class="lede">Every release of each standard is kept as a snapshot. Two snapshots of the same document give a change list: each control or setting before and after, what changed, and the publisher's stated reason.</p>
        ${stats.changes === 0
          ? html`<div class="empty">
              <b>The Register has no diffs yet.</b>
              <p>No standard has been read yet. The Register fills as the standards sources are fetched — on the scheduler's next pass, or now from the <a href="/sources">Sources</a> page — and the first diff appears once a standard has two versions here. The <a href="/">News</a> and the <a href="/vulnerabilities">Vulnerabilities</a> table are live meanwhile.</p>
            </div>`
          : ""}
        <ul class="stds">${standardCards}</ul>
      </section>

      <aside class="side">
        <section class="box">
          <h2><a href="/triage">Needs you</a></h2>
          <dl class="kv">
            <dt>Affects us</dt><dd><a href="/triage#affects">${counts.affects}</a></dd>
            <dt>Reviewing</dt><dd><a href="/triage#reviewing">${counts.reviewing}</a></dd>
            <dt>Inbox</dt><dd><a href="/triage#new">${inboxCount} not yet placed</a></dd>
            <dt>Last digest</dt><dd>${digest ? html`<a href="/digest#latest">${relativeTime(digest.generated_at, now)}</a>` : html`<a href="/digest">none yet</a>`}</dd>
            ${alerts.length ? html`<dt>Last alert</dt><dd><a href="/digest#alerts">${alerts[0]!.title}</a> <span class="small">(${alerts[0]!.status}, ${relativeTime(alerts[0]!.sent_at, now)})</span></dd>` : ""}
          </dl>
        </section>
        <section class="box">
          <h2><a href="/?kind=kev">Known exploited, newest</a>${kevVersion ? html` <span class="count"><a href="/standards/cisa-kev">catalog ${kevVersion}</a></span>` : ""}</h2>
          ${kev.length ? html`<ul class="kev-list">${kevList}</ul><p class="small"><a href="/?kind=kev">All KEV additions in the News</a></p>` : html`<p class="small">Nothing fetched yet. The CISA catalog is checked hourly.</p>`}
        </section>
        <section class="box" id="instance">
          <h2><a href="/health">This instance</a></h2>
          <dl class="kv">
            <dt>Address</dt><dd>${config.baseUrl}</dd>
            <dt>Reading</dt><dd>${config.publicRead ? "open to anyone who can reach the page" : "owner only"}</dd>
            <dt>Writes</dt><dd>${config.adminPassword ? (owner ? "you are signed in as the owner" : html`<a href="/login">owner sign-in required</a>`) : "open (no owner password set)"}</dd>
            <dt>Last fetch</dt><dd>${lastFetch ? html`<a href="/sources">${relativeTime(lastFetch, now)}</a>` : html`<a href="/sources">never</a>`}</dd>
            <dt>Time zone</dt><dd>${config.timeZone}</dd>
            <dt>Data</dt><dd>${owner ? config.dataDir : "set"}</dd>
            <dt>NVD API key</dt><dd>${config.nvdApiKey ? "set" : "not set (5 requests per 30 s)"}</dd>
            <dt>Notifications</dt><dd>${config.notifyUrl ? "set" : "not set"}</dd>
            <dt>Local model</dt><dd>${config.llmUrl ? "set, summaries badged as generated" : "off"}</dd>
            <dt>Schema</dt><dd>${migrations.length} migrations applied</dd>
          </dl>
        </section>
        <section class="box">
          <h2><a href="${repositoryUrl}/blob/main/docs/PLAN.md" ${newTab}>What comes next</a></h2>
          <ol class="plan">
            <li><b>M3 Register.</b> OSCAL snapshots and the first real diff on this page: NIST SP 800-53 Release 5.1.1 to 5.2.0.</li>
            <li><b>M4 Register.</b> DISA STIGs and Microsoft baselines, rule by rule and setting by setting.</li>
            <li><b>M5 Explain.</b> The publisher's reason beside every change, and an optional badged summary.</li>
          </ol>
          <p class="small">The full plan is in the repository under <a href="${repositoryUrl}/blob/main/docs/PLAN.md" ${newTab}>docs/PLAN.md</a>.</p>
        </section>
      </aside>
    </div>`;

  return page({
    title: "Register",
    active: "register",
    content,
    meta: html`Tracking ${stats.standards} standards · ${stats.snapshots} snapshots`,
    owner,
    open: !config.adminPassword,
    look,
  });
}
