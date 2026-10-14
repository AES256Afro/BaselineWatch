import type { DatabaseSync } from "node:sqlite";
import type { Config } from "../config.ts";
import { countRows, databaseBytes } from "../db.ts";
import { formatBytes, html } from "../html.ts";
import { page } from "./layout.ts";
import { productName } from "../version.ts";

interface StandardRow {
  id: string;
  name: string;
  format: string;
  schedule: string;
  enabled: number;
  notes: string | null;
  snapshot_count: number;
  change_count: number;
  latest_version: string | null;
  latest_published: string | null;
}

const formatLabel: Record<string, string> = {
  "oscal-json": "OSCAL JSON",
  "cprt-json": "CPRT JSON",
  "xccdf-zip": "XCCDF in zips",
  "sct-zip": "GPO backups and Excel",
  "pdf-upload": "PDF you upload",
  git: "git history",
  rss: "RSS",
  atom: "Atom",
  json: "JSON",
  csv: "CSV",
  html: "HTML listing",
};

export function renderHome(ctx: { config: Config; db: DatabaseSync; migrations: string[] }): string {
  const { config, db } = ctx;
  const standards = db
    .prepare(
      `SELECT s.id, s.name, s.format, s.schedule, s.enabled, s.notes,
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
    bytes: databaseBytes(db),
  };

  const standardCards = standards.map((s) => {
    const state =
      s.snapshot_count === 0
        ? s.format === "pdf-upload"
          ? html`<span class="state wait">Waiting for your first upload</span>`
          : html`<span class="state wait">No snapshot yet</span>`
        : html`<span class="state ok">${s.latest_version ?? "latest"}${s.latest_published ? html` · ${s.latest_published.slice(0, 10)}` : ""}</span>`;
    return html`<li class="std">
      <div class="std-head"><b>${s.name}</b>${state}</div>
      <div class="std-meta"><span>${formatLabel[s.format] ?? s.format}</span><span>${s.schedule === "manual" ? "manual" : `checked ${s.schedule}`}</span><span class="n">${s.snapshot_count} snapshots · ${s.change_count} changes</span></div>
      ${s.notes ? html`<p class="std-note">${s.notes}</p>` : ""}
    </li>`;
  });

  const content = html`
    <div class="stats" aria-label="Totals">
      <div><small>Standards tracked</small><b>${stats.standards}</b></div>
      <div><small>Sources enabled</small><b>${stats.sources}</b></div>
      <div><small>Snapshots</small><b>${stats.snapshots}</b></div>
      <div><small>Changes</small><b>${stats.changes}</b></div>
      <div><small>Timeline items</small><b>${stats.items}</b></div>
      <div><small>Database</small><b>${formatBytes(stats.bytes)}</b></div>
    </div>

    <div class="cols">
      <section class="main">
        <h1>Tracked standards</h1>
        <p class="lede">Every release of each standard is kept as a snapshot. Two snapshots of the same document give a change list: each control or setting before and after, what changed, and the publisher's stated reason.</p>
        ${stats.snapshots === 0
          ? html`<div class="empty">
              <b>The Register is empty.</b>
              <p>This build (M0) proves the container, the database and this page. Fetching arrives with M1 (news, KEV) and M3 (the first OSCAL diff: NIST SP 800-53 Release 5.1.1 to 5.2.0). Nothing has been downloaded yet.</p>
            </div>`
          : ""}
        <ul class="stds">${standardCards}</ul>
      </section>

      <aside class="side">
        <section class="box">
          <h2>This instance</h2>
          <dl class="kv">
            <dt>Address</dt><dd>${config.baseUrl}</dd>
            <dt>Reading</dt><dd>${config.publicRead ? "open to anyone who can reach the page" : "owner only"}</dd>
            <dt>Time zone</dt><dd>${config.timeZone}</dd>
            <dt>Data</dt><dd>${config.dataDir}</dd>
            <dt>NVD API key</dt><dd>${config.nvdApiKey ? "set" : "not set (5 requests per 30 s)"}</dd>
            <dt>Notifications</dt><dd>${config.notifyUrl ? "set" : "not set"}</dd>
            <dt>Local model</dt><dd>${config.llmUrl ? "set, summaries badged as generated" : "off"}</dd>
            <dt>Schema</dt><dd>${ctx.migrations.length} migrations applied</dd>
          </dl>
        </section>
        <section class="box">
          <h2>What comes next</h2>
          <ol class="plan">
            <li><b>M1 Wire.</b> News feeds, CISA KEV, CSRC drafts into one timeline with search.</li>
            <li><b>M2 Vulnerabilities.</b> NVD and CVE List deltas, EPSS, a watchlist for your stack.</li>
            <li><b>M3 Register.</b> OSCAL snapshots and the first real diff on this page.</li>
          </ol>
          <p class="small">The full plan is in the repository under docs/PLAN.md.</p>
        </section>
      </aside>
    </div>`;

  return page({
    title: productName,
    active: "register",
    content,
    meta: html`Tracking ${stats.standards} standards · ${stats.snapshots} snapshots`,
  });
}
