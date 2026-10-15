import type { DatabaseSync } from "node:sqlite";
import { html, type Html } from "../html.ts";
import { relativeTime } from "../time.ts";
import type { TriageState } from "../triage.ts";
import { listWire, sourceCounts, type WireFilters, type WireItem } from "../wire.ts";
import { page } from "./layout.ts";
import { triageButtons } from "./triage.ts";

interface Signals {
  kev?: boolean;
  cves?: string[];
  dueDate?: string;
  ransomware?: boolean;
  vendor?: string;
  product?: string;
  score?: number;
  comments?: number;
  thread?: string;
  epss?: number | null;
  watch?: string[];
}

function signals(item: WireItem): Signals {
  if (!item.signals_json) return {};
  try {
    return JSON.parse(item.signals_json) as Signals;
  } catch {
    return {};
  }
}

function query(filters: WireFilters, overrides: Partial<WireFilters>): string {
  const merged = { ...filters, ...overrides };
  const params = new URLSearchParams();
  if (merged.source) params.set("source", merged.source);
  if (merged.group) params.set("group", merged.group);
  if (merged.kind) params.set("kind", merged.kind);
  if (merged.q) params.set("q", merged.q);
  if (merged.unread) params.set("unread", "1");
  if (merged.before) params.set("before", String(merged.before));
  const s = params.toString();
  return s ? `/wire?${s}` : "/wire";
}

function chips(item: WireItem): Html[] {
  const s = signals(item);
  const out: Html[] = [];
  if (item.kind === "kev" || (item.kind === "vulnerability" && s.kev)) out.push(html`<span class="chip kev">KEV${s.dueDate ? html` · due ${s.dueDate}` : ""}</span>`);
  if (item.kind === "vulnerability") {
    if (typeof s.epss === "number") out.push(html`<span class="chip epss">EPSS ${(s.epss * 100).toFixed(0)}%</span>`);
    if (s.watch?.length) out.push(html`<span class="chip mine">${s.watch.join(", ")}</span>`);
    if (s.cves?.[0]) out.push(html`<a class="chip" href="/vulnerabilities/${s.cves[0]}">details</a>`);
  }
  if (s.ransomware) out.push(html`<span class="chip kev">ransomware</span>`);
  if (s.cves?.length && item.kind !== "kev") out.push(html`<span class="chip">${s.cves.slice(0, 3).join(", ")}${s.cves.length > 3 ? html` +${s.cves.length - 3}` : ""}</span>`);
  if (typeof s.score === "number" && s.thread) out.push(html`<a class="chip" href="${s.thread}" rel="noopener">${s.score} pts · ${s.comments ?? 0} comments</a>`);
  if (item.starred) out.push(html`<span class="chip star">starred</span>`);
  return out;
}

export interface WirePageOptions {
  db: DatabaseSync;
  filters: WireFilters;
  owner: boolean;
  open: boolean;
  now: Date;
}

export function renderWire({ db, filters, owner, open, now }: WirePageOptions): string {
  const items = listWire(db, { ...filters, limit: 50 });
  const counts = sourceCounts(db).filter((c) => c.total > 0 || c.source_id === filters.source);
  const triageState = new Map<number, TriageState>();
  if (items.length) {
    for (const r of db.prepare(`SELECT subject_id, state FROM triage WHERE subject_kind = 'item' AND subject_id IN (${items.map(() => "?").join(",")})`).all(...items.map((i) => i.id)) as { subject_id: number; state: TriageState }[]) {
      triageState.set(r.subject_id, r.state);
    }
  }
  const totalUnread = counts.reduce((n, c) => n + (c.unread ?? 0), 0);
  const current = query(filters, {});
  const last = items[items.length - 1];

  const rows = items.map((item) => {
    const back = html`<input type="hidden" name="back" value="${current}">`;
    return html`<li class="wi ${item.read ? "read" : "unread"} ${item.kind}">
      <div class="wi-head">
        <span class="wi-src">${item.source_name}</span>
        <time class="wi-time" datetime="${item.published_at ?? item.fetched_at}">${relativeTime(item.published_at ?? item.fetched_at, now)}</time>
      </div>
      <h3 class="wi-title">${item.url ? html`<a href="${item.url}" rel="noopener">${item.title}</a>` : item.title}</h3>
      ${item.summary ? html`<p class="wi-sum">${item.summary}</p>` : ""}
      <div class="wi-foot">
        <div class="chips">${chips(item)}</div>
        ${owner
          ? html`<div class="acts">
              <form method="post" action="/items/${item.id}/${item.read ? "unread" : "read"}">${back}<button type="submit">${item.read ? "Mark unread" : "Mark read"}</button></form>
              <form method="post" action="/items/${item.id}/${item.starred ? "unstar" : "star"}">${back}<button type="submit">${item.starred ? "Unstar" : "Star"}</button></form>
              ${item.kind !== "article" ? triageButtons({ kind: "item", id: item.id }, triageState.get(item.id) ?? null, current, { compact: true }) : ""}
            </div>`
          : ""}
      </div>
    </li>`;
  });

  const sourceList = counts.map(
    (c) => html`<li class="${filters.source === c.source_id ? "on" : ""}"><a href="${query(filters, { source: c.source_id, before: undefined })}">${c.name}</a><b>${c.unread ?? 0}</b></li>`,
  );

  const content = html`
    <div class="cols wire">
      <section class="main">
        <div class="wire-top">
          <h1>Wire${filters.source ? html` <small>· ${counts.find((c) => c.source_id === filters.source)?.name ?? filters.source}</small>` : ""}</h1>
          <form method="get" action="/wire" class="search" role="search">
            ${filters.source ? html`<input type="hidden" name="source" value="${filters.source}">` : ""}
            ${filters.group ? html`<input type="hidden" name="group" value="${filters.group}">` : ""}
            ${filters.kind ? html`<input type="hidden" name="kind" value="${filters.kind}">` : ""}
            <label class="visually-hidden" for="q">Search the Wire</label>
            <input type="search" id="q" name="q" value="${filters.q ?? ""}" placeholder="Search titles and summaries">
            <button type="submit">Search</button>
          </form>
        </div>
        <div class="filters">
          <a class="${!filters.kind && !filters.group ? "on" : ""}" href="${query(filters, { kind: undefined, group: undefined, before: undefined })}">All</a>
          <a class="${filters.group === "news" ? "on" : ""}" href="${query(filters, { group: "news", kind: undefined, before: undefined })}">News</a>
          <a class="${filters.group === "vulnerabilities" && filters.kind === "article" ? "on" : ""}" href="${query(filters, { group: "vulnerabilities", kind: "article", before: undefined })}">Vendor advisories</a>
          <a class="${filters.kind === "kev" ? "on" : ""}" href="${query(filters, { kind: "kev", group: undefined, before: undefined })}">Known exploited</a>
          <a class="${filters.kind === "vulnerability" ? "on" : ""}" href="${query(filters, { kind: "vulnerability", group: undefined, before: undefined })}">Notable CVEs</a>
          <a class="${filters.kind === "release" ? "on" : ""}" href="${query(filters, { kind: "release", group: undefined, before: undefined })}">Releases</a>
          <a class="${filters.unread ? "on" : ""}" href="${query(filters, { unread: !filters.unread, before: undefined })}">Unread only</a>
          ${owner && items.length
            ? html`<form method="post" action="/wire/read-all" class="inline">
                ${filters.source ? html`<input type="hidden" name="source" value="${filters.source}">` : ""}
                ${filters.kind ? html`<input type="hidden" name="kind" value="${filters.kind}">` : ""}
                ${filters.q ? html`<input type="hidden" name="q" value="${filters.q}">` : ""}
                <input type="hidden" name="back" value="${current}">
                <button type="submit">Mark all read</button>
              </form>`
            : ""}
        </div>
        ${items.length === 0
          ? html`<div class="empty"><b>Nothing here yet.</b><p>${filters.q || filters.source || filters.kind || filters.unread ? "No items match these filters." : "The first fetch has not run. Sources are fetched on their schedule; the owner can fetch one now from the Sources page."}</p></div>`
          : html`<ul class="wire-list">${rows}</ul>`}
        ${items.length === 50 && last ? html`<p class="more"><a href="${query(filters, { before: last.id })}">Older</a></p>` : ""}
      </section>
      <aside class="side">
        <section class="box">
          <h2>Sources <span class="count">${totalUnread} unread</span></h2>
          <ul class="src-list">
            <li class="${!filters.source ? "on" : ""}"><a href="${query(filters, { source: undefined, before: undefined })}">All sources</a><b>${totalUnread}</b></li>
            ${sourceList}
          </ul>
        </section>
      </aside>
    </div>`;

  return page({ title: "Wire", active: "wire", content, meta: html`${totalUnread} unread`, owner, open });
}
