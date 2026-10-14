import type { DatabaseSync } from "node:sqlite";
import { html, type Html } from "../html.ts";
import { relativeTime } from "../time.ts";
import { listWire, sourceCounts, type WireFilters, type WireItem } from "../wire.ts";
import { page } from "./layout.ts";

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
  if (item.kind === "kev") out.push(html`<span class="chip kev">KEV${s.dueDate ? html` · due ${s.dueDate}` : ""}</span>`);
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
            ${filters.kind ? html`<input type="hidden" name="kind" value="${filters.kind}">` : ""}
            <label class="visually-hidden" for="q">Search the Wire</label>
            <input type="search" id="q" name="q" value="${filters.q ?? ""}" placeholder="Search titles and summaries">
            <button type="submit">Search</button>
          </form>
        </div>
        <div class="filters">
          <a class="${!filters.kind ? "on" : ""}" href="${query(filters, { kind: undefined, before: undefined })}">All</a>
          <a class="${filters.kind === "article" ? "on" : ""}" href="${query(filters, { kind: "article", before: undefined })}">News</a>
          <a class="${filters.kind === "kev" ? "on" : ""}" href="${query(filters, { kind: "kev", before: undefined })}">Known exploited</a>
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
