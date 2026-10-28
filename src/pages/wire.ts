import { platformChoiceName } from "../platforms.ts";
import { platformPicker } from "./platform-pick.ts";
import type { DatabaseSync } from "node:sqlite";
import { fixContext, fixesFor, fixSummary, kevFor } from "../fix.ts";
import { html, newTab, newTabIf, type Html } from "../html.ts";
import { getVuln } from "../vulns.ts";
import { relativeTime } from "../time.ts";
import { triageCounts, type TriageState } from "../triage.ts";
import { listWire, ownerOnlySources, sourceCounts, type WireFilters, type WireItem } from "../wire.ts";
import type { LookState } from "../look.ts";
import { page, registerStrip } from "./layout.ts";
import { saveSearchForm } from "./saved.ts";
import { triageButtons } from "./triage.ts";

/**
 * The News page: the home timeline with its featured cards and strip, the source and kind filters,
 * search, and the read and star controls for the owner.
 */
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

function signals(item: Pick<WireItem, "signals_json">): Signals {
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
  if (merged.platform) params.set("platform", merged.platform);
  if (merged.danger) params.set("danger", "1");
  if (merged.unread) params.set("unread", "1");
  if (merged.before) params.set("before", String(merged.before));
  const s = params.toString();
  return s ? `/?${s}` : "/";
}

function chips(item: WireItem, owner: boolean): Html[] {
  const s = signals(item);
  const out: Html[] = [];
  if (item.kind === "kev" || (item.kind === "vulnerability" && s.kev)) out.push(html`<span class="chip kev">KEV${s.dueDate ? html` · due ${s.dueDate}` : ""}</span>`);
  if (item.kind === "vulnerability") {
    if (typeof s.epss === "number") out.push(html`<span class="chip epss">EPSS ${(s.epss * 100).toFixed(0)}%</span>`);
    if (owner && s.watch?.length) out.push(html`<span class="chip mine">${s.watch.join(", ")}</span>`);
    if (s.cves?.[0]) out.push(html`<a class="chip" href="/vulnerabilities/${s.cves[0]}">details</a>`);
  }
  if (s.ransomware) out.push(html`<span class="chip kev">ransomware</span>`);
  if (s.cves?.length && item.kind !== "kev") out.push(html`<span class="chip">${s.cves.slice(0, 3).join(", ")}${s.cves.length > 3 ? html` +${s.cves.length - 3}` : ""}</span>`);
  if (typeof s.score === "number" && s.thread) out.push(html`<a class="chip" href="${s.thread}" ${newTab}>${s.score} pts · ${s.comments ?? 0} comments</a>`);
  if (owner && item.starred) out.push(html`<span class="chip star">starred</span>`);
  return out;
}

export interface NewsPageOptions {
  db: DatabaseSync;
  filters: WireFilters;
  owner: boolean;
  open: boolean;
  now: Date;
  look: LookState;
}

/** The four newest stories as image cards, BleepingComputer-fashion; a § placeholder when a story brought no image. */
function featuredCards(items: WireItem[]): Html {
  const cards = items.map((item) => {
    const art = item.image_blob ? html`<img src="/img/${item.image_blob}" alt="" loading="lazy">` : html`<span class="ph" aria-hidden="true">§</span>`;
    const inner = html`${art}<span class="fsrc">${item.source_name}</span><h3><span>${item.title}</span></h3>`;
    return item.url ? html`<a class="fcard${item.image_blob ? "" : " noimg"}" href="${item.url}" ${newTabIf(item.url)}>${inner}</a>` : html`<div class="fcard${item.image_blob ? "" : " noimg"}">${inner}</div>`;
  });
  return html`<div class="feat" aria-label="Latest, featured">${cards}</div>`;
}

/** What makes two articles one story: the same address once canonical, or the same headline (a short one proves nothing). */
function storyKeys(item: WireItem): string[] {
  if (item.kind !== "article") return [];
  const keys: string[] = [];
  if (item.canonical_url) keys.push(`u:${item.canonical_url}`);
  const headline = item.title.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim().slice(0, 80);
  if (headline.length >= 24) keys.push(`t:${headline}`);
  return keys;
}

export function renderNews({ db, filters: asked, owner, open, now, look }: NewsPageOptions): string {
  // What the owner has read and starred is theirs: a visitor's list is not filtered by it, and the counts are totals.
  const filters: WireFilters = owner ? asked : { ...asked, unread: false };
  // Copies of one address are fetched here so the other sources can be named; the clustering below folds them.
  const fetched = listWire(db, { ...filters, limit: 50 }, { copies: true, owner });
  // One story from several sources is one card: the first by date, the others named on it.
  const alsoOn = new Map<number, WireItem[]>();
  const firstByKey = new Map<string, WireItem>();
  const items: WireItem[] = [];
  for (const item of fetched) {
    const keys = storyKeys(item);
    const first = keys.map((k) => firstByKey.get(k)).find((f) => f !== undefined && f.source_id !== item.source_id);
    if (first) {
      alsoOn.set(first.id, [...(alsoOn.get(first.id) ?? []), item]);
      continue;
    }
    for (const k of keys) if (!firstByKey.has(k)) firstByKey.set(k, item);
    items.push(item);
  }
  const counts = sourceCounts(db)
    .filter((c) => owner || !ownerOnlySources.includes(c.source_id))
    .filter((c) => c.total > 0 || c.source_id === filters.source)
    .map((c) => (owner ? c : { ...c, unread: c.total }));
  const triageState = new Map<number, TriageState>();
  if (items.length) {
    for (const r of db.prepare(`SELECT subject_id, state FROM triage WHERE subject_kind = 'item' AND subject_id IN (${items.map(() => "?").join(",")})`).all(...items.map((i) => i.id)) as { subject_id: number; state: TriageState }[]) {
      triageState.set(r.subject_id, r.state);
    }
  }
  const totalUnread = counts.reduce((n, c) => n + (c.unread ?? 0), 0);
  const current = query(filters, {});
  const last = fetched[fetched.length - 1];
  // The front page leads with image cards; a filtered or paged view is the plain list.
  const plain = !filters.source && !filters.group && !filters.kind && !filters.q && !filters.unread && !filters.before && !filters.platform && !filters.danger;
  const featured = plain ? items.slice(0, 4) : [];
  const listed = plain ? items.slice(featured.length) : items;
  // The fix line on a CVE or KEV item: the same facts as the CVE page's Fix panel, in one sentence.
  const fixes = items.some((i) => i.kind === "vulnerability" || i.kind === "kev") ? fixContext(db) : null;
  const fixLine = (item: WireItem): Html => {
    if (!fixes || (item.kind !== "vulnerability" && item.kind !== "kev")) return html``;
    const cve = item.kind === "kev" ? item.external_id : (signals(item).cves?.[0] ?? item.external_id);
    const row = getVuln(db, cve);
    if (row) return html`<p class="wi-fix"><b>Fix:</b> ${fixSummary(fixesFor(db, fixes, row))} <a href="/vulnerabilities/${row.cve_id}">Fix panel</a></p>`;
    const kev = kevFor(db, cve);
    return kev?.requiredAction ? html`<p class="wi-fix"><b>Fix:</b> CISA: ${kev.requiredAction}${kev.dueDate ? html` (due ${kev.dueDate})` : ""}</p>` : html``;
  };

  const rows = listed.map((item) => {
    const back = html`<input type="hidden" name="back" value="${current}">`;
    return html`<li class="wi ${owner && item.read ? "read" : "unread"} ${item.kind}${item.image_blob ? " with-img" : ""}">
      ${item.image_blob ? html`<a class="wi-img" href="${item.url ?? `/img/${item.image_blob}`}" ${newTabIf(item.url)} tabindex="-1" aria-hidden="true"><img src="/img/${item.image_blob}" alt="" loading="lazy"></a>` : ""}
      <div class="wi-body">
      <div class="wi-head">
        <span class="wi-src">${item.source_name}</span>
        <time class="wi-time" datetime="${item.published_at ?? item.fetched_at}">${relativeTime(item.published_at ?? item.fetched_at, now)}</time>
      </div>
      <h3 class="wi-title">${item.url ? html`<a href="${item.url}" ${newTabIf(item.url)}>${item.title}</a>` : item.title}</h3>
      ${item.summary ? html`<p class="wi-sum">${item.summary}</p>` : ""}
      ${fixLine(item)}
      <div class="wi-foot">
        <div class="chips">${chips(item, owner)}${(alsoOn.get(item.id) ?? []).map((d) => html`<a class="chip also" href="${d.url ?? "#"}" ${newTabIf(d.url)}>also on ${d.source_name}</a>`)}</div>
        ${owner
          ? html`<div class="acts">
              <form method="post" action="/items/${item.id}/${item.read ? "unread" : "read"}">${back}<button type="submit">${item.read ? "Mark unread" : "Mark read"}</button></form>
              <form method="post" action="/items/${item.id}/${item.starred ? "unstar" : "star"}">${back}<button type="submit">${item.starred ? "Unstar" : "Star"}</button></form>
              ${item.kind !== "article" ? triageButtons({ kind: "item", id: item.id }, triageState.get(item.id) ?? null, current, { compact: true }) : ""}
            </div>`
          : ""}
      </div>
      </div>
    </li>`;
  });

  const sourceList = counts.map(
    (c) => html`<li class="${filters.source === c.source_id ? "on" : ""}"><a href="${query(filters, { source: c.source_id, before: undefined })}">${c.name}</a><b>${owner ? html`<a href="${query(filters, { source: c.source_id, unread: true, before: undefined })}">${c.unread ?? 0}</a>` : c.total}</b></li>`,
  );

  // The desk box: the owner's queue at a glance, or the sign-in prompt on the public site.
  const tc = owner ? triageCounts(db) : null;
  const deskBox = owner
    ? html`<section class="box desk-box">
        <h2><a href="/triage">Owner's desk</a></h2>
        <ul class="kev-list">
          <li><a href="/triage">Triage</a><a class="when" href="/triage#affects">${(tc?.affects ?? 0) + (tc?.reviewing ?? 0)} open</a></li>
          <li><a href="/watchlist">Watchlist</a></li>
          <li><a href="/digest">Digest</a></li>
          <li><a href="/sources">Sources</a></li>
          <li><a href="/branding">Branding</a></li>
        </ul>
      </section>`
    : open
      ? ""
      : html`<section class="box desk-box"><h2><a href="/login">Owner's desk</a></h2><p class="small">Triage, watchlist, digest and sources live in the Desk menu. <a href="/login">Sign in</a> to see your queue here.</p></section>`;

  // In the KEV lately: the newest catalog entries, each linking to its CVE page when it has one.
  const kevRows = db
    .prepare("SELECT title, url, external_id, published_at, fetched_at, signals_json FROM items WHERE kind = 'kev' ORDER BY COALESCE(published_at, fetched_at) DESC, id DESC LIMIT 5")
    .all() as Pick<WireItem, "title" | "url" | "external_id" | "published_at" | "fetched_at" | "signals_json">[];
  const kevBox = kevRows.length
    ? html`<section class="box">
        <h2><a href="/?kind=kev">In the KEV lately</a></h2>
        <ul class="kev-list">
          ${kevRows.map((k) => {
            const due = signals(k).dueDate;
            const href = /^CVE-\d{4}-\d{4,7}$/.test(k.external_id) ? `/vulnerabilities/${k.external_id}` : (k.url ?? "/vulnerabilities?kev=1");
            return html`<li><a href="${href}">${k.title}</a><span class="when">${relativeTime(k.published_at ?? k.fetched_at, now)}${due ? html` · due ${due}` : ""}</span></li>`;
          })}
        </ul>
        <p class="small"><a href="/vulnerabilities?kev=1">All of them, in the table</a></p>
      </section>`
    : "";

  const content = html`
    <div class="wire-top">
      <h1>News${filters.source ? html` <small>· ${counts.find((c) => c.source_id === filters.source)?.name ?? filters.source}</small>` : filters.platform ? html` <small>· ${platformChoiceName(filters.platform)}${filters.danger ? ", the most dangerous" : ""}</small>` : filters.danger ? html` <small>· the most dangerous</small>` : plain ? html` <small class="motto">Advisories, exploited vulnerabilities and the stories behind them</small>` : ""}</h1>
      ${saveSearchForm(db, query(filters, { before: undefined }), owner)}
      <form method="get" action="/" class="search" role="search">
        ${filters.source ? html`<input type="hidden" name="source" value="${filters.source}">` : ""}
        ${filters.group ? html`<input type="hidden" name="group" value="${filters.group}">` : ""}
        ${filters.kind ? html`<input type="hidden" name="kind" value="${filters.kind}">` : ""}
        ${filters.platform ? html`<input type="hidden" name="platform" value="${filters.platform}">` : ""}
        ${filters.danger ? html`<input type="hidden" name="danger" value="1">` : ""}
        <label class="visually-hidden" for="q">Search the news</label>
        <input type="search" id="q" name="q" value="${filters.q ?? ""}" placeholder="Search titles and summaries">
        <button type="submit">Search</button>
      </form>
    </div>
    ${featured.length ? featuredCards(featured) : ""}
    <div class="cols wire">
      <section class="main">
        ${platformPicker(filters, (next) => query(filters, { platform: next.platform, danger: next.danger === true, before: undefined }))}
        <div class="filters">
          <a class="${!filters.kind && !filters.group ? "on" : ""}" href="${query(filters, { kind: undefined, group: undefined, before: undefined })}">All</a>
          <a class="${filters.group === "news" ? "on" : ""}" href="${query(filters, { group: "news", kind: undefined, before: undefined })}">News</a>
          <a class="${filters.group === "vulnerabilities" && filters.kind === "article" ? "on" : ""}" href="${query(filters, { group: "vulnerabilities", kind: "article", before: undefined })}">Vendor advisories</a>
          <a class="${filters.kind === "kev" ? "on" : ""}" href="${query(filters, { kind: "kev", group: undefined, before: undefined })}">Known exploited</a>
          <a class="${filters.kind === "vulnerability" ? "on" : ""}" href="${query(filters, { kind: "vulnerability", group: undefined, before: undefined })}">Notable CVEs</a>
          <a class="${filters.kind === "release" ? "on" : ""}" href="${query(filters, { kind: "release", group: undefined, before: undefined })}">Releases</a>
          ${owner ? html`<a class="${filters.unread ? "on" : ""}" href="${query(filters, { unread: !filters.unread, before: undefined })}">Unread only</a>` : ""}
          ${owner && items.length
            ? html`<form method="post" action="/wire/read-all" class="inline">
                ${filters.source ? html`<input type="hidden" name="source" value="${filters.source}">` : ""}
                ${filters.group ? html`<input type="hidden" name="group" value="${filters.group}">` : ""}
                ${filters.kind ? html`<input type="hidden" name="kind" value="${filters.kind}">` : ""}
                ${filters.q ? html`<input type="hidden" name="q" value="${filters.q}">` : ""}
                ${filters.platform ? html`<input type="hidden" name="platform" value="${filters.platform}">` : ""}
                ${filters.danger ? html`<input type="hidden" name="danger" value="1">` : ""}
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
        ${kevBox}
        <section class="box">
          <h2><a href="/sources">Sources</a> <span class="count">${owner ? html`<a href="${query(filters, { unread: true, before: undefined })}">${totalUnread} unread</a>` : html`${totalUnread} items`}</span></h2>
          <ul class="src-list">
            <li class="${!filters.source ? "on" : ""}"><a href="${query(filters, { source: undefined, before: undefined })}">All sources</a><b>${owner ? html`<a href="${query(filters, { source: undefined, unread: true, before: undefined })}">${totalUnread}</a>` : totalUnread}</b></li>
            ${sourceList}
          </ul>
        </section>
        ${deskBox}
      </aside>
    </div>`;

  const feedQuery = query(filters, { before: undefined, unread: false });
  const feed = { href: feedQuery === "/" ? "/feed.xml" : `/feed.xml${feedQuery.slice(1)}`, title: "News" };
  return page({ title: "News", active: "wire", content, meta: owner ? html`${totalUnread} unread` : html``, owner, open, strip: registerStrip(db, now), look, feed, canonical: "/", description: "Security news, vendor advisories and the CVEs that matter, in one timeline, with what to do about each." });
}
