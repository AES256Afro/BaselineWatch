import type { DatabaseSync } from "node:sqlite";
import { figure, html, newTabIf, type Html } from "../html.ts";
import { kevChip } from "../wire.ts";
import { relativeTime } from "../time.ts";
import {
  backlogUndoHours,
  inboxCutoff,
  inboxDays,
  lastBacklogDismissal,
  listTriage,
  stateLabel,
  triageBacklogCount,
  triageCounts,
  triageInbox,
  triageInboxCount,
  triageStates,
  type TriageCard,
  type TriageKind,
  type TriageState,
} from "../triage.ts";
import type { LookState } from "../look.ts";
import { page } from "./layout.ts";
import { counted, epssPercent } from "../words.ts";

/** The small form every page uses to move a subject to a state. */
export function triageButtons(subject: { kind: TriageKind; id: number; key?: string }, current: TriageState | null, back: string, options: { compact?: boolean } = {}): Html {
  const states: TriageState[] = options.compact ? ["reviewing", "affects", "dismissed"] : ["new", "reviewing", "affects", "done", "dismissed"];
  return html`<div class="acts triage-acts">${states.map(
    (s) => html`<form method="post" action="/triage" class="inline">
      <input type="hidden" name="kind" value="${subject.kind}"><input type="hidden" name="id" value="${subject.id}"><input type="hidden" name="key" value="${subject.key ?? ""}">
      <input type="hidden" name="state" value="${s}"><input type="hidden" name="back" value="${back}">
      <button type="submit" class="${current === s ? "on" : ""}" ${current === s ? "disabled" : ""}>${stateLabel[s]}</button>
    </form>`,
  )}</div>`;
}

/** The fuller form with a note and a due date, for detail pages. */
export function triageForm(subject: { kind: TriageKind; id: number; key?: string }, current: { state: TriageState; note: string | null; due_at: string | null; updated_at?: string } | null, back: string): Html {
  return html`<form method="post" action="/triage" class="stack triage-form">
    <input type="hidden" name="kind" value="${subject.kind}"><input type="hidden" name="id" value="${subject.id}"><input type="hidden" name="key" value="${subject.key ?? ""}">
    <input type="hidden" name="back" value="${back}">
    <label for="triage-state">State</label>
    <select id="triage-state" name="state">${triageStates.map((s) => html`<option value="${s}" ${current?.state === s ? "selected" : ""}>${stateLabel[s]}</option>`)}</select>
    <label for="triage-note">Note</label>
    <textarea id="triage-note" name="note" rows="3" maxlength="2000" placeholder="What you checked, who owns it, what is left.">${current?.note ?? ""}</textarea>
    ${current?.updated_at ? html`<p class="small saved-at">Last saved ${current.updated_at.slice(0, 16).replace("T", " ")} UTC</p>` : ""}
    <label for="triage-due">Due</label>
    <input type="date" id="triage-due" name="due" value="${current?.due_at ?? ""}">
    <div class="acts"><button type="submit" class="primary">Save</button>${current ? html`</form><form method="post" action="/triage/clear" class="inline"><input type="hidden" name="kind" value="${subject.kind}"><input type="hidden" name="id" value="${subject.id}"><input type="hidden" name="key" value="${subject.key ?? ""}"><input type="hidden" name="back" value="${back}"><button type="submit">Remove from triage</button></form>` : html`</div></form>`}
    ${current ? html`</div>` : ""}`;
}

function card(c: TriageCard, owner: boolean, now: Date, next?: TriageCard): Html {
  const s = c.signals as { cvss?: number | null; epss?: number | null; kev?: boolean; dueDate?: string; itemKind?: string; release?: boolean };
  // Each card has an address, and its buttons return to the card that follows it: working down a
  // column of thirty no longer means scrolling back from the top after every press.
  const id = `t-${c.subject_kind}-${c.subject_id}${c.subject_key ? `-${c.subject_key.replace(/[^a-z0-9]/gi, "")}` : ""}`;
  const nextId = next ? `t-${next.subject_kind}-${next.subject_id}${next.subject_key ? `-${next.subject_key.replace(/[^a-z0-9]/gi, "")}` : ""}` : id;
  return html`<li id="${id}" class="tcard ${c.subject_kind} ${s.kev ? "kev" : ""}">
    <div class="k"><span>${c.subject_kind === "vuln" ? "CVE" : c.subject_kind === "control" ? "control" : (s.itemKind ?? "item")}</span><span>${relativeTime(c.updated_at, now)}</span></div>
    <b><a href="${c.url}" ${newTabIf(c.url)}>${c.title}</a></b>
    ${c.detail ? html`<p>${c.detail.length > 180 ? `${c.detail.slice(0, 179)}…` : c.detail}</p>` : ""}
    <div class="chips">
      ${s.kev ? kevChip(s.dueDate, now) : ""}
      ${typeof s.cvss === "number" ? html`<span class="chip">CVSS ${s.cvss.toFixed(1)}</span>` : ""}
      ${typeof s.epss === "number" ? html`<span class="chip epss">EPSS ${epssPercent(s.epss)}</span>` : ""}
      ${c.due_at ? html`<span class="chip ${c.due_at < now.toISOString().slice(0, 10) && c.state !== "done" ? "kev" : ""}">due ${c.due_at}</span>` : ""}
    </div>
    ${c.note ? html`<div class="note">${c.note}</div>` : ""}
    ${owner ? triageButtons({ kind: c.subject_kind, id: c.subject_id, key: c.subject_key }, c.state, `/triage#${nextId}`, { compact: false }) : ""}
  </li>`;
}

/** How many inbox cards a page of /triage draws. */
const inboxPage = 30;

/** Where the inbox page starts: the asked offset, never past the start of the last page (a stale ?offset= after cards were placed lands on the last page, not a one-card one). */
export function inboxOffset(requested: number | undefined, waiting: number): number {
  const lastStart = waiting > 0 ? Math.floor((waiting - 1) / inboxPage) * inboxPage : 0;
  return Math.min(Math.max(0, Math.floor(requested ?? 0)), lastStart);
}

export function renderTriage(options: {
  db: DatabaseSync;
  owner: boolean;
  open: boolean;
  now: Date;
  notice?: string | undefined;
  dismissed?: boolean;
  look: LookState;
  /** Where the inbox page starts (?offset=). */
  offset?: number;
  /** The owner asked to mark the backlog not ours: draw the confirming form with its count. */
  confirmBacklog?: boolean;
}): string {
  const { db, owner, open, now, notice, look } = options;
  const counts = triageCounts(db);
  const cards = listTriage(db, { limit: 300, notes: owner, restrictedLabels: owner });
  const byState = new Map<TriageState, TriageCard[]>();
  for (const c of cards) byState.set(c.state, [...(byState.get(c.state) ?? []), c]);
  // A visitor's inbox is the window alone; the watchlist arm is the owner's (triage.ts, inboxSqlFor).
  const waiting = triageInboxCount(db, now, { owner });
  const offset = inboxOffset(options.offset, waiting);
  const inbox = triageInbox(db, now, inboxPage, { owner, offset });
  const backlog = owner ? triageBacklogCount(db, now) : 0;
  const undo = owner ? lastBacklogDismissal(db, now) : null;
  const cutoffDay = inboxCutoff(now).slice(0, 10);
  const column = (state: TriageState, after: Html = html``): Html => html`<section class="tcol ${state}" id="${state}">
    <h2><a href="#${state}">${stateLabel[state]}</a> <span class="count"><a href="#${state}">${counts[state]}</a></span></h2>
    <ul class="tcards">${(byState.get(state) ?? []).map((c, i, all) => card(c, owner, now, all[i + 1]))}</ul>
    ${after}
  </section>`;
  // The dismissed cards stay out of the way under Done; the count on the board opens them (?dismissed=1).
  const dismissed = (byState.get("dismissed") ?? []).length
    ? options.dismissed
      ? html`<h3 class="small" id="dismissed"><a href="#dismissed">Not ours</a> <span class="count"><a href="#dismissed">${counts.dismissed}</a></span></h3><ul class="tcards">${(byState.get("dismissed") ?? []).map((c, i, all) => card(c, owner, now, all[i + 1]))}</ul><p class="small"><a href="/triage#done">Hide them again</a></p>`
      : html`<p class="small"><a href="/triage?dismissed=1#dismissed">${counts.dismissed} marked not ours</a>, kept out of the way.</p>`
    : html``;

  const inboxList = html`${inbox.length
    ? html`<ul class="tcards inbox">${inbox.map((i, index) => {
        const nextInbox = inbox[index + 1];
        let s: { dueDate?: string; cvss?: number | null; kev?: boolean } = {};
        try {
          s = JSON.parse(i.signals_json ?? "{}") as typeof s;
        } catch {
          s = {};
        }
        // A CVE's card leads to its page here, where the fix, the history and the triage form are; the source is one link on it.
        const href = i.cve_id ? `/vulnerabilities/${i.cve_id}` : i.url;
        return html`<li id="in-${i.id}" class="tcard inbox-card ${i.kind}">
          <div class="k"><span>${i.source_name}</span><span>${relativeTime(i.published_at, now)}</span></div>
          <b>${href ? html`<a href="${href}" ${newTabIf(href)}>${i.title}</a>` : i.title}</b>
          ${i.lead ? html`<p>${i.lead}</p>` : ""}
          <div class="chips">${i.kind === "kev" || s.kev ? kevChip(s.dueDate, now) : ""}${typeof s.cvss === "number" && !i.title.includes("CVSS") ? html`<span class="chip">CVSS ${s.cvss.toFixed(1)}</span>` : ""}${i.kind === "release" ? html`<span class="chip">release</span>` : ""}</div>
          ${owner ? triageButtons({ kind: "item", id: i.id }, null, `${offset > 0 ? `/triage?offset=${offset}` : "/triage"}${nextInbox ? `#in-${nextInbox.id}` : "#new"}`, { compact: true }) : ""}
        </li>`;
      })}</ul>`
    : html`<p class="small">Nothing waiting. New KEV entries, notable CVEs and standard releases land here until you place them.</p>`}
    ${waiting > inbox.length
      ? html`<p class="small inbox-pages">${figure(offset + 1)}–${figure(offset + inbox.length)} of ${figure(waiting)} shown, the newest first.${offset > 0 ? html` <a href="${offset > inboxPage ? `/triage?offset=${offset - inboxPage}` : "/triage"}#new">Previous ${inboxPage}</a>` : ""}${offset + inbox.length < waiting ? html` <a href="/triage?offset=${offset + inboxPage}#new">Next ${Math.min(inboxPage, waiting - offset - inbox.length)}</a>` : ""}</p>`
      : ""}
    <p class="small">The last ${inboxDays} days${owner ? ", and anything older that is on your watchlist" : ""}.</p>
    ${undo
      ? html`<form method="post" action="/triage/undo-dismiss" class="backlog">
          <button type="submit">Undo the last bulk dismissal</button>
          <span class="small">${counted(undo.count, "item")} marked not ours ${relativeTime(undo.at, now)}; any you have moved since stay where you put them. Possible for ${backlogUndoHours} hours.</span>
        </form>`
      : ""}
    ${backlog
      ? options.confirmBacklog
        ? html`<form method="post" action="/triage/dismiss-older" class="backlog confirm" id="backlog">
            <input type="hidden" name="before" value="${cutoffDay}"><input type="hidden" name="confirm" value="1"><input type="hidden" name="count" value="${backlog}">
            <p><b>Mark ${counted(backlog, "KEV entry or CVE", "KEV entries and CVEs")} from before ${cutoffDay} not ours?</b></p>
            <p class="small">Unread, unplaced and not on the watchlist; standard releases are left alone. The last such action can be undone here for ${backlogUndoHours} hours, and each item can still be moved from its own page.</p>
            <div class="acts"><button type="submit" class="primary">Mark the ${figure(backlog)} not ours</button> <a href="/triage#new">Cancel</a></div>
          </form>`
        : html`<form method="get" action="/triage#backlog" class="backlog" id="backlog">
            <input type="hidden" name="confirm" value="older">
            <button type="submit">Mark the ${figure(backlog)} older than ${cutoffDay} not ours…</button>
            <span class="small">KEV entries and CVEs that are unread, unplaced and not on the watchlist. You are asked to confirm.</span>
          </form>`
      : ""}`;

  const content = html`
    <div class="wire-top">
      <h1>Triage</h1>
      <div class="small">${owner ? html`<a href="/triage.csv" download>CSV of every triaged card (state, title, link, note, due date)</a> · ` : ""}<a href="#affects">${counts.affects} affect us</a> · <a href="#reviewing">${counts.reviewing} reviewing</a> · <a href="#done">${counts.done} done</a></div>
    </div>
    <p class="lede">Where each thing sits on your desk. The inbox is what arrived and has not been placed; the owner moves things with the buttons and adds notes on each item's own page.</p>
    ${notice ? html`<div class="notice ok">${notice}</div>` : ""}
    <div class="board">
      <section class="tcol new" id="new"><h2><a href="#new">Inbox</a> <span class="count"><a href="#new">${figure(waiting)}</a></span></h2>${inboxList}${(byState.get("new") ?? []).length ? html`<h3 class="small" id="placed"><a href="#placed">Placed as new</a> <span class="count"><a href="#placed">${counts.new}</a></span></h3><ul class="tcards">${(byState.get("new") ?? []).map((c, i, all) => card(c, owner, now, all[i + 1]))}</ul>` : ""}</section>
      ${column("reviewing")}
      ${column("affects")}
      ${column("done", dismissed)}
    </div>`;

  return page({ title: "Triage", active: "triage", content, meta: html`${counts.affects + counts.reviewing} open`, owner, open, look });
}
