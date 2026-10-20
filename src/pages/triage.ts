import type { DatabaseSync } from "node:sqlite";
import { html, newTabIf, type Html } from "../html.ts";
import { relativeTime } from "../time.ts";
import { listTriage, stateLabel, triageCounts, triageInbox, triageStates, type TriageCard, type TriageKind, type TriageState } from "../triage.ts";
import type { LookState } from "../look.ts";
import { page } from "./layout.ts";

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
export function triageForm(subject: { kind: TriageKind; id: number; key?: string }, current: { state: TriageState; note: string | null; due_at: string | null } | null, back: string): Html {
  return html`<form method="post" action="/triage" class="stack triage-form">
    <input type="hidden" name="kind" value="${subject.kind}"><input type="hidden" name="id" value="${subject.id}"><input type="hidden" name="key" value="${subject.key ?? ""}">
    <input type="hidden" name="back" value="${back}">
    <label for="triage-state">State</label>
    <select id="triage-state" name="state">${triageStates.map((s) => html`<option value="${s}" ${current?.state === s ? "selected" : ""}>${stateLabel[s]}</option>`)}</select>
    <label for="triage-note">Note</label>
    <textarea id="triage-note" name="note" rows="3" maxlength="2000" placeholder="What you checked, who owns it, what is left.">${current?.note ?? ""}</textarea>
    <label for="triage-due">Due</label>
    <input type="date" id="triage-due" name="due" value="${current?.due_at ?? ""}">
    <div class="acts"><button type="submit" class="primary">Save</button>${current ? html`</form><form method="post" action="/triage/clear" class="inline"><input type="hidden" name="kind" value="${subject.kind}"><input type="hidden" name="id" value="${subject.id}"><input type="hidden" name="key" value="${subject.key ?? ""}"><input type="hidden" name="back" value="${back}"><button type="submit">Remove from triage</button></form>` : html`</div></form>`}
    ${current ? html`</div>` : ""}`;
}

function card(c: TriageCard, owner: boolean, now: Date): Html {
  const s = c.signals as { cvss?: number | null; epss?: number | null; kev?: boolean; dueDate?: string; itemKind?: string; release?: boolean };
  return html`<li class="tcard ${c.subject_kind} ${s.kev ? "kev" : ""}">
    <div class="k"><span>${c.subject_kind === "vuln" ? "CVE" : c.subject_kind === "control" ? "control" : (s.itemKind ?? "item")}</span><span>${relativeTime(c.updated_at, now)}</span></div>
    <b><a href="${c.url}" ${newTabIf(c.url)}>${c.title}</a></b>
    ${c.detail ? html`<p>${c.detail.length > 180 ? `${c.detail.slice(0, 179)}…` : c.detail}</p>` : ""}
    <div class="chips">
      ${s.kev ? html`<span class="chip kev">KEV${s.dueDate ? html` · due ${s.dueDate}` : ""}</span>` : ""}
      ${typeof s.cvss === "number" ? html`<span class="chip">CVSS ${s.cvss.toFixed(1)}</span>` : ""}
      ${typeof s.epss === "number" ? html`<span class="chip epss">EPSS ${(s.epss * 100).toFixed(0)}%</span>` : ""}
      ${c.due_at ? html`<span class="chip ${c.due_at < now.toISOString().slice(0, 10) && c.state !== "done" ? "kev" : ""}">due ${c.due_at}</span>` : ""}
    </div>
    ${c.note ? html`<div class="note">${c.note}</div>` : ""}
    ${owner ? triageButtons({ kind: c.subject_kind, id: c.subject_id, key: c.subject_key }, c.state, "/triage", { compact: false }) : ""}
  </li>`;
}

export function renderTriage(options: { db: DatabaseSync; owner: boolean; open: boolean; now: Date; notice?: string | undefined; look: LookState }): string {
  const { db, owner, open, now, notice, look } = options;
  const counts = triageCounts(db);
  const cards = listTriage(db, { limit: 300, owner });
  const byState = new Map<TriageState, TriageCard[]>();
  for (const c of cards) byState.set(c.state, [...(byState.get(c.state) ?? []), c]);
  const inbox = triageInbox(db, 30);
  const column = (state: TriageState, extra: Html = html``): Html => html`<section class="tcol ${state}">
    <h2>${stateLabel[state]} <span class="count">${counts[state]}</span></h2>
    ${extra}
    <ul class="tcards">${(byState.get(state) ?? []).map((c) => card(c, owner, now))}</ul>
  </section>`;

  const inboxList = html`${inbox.length
    ? html`<ul class="tcards inbox">${inbox.map((i) => {
        let s: { dueDate?: string; cvss?: number | null; kev?: boolean } = {};
        try {
          s = JSON.parse(i.signals_json ?? "{}") as typeof s;
        } catch {
          s = {};
        }
        return html`<li class="tcard inbox-card ${i.kind}">
          <div class="k"><span>${i.source_name}</span><span>${relativeTime(i.published_at, now)}</span></div>
          <b>${i.url ? html`<a href="${i.url}" ${newTabIf(i.url)}>${i.title}</a>` : i.title}</b>
          <div class="chips">${i.kind === "kev" || s.kev ? html`<span class="chip kev">KEV${s.dueDate ? html` · due ${s.dueDate}` : ""}</span>` : ""}${typeof s.cvss === "number" ? html`<span class="chip">CVSS ${s.cvss.toFixed(1)}</span>` : ""}${i.kind === "release" ? html`<span class="chip">release</span>` : ""}</div>
          ${owner ? triageButtons({ kind: "item", id: i.id }, null, "/triage", { compact: true }) : ""}
        </li>`;
      })}</ul>`
    : html`<p class="small">Nothing waiting. New KEV entries, notable CVEs and standard releases land here until you place them.</p>`}`;

  const content = html`
    <div class="wire-top">
      <h1>Triage</h1>
      <div class="small">${owner ? html`<a href="/triage.csv">Download CSV</a> · ` : ""}${counts.affects} affect us · ${counts.reviewing} reviewing · ${counts.done} done</div>
    </div>
    <p class="lede">Where each thing sits on your desk. The inbox is what arrived and has not been placed; the owner moves things with the buttons and adds notes on each item's own page.</p>
    ${notice ? html`<div class="notice ok">${notice}</div>` : ""}
    <div class="board">
      <section class="tcol new"><h2>Inbox <span class="count">${inbox.length}</span></h2>${inboxList}${(byState.get("new") ?? []).length ? html`<h3 class="small">Placed as new</h3><ul class="tcards">${(byState.get("new") ?? []).map((c) => card(c, owner, now))}</ul>` : ""}</section>
      ${column("reviewing")}
      ${column("affects")}
      ${column("done", (byState.get("dismissed") ?? []).length ? html`<p class="small">${counts.dismissed} marked not ours, kept out of the way.</p>` : html``)}
    </div>`;

  return page({ title: "Triage", active: "triage", content, meta: html`${counts.affects + counts.reviewing} open`, owner, open, look });
}
