import { renderLogin } from "../pages/login.ts";
import type { Request, Response } from "express";


import { cisAdapter, cisKey } from "../adapters/cis.ts";

import { boundaryOf, parseMultipart } from "../multipart.ts";
import { authState } from "../auth.ts";
import { flashHeader, flashText, takeFlash } from "../flash.ts";

import { httpGet } from "../http.ts";
import { getSource, ingestSource, setSourceEnabled, storeUploadedDocument, type IngestResult } from "../ingest.ts";

import { renderAppearance } from "../pages/appearance.ts";

import { renderSourceProbe, renderSources } from "../pages/sources.ts";
import { addSource, logSourceChange, probeFeed, readNewSource, sourceWithUrl } from "../newsource.ts";
import { adoptFallback, useRepair } from "../repairs.ts";

import { renderDigest } from "../pages/digest.ts";
import { renderVisitors } from "../pages/visitors.ts";
import { visitReport, visitWindows } from "../visits.ts";

import { renderTriage } from "../pages/triage.ts";

import { renderWatchlist } from "../pages/watchlist.ts";
import { renderSaved } from "../pages/saved.ts";
import { addSaved, deleteSaved, openSaved, savablePath } from "../saved.ts";

import { applyBrandMark, clearBrandImage, isBrandKind, maxBrandBytes, readBrand, saveBrandImage, saveBrandText } from "../branding.ts";
import { renderBranding } from "../pages/branding.ts";

import { safeBack } from "../paths.ts";
import { readSbom } from "../sbom.ts";
import { productVersion } from "../version.ts";
import { pullSettings } from "../ingest.ts";
import { isPlatformKey, platformKeys } from "../platforms.ts";
import { parsePackageValue, recomputeWatchHits } from "../vulns.ts";
import { writeDigest } from "../digest.ts";
import { notify, parseNotifyUrl } from "../notify.ts";

import { checkLatestRelease } from "../pipeline.ts";
import { clearTriage, dismissBacklog, inboxCutoff, isTriageState, setTriage, triageBacklogCount, triageCsv, undoBacklog, type TriageKind } from "../triage.ts";

import { str } from "./query.ts";
import { requirementIn } from "../register.ts";
import { type RouteContext } from "./context.ts";
import { counted } from "../words.ts";

/**
 * The Desk: the owner's watchlist, triage, digest, uploads, sources, branding and appearance. Mounted by createApp in app.ts, which hands over the
 * app, the config, the database, the clock and the helpers every route shares.
 */
export function mountDesk(r: RouteContext): void {
  const { app, config, db, now, ctx, lookOf, who, requireOwner, secureCookies, brandMarks } = r;
  app.get("/appearance", (req, res) => {
    const state = authState(req, config, now().getTime());
    res.type("html").send(renderAppearance({ owner: state.owner, open: state.open, look: lookOf(req), defaultLook: config.look }));
  });

  // The watchlist says what the owner runs, which is exactly what a visitor should not learn: the
  // page is the owner's, and a visitor is sent to sign in. The table's platform cards are what
  // everyone else reads instead.
  app.get("/watchlist", (req, res) => {
    if (res.locals.owner !== true) return res.status(401).type("html").send(renderLogin({ next: "/watchlist", open: false, look: lookOf(req) }));
    res.type("html").send(renderWatchlist({ db, ...who(req, res), notice: flashText(req, res, secureCookies(req)) }));
  });
  app.post("/watchlist", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const kind = str(body.kind);
    // One entry a line: a list pasted from an inventory goes in at once. A single value is the one-line case.
    const raw = typeof body.value === "string" ? body.value : "";
    const values = [...new Set(raw.split(/\r?\n/).map((line) => str(line)).filter((v): v is string => v !== undefined))];
    const label = str(body.label, 60) ?? null;
    if (!kind || !["product", "keyword", "baseline", "family", "package", "platform"].includes(kind) || values.length === 0) {
      return res.status(400).type("text").send("A kind and a value are needed.");
    }
    if (values.length > 200) return res.status(400).type("text").send("Two hundred entries at a time at most.");
    for (const value of values) {
      if (kind === "package" && !parsePackageValue(value)) {
        return res.status(400).type("text").send(`A package is written ecosystem:name, such as npm:express or PyPI:django; "${value}" is not.`);
      }
      if (kind === "platform" && !isPlatformKey(value.toLowerCase())) {
        return res.status(400).type("text").send(`A platform is one of ${platformKeys.join(", ")}.`);
      }
    }
    const insert = db.prepare("INSERT OR IGNORE INTO watchlist (kind, value, label, created_at) VALUES (?, ?, ?, ?)");
    const at = now().toISOString();
    let added = 0;
    for (const value of values) added += Number(insert.run(kind, kind === "platform" ? value.toLowerCase() : value, label, at).changes);
    const changed = added ? recomputeWatchHits(db) : 0;
    const what = values.length === 1 ? values[0] : counted(added, "entry", "entries");
    res.append("Set-Cookie", flashHeader(`Added ${what}; ${counted(changed, "CVE")} re-marked.`, secureCookies(req)));
    // The CVE page's Watch buttons come back to the CVE; the form on /watchlist comes back to the list.
    res.redirect(303, safeBack(body.back, "/watchlist"));
  });
  // An SBOM's components as package entries, by file: the one upload the watchlist takes.
  // Saved searches: a named path with its query, kept on the desk.
  app.get("/saved", (req, res) => {
    res.type("html").send(renderSaved({ db, ...who(req, res), now: now(), notice: flashText(req, res, secureCookies(req)) }));
  });
  app.post("/saved", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const path = savablePath(body.path);
    const name = str(body.name, 60);
    if (!path || !name) return res.status(400).type("text").send("A saved search is a name and a list page with its filters.");
    const added = addSaved(db, name, path, now().toISOString());
    res.append("Set-Cookie", flashHeader(added ? `Saved “${name}”.` : "That list was already saved.", secureCookies(req)));
    res.redirect(303, path);
  });
  // Opening a saved search through here keeps the time, so "new since last opened" starts again.
  // A GET that only moves the owner's own timestamp; a visitor is sent to sign in.
  app.get("/saved/:id/open", requireOwner, (req, res) => {
    const id = Number(req.params.id);
    const path = Number.isInteger(id) ? openSaved(db, id, now().toISOString()) : null;
    if (!path) return res.status(404).type("text").send("No such saved search.");
    res.setHeader("Cache-Control", "no-store");
    res.redirect(303, path);
  });
  app.post("/saved/:id/delete", requireOwner, (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || !deleteSaved(db, id)) return res.status(404).type("text").send("No such saved search.");
    res.redirect(303, "/saved");
  });
  app.post("/watchlist/sbom", requireOwner, async (req, res) => {
    const boundary = boundaryOf(req.headers["content-type"]);
    if (!boundary) return res.status(400).type("text").send("Send the SBOM as multipart/form-data.");
    const chunks: Buffer[] = [];
    let size = 0;
    const limit = 16 * 1024 * 1024;
    try {
      for await (const chunk of req.iterator({ destroyOnReturn: false })) {
        size += (chunk as Buffer).length;
        if (size > limit) {
          res.status(413).type("text").send("That file is larger than 16 MB.");
          return;
        }
        chunks.push(chunk as Buffer);
      }
    } catch {
      return res.status(400).type("text").send("The upload did not complete.");
    }
    const form = parseMultipart(Buffer.concat(chunks), boundary);
    const file = form.files.find((f) => f.field === "sbom") ?? form.files[0];
    if (!file || file.bytes.length === 0) return res.status(400).type("text").send("No SBOM was attached.");
    let reading;
    try {
      reading = readSbom(new TextDecoder("utf-8").decode(file.bytes));
    } catch (error) {
      return res.status(400).type("text").send(error instanceof Error ? error.message : "That file could not be read.");
    }
    const label = (reading.name ?? file.filename.replace(/\.[^.]+$/, "")).slice(0, 60) || null;
    const insert = db.prepare("INSERT OR IGNORE INTO watchlist (kind, value, label, created_at) VALUES ('package', ?, ?, ?)");
    let added = 0;
    const at = now().toISOString();
    for (const p of reading.packages) added += Number(insert.run(p.value, label, at).changes);
    const changed = added ? recomputeWatchHits(db) : 0;
    res.append("Set-Cookie", flashHeader(`Imported ${counted(added, "package")} from ${label ?? "the SBOM"} (${reading.packages.length - added} already listed, ${counted(reading.skipped, "component")} without a package URL an advisory feed covers); ${counted(changed, "CVE")} re-marked.`, secureCookies(req)));
    res.redirect(303, "/watchlist");
  });
  app.post("/watchlist/:id/delete", requireOwner, (req, res) => {
    const id = Number(req.params.id);
    if (Number.isInteger(id) && id > 0) {
      db.prepare("DELETE FROM watchlist WHERE id = ?").run(id);
      recomputeWatchHits(db);
    }
    res.redirect(303, "/watchlist");
  });

  app.get("/triage", (req, res) => {
    const offset = Number(str(req.query.offset, 9) ?? 0);
    const viewer = who(req, res);
    res.type("html").send(
      renderTriage({
        db,
        ...viewer,
        now: now(),
        notice: flashText(req, res, secureCookies(req)),
        dismissed: str(req.query.dismissed) === "1",
        offset: Number.isInteger(offset) && offset > 0 ? offset : 0,
        confirmBacklog: viewer.owner && str(req.query.confirm) === "older",
      }),
    );
  });
  app.get("/triage.csv", requireOwner, (_req, res) => {
    res.setHeader("Content-Disposition", 'attachment; filename="baselinewatch-triage.csv"');
    res.type("text/csv").send(triageCsv(db));
  });
  // 2026-02-31 matches the pattern and Date rolls it into March; only a day that reads back as itself is one.
  const isCalendarDay = (day: string): boolean => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return false;
    const parsed = new Date(`${day}T00:00:00Z`);
    return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === day;
  };
  const triageSubject = (body: Record<string, unknown>): { kind: TriageKind; id: number; key: string } | null => {
    const kind = str(body.kind);
    const id = Number(str(body.id));
    if ((kind !== "item" && kind !== "vuln" && kind !== "control") || !Number.isInteger(id) || id <= 0) return null;
    return { kind, id, key: str(body.key, 200) ?? "" };
  };
  app.post("/triage", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const subject = triageSubject(body);
    const state = str(body.state);
    if (!subject || !isTriageState(state)) return res.status(400).type("text").send("A subject and a state are needed.");
    const note = body.note === undefined ? undefined : (str(body.note, 2000) ?? null);
    const due = body.due === undefined ? undefined : (str(body.due, 10) ?? null);
    if (due && !isCalendarDay(due)) return res.status(400).type("text").send("The due date must be a real day, YYYY-MM-DD.");
    // A control is placed by its release and ref; one the release does not hold would be a card for nothing.
    if (subject.kind === "control" && !requirementIn(db, subject.id, subject.key)) return res.status(400).type("text").send("No such control in that release.");
    // Nor is a CVE or an item this instance has no row for: a phantom card linked /vulnerabilities/null.
    if (subject.kind === "vuln" && !db.prepare("SELECT 1 FROM vulns WHERE id = ?").get(subject.id)) return res.status(400).type("text").send("No such CVE.");
    if (subject.kind === "item" && !db.prepare("SELECT 1 FROM items WHERE id = ?").get(subject.id)) return res.status(400).type("text").send("No such item.");
    setTriage(db, subject, { state, note, dueAt: due }, now().toISOString());
    res.redirect(303, safeBack(body.back, "/triage"));
  });
  // The backlog in one action: what waits from before the inbox's window and is not watched, marked not ours.
  app.post("/triage/dismiss-older", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    // One click asks; the confirming form, which shows the count, carries confirm=1.
    if (str(body.confirm) !== "1") return res.redirect(303, "/triage?confirm=older#backlog");
    const before = str(body.before, 10);
    if (!before || !/^\d{4}-\d{2}-\d{2}$/.test(before) || Number.isNaN(Date.parse(before))) return res.status(400).type("text").send("A date, YYYY-MM-DD, is needed.");
    // No later than the inbox's own window: the button names that date, and a typed later one would sweep the inbox itself.
    const cutoff = inboxCutoff(now()).slice(0, 10);
    const day = before < cutoff ? before : cutoff;
    // The form names a count; if the backlog has moved since it was drawn (new items, another tab),
    // what would be marked is not what was confirmed, so ask again with the count as it is now.
    const shown = Number(str(body.count, 9));
    if (Number.isInteger(shown) && shown >= 0 && shown !== triageBacklogCount(db, now(), `${day}T00:00:00.000Z`)) {
      res.append("Set-Cookie", flashHeader("The backlog changed since that count was shown; nothing was marked. Check the new count and confirm again.", secureCookies(req)));
      return res.redirect(303, "/triage?confirm=older#backlog");
    }
    if (!Number.isInteger(shown)) return res.status(400).type("text").send("The confirming form's count is needed.");
    const marked = dismissBacklog(db, `${day}T00:00:00.000Z`, now().toISOString());
    res.append("Set-Cookie", flashHeader(`Marked ${counted(marked, "item")} from before ${day} not ours. The inbox has an undo for the next day.`, secureCookies(req)));
    res.redirect(303, "/triage");
  });
  // The last bulk dismissal taken back, within its day: rows the owner has touched since stay.
  app.post("/triage/undo-dismiss", requireOwner, (req, res) => {
    const restored = undoBacklog(db, now());
    res.append("Set-Cookie", flashHeader(restored ? `${counted(restored, "item")} back in the backlog.` : "Nothing to undo: the last bulk dismissal is more than a day old or already undone.", secureCookies(req)));
    res.redirect(303, "/triage");
  });
  app.post("/triage/clear", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const subject = triageSubject(body);
    if (subject) clearTriage(db, subject);
    res.redirect(303, safeBack(body.back, "/triage"));
  });

  // Who reads the site (src/visits.ts): the owner's alone, like the triage board.
  app.get("/visitors", requireOwner, (req, res) => {
    const days = visitWindows.find((d) => String(d) === str(req.query.days)) ?? 7;
    const asked = str(req.query.host, 100)?.toLowerCase();
    const host = asked && /^[a-z0-9.-]+$/.test(asked) ? asked : null;
    const at = now();
    res.type("html").send(renderVisitors({ report: visitReport(db, { now: at, timeZone: config.timeZone, days, host }), now: at, timeZone: config.timeZone, counting: config.visits, ...who(req, res) }));
  });

  app.get("/digest", (req, res) => {
    res.type("html").send(renderDigest({ db, ...who(req, res), now: now(), period: config.digest, hour: config.digestHour, timeZone: config.timeZone, notifyConfigured: parseNotifyUrl(config.notifyUrl) !== null, baseUrl: config.baseUrl }));
  });
  app.post("/digest/run", requireOwner, async (_req, res) => {
    const period = config.digest === "off" ? "daily" : config.digest;
    const row = writeDigest(db, { now: now(), baseUrl: config.baseUrl, period });
    await notify(db, parseNotifyUrl(config.notifyUrl), { kind: "digest", title: `BaselineWatch ${period} digest`, body: row.text.slice(0, 3500), url: `${config.baseUrl}/digest` }, ctx.http, now);
    res.redirect(303, "/digest");
  });

  // CIS Benchmarks come in by hand: the owner uploads the PDF, the Register diffs it against the last upload of the same benchmark.
  app.post("/uploads/cis", requireOwner, async (req, res) => {
    const boundary = boundaryOf(req.headers["content-type"]);
    if (!boundary) return res.status(400).type("text").send("Send the PDF as multipart/form-data.");
    const chunks: Buffer[] = [];
    let size = 0;
    const limit = 60 * 1024 * 1024;
    try {
      // Leaving the loop early must not destroy the socket, or the 413 never reaches the browser.
      for await (const chunk of req.iterator({ destroyOnReturn: false })) {
        size += (chunk as Buffer).length;
        if (size > limit) {
          res.status(413).type("text").send("That file is larger than 60 MB.");
          return;
        }
        chunks.push(chunk as Buffer);
      }
    } catch {
      return res.status(400).type("text").send("The upload did not complete.");
    }
    const form = parseMultipart(Buffer.concat(chunks), boundary);
    const file = form.files.find((f) => f.field === "pdf") ?? form.files[0];
    if (!file || file.bytes.length === 0) return res.status(400).type("text").send("No PDF was attached.");
    const source = getSource(db, "cis-benchmarks");
    if (!source) return res.status(500).type("text").send("The CIS source is missing from the database.");
    const versionLabel = str(form.fields.version, 40) ?? null;
    const publishedAt = str(form.fields.published, 10);
    const outcome = await storeUploadedDocument(db, config.dataDir, source, cisAdapter, file.bytes, {
      filename: file.filename,
      keyFor: (title) => cisKey(title, file.filename),
      versionLabel,
      publishedAt: publishedAt && /^\d{4}-\d{2}-\d{2}$/.test(publishedAt) ? `${publishedAt}T00:00:00.000Z` : null,
      now,
    });
    if (outcome.status === "error") return res.status(422).type("text").send(`Could not read that benchmark: ${outcome.error}`);
    const notice = outcome.status === "unchanged" ? `${file.filename} was already loaded.` : `${file.filename} loaded as ${outcome.key} ${outcome.versionLabel ?? ""}: ${outcome.summary}`;
    res.append("Set-Cookie", flashHeader(notice, secureCookies(req)));
    res.redirect(303, "/standards/cis-benchmarks");
  });

  app.get("/sources", (req, res) => {
    // The outcome of a Fetch now, or of a Turn on or Turn off, rides over in the flash cookie, never in the query string, so no link can forge one.
    const flash = takeFlash(req, res, secureCookies(req)) as { sourceId?: unknown; status?: unknown; detail?: unknown } | undefined;
    const notice =
      flash && typeof flash.sourceId === "string" && typeof flash.status === "string"
        ? { sourceId: flash.sourceId.slice(0, 80), status: flash.status.slice(0, 20), detail: typeof flash.detail === "string" ? flash.detail.slice(0, 1200) : "" }
        : null;
    res.type("html").send(renderSources({ db, ...who(req, res), notice, now: now() }));
  });
  // Turning a source on or off: the scheduler reads the flag on its next pass; what was loaded stays.
  const setEnabled = (enabled: boolean) => (req: Request, res: Response) => {
    const source = getSource(db, String(req.params.id));
    if (!source) return res.status(404).type("text").send("No such source.");
    setSourceEnabled(db, source.id, enabled);
    if (Boolean(source.enabled) !== enabled) logSourceChange(db, source.id, now().toISOString(), enabled ? "enabled" : "disabled", null, null);
    const detail = enabled ? `checked ${source.schedule} from the scheduler's next pass; Fetch now runs it at once` : "no longer fetched; what was loaded stays on the Register";
    res.append("Set-Cookie", flashHeader({ sourceId: source.id, status: enabled ? "enabled" : "disabled", detail }, secureCookies(req)));
    res.redirect(303, `/sources#src-${source.id}`);
  };
  // Branding (the Desk): the owner picks one of the repo's marks or uploads an image, and every
  // page wears it at once. The bytes go to the blob store; app_settings carries hash and type.
  app.get("/branding", (req, res) => {
    res.type("html").send(renderBranding({ brand: readBrand(db), marks: brandMarks, ...who(req, res), notice: flashText(req, res, secureCookies(req)) }));
  });
  app.get("/branding/marks/:id", (req, res, next) => {
    const mark = brandMarks.find((m) => m.id === String(req.params.id));
    if (!mark) return next();
    res.setHeader("Cache-Control", "public, max-age=86400");
    res.type("image/svg+xml").send(Buffer.from(mark.bytes));
  });
  // Before /branding/:kind, which would read "text" as an image kind and pass it on.
  app.post("/branding/text", requireOwner, (req, res) => {
    saveBrandText(db, (req.body ?? {}) as Record<string, unknown>, now().toISOString());
    res.append("Set-Cookie", flashHeader("Wording saved; every page uses it now.", secureCookies(req)));
    res.redirect(303, "/branding#wording");
  });
  app.post("/branding/mark", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const kind = str(body.kind, 10);
    const mark = brandMarks.find((m) => m.id === str(body.mark, 80));
    if (!isBrandKind(kind) || !mark) return res.status(400).type("text").send("Pick a mark and whether it is the logo or the favicon.");
    applyBrandMark(db, config.dataDir, kind, mark, now().toISOString());
    res.append("Set-Cookie", flashHeader(`${mark.title} is now the ${kind}, on every page at once.`, secureCookies(req)));
    res.redirect(303, "/branding");
  });
  app.post("/branding/:kind", requireOwner, async (req, res, next) => {
    const kind = String(req.params.kind);
    if (!isBrandKind(kind)) return next();
    const boundary = boundaryOf(req.headers["content-type"]);
    if (!boundary) return res.status(400).type("text").send("Send the image as multipart/form-data.");
    const chunks: Buffer[] = [];
    let size = 0;
    // The image plus the form's own framing; what the file itself may hold is branding.ts's call.
    const limit = maxBrandBytes + 16 * 1024;
    try {
      // Leaving the loop early must not destroy the socket, or the 413 never reaches the browser.
      for await (const chunk of req.iterator({ destroyOnReturn: false })) {
        size += (chunk as Buffer).length;
        if (size > limit) {
          res.status(413).type("text").send("That file is larger than 2 MB.");
          return;
        }
        chunks.push(chunk as Buffer);
      }
    } catch {
      return res.status(400).type("text").send("The upload did not complete.");
    }
    const form = parseMultipart(Buffer.concat(chunks), boundary);
    const file = form.files.find((f) => f.field === "image") ?? form.files[0];
    if (!file || file.bytes.length === 0) return res.status(400).type("text").send("No image was attached.");
    const outcome = saveBrandImage(db, config.dataDir, kind, file.bytes, now().toISOString());
    if (!outcome.ok) return res.status(422).type("text").send(`Could not use ${file.filename}: ${outcome.error}.`);
    res.append("Set-Cookie", flashHeader(`${file.filename} is now the ${kind}, on every page at once.`, secureCookies(req)));
    res.redirect(303, "/branding");
  });
  app.post("/branding/:kind/remove", requireOwner, (req, res, next) => {
    const kind = String(req.params.kind);
    if (!isBrandKind(kind)) return next();
    clearBrandImage(db, kind);
    res.append("Set-Cookie", flashHeader(kind === "logo" ? "The logo is removed; the masthead carries the wordmark alone." : "The favicon is removed.", secureCookies(req)));
    res.redirect(303, "/branding");
  });

  // The one request this product makes about itself, and only when the owner asks for it (M13.2).
  app.post("/sources/check-version", requireOwner, async (req, res) => {
    const result = await checkLatestRelease(db, ctx.http ?? httpGet, now());
    res.append(
      "Set-Cookie",
      flashHeader(
        {
          sourceId: "this instance",
          status: result.version ? "ok" : "error",
          detail: result.version
            ? result.newer
              ? `${result.version} is published; this instance runs ${productVersion}`
              : `${productVersion} is the newest release`
            : "GitHub did not answer with a version",
        },
        secureCookies(req),
      ),
    );
    res.redirect(303, "/sources#storage");
  });

  // Adding a source (M20.2): the probe shows what the feed holds before anything is saved, and
  // the add probes again rather than trusting the form, then fetches once so its entries arrive now.
  const ingestDeps = () => ({
    now,
    settings: pullSettings(config),
    log: (line: string) => console.log(line),
    transport: parseNotifyUrl(config.notifyUrl),
    baseUrl: config.baseUrl,
    ...(ctx.http ? { http: ctx.http } : {}),
  });
  app.post("/sources/probe", requireOwner, async (req, res) => {
    const input = readNewSource((req.body ?? {}) as Record<string, unknown>);
    if (typeof input === "string") return res.status(400).type("html").send(renderSourceProbe({ ...who(req, res), input: null, probe: { ok: false, error: input }, duplicate: null }));
    const duplicate = sourceWithUrl(db, input.url);
    const probe = duplicate ? null : await probeFeed(ctx.http ?? httpGet, input.url);
    res.status(probe && !probe.ok ? 422 : 200).type("html").send(renderSourceProbe({ ...who(req, res), input, probe, duplicate }));
  });
  app.post("/sources/add", requireOwner, async (req, res) => {
    const input = readNewSource((req.body ?? {}) as Record<string, unknown>);
    if (typeof input === "string") return res.status(400).type("html").send(renderSourceProbe({ ...who(req, res), input: null, probe: { ok: false, error: input }, duplicate: null }));
    const duplicate = sourceWithUrl(db, input.url);
    if (duplicate) return res.status(409).type("html").send(renderSourceProbe({ ...who(req, res), input, probe: null, duplicate }));
    const probe = await probeFeed(ctx.http ?? httpGet, input.url);
    if (!probe.ok) return res.status(422).type("html").send(renderSourceProbe({ ...who(req, res), input, probe, duplicate: null }));
    const id = addSource(db, input, probe.feed, now().toISOString());
    const result = await ingestSource(db, config.dataDir, getSource(db, id)!, ingestDeps());
    const detail = result.status === "error" ? `added, but its first fetch failed: ${result.error ?? "error"}` : `added; ${result.items} entries, ${result.inserted} new on the News`;
    res.append("Set-Cookie", flashHeader({ sourceId: id, status: result.status === "error" ? "error" : "added", detail }, secureCookies(req)));
    res.redirect(303, `/sources#src-${id}`);
  });
  // Repairs (M20.3): the owner's click on a proposal, or on the fallback that has been answering.
  const afterMove = async (req: Request, res: Response, sourceId: string, url: string) => {
    const result = await ingestSource(db, config.dataDir, getSource(db, sourceId)!, ingestDeps());
    const detail = `now read from ${url}; ${result.status === "error" ? `its first fetch failed: ${result.error ?? "error"}` : `${result.items} entries`}`;
    res.append("Set-Cookie", flashHeader({ sourceId, status: result.status, detail }, secureCookies(req)));
    res.redirect(303, `/sources#src-${sourceId}`);
  };
  app.post("/sources/:id/repairs/:repair/use", requireOwner, async (req, res) => {
    const source = getSource(db, String(req.params.id));
    if (!source) return res.status(404).type("text").send("No such source.");
    const repair = useRepair(db, source, Number(req.params.repair), now().toISOString());
    if (!repair) return res.status(404).type("text").send("That repair is no longer proposed; the source may have answered again.");
    await afterMove(req, res, source.id, repair.url);
  });
  app.post("/sources/:id/adopt-fallback", requireOwner, async (req, res) => {
    const source = getSource(db, String(req.params.id));
    if (!source) return res.status(404).type("text").send("No such source.");
    const url = adoptFallback(db, source, now().toISOString());
    if (!url) return res.status(409).type("text").send("No fallback is answering for this source.");
    await afterMove(req, res, source.id, url);
  });

  app.post("/sources/:id/enable", requireOwner, setEnabled(true));
  app.post("/sources/:id/disable", requireOwner, setEnabled(false));
  app.post("/sources/:id/fetch", requireOwner, async (req, res) => {
    const source = getSource(db, String(req.params.id));
    if (!source) return res.status(404).type("text").send("No such source.");
    const result: IngestResult = await ingestSource(db, config.dataDir, source, ingestDeps());
    const detail = result.status === "ok" ? (result.detail ?? `${result.items} items, ${result.inserted} new, ${result.updated} changed`) : (result.error ?? result.status);
    res.append("Set-Cookie", flashHeader({ sourceId: source.id, status: result.status, detail }, secureCookies(req)));
    res.redirect(303, `/sources#src-${source.id}`);
  });
}
