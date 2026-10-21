import type { Request, Response } from "express";


import { cisAdapter, cisKey } from "../adapters/cis.ts";

import { boundaryOf, parseMultipart } from "../multipart.ts";
import { authState } from "../auth.ts";
import { flashHeader, flashText, takeFlash } from "../flash.ts";

import { httpGet } from "../http.ts";
import { getSource, ingestSource, setSourceEnabled, storeUploadedDocument, type IngestResult } from "../ingest.ts";

import { renderAppearance } from "../pages/appearance.ts";

import { renderSources } from "../pages/sources.ts";

import { renderDigest } from "../pages/digest.ts";

import { renderTriage } from "../pages/triage.ts";

import { renderWatchlist } from "../pages/watchlist.ts";

import { applyBrandMark, clearBrandImage, isBrandKind, maxBrandBytes, readBrand, saveBrandImage } from "../branding.ts";
import { renderBranding } from "../pages/branding.ts";

import { safeBack } from "../paths.ts";
import { productVersion } from "../version.ts";
import { pullSettings } from "../ingest.ts";
import { isPlatformKey, platformKeys } from "../platforms.ts";
import { parsePackageValue, recomputeWatchHits } from "../vulns.ts";
import { writeDigest } from "../digest.ts";
import { notify, parseNotifyUrl } from "../notify.ts";

import { checkLatestRelease } from "../pipeline.ts";
import { clearTriage, isTriageState, setTriage, triageCsv, type TriageKind } from "../triage.ts";

import { str } from "./query.ts";
import { type RouteContext } from "./context.ts";

/**
 * The Desk: the owner's watchlist, triage, digest, uploads, sources, branding and appearance. Mounted by createApp in app.ts, which hands over the
 * app, the config, the database, the clock and the helpers every route shares.
 */
export function mountDesk(r: RouteContext): void {
  const { app, config, db, now, ctx, lookOf, who, requireOwner, secureCookies, brandMarks } = r;
  app.get("/appearance", (req, res) => {
    const state = authState(req, config, now().getTime());
    res.type("html").send(renderAppearance({ owner: state.owner, open: state.open, look: lookOf(req) }));
  });

  app.get("/watchlist", (req, res) => {
    res.type("html").send(renderWatchlist({ db, ...who(req, res), notice: flashText(req, res, secureCookies(req)) }));
  });
  app.post("/watchlist", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const kind = str(body.kind);
    const value = str(body.value);
    const label = str(body.label, 60) ?? null;
    if (!kind || !["product", "keyword", "baseline", "family", "package", "platform"].includes(kind) || !value) {
      return res.status(400).type("text").send("A kind and a value are needed.");
    }
    if (kind === "package" && !parsePackageValue(value)) {
      return res.status(400).type("text").send("A package is written ecosystem:name, such as npm:express or PyPI:django.");
    }
    if (kind === "platform" && !isPlatformKey(value.toLowerCase())) {
      return res.status(400).type("text").send(`A platform is one of ${platformKeys.join(", ")}.`);
    }
    db.prepare("INSERT OR IGNORE INTO watchlist (kind, value, label, created_at) VALUES (?, ?, ?, ?)").run(kind, kind === "platform" ? value.toLowerCase() : value, label, now().toISOString());
    const changed = recomputeWatchHits(db);
    res.append("Set-Cookie", flashHeader(`Added ${value}; ${changed} CVE(s) re-marked.`, secureCookies(req)));
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
    res.type("html").send(renderTriage({ db, ...who(req, res), now: now(), notice: flashText(req, res, secureCookies(req)), dismissed: str(req.query.dismissed) === "1" }));
  });
  app.get("/triage.csv", requireOwner, (_req, res) => {
    res.setHeader("Content-Disposition", 'attachment; filename="baselinewatch-triage.csv"');
    res.type("text/csv").send(triageCsv(db));
  });
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
    if (due && !/^\d{4}-\d{2}-\d{2}$/.test(due)) return res.status(400).type("text").send("The due date must be YYYY-MM-DD.");
    setTriage(db, subject, { state, note, dueAt: due }, now().toISOString());
    res.redirect(303, safeBack(body.back, "/triage"));
  });
  app.post("/triage/clear", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const subject = triageSubject(body);
    if (subject) clearTriage(db, subject);
    res.redirect(303, safeBack(body.back, "/triage"));
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
    res.type("html").send(renderSources({ db, ...who(req, res), notice }));
  });
  // Turning a source on or off: the scheduler reads the flag on its next pass; what was loaded stays.
  const setEnabled = (enabled: boolean) => (req: Request, res: Response) => {
    const source = getSource(db, String(req.params.id));
    if (!source) return res.status(404).type("text").send("No such source.");
    setSourceEnabled(db, source.id, enabled);
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

  app.post("/sources/:id/enable", requireOwner, setEnabled(true));
  app.post("/sources/:id/disable", requireOwner, setEnabled(false));
  app.post("/sources/:id/fetch", requireOwner, async (req, res) => {
    const source = getSource(db, String(req.params.id));
    if (!source) return res.status(404).type("text").send("No such source.");
    const result: IngestResult = await ingestSource(db, config.dataDir, source, {
      now,
      settings: pullSettings(config),
      log: (line) => console.log(line),
      transport: parseNotifyUrl(config.notifyUrl),
      baseUrl: config.baseUrl,
      ...(ctx.http ? { http: ctx.http } : {}),
    });
    const detail = result.status === "ok" ? (result.detail ?? `${result.items} items, ${result.inserted} new, ${result.updated} changed`) : (result.error ?? result.status);
    res.append("Set-Cookie", flashHeader({ sourceId: source.id, status: result.status, detail }, secureCookies(req)));
    res.redirect(303, `/sources#src-${source.id}`);
  });
}
