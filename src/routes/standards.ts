import { policyScope } from "../adapters/sct.ts";



import { authState } from "../auth.ts";
import { flashText } from "../flash.ts";

import { renderCatalog } from "../pages/catalog.ts";
import { renderControls } from "../pages/controls.ts";
import { renderHome } from "../pages/home.ts";
import { renderLearn } from "../pages/learn.ts";

import { renderBrowse, renderControl, renderRelease, renderStandard } from "../pages/register.ts";

import { renderStigPlatform, renderStigsIndex } from "../pages/stigs.ts";

import { isPlatformId, type Cat } from "../stigs.ts";

import { str } from "./query.ts";
import { releaseChangesCsv } from "../api.ts";
import { getSource } from "../ingest.ts";
import { getDocument } from "../register.ts";
import { safeFilename } from "../paths.ts";
import { type RouteContext } from "./context.ts";

/**
 * Standards: the Register, Controls, every standard's pages, the STIGs and Learn. Mounted by createApp in app.ts, which hands over the
 * app, the config, the database, the clock and the helpers every route shares.
 */
export function mountStandards(r: RouteContext): void {
  const { app, config, db, now, ctx, lookOf, who, secureCookies } = r;
  app.get("/register", (req, res) => {
    const { owner, look } = who(req, res);
    res.type("html").send(renderHome({ config, db, migrations: ctx.migrations, owner, look, now: now() }));
  });

  // The ladder's third rung (/guide#ladder): one rule at a time, across every standard's current version.
  app.get("/controls", (req, res) => {
    const state = authState(req, config, now().getTime());
    const q = typeof req.query.q === "string" ? req.query.q.slice(0, 200) : undefined;
    res.type("html").send(renderControls({ db, q, now: now(), owner: state.owner, open: state.open, look: lookOf(req) }));
  });

  // Where every rule comes from (M17): the chain from law to setting, and every publisher on it.
  app.get("/learn", (req, res) => {
    res.type("html").send(renderLearn({ db, ...who(req, res), now: now(), sector: str(req.query.sector, 20), rung: str(req.query.rung, 20) }));
  });

  app.get("/standards", (req, res) => {
    res.type("html").send(renderCatalog({ db, ...who(req, res), now: now() }));
  });
  app.get("/standards/:source", (req, res, next) => {
    const html = renderStandard({ db, sourceId: String(req.params.source), ...who(req, res), now: now(), notice: flashText(req, res, secureCookies(req)) });
    if (!html) return next();
    res.type("html").send(html);
  });
  app.get("/standards/:source/:doc", (req, res, next) => {
    const documentId = Number(req.params.doc);
    if (!Number.isInteger(documentId) || documentId <= 0) return next();
    const html = renderRelease({ db, sourceId: String(req.params.source), documentId, family: str(req.query.family, 40), ...who(req, res), now: now() });
    if (!html) return next();
    res.type("html").send(html);
  });
  // A release's changes as a file, for a ticket or a spreadsheet: public-domain sources only. A
  // restricted source's entries and the owner's licensed copies (CIS, Microsoft) never leave as a
  // file, to anyone (AGENTS.md), so the answer for those is a refusal, not an empty file.
  app.get("/standards/:source/:doc/changes.csv", (req, res, next) => {
    const documentId = Number(req.params.doc);
    if (!Number.isInteger(documentId) || documentId <= 0) return next();
    const source = getSource(db, String(req.params.source));
    const doc = source ? getDocument(db, documentId) : null;
    if (!source || !doc || doc.source_id !== source.id) return next();
    const csv = releaseChangesCsv(db, source, documentId, config.baseUrl);
    if (csv === null) return res.status(403).type("text").send(`${source.name} is licensed or restricted: its entries are shown on the page and never exported.`);
    res.setHeader("Content-Disposition", `attachment; filename="${safeFilename(`baselinewatch-${source.id}-${doc.version_label ?? documentId}-changes.csv`)}"`);
    res.type("text/csv; charset=utf-8").send(csv);
  });
  app.get("/standards/:source/:doc/browse", (req, res, next) => {
    const documentId = Number(req.params.doc);
    if (!Number.isInteger(documentId) || documentId <= 0) return next();
    const html = renderBrowse({ db, sourceId: String(req.params.source), documentId, q: str(req.query.q, 100), family: str(req.query.family, 40), ...who(req, res) });
    if (!html) return next();
    res.type("html").send(html);
  });
  app.get("/standards/:source/:doc/:ref", (req, res, next) => {
    const documentId = Number(req.params.doc);
    if (!Number.isInteger(documentId) || documentId <= 0) return next();
    const sourceId = String(req.params.source);
    const ref = String(req.params.ref).toLowerCase();
    const html = renderControl({ db, sourceId, documentId, ref, ...who(req, res), now: now() });
    if (html) return void res.type("html").send(html);
    // A Microsoft baseline setting's address named its release until 0061 ("windows 11 25h2 -
    // computer|…"); an old link is sent on to the setting it named.
    if (sourceId === "microsoft-sct") {
      const [head = "", ...tail] = ref.split("|");
      const moved = [policyScope(head).toLowerCase(), ...tail].join("|");
      if (moved !== ref && db.prepare("SELECT 1 FROM requirements WHERE document_id = ? AND ref = ?").get(documentId, moved)) {
        return res.redirect(301, `/standards/${sourceId}/${documentId}/${encodeURIComponent(moved)}`);
      }
    }
    next();
  });

  app.get("/stigs", (req, res) => {
    res.type("html").send(renderStigsIndex({ db, ...who(req, res), now: now() }));
  });
  app.get("/stigs/:platform", (req, res, next) => {
    const platform = String(req.params.platform);
    if (!isPlatformId(platform)) return next();
    const catParam = str(req.query.cat, 3);
    const cat: Cat | undefined = catParam === "1" ? "CAT I" : catParam === "2" ? "CAT II" : catParam === "3" ? "CAT III" : undefined;
    res.type("html").send(renderStigPlatform({ db, platform, stigKey: str(req.query.stig, 120), cat, ...who(req, res), now: now() }));
  });
}
