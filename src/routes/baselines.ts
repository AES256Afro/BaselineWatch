import type { NextFunction, Request, Response } from "express";


import { renderBaselinesIndex, renderBuilder } from "../pages/baselines.ts";
import { renderDecide, renderDecisionBoard } from "../pages/decisions.ts";
import { decisionsCsv, isDecisionKind, saveDecision } from "../decisions.ts";
import { renderTestPlan } from "../pages/testplans.ts";
import { renderPlatforms } from "../pages/platforms.ts";
import { buildTestPlan, exportPlan, isArea, isPlanFormat, isPlanPlatform, type PlanOptions } from "../testplans.ts";
import { buildProfile, isBuilderPlatform, isSectionId, sectionOf, type ProfileOptions } from "../baselines.ts";
import { exportProfile, isExportFormat, isFlavour, publicProfile, type Flavour } from "../exports.ts";

import { productVersion } from "../version.ts";

import { str } from "./query.ts";
import { type RouteContext } from "./context.ts";

/**
 * Baselines: the builder, decisions, test plans and their exports, and the fleet. Mounted by createApp in app.ts, which hands over the
 * app, the config, the database, the clock and the helpers every route shares.
 */
export function mountBaselines(r: RouteContext): void {
  const { app, config, db, now, who, requireOwner } = r;
  // The baseline builder: ordinary forms, nothing stored. GET draws the strict profile; POST
  // redraws it with the unticked items dropped; export answers either way, so a JSON export
  // with query fields is also an API. The page draws one section at a time: `shown` names the
  // section whose checkboxes are in the form, hidden `drop` fields carry the other sections'
  // drops, and a `section` button picks the next one to draw.
  const list = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => String(x)) : typeof v === "string" ? [v] : []);
  const profileOptions = (platform: ProfileOptions["platform"], fields: Record<string, unknown>): ProfileOptions => {
    const applied = str(fields.applied) === "1";
    const keep = applied ? new Set(list(fields.keep).slice(0, 5000)) : null;
    const drop = list(fields.drop).slice(0, 5000);
    const shown = str(fields.shown, 20);
    const options: ProfileOptions = { platform, stig: str(fields.stig, 160), sct: str(fields.sct, 160), mscp: str(fields.mscp, 160), cat3: str(fields.cat3) === "1" };
    if (keep) {
      // The form sends what is kept; the profile wants what is dropped: everything it holds that was not sent.
      const all = buildProfile(db, options).items;
      if (isSectionId(shown)) {
        // Only one section's checkboxes were drawn; the other sections' drops rode along as hidden fields.
        const carried = new Set(drop);
        options.drop = all.filter((i) => (sectionOf(i) === shown ? !keep.has(i.id) : carried.has(i.id))).map((i) => i.id);
      } else options.drop = all.filter((i) => !keep.has(i.id)).map((i) => i.id);
    } else if (drop.length) options.drop = drop;
    return options;
  };
  const flavourOf = (fields: Record<string, unknown>): Flavour => (isFlavour(fields.flavour) ? fields.flavour : "plain");
  app.get("/baselines", (req, res) => {
    res.type("html").send(renderBaselinesIndex({ db, ...who(req, res) }));
  });
  const drawBuilder = (req: Request, res: Response, next: NextFunction, fields: Record<string, unknown>): void => {
    const platform = String(req.params.platform);
    if (!isBuilderPlatform(platform)) return next();
    const profile = buildProfile(db, profileOptions(platform, fields));
    const section = str(fields.section, 20) ?? str(fields.shown, 20);
    res.type("html").send(renderBuilder({ db, profile, flavour: flavourOf(fields), section: isSectionId(section) ? section : undefined, text: str(fields.text) === "1", ...who(req, res) }));
  };
  app.get("/baselines/:platform", (req, res, next) => drawBuilder(req, res, next, req.query as Record<string, unknown>));
  app.post("/baselines/:platform", (req, res, next) => drawBuilder(req, res, next, (req.body ?? {}) as Record<string, unknown>));
  const sendExport = (req: Request, res: Response, next: NextFunction, fields: Record<string, unknown>): void => {
    const platform = String(req.params.platform);
    if (!isBuilderPlatform(platform)) return next();
    const format = isExportFormat(fields.format) ? fields.format : "json";
    const profile = buildProfile(db, profileOptions(platform, fields));
    // A reader who is not the owner takes the profile without Microsoft's values: on screen only, never in bulk.
    const out = exportProfile(who(req, res).owner ? profile : publicProfile(profile), format, flavourOf(fields), { baseUrl: config.baseUrl, generatedAt: now().toISOString(), version: productVersion });
    res.setHeader("Content-Disposition", `attachment; filename="${out.filename}"`);
    res.setHeader("Cache-Control", "no-store");
    res.type(out.contentType).send(out.body);
  };
  app.get("/baselines/:platform/export", (req, res, next) => sendExport(req, res, next, req.query as Record<string, unknown>));

  // Decisions: the owner's answer to each item's recommendation (apply, modify, exclude), stored.
  // The board lists them per platform (and as CSV); the decide page shows one item against its
  // recommendation. CAT III rules are included so a decision on one is always reachable.
  const decisionProfile = (platform: ProfileOptions["platform"], fields: Record<string, unknown>) => buildProfile(db, { platform, stig: str(fields.stig, 160), mscp: str(fields.mscp, 160), sct: str(fields.sct, 160), cat3: true });
  app.get("/baselines/:platform/decisions", (req, res, next) => {
    const platform = String(req.params.platform);
    if (!isBuilderPlatform(platform)) return next();
    const saved = Number(str(req.query.saved, 6) ?? "");
    res.type("html").send(renderDecisionBoard({ profile: decisionProfile(platform, req.query as Record<string, unknown>), ...(Number.isInteger(saved) && saved >= 0 && req.query.saved !== undefined ? { saved } : {}), ...who(req, res) }));
  });
  app.get("/baselines/:platform/decisions.csv", (req, res, next) => {
    const platform = String(req.params.platform);
    if (!isBuilderPlatform(platform)) return next();
    const profile = decisionProfile(platform, req.query as Record<string, unknown>);
    res.setHeader("Content-Disposition", `attachment; filename="baselinewatch-${platform}-decisions.csv"`);
    res.setHeader("Cache-Control", "no-store");
    // Microsoft's values are quoted on screen only: a reader who is not the owner downloads the decisions without them.
    res.type("text/csv; charset=utf-8").send(decisionsCsv(who(req, res).owner ? profile : publicProfile(profile), config.baseUrl));
  });
  app.get("/baselines/:platform/decide", (req, res, next) => {
    const platform = String(req.params.platform);
    if (!isBuilderPlatform(platform)) return next();
    const id = str(req.query.item, 300);
    const profile = decisionProfile(platform, req.query as Record<string, unknown>);
    const item = id ? profile.items.find((i) => i.id === id) : undefined;
    if (!item) return next();
    res.type("html").send(renderDecide({ profile, item, saved: str(req.query.saved) === "1", ...who(req, res) }));
  });
  app.post("/baselines/:platform/decide", requireOwner, (req, res, next) => {
    const platform = String(req.params.platform);
    if (!isBuilderPlatform(platform)) return next();
    const fields = (req.body ?? {}) as Record<string, unknown>;
    const id = str(fields.item, 300);
    const item = id ? decisionProfile(platform, fields).items.find((i) => i.id === id) : undefined;
    if (!item || !isDecisionKind(fields.decision)) return void res.status(400).type("text").send("Pick an item and a decision.");
    saveDecision(db, platform, item.id, { decision: fields.decision, value: str(fields.value, 500) ?? null, reason: str(fields.reason, 2000) ?? null, owner: str(fields.owner, 120) ?? null }, now());
    res.redirect(303, `/baselines/${platform}/decide?item=${encodeURIComponent(item.id)}&saved=1`);
  });
  // The builder's unticked items, recorded as not applying in one go, with one reason for all of them.
  app.post("/baselines/:platform/decide-unticked", requireOwner, (req, res, next) => {
    const platform = String(req.params.platform);
    if (!isBuilderPlatform(platform)) return next();
    const fields = (req.body ?? {}) as Record<string, unknown>;
    const profile = buildProfile(db, profileOptions(platform, fields));
    const reason = str(fields.reason, 2000) ?? null;
    const owner = str(fields.owner, 120) ?? null;
    let saved = 0;
    // One transaction for the whole set: all the exclusions land, or none do, and one fsync rather than hundreds.
    db.exec("BEGIN IMMEDIATE");
    try {
      for (const item of profile.items) {
        if (item.included || item.decision?.decision === "exclude") continue;
        saveDecision(db, platform, item.id, { decision: "exclude", reason, owner }, now());
        saved += 1;
      }
      db.exec("COMMIT");
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
    res.redirect(303, `/baselines/${platform}/decisions?saved=${saved}`);
  });
  app.post("/baselines/:platform/export", (req, res, next) => sendExport(req, res, next, (req.body ?? {}) as Record<string, unknown>));

  // Test plans: the same form shape over the derived checks and the owner's templates, drawn one
  // area at a time the way the builder draws one section: `shown` names the area whose checkboxes
  // are in the form, hidden `drop` fields carry the other areas' drops, `section` picks the next.
  const planOptions = (platform: PlanOptions["platform"], fields: Record<string, unknown>): PlanOptions => {
    const applied = str(fields.applied) === "1";
    const keep = applied ? new Set(list(fields.keep).slice(0, 5000)) : null;
    const drop = list(fields.drop).slice(0, 5000);
    const shown = str(fields.shown, 20);
    // The areas to test ride along as checkboxes once the form has been applied; a first GET tests every area.
    // The hidden `areas` marker says the area checkboxes were drawn, so an empty list means none; an older form or a script without it tests every area.
    const chosen = str(fields.areas) === "1" || fields.area !== undefined ? list(fields.area).filter(isArea) : undefined;
    const base: PlanOptions = { platform, stig: str(fields.stig, 160), mscp: str(fields.mscp, 160), cat3: str(fields.cat3) === "1", templates: applied ? str(fields.templates) === "1" : str(fields.templates) !== "0", version: str(fields.version, 40), hardware: str(fields.hardware, 60), areas: chosen, style: str(fields.style, 20) };
    if (keep) {
      const all = buildTestPlan(db, base).items;
      if (isArea(shown)) {
        // Only one area's checkboxes were drawn; the other areas' drops rode along as hidden fields.
        const carried = new Set(drop);
        return { ...base, drop: all.filter((i) => (i.area === shown ? !keep.has(i.id) : carried.has(i.id))).map((i) => i.id) };
      }
      return { ...base, drop: all.filter((i) => !keep.has(i.id)).map((i) => i.id) };
    }
    return drop.length ? { ...base, drop } : base;
  };
  const drawPlan = (req: Request, res: Response, next: NextFunction, fields: Record<string, unknown>): void => {
    const platform = String(req.params.platform);
    if (!isPlanPlatform(platform)) return next();
    const area = str(fields.section, 20) ?? str(fields.shown, 20);
    res.type("html").send(renderTestPlan({ db, plan: buildTestPlan(db, planOptions(platform, fields)), area: isArea(area) ? area : undefined, ...who(req, res) }));
  };
  // Renamed from Platforms to Fleet (it is the owner's own inventory, and src/fleet.ts always
  // called it that); the old address keeps working the way /wire does.
  app.get("/platforms", (_req, res) => {
    res.redirect(301, "/fleet");
  });
  app.get("/fleet", (req, res) => {
    res.type("html").send(renderPlatforms({ db, now: now(), ...who(req, res) }));
  });
  app.get("/baselines/:platform/tests", (req, res, next) => drawPlan(req, res, next, req.query as Record<string, unknown>));
  app.post("/baselines/:platform/tests", (req, res, next) => drawPlan(req, res, next, (req.body ?? {}) as Record<string, unknown>));
  const sendPlan = (req: Request, res: Response, next: NextFunction, fields: Record<string, unknown>): void => {
    const platform = String(req.params.platform);
    if (!isPlanPlatform(platform)) return next();
    const out = exportPlan(buildTestPlan(db, planOptions(platform, fields)), isPlanFormat(fields.format) ? fields.format : "json", { baseUrl: config.baseUrl, generatedAt: now().toISOString(), version: productVersion });
    res.setHeader("Content-Disposition", `attachment; filename="${out.filename}"`);
    res.setHeader("Cache-Control", "no-store");
    res.type(out.contentType).send(typeof out.body === "string" ? out.body : Buffer.from(out.body));
  };
  app.get("/baselines/:platform/tests/export", (req, res, next) => sendPlan(req, res, next, req.query as Record<string, unknown>));
  app.post("/baselines/:platform/tests/export", (req, res, next) => sendPlan(req, res, next, (req.body ?? {}) as Record<string, unknown>));
}
