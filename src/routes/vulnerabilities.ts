import type { Request, Response } from "express";



import { cveIdPattern } from "../vulns.ts";
import { patchTuesdayCsv, renderPatchTuesday, type PatchTuesdayOptions } from "../pages/patch-tuesday.ts";
import { renderVulnDetail, renderVulnNotHeld, renderVulnList } from "../pages/vulnerabilities.ts";

import { safeFilename } from "../paths.ts";
import { vulnsCsv } from "../vulns.ts";
import { ignoredVulnParams, str, vulnFilters } from "./query.ts";
import { type RouteContext } from "./context.ts";

/**
 * Vulnerabilities: the table and the CVE page. Mounted by createApp in app.ts, which hands over the
 * app, the config, the database, the clock and the helpers every route shares.
 */
export function mountVulnerabilities(r: RouteContext): void {
  const { app, config, db, now, who } = r;
  app.get("/vulnerabilities", (req, res) => {
    const owner = res.locals.owner === true;
    const filters = vulnFilters(req.query as Record<string, unknown>, now(), owner);
    res.type("html").send(renderVulnList({ db, filters, ...who(req, res), now: now(), ignored: ignoredVulnParams(req.query as Record<string, unknown>, filters, owner) }));
  });
  // The table as a CSV, under the same filters and in the same order as the page. Registered
  // before /vulnerabilities/:cve, which would otherwise see "vulnerabilities.csv" as a CVE id and
  // hand it on; it falls through anyway, but ordering says the intent.
  app.get("/vulnerabilities.csv", (req, res) => {
    const filters = vulnFilters(req.query as Record<string, unknown>, now(), res.locals.owner === true);
    res.setHeader("Content-Disposition", `attachment; filename="${safeFilename(`baselinewatch-cves-${now().toISOString().slice(0, 10)}.csv`)}"`);
    res.setHeader("Cache-Control", "no-store");
    res.type("text/csv; charset=utf-8").send(vulnsCsv(db, { ...filters, limit: 1000 }, config.baseUrl, res.locals.owner === true));
  });
  // Patch Tuesday and its CVE table as a CSV, read from the same query: release, component,
  // search, the republished rows, the fleet's releases and the page.
  const patchOptions = (req: Request, res: Response): PatchTuesdayOptions | undefined => {
    const query = req.query as Record<string, unknown>;
    const release = str(query.release, 12);
    if (release !== undefined && !/^\d{4}-[A-Z][a-z]{2}$/.test(release)) return undefined;
    const pageNo = Number(str(query.page, 6) ?? "1");
    return { db, releaseId: release, family: str(query.family, 80), q: str(query.q, 100), all: str(query.all) === "1", fleet: str(query.fleet) === "1", page: Number.isFinite(pageNo) ? pageNo : 1, ...who(req, res), now: now() };
  };
  app.get("/vulnerabilities/microsoft", (req, res, next) => {
    const options = patchOptions(req, res);
    const html = options && renderPatchTuesday(options);
    if (!html) return next();
    res.type("html").send(html);
  });
  app.get("/vulnerabilities/microsoft.csv", (req, res, next) => {
    const options = patchOptions(req, res);
    const csv = options && patchTuesdayCsv(options, config.baseUrl);
    if (!csv) return next();
    res.setHeader("Content-Disposition", `attachment; filename="${safeFilename(`baselinewatch-patch-tuesday-${options.releaseId ?? "latest"}.csv`)}"`);
    res.setHeader("Cache-Control", "no-store");
    res.type("text/csv; charset=utf-8").send(csv);
  });
  app.get("/vulnerabilities/:cve", (req, res, next) => {
    const cveId = String(req.params.cve).toUpperCase();
    if (!cveIdPattern.test(cveId)) return next();
    const html = renderVulnDetail({ db, cveId, ...who(req, res), now: now() });
    if (html) return void res.type("html").send(html);
    // A well-formed id with no row is a question with an answer elsewhere, not a missing page.
    const { owner, open, look } = who(req, res);
    res.status(404).type("html").send(renderVulnNotHeld({ db, cveId, owner, open, look }));
  });
}
