


import { renderPatchTuesday } from "../pages/patch-tuesday.ts";
import { renderVulnDetail, renderVulnList } from "../pages/vulnerabilities.ts";

import { safeFilename } from "../paths.ts";
import { vulnsCsv } from "../vulns.ts";
import { str, vulnFilters } from "./query.ts";
import { type RouteContext } from "./context.ts";

/**
 * Vulnerabilities: the table and the CVE page. Mounted by createApp in app.ts, which hands over the
 * app, the config, the database, the clock and the helpers every route shares.
 */
export function mountVulnerabilities(r: RouteContext): void {
  const { app, config, db, now, who } = r;
  app.get("/vulnerabilities", (req, res) => {
    res.type("html").send(renderVulnList({ db, filters: vulnFilters(req.query as Record<string, unknown>, now()), ...who(req, res), now: now() }));
  });
  // The table as a CSV, under the same filters and in the same order as the page. Registered
  // before /vulnerabilities/:cve, which would otherwise see "vulnerabilities.csv" as a CVE id and
  // hand it on; it falls through anyway, but ordering says the intent.
  app.get("/vulnerabilities.csv", (req, res) => {
    const filters = vulnFilters(req.query as Record<string, unknown>, now());
    res.setHeader("Content-Disposition", `attachment; filename="${safeFilename(`baselinewatch-cves-${now().toISOString().slice(0, 10)}.csv`)}"`);
    res.setHeader("Cache-Control", "no-store");
    res.type("text/csv; charset=utf-8").send(vulnsCsv(db, { ...filters, limit: 1000 }, config.baseUrl));
  });
  app.get("/vulnerabilities/microsoft", (req, res, next) => {
    const query = req.query as Record<string, unknown>;
    const release = str(query.release, 12);
    if (release !== undefined && !/^\d{4}-[A-Z][a-z]{2}$/.test(release)) return next();
    const html = renderPatchTuesday({ db, releaseId: release, family: str(query.family, 80), q: str(query.q, 100), all: str(query.all) === "1", ...who(req, res), now: now() });
    if (!html) return next();
    res.type("html").send(html);
  });
  app.get("/vulnerabilities/:cve", (req, res, next) => {
    const cveId = String(req.params.cve).toUpperCase();
    if (!/^CVE-\d{4}-\d{4,7}$/.test(cveId)) return next();
    const html = renderVulnDetail({ db, cveId, ...who(req, res), now: now() });
    if (!html) return next();
    res.type("html").send(html);
  });
}
