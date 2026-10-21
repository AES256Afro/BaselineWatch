


import { renderPatchTuesday } from "../pages/patch-tuesday.ts";
import { renderVulnDetail, renderVulnList } from "../pages/vulnerabilities.ts";

import { str, vulnFilters } from "./query.ts";
import { type RouteContext } from "./context.ts";

/**
 * Vulnerabilities: the table and the CVE page. Mounted by createApp in app.ts, which hands over the
 * app, the config, the database, the clock and the helpers every route shares.
 */
export function mountVulnerabilities(r: RouteContext): void {
  const { app, db, now, who } = r;
  app.get("/vulnerabilities", (req, res) => {
    res.type("html").send(renderVulnList({ db, filters: vulnFilters(req.query as Record<string, unknown>, now()), ...who(req, res), now: now() }));
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
