


import { renderAtlas } from "../pages/atlas.ts";

import { renderGuide } from "../pages/guide.ts";

import { renderToday } from "../pages/today.ts";

import { setTriage } from "../triage.ts";
import { safeBack } from "../paths.ts";
import { str } from "./query.ts";
import { type RouteContext } from "./context.ts";

/**
 * Reading: Today, the Atlas and the guide. Mounted by createApp in app.ts, which hands over the
 * app, the config, the database, the clock and the helpers every route shares.
 */
export function mountReading(r: RouteContext): void {
  const { app, db, now, who, requireOwner } = r;
  app.get("/today", (req, res) => {
    const since = Number(str(req.query.since));
    const hours = since === 72 || since === 168 ? since : 24;
    res.type("html").send(renderToday({ db, ...who(req, res), now: now(), hours }));
  });
  // Today's remedy rows end in a verb, so they end in a button: one update done is every CVE it
  // clears marked done, which is the same triage row the board and the CVE page write.
  app.post("/today/done", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const ids = (str(body.cves, 4000) ?? "")
      .split(",")
      .map((c) => c.trim().toUpperCase())
      .filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c));
    if (ids.length === 0) return res.status(400).type("text").send("A list of CVE ids is needed.");
    const at = now().toISOString();
    for (const cveId of ids) {
      const row = db.prepare("SELECT id FROM vulns WHERE cve_id = ?").get(cveId) as { id: number } | undefined;
      if (row) setTriage(db, { kind: "vuln", id: row.id }, { state: "done" }, at);
    }
    res.redirect(303, safeBack(body.back, "/today"));
  });
  app.get("/atlas", (req, res) => {
    res.type("html").send(renderAtlas({ db, ...who(req, res), now: now() }));
  });
  app.get("/guide", (req, res) => {
    res.type("html").send(renderGuide(who(req, res)));
  });
}
