


import { isPlatformChoice } from "../platforms.ts";
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
    const platform = str(req.query.platform);
    const scope = { platform: isPlatformChoice(platform) ? platform : undefined, danger: str(req.query.danger) === "1" };
    res.type("html").send(renderToday({ db, ...who(req, res), now: now(), hours, scope }));
  });
  // Today's remedy rows end in a verb, so they end in a button: one update done is every CVE it
  // clears marked done, which is the same triage row the board and the CVE page write.
  app.post("/today/done", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    // Read whole, never cut: a list cut at a length can end in a shorter id that is another CVE.
    // The body parser's own limit (16 kB) bounds it; a cumulative update clears a few hundred.
    const raw = typeof body.cves === "string" ? body.cves : "";
    const ids = raw
      .split(",")
      .map((c) => c.trim().toUpperCase())
      .filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c));
    if (ids.length === 0) return res.status(400).type("text").send("A list of CVE ids is needed.");
    const at = now().toISOString();
    const find = db.prepare("SELECT id FROM vulns WHERE cve_id = ?");
    db.exec("BEGIN");
    try {
      for (const cveId of ids) {
        const row = find.get(cveId) as { id: number } | undefined;
        if (row) setTriage(db, { kind: "vuln", id: row.id }, { state: "done" }, at);
      }
      db.exec("COMMIT");
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
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
