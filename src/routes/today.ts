


import { renderAtlas } from "../pages/atlas.ts";

import { renderGuide } from "../pages/guide.ts";

import { renderToday } from "../pages/today.ts";

import { str } from "./query.ts";
import { type RouteContext } from "./context.ts";

/**
 * Reading: Today, the Atlas and the guide. Mounted by createApp in app.ts, which hands over the
 * app, the config, the database, the clock and the helpers every route shares.
 */
export function mountReading(r: RouteContext): void {
  const { app, db, now, who } = r;
  app.get("/today", (req, res) => {
    const since = Number(str(req.query.since));
    const hours = since === 72 || since === 168 ? since : 24;
    res.type("html").send(renderToday({ db, ...who(req, res), now: now(), hours }));
  });
  app.get("/atlas", (req, res) => {
    res.type("html").send(renderAtlas({ db, ...who(req, res), now: now() }));
  });
  app.get("/guide", (req, res) => {
    res.type("html").send(renderGuide(who(req, res)));
  });
}
