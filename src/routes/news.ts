import type { Request, Response } from "express";


import { renderNews } from "../pages/wire.ts";
import { getBlob } from "../blobs.ts";

import { imageFor } from "../images.ts";

import { safeBack } from "../paths.ts";

import { markAllRead, setRead, setStarred } from "../wire.ts";
import { wireFilters } from "./query.ts";
import { type RouteContext } from "./context.ts";

/**
 * News: the home timeline, its images, and the read and star marks. Mounted by createApp in app.ts, which hands over the
 * app, the config, the database, the clock and the helpers every route shares.
 */
export function mountNews(r: RouteContext): void {
  const { app, config, db, now, who, requireOwner } = r;
  // News is home; the Register (the old home) lives at /register; /wire stays good as an alias.
  app.get("/", (req, res) => {
    res.type("html").send(renderNews({ db, filters: wireFilters(req.query as Record<string, unknown>), ...who(req, res), now: now() }));
  });
  app.get("/wire", (req, res) => {
    const at = req.originalUrl.indexOf("?");
    res.redirect(301, at === -1 ? "/" : `/${req.originalUrl.slice(at)}`);
  });
  // Cached article images, served only by a hash some item carries, so snapshots stay private.
  app.get("/img/:hash", (req, res, next) => {
    const image = imageFor(db, String(req.params.hash));
    if (!image) return next();
    const bytes = getBlob(config.dataDir, image.sha256);
    if (!bytes) return next();
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    res.type(image.type).send(bytes);
  });

  const itemAction = (action: "read" | "unread" | "star" | "unstar") => (req: Request, res: Response) => {
    const id = Number(req.params.id);
    const back = safeBack(((req.body ?? {}) as Record<string, unknown>).back, "/");
    if (!Number.isInteger(id) || id <= 0) return res.status(404).type("text").send("No such item.");
    const ok = action === "read" || action === "unread" ? setRead(db, id, action === "read") : setStarred(db, id, action === "star");
    if (!ok) return res.status(404).type("text").send("No such item.");
    res.redirect(303, back);
  };
  app.post("/items/:id/read", requireOwner, itemAction("read"));
  app.post("/items/:id/unread", requireOwner, itemAction("unread"));
  app.post("/items/:id/star", requireOwner, itemAction("star"));
  app.post("/items/:id/unstar", requireOwner, itemAction("unstar"));
  app.post("/wire/read-all", requireOwner, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    markAllRead(db, wireFilters(body));
    res.redirect(303, safeBack(body.back, "/"));
  });
}
