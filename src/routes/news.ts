import { parseCookies } from "../auth.ts";
import type { Request, Response } from "express";


import { renderNews } from "../pages/wire.ts";
import { getBlob } from "../blobs.ts";

import { imageFor } from "../images.ts";

import { safeBack } from "../paths.ts";

import { markAllRead, setRead, setStarred } from "../wire.ts";
import { str, wireFilters } from "./query.ts";
import { type RouteContext } from "./context.ts";

/**
 * News: the home timeline, its images, and the read and star marks. Mounted by createApp in app.ts, which hands over the
 * app, the config, the database, the clock and the helpers every route shares.
 */
/** The News leaves AI stories out for a browser carrying this cookie. */
const aiCookie = "bw_ai";

export function mountNews(r: RouteContext): void {
  const { app, config, db, now, who, requireOwner, secureCookies } = r;
  // News is home; the Register (the old home) lives at /register; /wire stays good as an alias.
  app.get("/", (req, res) => {
    const filters = wireFilters(req.query as Record<string, unknown>);
    // AI stories come in unless this browser said otherwise; `ai=show` or `ai=hide` on a link wins over the cookie.
    const asked = str((req.query as Record<string, unknown>).ai);
    filters.hideAi = asked === "hide" ? true : asked === "show" ? false : parseCookies(req.headers.cookie)[aiCookie] === "hide";
    res.type("html").send(renderNews({ db, filters, ...who(req, res), now: now() }));
  });
  // The reader's choice to leave AI out of the News, per browser like the look: one cookie, a year long.
  app.post("/news/ai", (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const hide = body.ai === "hide";
    const attributes = `Path=/; HttpOnly; SameSite=Lax${secureCookies(req) ? "; Secure" : ""}`;
    res.setHeader("Set-Cookie", hide ? `${aiCookie}=hide; ${attributes}; Max-Age=${365 * 24 * 60 * 60}` : `${aiCookie}=; ${attributes}; Max-Age=0`);
    res.redirect(303, safeBack(body.back, "/"));
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
    // The hash is the content: an ETag of it spares Express hashing the whole image on every request.
    res.setHeader("ETag", `"${image.sha256}"`);
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
