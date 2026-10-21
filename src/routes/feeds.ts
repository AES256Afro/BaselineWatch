import type { Response } from "express";
import { kevCalendar, opmlDocument, sitemapDocument, vulnFeed, wireFeed } from "../feeds.ts";
import { renderFeeds } from "../pages/feeds.ts";
import { type RouteContext } from "./context.ts";
import { vulnFilters, wireFilters } from "./query.ts";

/**
 * Feeds: the News and the Vulnerabilities table as RSS, the sources as OPML, KEV due dates as a
 * calendar, the sitemap, and the page that lists them. Mounted by createApp in app.ts, which hands
 * over the app, the config, the database, the clock and the helpers every route shares.
 * robots.txt is in app.ts, ahead of the reading gate, because a closed instance must still answer it.
 */
export function mountFeeds(r: RouteContext): void {
  const { app, config, db, now, who } = r;
  const send = (res: Response, type: string, body: string): void => {
    res.setHeader("Content-Type", type);
    res.setHeader("Cache-Control", "public, max-age=300");
    res.send(body);
  };
  const self = (path: string): string => `${config.baseUrl}${path}`;
  app.get("/feed.xml", (req, res) => send(res, "application/rss+xml; charset=utf-8", wireFeed(db, config.baseUrl, wireFilters(req.query as Record<string, unknown>), self(req.originalUrl))));
  app.get("/vulnerabilities/feed.xml", (req, res) => send(res, "application/rss+xml; charset=utf-8", vulnFeed(db, config.baseUrl, vulnFilters(req.query as Record<string, unknown>, now()), self(req.originalUrl))));
  app.get("/sources.opml", (_req, res) => send(res, "text/x-opml; charset=utf-8", opmlDocument(db, config.baseUrl)));
  app.get("/vulnerabilities/kev.ics", (req, res) => {
    res.setHeader("Content-Disposition", 'inline; filename="kev.ics"');
    send(res, "text/calendar; charset=utf-8", kevCalendar(db, config.baseUrl, { watch: String((req.query as Record<string, unknown>).watch ?? "") === "1", now: now() }));
  });
  app.get("/sitemap.xml", (_req, res) => send(res, "application/xml; charset=utf-8", sitemapDocument(db, config.baseUrl)));
  app.get("/feeds", (req, res) => {
    res.type("html").send(renderFeeds({ baseUrl: config.baseUrl, ...who(req, res) }));
  });
}
