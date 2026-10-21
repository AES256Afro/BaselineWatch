import { renderSearch } from "../pages/search.ts";
import { getVuln } from "../vulns.ts";
import { type RouteContext } from "./context.ts";
import { str } from "./query.ts";

/**
 * Search: the masthead's one box. A CVE id typed whole goes straight to its page; anything else
 * is the page of sections. Mounted by createApp in app.ts.
 */
export function mountSearch(r: RouteContext): void {
  const { app, db, now, who } = r;
  app.get("/search", (req, res) => {
    const q = str((req.query as Record<string, unknown>).q, 120);
    if (q && /^CVE-\d{4}-\d{4,7}$/i.test(q) && getVuln(db, q.toUpperCase())) return res.redirect(302, `/vulnerabilities/${q.toUpperCase()}`);
    res.type("html").send(renderSearch({ db, q, ...who(req, res), now: now() }));
  });
}
