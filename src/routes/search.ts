import { cveIdPattern, cweOf, getVuln } from "../vulns.ts";
import { renderSearch } from "../pages/search.ts";
import { type RouteContext } from "./context.ts";
import { str } from "./query.ts";

/**
 * Search: the masthead's one box. A CVE id typed whole goes straight to its page, and a weakness
 * id (CWE-79) to the Vulnerabilities table filtered by it, which holds every CVE NVD files under
 * it where a text search finds only the descriptions that spell it out; anything else is the page
 * of sections. Mounted by createApp in app.ts.
 */
export function mountSearch(r: RouteContext): void {
  const { app, db, now, who } = r;
  app.get("/search", (req, res) => {
    const q = str((req.query as Record<string, unknown>).q, 120);
    const cwe = q && /^\s*cwe-?\d{1,5}\s*$/i.test(q) ? cweOf(q) : undefined;
    if (cwe) return res.redirect(302, `/vulnerabilities?cwe=${encodeURIComponent(cwe)}`);
    if (q && cveIdPattern.test(q) && getVuln(db, q.toUpperCase())) return res.redirect(302, `/vulnerabilities/${q.toUpperCase()}`);
    res.type("html").send(renderSearch({ db, q, ...who(req, res), now: now() }));
  });
}
