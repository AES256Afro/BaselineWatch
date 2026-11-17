-- The CVEs the watchlist matches, by id. News's "watched" view and Triage ask
-- `external_id IN (SELECT cve_id FROM vulns WHERE watch_hit = 1)`, and vulns_watch leads with
-- watch_hit but orders by last_modified_at, so the id came from the table row each time. A partial
-- index holds only the watched rows (a few hundred of 46,000) and answers the question from itself.
CREATE INDEX vulns_watched ON vulns (cve_id) WHERE watch_hit = 1;
-- Fresh statistics for the planner on the two tables these migrations touch; a few hundred
-- milliseconds once, at the start that applies them.
ANALYZE vulns;
ANALYZE vuln_cwes;
