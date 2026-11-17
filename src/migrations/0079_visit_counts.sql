-- Most of what reads a public site is not a person (2026-11-17: on cybercard.net and the name
-- routed beside it, nineteen in twenty requests were AI and search crawlers walking the
-- Vulnerabilities list's filters). `visits` keeps a row for a person's page view; everything else
-- is a count per day here, keyed by what the Visitors page shows of it, with the path kept only
-- for a 404. Text keys are '' rather than NULL so that one day's requests meet in one row.
CREATE TABLE visit_counts (
  day TEXT NOT NULL,
  host TEXT NOT NULL,
  path TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL CHECK (kind IN ('page', 'feed', 'api')),
  status INTEGER NOT NULL,
  agent TEXT NOT NULL CHECK (agent IN ('person', 'assistant', 'crawler', 'reader', 'tool', 'unknown')),
  agent_name TEXT NOT NULL DEFAULT '',
  country TEXT NOT NULL DEFAULT '',
  network TEXT NOT NULL DEFAULT '',
  network_confirmed INTEGER NOT NULL DEFAULT 0,
  requests INTEGER NOT NULL,
  last_at TEXT NOT NULL,
  PRIMARY KEY (day, host, path, kind, status, agent, agent_name, country, network, network_confirmed)
) WITHOUT ROWID;

-- Rows 0.57.0 kept one by one for what was not a person's page view become counts.
INSERT INTO visit_counts (day, host, path, kind, status, agent, agent_name, country, network, network_confirmed, requests, last_at)
SELECT day, host, CASE WHEN status = 404 THEN path ELSE '' END, kind, status, agent, COALESCE(agent_name, ''), COALESCE(country, ''),
       COALESCE(network, ''), network_confirmed, COUNT(*), MAX(at)
FROM visits
WHERE NOT (agent = 'person' AND kind = 'page' AND status <> 404)
GROUP BY day, host, CASE WHEN status = 404 THEN path ELSE '' END, kind, status, agent, COALESCE(agent_name, ''), COALESCE(country, ''), COALESCE(network, ''), network_confirmed;
DELETE FROM visits WHERE NOT (agent = 'person' AND kind = 'page' AND status <> 404);
