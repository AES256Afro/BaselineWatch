-- Visits (src/visits.ts): one row per page, feed or API answer this instance gave anyone but its
-- owner, counted on the server. No address is kept: `visitor` is a hash of the address and the
-- browser under the day's salt, and a day's salt is deleted when the next day's is made, so a hash
-- cannot be traced back once its day is over. `network` is the domain the address's reverse DNS
-- names, `network_confirmed` whether that name resolves back to the address. The weekly
-- housekeeping pass deletes rows past their window (Retention.visitDays).
CREATE TABLE visits (
  id INTEGER PRIMARY KEY,
  at TEXT NOT NULL,
  day TEXT NOT NULL,
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('page', 'feed', 'api')),
  status INTEGER NOT NULL,
  visitor TEXT NOT NULL,
  agent TEXT NOT NULL CHECK (agent IN ('person', 'assistant', 'crawler', 'reader', 'tool', 'unknown')),
  agent_name TEXT,
  os TEXT,
  device TEXT,
  country TEXT,
  referrer TEXT,
  network TEXT,
  network_confirmed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX visits_day ON visits (day, agent);
CREATE INDEX visits_at ON visits (at);

CREATE TABLE visit_salts (
  day TEXT PRIMARY KEY,
  salt TEXT NOT NULL
);
