-- EPSS crossing 50% as an armed state (bug sweep 3a). A crossing was a score at or over 50% whose
-- previous day's score was below 40%, so a gradual rise (35%, 45%, 55%) never counted. Now a
-- score at or over 50% marks the CVE with the time it got there, the mark is cleared when the score
-- falls below 40%, and a crossing is a score reaching 50% from below while no mark is held: once
-- per rise, however gradual, and not again while it hovers. applyEpss in src/vulns.ts keeps it.
ALTER TABLE vulns ADD COLUMN epss_crossed_at TEXT;
-- A score already at or over 50% has been there; whether it was news then is history.
UPDATE vulns SET epss_crossed_at = COALESCE(epss_date, '1970-01-01') WHERE epss >= 0.5;
