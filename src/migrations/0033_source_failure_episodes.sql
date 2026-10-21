-- When a source started failing, and whether that episode has been alerted (M13.2). The status
-- column says a source is failing now; it never said since when, so nothing could tell a feed
-- that 403s for an hour from a key that has been invalid for three days — the NVD lesson.
-- failing_since is set on the first failure after a success and cleared the moment one succeeds;
-- failing_alerted_at marks the one notification per episode, so a stuck source is not a daily nag.
ALTER TABLE sources ADD COLUMN failing_since TEXT;
ALTER TABLE sources ADD COLUMN failing_alerted_at TEXT;
