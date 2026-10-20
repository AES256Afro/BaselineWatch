-- Licence-restricted sources. A publisher whose terms forbid showing its content to third parties
-- can still be tracked: the signed-in owner sees a restricted source's entries (requirement names
-- and text) on the Register as for any other source; a visitor sees its versions, counts and
-- change counts and nothing more; the JSON API and the MCP tools return neither names nor text
-- to anyone. Everything keys off this column; no code path names a source.
ALTER TABLE sources ADD COLUMN restricted INTEGER NOT NULL DEFAULT 0 CHECK (restricted IN (0, 1));

-- The OpenPhish canary set: the Community Feed's terms forbid display to third parties, so its
-- entries are owner-only. It stays off until the owner turns it on from the Sources page.
UPDATE sources SET restricted = 1,
  notes = 'Twelve phishing hosts derived from the OpenPhish Community Feed (refreshed every twelve hours) the same way as the malware canaries: registrable names only, the twelve that hash lowest; each entry keeps the origin alone, never a path. OpenPhish''s terms forbid showing any part of the feed to third parties, so this source is restricted: the signed-in owner sees the names, a visitor sees the versions and counts only, and the API and MCP tools return neither. Registered off until the owner turns it on from the Sources page.'
WHERE id = 'canary-phishing';

-- A release item written before the switch existed names the entries that came and went; the
-- owner-only rule applies to it too.
UPDATE items SET summary = 'Entries withheld under the publisher''s licence; the owner sees them on the Register.'
WHERE kind = 'release' AND source_id IN (SELECT id FROM sources WHERE restricted = 1)
  AND (summary LIKE 'Added: %' OR summary LIKE 'Revised: %' OR summary LIKE 'Removed: %');
