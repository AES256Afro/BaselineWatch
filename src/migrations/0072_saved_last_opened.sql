-- When the owner last opened each saved search (added 2026-11-16): Today and /saved count what
-- the list holds now and how much of it arrived since then. Null until the search is first opened
-- through /saved/<id>/open; until then everything the list holds counts as new.
ALTER TABLE saved_searches ADD COLUMN last_opened_at TEXT;
