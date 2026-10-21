-- Saved searches (added 2026-10-21, N6): the lists the owner comes back to — a filtered table, a
-- News filter, a search, a Patch Tuesday component — named once and kept on the desk.
CREATE TABLE saved_searches (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  path       TEXT NOT NULL,                      -- a path on this site with its query string: '/vulnerabilities?kev=1&platform=windows'
  created_at TEXT NOT NULL,
  UNIQUE (path)
);
