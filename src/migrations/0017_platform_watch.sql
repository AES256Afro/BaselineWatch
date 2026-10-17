-- M9.5: a watchlist entry may name a platform (windows, apple, linux, android, chrome, firefox,
-- edge, network), so every CVE on that platform is the person's stack.
CREATE TABLE watchlist_new (
  id         INTEGER PRIMARY KEY,
  kind       TEXT NOT NULL CHECK (kind IN ('product', 'baseline', 'family', 'keyword', 'package', 'platform')),
  value      TEXT NOT NULL,
  label      TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (kind, value)
);
INSERT INTO watchlist_new (id, kind, value, label, created_at) SELECT id, kind, value, label, created_at FROM watchlist;
DROP TABLE watchlist;
ALTER TABLE watchlist_new RENAME TO watchlist;
