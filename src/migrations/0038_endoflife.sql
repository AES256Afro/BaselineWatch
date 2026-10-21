-- endoflife.date (added 2026-10-21, N5): the support and end-of-life dates of the releases the
-- fleet runs, read from the one public source that keeps them for every vendor, so the Fleet page
-- shows the vendor's date beside the owner's and the Wire says when a release is about to run out.
CREATE TABLE eol_cycles (
  product             TEXT NOT NULL,              -- endoflife.date's product slug: windows, macos, ubuntu
  cycle               TEXT NOT NULL,              -- its cycle id: '11-24h2-w', '27', '24.04'
  label               TEXT,                       -- releaseLabel or codename, as published
  release_date        TEXT,
  eol                 TEXT NOT NULL,              -- a date, or 'false' (not yet) / 'true' (already, undated)
  support             TEXT,                       -- a date, or 'false' / 'true', or NULL when the product has no such phase
  latest              TEXT,
  latest_release_date TEXT,
  lts                 INTEGER NOT NULL DEFAULT 0,
  link                TEXT,
  seen_at             TEXT NOT NULL,
  PRIMARY KEY (product, cycle)
);

INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('endoflife', 'endoflife.date', 'listing', 'news', 'https://endoflife.date/api/', 'json', 'daily', 1, 'MIT (the data, endoflife.date on GitHub)', 'endoflife.date', 'Support and end-of-life dates for the products the fleet runs (Windows, macOS, iOS, iPadOS, Android, RHEL, Ubuntu), one small JSON file each, read daily. The Fleet page shows them beside the owner''s dates; a release within ninety days of its end, or past it within the month, is one Wire item.');
