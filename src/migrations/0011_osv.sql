-- Package advisories from OSV.dev (which carries the GitHub Advisory Database): affected packages
-- and advisory ids on a CVE, a watchlist kind for packages, and the source (checked 2026-10-15).

ALTER TABLE vulns ADD COLUMN packages_json TEXT;   -- [{"ecosystem":"PyPI","name":"pyjwt","fixed":["2.14.0"],"introduced":["0"],"advisory":"GHSA-..."}]
ALTER TABLE vulns ADD COLUMN aliases_json TEXT;    -- ["GHSA-2gx3-rcp4-g85q", "PYSEC-2026-4140"]

-- SQLite cannot widen a CHECK constraint in place: rebuild the watchlist with the new kind.
CREATE TABLE watchlist_new (
  id         INTEGER PRIMARY KEY,
  kind       TEXT NOT NULL CHECK (kind IN ('product', 'baseline', 'family', 'keyword', 'package')),
  value      TEXT NOT NULL,
  label      TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (kind, value)
);
INSERT INTO watchlist_new (id, kind, value, label, created_at) SELECT id, kind, value, label, created_at FROM watchlist;
DROP TABLE watchlist;
ALTER TABLE watchlist_new RENAME TO watchlist;

INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('osv', 'OSV (package advisories)', 'vulnerability', 'vulnerabilities', 'https://api.osv.dev/v1/query', 'json', 'daily', 1, 'OSV data under its sources'' licences; GitHub Advisory Database CC-BY 4.0', 'Package advisory data from OSV.dev, including the GitHub Advisory Database (CC-BY 4.0).', 'Queried for each package on the watchlist (kind "package", value "ecosystem:name" such as "npm:express", "PyPI:django", "Maven:org.apache.logging.log4j:log4j-core" or "Debian:12:openssl"). An advisory is kept under its CVE id when it has one, else under its GHSA or OSV id, with the affected and fixed versions.');
