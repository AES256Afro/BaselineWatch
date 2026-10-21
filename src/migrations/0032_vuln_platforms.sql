-- The platform a CVE affects (src/platforms.ts: windows, apple, linux, android, chrome, firefox,
-- edge, network), derived from its CPEs, then the vendor and product names, then the description.
-- It was computed on every page that needed it; Today groups the window's CVEs by it and the
-- Vulnerabilities table filters on it, so it is stored at upsert and backfilled once at start.
ALTER TABLE vulns ADD COLUMN platforms_json TEXT;
