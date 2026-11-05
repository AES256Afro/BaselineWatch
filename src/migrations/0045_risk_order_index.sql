-- The audit of 28 October: the table's default order (KEV, then a public exploit, then EPSS, then
-- CVSS) asked `EXISTS (SELECT 1 FROM exploits ...)` of every row, which no index can serve, so a
-- deep page — `/vulnerabilities?offset=20000`, the API, the MCP tool, the CSV — walked all 46,000
-- CVEs and sorted them in a temporary tree: 270 ms at offset 20,000 and 340 ms at 40,000, and
-- node:sqlite is synchronous, so the whole server waited that long. The exploit is now a column
-- kept by triggers, and one index serves the whole order: 0.3 ms at any depth.
ALTER TABLE vulns ADD COLUMN has_exploit INTEGER NOT NULL DEFAULT 0 CHECK (has_exploit IN (0, 1));
UPDATE vulns SET has_exploit = 1 WHERE cve_id IN (SELECT cve_id FROM exploits);

CREATE TRIGGER exploits_mark_vuln AFTER INSERT ON exploits BEGIN
  UPDATE vulns SET has_exploit = 1 WHERE cve_id = NEW.cve_id AND has_exploit = 0;
END;
CREATE TRIGGER exploits_unmark_vuln AFTER DELETE ON exploits BEGIN
  UPDATE vulns SET has_exploit = EXISTS (SELECT 1 FROM exploits e WHERE e.cve_id = OLD.cve_id) WHERE cve_id = OLD.cve_id;
END;
-- A CVE whose exploit arrived before NVD published it.
CREATE TRIGGER vulns_mark_exploit AFTER INSERT ON vulns BEGIN
  UPDATE vulns SET has_exploit = 1 WHERE id = NEW.id AND EXISTS (SELECT 1 FROM exploits e WHERE e.cve_id = NEW.cve_id);
END;

CREATE INDEX vulns_risk ON vulns (kev DESC, has_exploit DESC, COALESCE(epss, 0) DESC, COALESCE(cvss_score, 0) DESC, last_modified_at DESC);
-- `NULLS LAST` cannot use vulns_score or vulns_epss; the same order written as a leading
-- IS NULL term can, with these. 276 ms to 0.3 ms at offset 20,000.
CREATE INDEX vulns_cvss_order ON vulns ((cvss_score IS NULL), cvss_score DESC, last_modified_at DESC);
CREATE INDEX vulns_epss_order ON vulns ((epss IS NULL), epss DESC, last_modified_at DESC);

-- The News, the feeds and the API order by when a story was published, or fetched when it says
-- nothing: an expression items_timeline cannot serve, so every page sorted all 7,000 items.
CREATE INDEX items_timeline_effective ON items (COALESCE(published_at, fetched_at) DESC, id DESC);
