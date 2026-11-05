-- Which platforms each CVE affects, one row a pair, kept by triggers from vulns.platforms_json
-- (src/platforms.ts decides them). The Vulnerabilities page now opens on "what is affecting
-- Windows, Apple, Linux, the browsers…", which is a count per platform on every view; read
-- through `platforms_json LIKE '%"windows"%'` that was a scan of all 46,000 rows each, 12 ms a
-- platform. Here it is an index.
CREATE TABLE vuln_platforms (
  vuln_id  INTEGER NOT NULL REFERENCES vulns(id) ON DELETE CASCADE,
  platform TEXT NOT NULL,
  PRIMARY KEY (platform, vuln_id)
) WITHOUT ROWID;
CREATE INDEX vuln_platforms_by_vuln ON vuln_platforms (vuln_id);

INSERT OR IGNORE INTO vuln_platforms (vuln_id, platform)
  SELECT v.id, j.value FROM vulns v, json_each(v.platforms_json) j
   WHERE v.platforms_json IS NOT NULL AND json_valid(v.platforms_json) AND j.type = 'text';

CREATE TRIGGER vulns_platforms_insert AFTER INSERT ON vulns
  WHEN NEW.platforms_json IS NOT NULL AND json_valid(NEW.platforms_json) BEGIN
  INSERT OR IGNORE INTO vuln_platforms (vuln_id, platform) SELECT NEW.id, value FROM json_each(NEW.platforms_json) WHERE type = 'text';
END;
CREATE TRIGGER vulns_platforms_update AFTER UPDATE OF platforms_json ON vulns
  WHEN OLD.platforms_json IS NOT NEW.platforms_json BEGIN
  DELETE FROM vuln_platforms WHERE vuln_id = NEW.id;
  INSERT OR IGNORE INTO vuln_platforms (vuln_id, platform)
    SELECT NEW.id, value FROM json_each(CASE WHEN json_valid(NEW.platforms_json) THEN NEW.platforms_json ELSE '[]' END) WHERE type = 'text';
END;
CREATE TRIGGER vulns_platforms_delete AFTER DELETE ON vulns BEGIN
  DELETE FROM vuln_platforms WHERE vuln_id = OLD.id;
END;

-- And a correction made the same day: a CVE whose CPE names some other product was being filed
-- by its description too, so a Ray flaw "exploitable via Firefox" counted as a browser's. The
-- rule is fixed in src/platforms.ts; these rows are cleared and recomputed at the next start
-- (recomputePlatforms), and the trigger above keeps vuln_platforms in step.
UPDATE vulns SET platforms_json = NULL
 WHERE platforms_json IS NOT NULL AND platforms_json <> '[]'
   AND ((cpes_json IS NOT NULL AND json_valid(cpes_json) AND json_array_length(cpes_json) > 0)
     OR (vendors_json IS NOT NULL AND json_valid(vendors_json) AND json_array_length(vendors_json) > 0));
