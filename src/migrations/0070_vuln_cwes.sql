-- Which weaknesses each CVE is filed under, one row a pair, kept by triggers from vulns.cwes_json
-- (written by upsertVuln, the KEV-only insert and applyAdvisory). The `cwe=` filter on the
-- Vulnerabilities page read `EXISTS (SELECT 1 FROM json_each(v.cwes_json) ...)`, which parses the
-- JSON of every row: 465 ms cold on the public instance's copy (2026-11-16). Here it is an index.
CREATE TABLE vuln_cwes (
  cwe     TEXT NOT NULL,
  vuln_id INTEGER NOT NULL REFERENCES vulns(id) ON DELETE CASCADE,
  PRIMARY KEY (cwe, vuln_id)
) WITHOUT ROWID;
CREATE INDEX vuln_cwes_by_vuln ON vuln_cwes (vuln_id);

INSERT OR IGNORE INTO vuln_cwes (cwe, vuln_id)
  SELECT j.value, v.id FROM vulns v, json_each(v.cwes_json) j
   WHERE v.cwes_json IS NOT NULL AND json_valid(v.cwes_json) AND j.type = 'text';

CREATE TRIGGER vulns_cwes_insert AFTER INSERT ON vulns
  WHEN NEW.cwes_json IS NOT NULL AND json_valid(NEW.cwes_json) BEGIN
  INSERT OR IGNORE INTO vuln_cwes (cwe, vuln_id) SELECT value, NEW.id FROM json_each(NEW.cwes_json) WHERE type = 'text';
END;
CREATE TRIGGER vulns_cwes_update AFTER UPDATE OF cwes_json ON vulns
  WHEN OLD.cwes_json IS NOT NEW.cwes_json BEGIN
  DELETE FROM vuln_cwes WHERE vuln_id = NEW.id;
  INSERT OR IGNORE INTO vuln_cwes (cwe, vuln_id)
    SELECT value, NEW.id FROM json_each(CASE WHEN json_valid(NEW.cwes_json) THEN NEW.cwes_json ELSE '[]' END) WHERE type = 'text';
END;
CREATE TRIGGER vulns_cwes_delete AFTER DELETE ON vulns BEGIN
  DELETE FROM vuln_cwes WHERE vuln_id = OLD.id;
END;
