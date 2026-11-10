-- A row the KEV catalogue made carries no publication date until the CVE list or NVD gives one;
-- rows made before that rule carried the date CISA added them as the date the CVE was published.
UPDATE vulns SET published_at = NULL WHERE source_identifier = 'CISA KEV' AND vuln_status = 'KEV only';
