-- 0058 filed every Microsoft KEV-only product under Windows, Exchange, Office and Internet Explorer
-- included. Cleared again so the start-up pass reads them with the STIG pages' Microsoft reading.
UPDATE vulns SET platforms_json = NULL WHERE source_identifier = 'CISA KEV' AND vuln_status = 'KEV only' AND vendors_json = '["microsoft"]';
