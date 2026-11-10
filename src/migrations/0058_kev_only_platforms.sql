-- KEV-only rows were given platforms by reading CISA's product words as CPE slugs, which matched
-- nothing for 1,060 of 1,676 ("win32k", "internet explorer", "multiple products"). Cleared here so
-- the start-up pass reads them again with the catalogue's own vendor and product.
UPDATE vulns SET platforms_json = NULL WHERE source_identifier = 'CISA KEV' AND vuln_status = 'KEV only';
