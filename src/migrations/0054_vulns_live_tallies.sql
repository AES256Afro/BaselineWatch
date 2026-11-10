-- The Vulnerabilities page's four headline counts in one pass over a covering index: they were four
-- full scans of vulns (about 50 ms of an 80 ms page on 46,000 rows), since excluding rejected CVEs
-- by status cannot use an index on anything else.
CREATE INDEX IF NOT EXISTS vulns_live_tallies ON vulns (vuln_status, kev, watch_hit, has_exploit);
