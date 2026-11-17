-- The CVE table and the STIG pages read a KEV entry's vendor and product with two copies of one
-- rule, and the table's copy fell behind: Red Hat's libuser and ABRT had no platform, HPE, Barracuda
-- Networks and "D-Link and TRENDnet" were not network devices, and Windows' "Internet Key Exchange
-- (IKE) Service Extensions" was taken for Exchange Server. src/platforms.ts now holds the one
-- reading (kevReading); KEV-only rows, whose NVD record has not arrived, are cleared so the
-- start-up pass (recomputePlatforms) reads them again with it, and the trigger from 0047 keeps
-- vuln_platforms in step.
UPDATE vulns SET platforms_json = NULL WHERE source_identifier = 'CISA KEV' AND vuln_status = 'KEV only';
