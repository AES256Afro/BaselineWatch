-- At every start recomputePlatforms asks for the CVEs whose platforms have not been read yet
-- (`WHERE platforms_json IS NULL`). With no index that is a scan of the whole table, 483 ms cold
-- on the public instance's copy (2026-11-16), to find what is almost always nothing. A partial
-- index holds only those rows, so the question costs a lookup into an empty index.
CREATE INDEX vulns_platforms_unread ON vulns (cve_id) WHERE platforms_json IS NULL;
