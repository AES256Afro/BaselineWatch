-- CISA's own vendor and product for a KEV entry (added 2026-11-16), kept in columns of their own so
-- an NVD record replacing vendors_json and products_json with CPE values does not lose them: a
-- watch made from a KEV-only page ("ivanti:connect secure") then still matches once NVD arrives.
-- Filled by applyKev and from the catalogue items this instance already holds; NVD never writes them.
ALTER TABLE vulns ADD COLUMN kev_vendor TEXT;
ALTER TABLE vulns ADD COLUMN kev_product TEXT;

UPDATE vulns SET
  kev_vendor = (SELECT lower(json_extract(i.signals_json, '$.vendor')) FROM items i
                 WHERE i.source_id = 'cisa-kev' AND i.kind = 'kev' AND i.external_id = vulns.cve_id AND json_valid(i.signals_json) LIMIT 1),
  kev_product = (SELECT lower(json_extract(i.signals_json, '$.product')) FROM items i
                 WHERE i.source_id = 'cisa-kev' AND i.kind = 'kev' AND i.external_id = vulns.cve_id AND json_valid(i.signals_json) LIMIT 1)
WHERE kev = 1;

-- Read every such row's platforms and watch hits again at the next start (recomputePlatforms, then
-- recomputeWatchHits on the ids it returns), so a pair watched before now matches its NVD row.
UPDATE vulns SET platforms_json = NULL WHERE kev_vendor IS NOT NULL;
