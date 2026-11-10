-- Three rows that never read anything and never will (audit of 2026-11-05). ComplianceAsCode was
-- enabled with no adapter, so /register said "checked daily" over "No snapshot yet" for good, and
-- the API and the sitemap listed it. SP 800-53A was folded into the 800-53 catalog, which carries
-- the assessment objectives. The MSRC row waited for M2; src/msrc.ts reads Microsoft's own
-- documents instead. Deleted only where nothing was ever fetched under them.
DELETE FROM sources
 WHERE id IN ('complianceascode', 'nist-sp-800-53a', 'msrc-blog')
   AND last_fetch_at IS NULL
   AND NOT EXISTS (SELECT 1 FROM snapshots s WHERE s.source_id = sources.id)
   AND NOT EXISTS (SELECT 1 FROM documents d WHERE d.source_id = sources.id)
   AND NOT EXISTS (SELECT 1 FROM items i WHERE i.source_id = sources.id);
