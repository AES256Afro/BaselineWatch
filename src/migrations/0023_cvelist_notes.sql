-- The cvelist-v5 adapter starts at the newest delta release and only moves forward;
-- the multi-hundred-megabyte "all CVEs" baseline is never loaded. Say so on the Sources page.
UPDATE sources
SET notes = 'Hourly delta releases are the trigger; NVD enriches. First pull starts at the newest delta release and only moves forward; the full historic baseline is never loaded (older records arrive via NVD).'
WHERE id = 'cvelist-v5';
