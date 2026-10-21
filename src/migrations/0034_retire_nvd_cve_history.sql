-- Retire the nvd-cve-history row (M13.2). It was seeded in 0002 and switched off in 0005 with the
-- note that BaselineWatch computes a CVE's history from successive NVD records, which has been
-- true and better ever since: the endpoint costs a request per CVE and says less than the diff
-- between two sightings. It has had no adapter for a month, so the Sources page carried a source
-- that would never run. Nothing references it; snapshots and items are keyed by source id and it
-- has neither.
DELETE FROM sources WHERE id = 'nvd-cve-history';
