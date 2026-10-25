-- NVD's CPE match criteria with their version ranges (added 2026-10-21). vulns.cpes_json keeps the
-- vulnerable criteria strings and everything that reads them is unchanged; what that column never
-- carried is the bounds NVD attaches to a criterion (versionStartIncluding, versionStartExcluding,
-- versionEndIncluding, versionEndExcluding), without which "cpe:2.3:a:openbsd:openssh:*" says only
-- that some OpenSSH is affected. One row per cpeMatch entry of the CVE's configurations, replaced
-- whole each time the CVE is normalised again, so the table says what NVD said last. A row with
-- vulnerable = 0 is the platform a match is conditioned on (the "running on" side of an AND
-- configuration), kept so the condition is not lost. Nothing reads the ranges yet beyond
-- rangesFor() in src/cpematches.ts; matching an installed application's version against them is
-- a later step. A CVE NVD has not touched since this migration has no rows until its next pull,
-- or until `npm run backfill -- nvd-cves` pulls the window again.
CREATE TABLE vuln_cpe_matches (
  id              INTEGER PRIMARY KEY,
  cve_id          TEXT NOT NULL,
  criteria        TEXT NOT NULL,                 -- the criterion as NVD wrote it, escapes and all
  part            TEXT NOT NULL,                 -- a (application), o (operating system), h (hardware)
  vendor          TEXT NOT NULL,
  product         TEXT NOT NULL,
  version         TEXT NOT NULL,                 -- the criterion's own version field: '*' when a range says it, '-' for none, else one version
  version_start   TEXT,                          -- the lower bound, when NVD gives one
  start_inclusive INTEGER CHECK (start_inclusive IN (0, 1)),   -- NULL when there is no lower bound
  version_end     TEXT,
  end_inclusive   INTEGER CHECK (end_inclusive IN (0, 1)),
  vulnerable      INTEGER NOT NULL CHECK (vulnerable IN (0, 1))
);
CREATE INDEX vuln_cpe_matches_by_product ON vuln_cpe_matches (vendor, product);
CREATE INDEX vuln_cpe_matches_by_cve ON vuln_cpe_matches (cve_id);
