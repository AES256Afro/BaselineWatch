-- A CVE's platforms are read in one place now (rowPlatforms, 2026-11-16): a Microsoft application CPE
-- is not placed from CISA's words, a Microsoft entry whose product is empty or "Multiple Products"
-- has no CISA reading, and a KEV-only row is placed by its description's words when CISA's give
-- none. Only rows with CISA's names read differently; the start-up pass (recomputePlatforms, then
-- recomputeWatchHits on the ids it returns) reads them again.
UPDATE vulns SET platforms_json = NULL WHERE kev_vendor IS NOT NULL;
