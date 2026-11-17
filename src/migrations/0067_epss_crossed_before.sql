-- EPSS crossings held from before 0063 (audit 2026-11-16, B4-1). Migration 0063 marked only a
-- score at or over 50% as having crossed. A CVE that rose past 50% and has since eased into 40%
-- to 50% is still held by the rule (the mark clears only below 40%), but it went unmarked, so its
-- next rise to 50% would read as news a second time. Its history says it crossed: an EPSS change
-- row whose after text is 50% or more, with no later row below 40%; the first such row since the
-- last fall below 40% is when it got there. Rows are percentage text since 0064 ("52%"); a bare
-- decimal is read as a fraction in case one was missed.
WITH readings AS (
  SELECT cve_id, observed_at,
         CASE WHEN after_text LIKE '%\%' ESCAPE '\' THEN CAST(rtrim(after_text, '%') AS REAL)
              ELSE CAST(after_text AS REAL) * 100 END AS pct
    FROM vuln_changes
   WHERE field = 'epss' AND after_text IS NOT NULL AND after_text <> ''
),
crossed AS (
  SELECT r.cve_id, MIN(r.observed_at) AS at
    FROM readings r
   WHERE r.pct >= 50
     AND NOT EXISTS (SELECT 1 FROM readings l WHERE l.cve_id = r.cve_id AND l.observed_at > r.observed_at AND l.pct < 40)
   GROUP BY r.cve_id
)
UPDATE vulns
   SET epss_crossed_at = (SELECT at FROM crossed WHERE crossed.cve_id = vulns.cve_id)
 WHERE epss_crossed_at IS NULL
   AND epss >= 0.4
   AND cve_id IN (SELECT cve_id FROM crossed);
