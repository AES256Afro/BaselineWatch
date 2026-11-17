-- EPSS change rows in one form (bug sweep 3a). Before the audit of 2026-11-16 an EPSS change was
-- written as a decimal with two places ("0.52"); since then as a percentage ("52%"), by
-- epssPercent in src/words.ts. The old rows are rewritten by the same rule: whole percent from
-- 10%, one place from 1%, two from 0.1%, three below, each threshold read on the value as it will
-- be shown. Only a text that is a bare decimal is touched, so running it again changes nothing.
UPDATE vuln_changes
   SET before_text = CASE
         WHEN round(CAST(before_text AS REAL) * 100, 1) >= 10 THEN printf('%.0f%%', CAST(before_text AS REAL) * 100)
         WHEN round(CAST(before_text AS REAL) * 100, 2) >= 1 THEN printf('%.1f%%', CAST(before_text AS REAL) * 100)
         WHEN round(CAST(before_text AS REAL) * 100, 3) >= 0.1 THEN printf('%.2f%%', CAST(before_text AS REAL) * 100)
         ELSE printf('%.3f%%', CAST(before_text AS REAL) * 100)
       END
 WHERE field = 'epss' AND before_text GLOB '[0-9]*' AND before_text NOT GLOB '*[^0-9.]*';
UPDATE vuln_changes
   SET after_text = CASE
         WHEN round(CAST(after_text AS REAL) * 100, 1) >= 10 THEN printf('%.0f%%', CAST(after_text AS REAL) * 100)
         WHEN round(CAST(after_text AS REAL) * 100, 2) >= 1 THEN printf('%.1f%%', CAST(after_text AS REAL) * 100)
         WHEN round(CAST(after_text AS REAL) * 100, 3) >= 0.1 THEN printf('%.2f%%', CAST(after_text AS REAL) * 100)
         ELSE printf('%.3f%%', CAST(after_text AS REAL) * 100)
       END
 WHERE field = 'epss' AND after_text GLOB '[0-9]*' AND after_text NOT GLOB '*[^0-9.]*';
