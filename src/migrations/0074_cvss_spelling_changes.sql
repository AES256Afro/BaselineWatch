-- CVSS change rows that were NVD's spelling alone (added 2026-11-16). NVD spells every CVSS 4.0
-- metric left "Not Defined" (`/E:X/CR:X/…`) in some records and omits them in others; cvssText in
-- src/vulns.ts now drops those metrics before comparing, but the rows stored before it read
-- "8.7 → 8.7". Each stored side is read the same way here: a row whose two sides then agree is
-- deleted, and every other one keeps its change, written without the X metrics. SQLite has no
-- regular expressions, so the metric names of CVSS 2.0, 3.x and 4.0 are listed; a metric is only
-- ever "X" in an environmental or threat group, so naming the base ones too changes nothing.
CREATE TEMP TABLE cvss_spelling AS
  SELECT id, replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(before_text, ')', '/)'), '/AV:X/', '/'), '/AC:X/', '/'), '/AT:X/', '/'), '/PR:X/', '/'), '/UI:X/', '/'), '/VC:X/', '/'), '/VI:X/', '/'), '/VA:X/', '/'), '/SC:X/', '/'), '/SI:X/', '/'), '/SA:X/', '/'), '/E:X/', '/'), '/CR:X/', '/'), '/IR:X/', '/'), '/AR:X/', '/'), '/MAV:X/', '/'), '/MAC:X/', '/'), '/MAT:X/', '/'), '/MPR:X/', '/'), '/MUI:X/', '/'), '/MVC:X/', '/'), '/MVI:X/', '/'), '/MVA:X/', '/'), '/MSC:X/', '/'), '/MSI:X/', '/'), '/MSA:X/', '/'), '/S:X/', '/'), '/AU:X/', '/'), '/R:X/', '/'), '/V:X/', '/'), '/RE:X/', '/'), '/U:X/', '/'), '/C:X/', '/'), '/I:X/', '/'), '/A:X/', '/'), '/RL:X/', '/'), '/RC:X/', '/'), '/MS:X/', '/'), '/MC:X/', '/'), '/MI:X/', '/'), '/MA:X/', '/'), '/Au:X/', '/'), '/CDP:X/', '/'), '/TD:X/', '/'), '/)', ')') AS b, replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(after_text, ')', '/)'), '/AV:X/', '/'), '/AC:X/', '/'), '/AT:X/', '/'), '/PR:X/', '/'), '/UI:X/', '/'), '/VC:X/', '/'), '/VI:X/', '/'), '/VA:X/', '/'), '/SC:X/', '/'), '/SI:X/', '/'), '/SA:X/', '/'), '/E:X/', '/'), '/CR:X/', '/'), '/IR:X/', '/'), '/AR:X/', '/'), '/MAV:X/', '/'), '/MAC:X/', '/'), '/MAT:X/', '/'), '/MPR:X/', '/'), '/MUI:X/', '/'), '/MVC:X/', '/'), '/MVI:X/', '/'), '/MVA:X/', '/'), '/MSC:X/', '/'), '/MSI:X/', '/'), '/MSA:X/', '/'), '/S:X/', '/'), '/AU:X/', '/'), '/R:X/', '/'), '/V:X/', '/'), '/RE:X/', '/'), '/U:X/', '/'), '/C:X/', '/'), '/I:X/', '/'), '/A:X/', '/'), '/RL:X/', '/'), '/RC:X/', '/'), '/MS:X/', '/'), '/MC:X/', '/'), '/MI:X/', '/'), '/MA:X/', '/'), '/Au:X/', '/'), '/CDP:X/', '/'), '/TD:X/', '/'), '/)', ')') AS a
    FROM vuln_changes WHERE field = 'cvss';

DELETE FROM vuln_changes WHERE id IN (SELECT id FROM cvss_spelling WHERE b IS a);

UPDATE vuln_changes SET
  before_text = (SELECT b FROM cvss_spelling s WHERE s.id = vuln_changes.id),
  after_text = (SELECT a FROM cvss_spelling s WHERE s.id = vuln_changes.id)
WHERE id IN (SELECT id FROM cvss_spelling);

DROP TABLE cvss_spelling;
