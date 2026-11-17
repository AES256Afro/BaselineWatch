-- The News items built from those CVSS changes (added 2026-11-16). Migration 0074 cleaned
-- vuln_changes, but a vulnerability item's summary was written from the change when it was made:
-- "CVSS 5.3 (v4.0, …/SA:N) → 5.3 (v4.0, …/SA:N/E:X/CR:X/…); Analyzed; …". The summary's opening
-- "CVSS <before> → <after>" clause (recordVulnItem in src/vulns.ts puts it first, ended by "; " or
-- ". ") is read with 0074's replace chain: where the two sides then agree, the clause goes, and
-- "cvss" leaves signals_json's $.changes; every other one keeps its change, written without the X
-- metrics. Six items on the public instance on the day.
CREATE TEMP TABLE cvss_item AS
  SELECT id, clause, rest,
         substr(clause, 6, instr(clause, ' → ') - 6) AS before_raw,
         substr(clause, instr(clause, ' → ') + 3) AS after_raw
    FROM (
      SELECT id,
             substr(summary, 1, cut - 1) AS clause,
             substr(summary, cut) AS rest
        FROM (
          SELECT id, summary,
                 CASE
                   WHEN instr(summary, '; ') > 0 AND (instr(summary, '. ') = 0 OR instr(summary, '; ') < instr(summary, '. ')) THEN instr(summary, '; ')
                   WHEN instr(summary, '. ') > 0 THEN instr(summary, '. ')
                   ELSE length(summary) + 1
                 END AS cut
            FROM items
           WHERE kind = 'vulnerability' AND summary LIKE 'CVSS %' AND instr(summary, ' → ') > 0
        )
    )
   WHERE instr(clause, ' → ') > 0;

CREATE TEMP TABLE cvss_item_read AS
  SELECT id, rest,
         replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(before_raw, ')', '/)'), '/AV:X/', '/'), '/AC:X/', '/'), '/AT:X/', '/'), '/PR:X/', '/'), '/UI:X/', '/'), '/VC:X/', '/'), '/VI:X/', '/'), '/VA:X/', '/'), '/SC:X/', '/'), '/SI:X/', '/'), '/SA:X/', '/'), '/E:X/', '/'), '/CR:X/', '/'), '/IR:X/', '/'), '/AR:X/', '/'), '/MAV:X/', '/'), '/MAC:X/', '/'), '/MAT:X/', '/'), '/MPR:X/', '/'), '/MUI:X/', '/'), '/MVC:X/', '/'), '/MVI:X/', '/'), '/MVA:X/', '/'), '/MSC:X/', '/'), '/MSI:X/', '/'), '/MSA:X/', '/'), '/S:X/', '/'), '/AU:X/', '/'), '/R:X/', '/'), '/V:X/', '/'), '/RE:X/', '/'), '/U:X/', '/'), '/C:X/', '/'), '/I:X/', '/'), '/A:X/', '/'), '/RL:X/', '/'), '/RC:X/', '/'), '/MS:X/', '/'), '/MC:X/', '/'), '/MI:X/', '/'), '/MA:X/', '/'), '/Au:X/', '/'), '/CDP:X/', '/'), '/TD:X/', '/'), '/)', ')') AS b,
         replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(after_raw, ')', '/)'), '/AV:X/', '/'), '/AC:X/', '/'), '/AT:X/', '/'), '/PR:X/', '/'), '/UI:X/', '/'), '/VC:X/', '/'), '/VI:X/', '/'), '/VA:X/', '/'), '/SC:X/', '/'), '/SI:X/', '/'), '/SA:X/', '/'), '/E:X/', '/'), '/CR:X/', '/'), '/IR:X/', '/'), '/AR:X/', '/'), '/MAV:X/', '/'), '/MAC:X/', '/'), '/MAT:X/', '/'), '/MPR:X/', '/'), '/MUI:X/', '/'), '/MVC:X/', '/'), '/MVI:X/', '/'), '/MVA:X/', '/'), '/MSC:X/', '/'), '/MSI:X/', '/'), '/MSA:X/', '/'), '/S:X/', '/'), '/AU:X/', '/'), '/R:X/', '/'), '/V:X/', '/'), '/RE:X/', '/'), '/U:X/', '/'), '/C:X/', '/'), '/I:X/', '/'), '/A:X/', '/'), '/RL:X/', '/'), '/RC:X/', '/'), '/MS:X/', '/'), '/MC:X/', '/'), '/MI:X/', '/'), '/MA:X/', '/'), '/Au:X/', '/'), '/CDP:X/', '/'), '/TD:X/', '/'), '/)', ')') AS a
    FROM cvss_item;

-- The two sides agree: the clause goes with its separator. "; " leads to the next change; ". " to
-- the description, which is then the whole summary, as recordVulnItem writes an item with no change.
UPDATE items SET
  summary = (SELECT substr(r.rest, 3) FROM cvss_item_read r WHERE r.id = items.id),
  signals_json = CASE WHEN json_valid(signals_json) AND json_type(signals_json, '$.changes') = 'array'
    THEN json_set(signals_json, '$.changes', (SELECT json_group_array(j.value) FROM json_each(items.signals_json, '$.changes') j WHERE j.value IS NOT 'cvss'))
    ELSE signals_json END
WHERE id IN (SELECT id FROM cvss_item_read WHERE b IS a);

-- The sides differ: the change stays, each side written without its X metrics.
UPDATE items SET
  summary = (SELECT 'CVSS ' || r.b || ' → ' || r.a || r.rest FROM cvss_item_read r WHERE r.id = items.id)
WHERE id IN (SELECT id FROM cvss_item_read WHERE b IS NOT a);

DROP TABLE cvss_item_read;
DROP TABLE cvss_item;
