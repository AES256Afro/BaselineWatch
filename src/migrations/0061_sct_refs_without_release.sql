-- Microsoft baseline refs without the release. A setting's ref is its GPO's name plus the setting,
-- and the GPO name carried the release ("Windows 11 25H2 - Computer", "Edge Version 151 - Computer"),
-- so every ref, and every decision on an `sct:` item, changed with each release. policyScope in
-- src/adapters/sct.ts now drops the release words from the product part of the name (before " - "):
-- a feature update such as 25H2, a four-digit release such as 1809 unless it follows "Server"
-- ("Server 2019" names a product), and "Version" with the number after it. The same test is
-- applied here to what is stored: the requirements (ref, sort key, family, extra.policy), the change
-- rows, triage on a setting, and the builder's decisions, so a decision follows its setting.
--
-- Where two stored refs of one document come down to the same ref, the first stored keeps it and
-- the others keep their old refs. Where several decisions come down to one id, a decision already
-- stored under that id stays; otherwise the most recent moves there and the others keep their old
-- ids (no longer shown on any release). Nothing is deleted. Running it again changes nothing.

-- Every GPO name stored: the family as published (mixed case) and the scope inside each ref (lower case).
CREATE TEMP TABLE sct_scope_names (old TEXT PRIMARY KEY);
INSERT OR IGNORE INTO sct_scope_names (old)
  SELECT r.family FROM requirements r JOIN documents d ON d.id = r.document_id
   WHERE d.source_id = 'microsoft-sct' AND r.family IS NOT NULL
  UNION SELECT substr(r.ref, 1, instr(r.ref, '|') - 1) FROM requirements r JOIN documents d ON d.id = r.document_id
   WHERE d.source_id = 'microsoft-sct' AND instr(r.ref, '|') > 0
  UNION SELECT substr(ref, 1, instr(ref, '|') - 1) FROM changes
   WHERE source_id = 'microsoft-sct' AND instr(ref, '|') > 0
  UNION SELECT substr(t.subject_key, 1, instr(t.subject_key, '|') - 1) FROM triage t JOIN documents d ON d.id = t.subject_id
   WHERE t.subject_kind = 'control' AND d.source_id = 'microsoft-sct' AND instr(t.subject_key, '|') > 0
  UNION SELECT substr(item_id, 5, instr(item_id, '|') - 5) FROM baseline_decisions
   WHERE item_id LIKE 'sct:%|%';

-- Each name without its release words: the product part split into words, each word read with the
-- one before and after it, the release words left out, the rest joined back with " - ..." after it.
CREATE TEMP TABLE sct_scope_map (old TEXT PRIMARY KEY, new TEXT NOT NULL);
WITH RECURSIVE
  parts (old, product, rest) AS (
    SELECT old,
           CASE WHEN instr(old, ' - ') > 0 THEN substr(old, 1, instr(old, ' - ') - 1) ELSE old END,
           CASE WHEN instr(old, ' - ') > 0 THEN substr(old, instr(old, ' - ')) ELSE '' END
      FROM sct_scope_names
  ),
  words (old, pos, word, tail) AS (
    SELECT old, 0, '', product || ' ' FROM parts
    UNION ALL
    SELECT old, pos + 1, substr(tail, 1, instr(tail, ' ') - 1), substr(tail, instr(tail, ' ') + 1)
      FROM words WHERE tail <> ''
  ),
  marked (old, pos, word, prev, next) AS (
    SELECT old, pos, word,
           lower(lag(word, 1, '') OVER (PARTITION BY old ORDER BY pos)),
           lead(word, 1, '') OVER (PARTITION BY old ORDER BY pos)
      FROM words WHERE pos > 0
  ),
  kept (old, pos, word) AS (
    SELECT old, pos, word FROM marked
     WHERE word <> ''
       AND NOT (
         word GLOB '[0-9][0-9][Hh][0-9]'
         OR (word GLOB '[0-9][0-9][0-9][0-9]' AND prev <> 'server')
         OR (lower(word) = 'version' AND next <> '' AND next NOT GLOB '*[^0-9]*')
         OR (word NOT GLOB '*[^0-9]*' AND prev = 'version')
       )
  ),
  joined (old, product) AS (
    SELECT DISTINCT old, group_concat(word, ' ') OVER (PARTITION BY old ORDER BY pos ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING)
      FROM kept
  )
INSERT INTO sct_scope_map (old, new)
SELECT p.old, trim(coalesce(j.product, '') || p.rest)
  FROM parts p LEFT JOIN joined j ON j.old = p.old
 WHERE trim(coalesce(j.product, '') || p.rest) <> p.old;

-- The requirements whose ref changes; where several would land on one ref in a document, or the ref
-- is already taken there, only the first stored moves.
CREATE TEMP TABLE sct_ref_map (id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL, old TEXT NOT NULL, new TEXT NOT NULL);
INSERT INTO sct_ref_map (id, document_id, old, new)
SELECT r.id, r.document_id, r.ref, m.new || substr(r.ref, instr(r.ref, '|'))
  FROM requirements r
  JOIN documents d ON d.id = r.document_id
  JOIN sct_scope_map m ON m.old = substr(r.ref, 1, instr(r.ref, '|') - 1)
 WHERE d.source_id = 'microsoft-sct' AND instr(r.ref, '|') > 0;
DELETE FROM sct_ref_map
 WHERE id <> (SELECT min(x.id) FROM sct_ref_map x WHERE x.document_id = sct_ref_map.document_id AND x.new = sct_ref_map.new)
    OR EXISTS (SELECT 1 FROM requirements r WHERE r.document_id = sct_ref_map.document_id AND r.ref = sct_ref_map.new);

UPDATE requirements
   SET ref = (SELECT new FROM sct_ref_map WHERE sct_ref_map.id = requirements.id),
       sort_key = CASE WHEN sort_key = ref THEN (SELECT new FROM sct_ref_map WHERE sct_ref_map.id = requirements.id) ELSE sort_key END
 WHERE id IN (SELECT id FROM sct_ref_map);

UPDATE requirements
   SET family = (SELECT new FROM sct_scope_map WHERE sct_scope_map.old = requirements.family)
 WHERE family IN (SELECT old FROM sct_scope_map)
   AND document_id IN (SELECT id FROM documents WHERE source_id = 'microsoft-sct');

UPDATE requirements
   SET extra_json = json_set(extra_json, '$.policy', (SELECT new FROM sct_scope_map WHERE sct_scope_map.old = json_extract(requirements.extra_json, '$.policy')))
 WHERE document_id IN (SELECT id FROM documents WHERE source_id = 'microsoft-sct')
   AND json_valid(extra_json)
   AND json_extract(extra_json, '$.policy') IN (SELECT old FROM sct_scope_map);

-- Triage on a setting follows the requirement it names.
UPDATE triage
   SET subject_key = (SELECT new FROM sct_ref_map WHERE sct_ref_map.document_id = triage.subject_id AND sct_ref_map.old = triage.subject_key)
 WHERE subject_kind = 'control'
   AND EXISTS (SELECT 1 FROM sct_ref_map WHERE sct_ref_map.document_id = triage.subject_id AND sct_ref_map.old = triage.subject_key)
   AND NOT EXISTS (
     SELECT 1 FROM triage t2 JOIN sct_ref_map x ON x.document_id = t2.subject_id AND x.new = t2.subject_key
      WHERE t2.subject_kind = 'control' AND x.document_id = triage.subject_id AND x.old = triage.subject_key
   );

-- Change rows keep their ref unless it is still a requirement's ref in either document (a ref that
-- did not move because another took its place).
UPDATE changes
   SET ref = (SELECT m.new FROM sct_scope_map m WHERE m.old = substr(changes.ref, 1, instr(changes.ref, '|') - 1)) || substr(ref, instr(ref, '|'))
 WHERE source_id = 'microsoft-sct'
   AND instr(ref, '|') > 0
   AND substr(ref, 1, instr(ref, '|') - 1) IN (SELECT old FROM sct_scope_map)
   AND NOT EXISTS (SELECT 1 FROM requirements r WHERE r.ref = changes.ref AND r.document_id IN (changes.to_document_id, changes.from_document_id));

-- The builder's decisions on Microsoft baseline items, keyed `sct:` + ref.
CREATE TEMP TABLE sct_decision_map (rid INTEGER PRIMARY KEY, platform TEXT NOT NULL, new TEXT NOT NULL, decided_at TEXT NOT NULL);
INSERT INTO sct_decision_map (rid, platform, new, decided_at)
SELECT b.rowid, b.platform, 'sct:' || m.new || substr(b.item_id, instr(b.item_id, '|')), b.decided_at
  FROM baseline_decisions b
  JOIN sct_scope_map m ON m.old = substr(b.item_id, 5, instr(b.item_id, '|') - 5)
 WHERE b.item_id LIKE 'sct:%|%';
DELETE FROM sct_decision_map
 WHERE EXISTS (SELECT 1 FROM baseline_decisions b WHERE b.platform = sct_decision_map.platform AND b.item_id = sct_decision_map.new)
    OR EXISTS (
      SELECT 1 FROM sct_decision_map x
       WHERE x.platform = sct_decision_map.platform AND x.new = sct_decision_map.new
         AND (x.decided_at > sct_decision_map.decided_at OR (x.decided_at = sct_decision_map.decided_at AND x.rid > sct_decision_map.rid))
    );
UPDATE baseline_decisions
   SET item_id = (SELECT new FROM sct_decision_map WHERE sct_decision_map.rid = baseline_decisions.rowid)
 WHERE rowid IN (SELECT rid FROM sct_decision_map);

DROP TABLE sct_decision_map;
DROP TABLE sct_ref_map;
DROP TABLE sct_scope_map;
DROP TABLE sct_scope_names;
