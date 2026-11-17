-- 0066 rewrote a KEV title only when it opened with the entry's vendor and product exactly as its
-- signals name them, so ten entries whose vendor or product CISA wrote with a trailing space, a
-- leading space or a narrow no-break space (U+202F) kept the doubled "<vendor> <product>: <name>"
-- title. Any KEV title that does not already open with "<CVE id> · " is rewritten to that id and
-- the text after its first ": ", whatever the spacing; running it again changes nothing.
UPDATE items
   SET title = external_id || ' · ' || substr(title, instr(title, ': ') + 2)
 WHERE source_id = 'cisa-kev' AND kind = 'kev'
   AND external_id IS NOT NULL
   AND substr(title, 1, length(external_id || ' · ')) <> external_id || ' · '
   AND instr(title, ': ') > 0;
