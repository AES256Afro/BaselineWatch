-- A KEV entry's title was "<vendor> <product>: <CISA's vulnerability name>", and CISA's name
-- already carries the vendor and product, so the News read "Collabora Collabora Online – …:
-- Collabora Online – … Vulnerability". From the audit of 2026-11-16 the adapter writes "<CVE id> ·
-- <name>"; the entries already stored are rewritten by the same rule, so the next pull of the
-- catalogue finds nothing to update. Only a title that still opens with the vendor and product
-- the entry's own signals name is touched, so running it again changes nothing.
UPDATE items
   SET title = external_id || ' · ' || substr(title, length(json_extract(signals_json, '$.vendor') || ' ' || json_extract(signals_json, '$.product') || ': ') + 1)
 WHERE source_id = 'cisa-kev' AND kind = 'kev'
   AND json_valid(signals_json)
   AND json_extract(signals_json, '$.vendor') IS NOT NULL
   AND json_extract(signals_json, '$.product') IS NOT NULL
   AND substr(title, 1, length(json_extract(signals_json, '$.vendor') || ' ' || json_extract(signals_json, '$.product') || ': '))
       = json_extract(signals_json, '$.vendor') || ' ' || json_extract(signals_json, '$.product') || ': ';
