-- A STIG release's News entry named the source that fetched it ("DISA STIG library V2R11: …"),
-- so nineteen STIGs read as one. From the audit of 2026-11-16 the entry is written with the STIG's
-- own name (documentName in src/register.ts: "Windows 11 STIG V2R11: …"); the entries already
-- written are renamed by the same rule. Only a title that still opens with the source's name is
-- touched, so running it again changes nothing.
UPDATE items
   SET title = (
         SELECT CASE
                  WHEN trim(replace(d.title, ' Security Technical Implementation Guide', '')) LIKE 'Microsoft Windows%'
                    THEN substr(trim(replace(d.title, ' Security Technical Implementation Guide', '')), 11)
                  ELSE trim(replace(d.title, ' Security Technical Implementation Guide', ''))
                END || ' STIG' || substr(items.title, 18)
           FROM documents d
          WHERE d.id = CAST(substr(items.external_id, instr(items.external_id, '#') + 1) AS INTEGER)
       )
 WHERE source_id = 'disa-stigs' AND kind = 'release' AND title LIKE 'DISA STIG library %'
   AND instr(external_id, '#') > 0
   AND EXISTS (
         SELECT 1 FROM documents d
          WHERE d.id = CAST(substr(items.external_id, instr(items.external_id, '#') + 1) AS INTEGER)
            AND d.title IS NOT NULL AND d.title <> ''
       );
