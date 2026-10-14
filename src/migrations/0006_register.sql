-- M3 Register: a sort key and a label on requirements, release-level data on documents, and the
-- NIST sources pointed at the files the OSCAL adapter reads.

ALTER TABLE requirements ADD COLUMN label TEXT;
ALTER TABLE requirements ADD COLUMN sort_key TEXT;
ALTER TABLE requirements ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
CREATE INDEX requirements_by_doc_sort ON requirements (document_id, sort_key);

ALTER TABLE documents ADD COLUMN source_url TEXT;
ALTER TABLE documents ADD COLUMN requirement_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE documents ADD COLUMN previous_document_id INTEGER REFERENCES documents(id);

UPDATE sources SET
  url = 'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json',
  format = 'oscal-json', schedule = 'daily',
  notes = 'The OSCAL catalog NIST publishes, which carries both the 800-53 controls and the 800-53A assessment objectives. Current Release 5.2.0 (2025-08-27). History is loaded from the same repository''s commits.'
  WHERE id = 'nist-sp-800-53';
UPDATE sources SET
  url = 'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/',
  format = 'oscal-json', schedule = 'daily',
  notes = 'The Low, Moderate, High and Privacy baseline profiles. Each release is diffed as control membership: which controls joined or left a baseline.'
  WHERE id = 'nist-sp-800-53b';
UPDATE sources SET enabled = 0,
  notes = 'Folded into the 800-53 catalog, which carries the assessment objectives; shown there as the assessment text of each control.'
  WHERE id = 'nist-sp-800-53a';
