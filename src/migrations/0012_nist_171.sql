-- NIST SP 800-171 Revision 3 from NIST's OSCAL (checked 2026-10-15): the security requirements for
-- protecting CUI in nonfederal systems, with their assessment objectives. CMMC Level 2 is this set.
-- The source was seeded in 0002 as a CPRT placeholder; it now reads the OSCAL catalog.

INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('nist-sp-800-171', 'NIST SP 800-171 Rev 3 (CUI; CMMC Level 2)', 'requirement-set', 'standards', 'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json', 'oscal-json', 'daily', 1, 'US Government work, public domain', NULL, NULL);

UPDATE sources SET
  name = 'NIST SP 800-171 Rev 3 (CUI; CMMC Level 2)',
  url = 'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json',
  format = 'oscal-json', schedule = 'daily', enabled = 1,
  notes = 'The 97 security requirements for protecting Controlled Unclassified Information, with their assessment objectives and organization-defined parameters; requirements withdrawn from Revision 2 are kept as withdrawn. Versions are NIST''s OSCAL conversions of Revision 3 (the publication dates from May 2024); tracking starts at OSCAL 1.1.0 because 1.0.0 left 29 statements empty, so a diff against it would show a conversion fix as a change to the publication.'
  WHERE id = 'nist-sp-800-171';
