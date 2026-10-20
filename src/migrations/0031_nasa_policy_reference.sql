-- NASA's Cybersecurity Policy Reference (added 2026-10-20): the public, quarterly Word document
-- in which NASA OCIO lists every key cybersecurity document — the NPD/NPR directives, the NAIIs,
-- the IT handbooks, the NASA standards (NASA-SPEC-2600's enumeration of the ASCS requirements and
-- the NASA-STD-26xx set), the CIO memoranda, and the FIPS and NIST publications NASA points its
-- contracts at, each with its dates and status notes. The ASCS technical standards themselves sit
-- behind cset.nasa.gov (NASA access only); this reference is the public register of that world,
-- and each quarterly update diffs here like any standard.

INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('nasa-cyber-ref', 'NASA Cybersecurity Policy Reference (OCIO/CSET)', 'requirement-set', 'standards', 'https://www.nasa.gov/cybersecurity-policies/', 'docx', 'weekly', 1, 'US Government work, public domain', NULL, 'The quarterly reference from NASA OCIO''s Cybersecurity Policy Team: directives, advisory implementing instructions, handbooks, NASA standards (including NASA-SPEC-2600, the enumeration of ASCS cybersecurity requirements), memoranda, and the FIPS and NIST documents NASA cites, each row diffed between editions. The per-OS ASCS standards live on cset.nasa.gov behind a NASA sign-in and are not public; this list is the public knowledge of them.');
