-- NIST publications that exist only as PDFs, tracked by topic through their CSRC pages (checked
-- 2026-10-19): the PIV and digital identity set (FIPS 201 and the SP 800-73/76/78/79/85A/87/96/
-- 116/156/157/217 family, IR 7863, SP 800-63-4 with 63A, 63B and 63C) and the platform security
-- set (FIPS 140-3, SP 800-147 and 147B, 800-193, 800-124r2, 800-219r1, 800-57 Part 1, IR 8320 A, B
-- and D). Each publication is one document whose numbered sections are the requirements; a new
-- revision is diffed section by section, with the PDF's own change log or revision history as
-- the publisher's reason, else the CSRC Planning Note.

INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('nist-piv',      'NIST PIV and digital identity',    'requirement-set', 'standards', 'https://csrc.nist.gov/topics/security-and-privacy/identity-and-access-management/piv', 'csrc-pdf', 'daily', 1, 'US Government work, public domain', NULL, 'FIPS 201-3 and the PIV special publications (SP 800-73-5 parts 1 to 3, 76-2, 78-5, 79-2, 85A-4, 87r2, 96, 116r1, 156, 157r1 draft, 217 draft, IR 7863) and the SP 800-63-4 Digital Identity Guidelines, each read from its CSRC page and diffed section by section when a revision is published. The first fetch also loads the revision each one superseded, so the first diff is real.'),
('nist-platform', 'NIST platform security: roots of trust, firmware and secure enclaves', 'requirement-set', 'standards', 'https://csrc.nist.gov/topics/technologies/hardware', 'csrc-pdf', 'daily', 1, 'US Government work, public domain', NULL, 'FIPS 140-3, SP 800-147 and 147B (BIOS protection), 800-193 (platform firmware resiliency), 800-124r2 (mobile devices), 800-219r1 (macOS Security Compliance Project), 800-57 Part 1 (key management) and IR 8320, 8320A, 8320B and 8320D (hardware-enabled security, confidential computing), each read from its CSRC page and diffed section by section when a revision is published.');
