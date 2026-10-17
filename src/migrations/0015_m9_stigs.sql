-- M9.2: the STIG pages. DISA's CCI list joins STIG rules to NIST SP 800-53; CISA's directives
-- are read from its listing page. The DISA source's default followed list grows (src/adapters/disa.ts).

INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('disa-cci', 'DISA Control Correlation Identifiers (CCI)', 'requirement-set', 'standards', 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/CCI_List.zip', 'xml-zip', 'weekly', 1, 'US Government work, public domain', NULL, 'The CCI list DISA publishes: each identifier''s definition and its index into NIST SP 800-53 Revisions 4 and 5. It is the join between every STIG rule and the Register''s control pages. Found through the STIG library listing, so an unchanged list costs one small request.'),
('cisa-directives', 'CISA directives (BOD and ED)', 'article', 'news', 'https://www.cisa.gov/news-events/directives/all', 'html', 'daily', 1, 'US Government work, public domain', NULL, 'Binding Operational Directives and Emergency Directives, read from CISA''s directive listing because CISA publishes no feed for them. Each is tagged with the platforms its title names, for the STIG pages.');

UPDATE sources SET
  notes = 'The STIG document library, read through the site''s own Apex listing call. Only the STIGs on your watchlist (kind "baseline", a name such as "Windows Server 2025") or the default set are downloaded: Windows 11, Windows Server 2025 and 2022, Red Hat Enterprise Linux 9 and 10, Ubuntu 24.04 and 22.04, Apple macOS 26 and 15, Microsoft Edge, Google Chrome, Mozilla Firefox, Cisco IOS XE Router, Application Security and Development. Each release is diffed rule by rule.'
  WHERE id = 'disa-stigs';
