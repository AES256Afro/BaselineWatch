-- The source register from docs/SOURCES.md, as rows. Adapters (M1 onward) look sources up by id.
-- Later edits to a source go in a new migration, never by editing this file.

INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
-- Standards and baselines
('nist-sp-800-53',  'NIST SP 800-53 (controls)',          'requirement-set', 'standards', 'https://github.com/usnistgov/oscal-content', 'oscal-json', 'daily', 1, 'US Government work, public domain', NULL, 'OSCAL catalog rev5; current Release 5.2.0 (2025-08-27). Rationale from the CSRC publication page.'),
('nist-sp-800-53a', 'NIST SP 800-53A (assessment)',       'requirement-set', 'standards', 'https://github.com/usnistgov/oscal-content', 'oscal-json', 'daily', 1, 'US Government work, public domain', NULL, 'Assessment procedures matching 800-53 releases.'),
('nist-sp-800-53b', 'NIST SP 800-53B (baselines)',        'requirement-set', 'standards', 'https://github.com/usnistgov/oscal-content', 'oscal-json', 'daily', 1, 'US Government work, public domain', NULL, 'Low, Moderate, High and Privacy baseline profiles.'),
('nist-sp-800-171', 'NIST SP 800-171 Rev 3',              'requirement-set', 'standards', 'https://csrc.nist.gov/projects/cprt', 'cprt-json', 'weekly', 1, 'US Government work, public domain', NULL, 'CPRT JSON; CAPORDINO converts to OSCAL.'),
('csrc-drafts',     'NIST CSRC drafts open for comment',  'article',         'standards', 'https://csrc.nist.gov/CSRC/media/feeds/pubs/drafts-open-for-comment.xml', 'rss', 'daily', 1, 'US Government work, public domain', NULL, NULL),
('disa-stigs',      'DISA STIG library',                  'listing',         'standards', 'https://www.cyber.mil/stigs/downloads/', 'xccdf-zip', 'daily', 1, 'US Government work, public domain', NULL, 'Quarterly compilation plus out-of-band drops; NIST NCP is the mirror. Listing page is JavaScript-rendered (verify in M4).'),
('microsoft-sct',   'Microsoft Security Baselines (SCT)', 'listing',         'standards', 'https://www.microsoft.com/en-us/download/details.aspx?id=55319', 'sct-zip', 'weekly', 1, 'Microsoft; no redistribution', 'Baseline content is Microsoft''s and is quoted, not republished.', 'Toolkit last published 2026-02-23. Rationale from the Microsoft Security Baselines blog.'),
('cis-benchmarks',  'CIS Benchmarks (manual upload)',     'requirement-set', 'standards', 'https://www.cisecurity.org/cis-benchmarks', 'pdf-upload', 'manual', 1, 'CIS licence; internal use, no redistribution', 'CIS Benchmarks are the property of the Center for Internet Security.', 'Registration-walled PDFs; upload your copy and diff locally.'),
('complianceascode','ComplianceAsCode/content',           'requirement-set', 'standards', 'https://github.com/ComplianceAsCode/content', 'git', 'daily', 1, 'BSD-3-Clause', NULL, 'Open STIG/CIS profiles; git history is the diff.'),
-- Vulnerabilities
('nvd-cves',        'NVD CVE API 2.0',                    'vulnerability',   'vulnerabilities', 'https://services.nvd.nist.gov/rest/json/cves/2.0', 'json', 'hourly', 1, 'Public domain, attribution requested', 'This product uses the NVD API but is not endorsed or certified by the NVD.', '5 requests/30 s without a key, 50 with; 120-day window per query.'),
('nvd-cve-history', 'NVD CVE change history',             'vulnerability',   'vulnerabilities', 'https://services.nvd.nist.gov/rest/json/cvehistory/2.0', 'json', 'hourly', 1, 'Public domain, attribution requested', NULL, 'Per-CVE change events: scores, CPEs, references.'),
('cvelist-v5',      'CVE List V5 (CVE Program)',          'vulnerability',   'vulnerabilities', 'https://github.com/CVEProject/cvelistV5', 'json', 'hourly', 1, 'CVE Terms of Use', 'CVE and the CVE logo are registered trademarks of The MITRE Corporation.', 'Hourly delta releases are the trigger; NVD enriches.'),
('cisa-kev',        'CISA Known Exploited Vulnerabilities','vulnerability',  'vulnerabilities', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 'json', 'hourly', 1, 'Public domain', 'Known Exploited Vulnerabilities Catalog provided by CISA.', 'Additions are high-priority events with due dates.'),
('first-epss',      'FIRST EPSS',                         'vulnerability',   'vulnerabilities', 'https://epss.cyentia.com/epss_scores-current.csv.gz', 'csv', 'daily', 1, 'FIRST EPSS terms', 'EPSS scores provided by FIRST.', NULL),
-- News
('bleeping',        'BleepingComputer',                   'article', 'news', 'https://www.bleepingcomputer.com/feed/', 'rss', 'hourly', 1, NULL, NULL, NULL),
('thehackernews',   'The Hacker News',                    'article', 'news', 'https://feeds.feedburner.com/TheHackersNews', 'rss', 'hourly', 1, NULL, NULL, NULL),
('krebs',           'Krebs on Security',                  'article', 'news', 'https://krebsonsecurity.com/feed/', 'rss', 'daily', 1, NULL, NULL, NULL),
('sans-isc',        'SANS Internet Storm Center',         'article', 'news', 'https://isc.sans.edu/rssfeed_full.xml', 'rss', 'daily', 1, NULL, NULL, NULL),
('the-record',      'The Record',                         'article', 'news', 'https://therecord.media/feed', 'rss', 'hourly', 1, NULL, NULL, NULL),
('schneier',        'Schneier on Security',               'article', 'news', 'https://www.schneier.com/feed/atom/', 'atom', 'daily', 1, NULL, NULL, NULL),
('darkreading',     'Dark Reading',                       'article', 'news', 'https://www.darkreading.com/rss.xml', 'rss', 'hourly', 1, NULL, NULL, NULL),
('securityweek',    'SecurityWeek',                       'article', 'news', 'https://feeds.feedburner.com/securityweek', 'rss', 'hourly', 1, NULL, NULL, NULL),
('riskybiz',        'Risky Business',                     'article', 'news', 'https://risky.biz/feeds/risky-business/', 'rss', 'daily', 1, NULL, NULL, NULL),
('projectzero',     'Google Project Zero',                'article', 'news', 'https://googleprojectzero.blogspot.com/feeds/posts/default', 'atom', 'daily', 1, NULL, NULL, NULL),
('msrc-blog',       'Microsoft Security Response Center', 'article', 'news', 'https://msrc.microsoft.com/blog/feed', 'rss', 'daily', 1, NULL, NULL, NULL),
('ncsc-uk',         'UK NCSC',                            'article', 'news', 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml', 'rss', 'daily', 1, NULL, NULL, NULL),
('cisa-advisories', 'CISA advisories and alerts',         'article', 'news', 'https://www.cisa.gov/news-events/cybersecurity-advisories', 'html', 'hourly', 1, 'Public domain', NULL, 'Direct RSS endpoint to confirm in M1; the listing page is the fallback.'),
('reddit-netsec',   'r/netsec',                           'article', 'news', 'https://www.reddit.com/r/netsec/new.json', 'json', 'hourly', 1, 'Reddit API terms; personal, identified use', NULL, 'Descriptive User-Agent, at most every 10 minutes, back off on 429. Link posts only.'),
('reddit-cybersecurity', 'r/cybersecurity',               'article', 'news', 'https://www.reddit.com/r/cybersecurity/new.json', 'json', 'hourly', 1, 'Reddit API terms; personal, identified use', NULL, NULL),
('reddit-blueteamsec', 'r/blueteamsec',                   'article', 'news', 'https://www.reddit.com/r/blueteamsec/new.json', 'json', 'hourly', 1, 'Reddit API terms; personal, identified use', NULL, NULL),
('hn-algolia',      'Hacker News (security terms)',       'article', 'news', 'https://hn.algolia.com/api/v1/search_by_date?tags=story', 'json', 'hourly', 1, NULL, NULL, 'Query terms come from app_settings.hn_terms.');
