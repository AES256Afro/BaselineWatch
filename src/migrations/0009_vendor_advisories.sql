-- Vendor security advisories as feeds, in the vulnerabilities group so the Wire can show them
-- apart from news (checked 2026-10-15), and an index for the Today page's windows.

INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('ubuntu-usn',       'Ubuntu Security Notices',          'article', 'vulnerabilities', 'https://ubuntu.com/security/notices/rss.xml', 'rss', 'hourly', 1, NULL, NULL, 'USNs as published; each names its CVEs.'),
('debian-dsa',       'Debian Security Advisories',       'article', 'vulnerabilities', 'https://www.debian.org/security/dsa', 'rss', 'hourly', 1, NULL, NULL, 'DSAs as published.'),
('cisco-psirt',      'Cisco Security Advisories',        'article', 'vulnerabilities', 'https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml', 'rss', 'hourly', 1, NULL, NULL, 'Cisco PSIRT advisories, all products.'),
('paloalto-psirt',   'Palo Alto Networks Security Advisories', 'article', 'vulnerabilities', 'https://security.paloaltonetworks.com/rss.xml', 'rss', 'hourly', 1, NULL, NULL, NULL),
('fortinet-psirt',   'Fortinet PSIRT Advisories',        'article', 'vulnerabilities', 'https://www.fortiguard.com/rss/ir.xml', 'rss', 'hourly', 1, NULL, NULL, 'FortiGuard PSIRT feed.'),
('redhat-security',  'Red Hat Security Blog',            'article', 'vulnerabilities', 'https://www.redhat.com/en/rss/blog/channel/security', 'rss', 'daily', 1, NULL, NULL, 'Red Hat''s security blog; CSAF/VEX data is a later source.');

CREATE INDEX IF NOT EXISTS items_kind_published ON items (kind, published_at DESC);
