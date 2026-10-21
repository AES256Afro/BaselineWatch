-- More feeds (added 2026-10-21, N5): what the security aggregators carry that this instance did
-- not — CERT/CC's vulnerability notes (advisories with CVEs, in the vulnerabilities group), and
-- six research blogs whose posts name the CVEs they find. Each was probed and answers real RSS or
-- Atom; each replays its real file in a test.
INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('certcc', 'CERT/CC Vulnerability Notes', 'article', 'vulnerabilities', 'https://kb.cert.org/vuls/atomfeed/', 'atom', 'daily', 1, NULL, 'CERT Coordination Center, Carnegie Mellon University', 'VU# notes: coordinated disclosures with the vendors'' statements, each naming its CVEs.'),
('microsoft-security-blog', 'Microsoft Security Blog', 'article', 'news', 'https://www.microsoft.com/en-us/security/blog/feed/', 'rss', 'daily', 1, NULL, 'Microsoft', 'Threat intelligence and product posts; the campaign write-ups name their CVEs.'),
('rapid7-blog', 'Rapid7 blog', 'article', 'news', 'https://www.rapid7.com/blog/rss/', 'rss', 'daily', 1, NULL, 'Rapid7', 'Emergent-threat responses and Patch Tuesday round-ups, each naming its CVEs.'),
('sentinellabs', 'SentinelLABS', 'article', 'news', 'https://www.sentinelone.com/labs/feed/', 'rss', 'daily', 1, NULL, 'SentinelOne', 'Research on campaigns and tooling.'),
('greynoise', 'GreyNoise blog', 'article', 'news', 'https://www.greynoise.io/blog/rss.xml', 'rss', 'daily', 1, NULL, 'GreyNoise', 'What is being scanned and exploited across the internet, by sensor.'),
('wiz-blog', 'Wiz blog', 'article', 'news', 'https://www.wiz.io/feed/rss.xml', 'rss', 'daily', 1, NULL, 'Wiz', 'Cloud and supply-chain research; the vulnerability posts name their CVEs. The feed carries the whole archive, so the first read is large.'),
('huntress-blog', 'Huntress blog', 'article', 'news', 'https://www.huntress.com/blog/rss.xml', 'rss', 'daily', 1, NULL, 'Huntress', 'Tradecraft and campaign write-ups from the SOC. The feed carries the whole archive, so the first read is large.');
