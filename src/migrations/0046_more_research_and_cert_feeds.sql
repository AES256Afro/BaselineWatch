-- More feeds, from the sources survey of the audit of 28 October: each answered with real XML
-- when checked that day, and each reads through the generic feed adapter (RSS, Atom or RDF), so
-- a row is all it takes. Headlines and links only, as every feed here: nothing is republished.
INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('mandiant',            'Google Threat Intelligence (Mandiant)',  'article', 'news', 'https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v', 'rss', 'daily', 1, NULL, 'Google Threat Intelligence', 'Mandiant''s research blog, now under Google Threat Intelligence. A large feed (about 1.4 MB a read); fetched daily.'),
('checkpoint-research', 'Check Point Research',                   'article', 'news', 'https://research.checkpoint.com/feed/', 'rss', 'daily', 1, NULL, 'Check Point Research', 'Threat and vulnerability research.'),
('sophos-xops',         'Sophos X-Ops',                           'article', 'news', 'https://www.sophos.com/en-us/category/threat-research/feed', 'rss', 'daily', 1, NULL, 'Sophos', 'Threat research; the old news.sophos.com address redirects here.'),
('portswigger-research','PortSwigger Research',                   'article', 'news', 'https://portswigger.net/research/rss', 'rss', 'daily', 1, NULL, 'PortSwigger', 'Web security research: new attack classes, often with the technique named.'),
('lobsters-security',   'Lobsters · security',                    'article', 'news', 'https://lobste.rs/t/security.rss', 'rss', 'hourly', 1, NULL, 'lobste.rs', 'Links the community submits under the security tag; a story starts here, it is reported elsewhere.'),
('tldrsec',             'tl;dr sec',                              'article', 'news', 'https://rss.beehiiv.com/feeds/xgTKUmMmUm.xml', 'rss', 'weekly', 1, NULL, 'Clint Gibler, tl;dr sec', 'A weekly newsletter of the week''s security reading; one item a week.'),
('horizon3',            'Horizon3.ai attack research',            'article', 'news', 'https://horizon3.ai/feed/', 'rss', 'daily', 1, NULL, 'Horizon3.ai', 'Exploit write-ups that usually name the CVE, often before a public proof of concept.'),
('dfir-report',         'The DFIR Report',                        'article', 'news', 'https://thedfirreport.com/feed/', 'rss', 'daily', 1, NULL, 'The DFIR Report', 'Intrusion case studies, start to finish; a post every month or two.'),
('ars-security',        'Ars Technica · Security',                'article', 'news', 'https://arstechnica.com/security/feed/', 'rss', 'hourly', 1, NULL, 'Ars Technica', 'Answering since October 2026; migration 0019 found it 404.'),
('ivanti-advisories',   'Ivanti security advisories',             'article', 'vulnerabilities', 'https://www.ivanti.com/blog/topics/security-advisory/rss', 'rss', 'daily', 1, NULL, 'Ivanti', 'Each advisory names its CVEs.'),
('cccs-advisories',     'Canadian Centre for Cyber Security',     'article', 'vulnerabilities', 'https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en', 'atom', 'daily', 1, 'Crown copyright; non-commercial reuse with attribution', 'Canadian Centre for Cyber Security', 'Alerts and advisories, many restating a vendor''s with the products named.'),
('cert-eu',             'CERT-EU security advisories',            'article', 'vulnerabilities', 'https://www.cert.europa.eu/publications/security-advisories-rss', 'rss', 'daily', 1, 'EU reuse policy, with attribution', 'CERT-EU', 'Advisories for EU institutions, with the CVEs and the fix.'),
('jpcert-en',           'JPCERT/CC (English)',                    'article', 'vulnerabilities', 'https://www.jpcert.or.jp/english/rss/jpcert-en.rdf', 'rss', 'daily', 1, NULL, 'JPCERT/CC', 'RDF; few items. The feed adapter reads rdf:RDF.'),
('k8s-cve-feed',        'Kubernetes official CVE feed',           'article', 'vulnerabilities', 'https://kubernetes.io/docs/reference/issues-security/official-cve-feed/feed.xml', 'rss', 'daily', 1, 'CC BY 4.0', 'The Kubernetes Authors', 'Every CVE the Kubernetes project announces. Probed and refused in October 2026; this feed now answers.');

-- Two corrections the survey found in rows already here. Project Zero moved to its own domain
-- and the old address only redirects to it. Talos was seeded twice (0019 and 0036, the same URL),
-- so every post arrived twice; the older row stops fetching and keeps what it already holds.
UPDATE sources SET url = 'https://projectzero.google/feed.xml', format = 'rss' WHERE id = 'projectzero' AND url = 'https://googleprojectzero.blogspot.com/feeds/posts/default';
UPDATE sources SET enabled = 0, notes = 'The same feed as cisco-talos (migration 0036); stopped by 0046 so each post arrives once.' WHERE id = 'talos';

-- "The Wire" became the News on 19 October; the notes three migrations wrote still said Wire.
UPDATE sources SET notes = replace(notes, 'Wire item', 'News item') WHERE notes LIKE '%Wire item%';
