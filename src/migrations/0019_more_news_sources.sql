-- More free news and research feeds, each verified answering with real XML before seeding
-- (2026-10-19), and three more subreddits through the existing reddit adapter. Ars Technica's
-- security feed and Sophos News were checked too and answer 404; they stay out until they do.
INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('theregister',     'The Register · Security',            'article', 'news', 'https://www.theregister.com/security/headlines.atom', 'rss', 'hourly', 1, NULL, NULL, 'The .atom path serves RSS 2.0; the feed adapter reads either.'),
('talos',           'Cisco Talos Intelligence',           'article', 'news', 'https://blog.talosintelligence.com/rss/', 'rss', 'daily', 1, NULL, NULL, NULL),
('unit42',          'Unit 42 (Palo Alto Networks)',       'article', 'news', 'https://unit42.paloaltonetworks.com/feed/', 'rss', 'daily', 1, NULL, NULL, NULL),
('securelist',      'Securelist (Kaspersky GReAT)',       'article', 'news', 'https://securelist.com/feed/', 'rss', 'daily', 1, NULL, NULL, NULL),
('welivesecurity',  'WeLiveSecurity (ESET)',              'article', 'news', 'https://www.welivesecurity.com/en/rss/feed/', 'rss', 'daily', 1, NULL, NULL, NULL),
('troyhunt',        'Troy Hunt',                          'article', 'news', 'https://www.troyhunt.com/rss/', 'rss', 'daily', 1, NULL, NULL, NULL),
('grahamcluley',    'Graham Cluley',                      'article', 'news', 'https://grahamcluley.com/feed/', 'rss', 'daily', 1, NULL, NULL, NULL),
('watchtowr',       'watchTowr Labs',                     'article', 'news', 'https://labs.watchtowr.com/rss/', 'rss', 'daily', 1, NULL, NULL, NULL),
('securityaffairs', 'Security Affairs',                   'article', 'news', 'https://securityaffairs.com/feed', 'rss', 'daily', 1, NULL, NULL, NULL),
('citizenlab',      'The Citizen Lab',                    'article', 'news', 'https://citizenlab.ca/feed/', 'rss', 'daily', 1, NULL, NULL, NULL),
('reddit-asknetsec',          'r/AskNetsec',              'article', 'news', 'https://www.reddit.com/r/AskNetsec/new.json?limit=50&raw_json=1', 'json', 'hourly', 1, 'Reddit API terms; personal, identified use', NULL, 'Descriptive User-Agent, at most every 10 minutes, back off on 429.'),
('reddit-malware',            'r/Malware',                'article', 'news', 'https://www.reddit.com/r/Malware/new.json?limit=50&raw_json=1', 'json', 'hourly', 1, 'Reddit API terms; personal, identified use', NULL, 'Descriptive User-Agent, at most every 10 minutes, back off on 429.'),
('reddit-reverseengineering', 'r/ReverseEngineering',     'article', 'news', 'https://www.reddit.com/r/ReverseEngineering/new.json?limit=50&raw_json=1', 'json', 'hourly', 1, 'Reddit API terms; personal, identified use', NULL, 'Descriptive User-Agent, at most every 10 minutes, back off on 429.');
