-- More advisory feeds for the Wire (checked 2026-10-15): CISA's industrial control systems
-- advisories, and the security releases of three products many teams run or ship with, in the
-- vulnerabilities group so the Wire files them with the other vendor advisories; and Google's
-- security blog as news.

INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('cisa-ics-advisories', 'CISA ICS Advisories',             'article', 'vulnerabilities', 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml', 'rss', 'hourly', 1, 'US Government work, public domain', NULL, 'Industrial control systems advisories (ICSA, ICSMA) as CISA publishes them; each names its CVEs and the affected products.'),
('chrome-releases',     'Google Chrome stable releases',   'article', 'vulnerabilities', 'https://chromereleases.googleblog.com/feeds/posts/default/-/Stable%20updates', 'atom', 'daily', 1, NULL, NULL, 'Stable channel updates for desktop and mobile; each lists the security fixes and their CVEs.'),
('gitlab-security',     'GitLab security releases',        'article', 'vulnerabilities', 'https://about.gitlab.com/security-releases.xml', 'atom', 'daily', 1, NULL, NULL, 'Patch and security releases with the CVEs each fixes.'),
('jenkins-security',    'Jenkins security advisories',     'article', 'vulnerabilities', 'https://www.jenkins.io/security/advisories/rss.xml', 'rss', 'daily', 1, NULL, NULL, 'Core and plugin advisories, each naming its CVEs.'),
('google-security-blog', 'Google Security Blog',           'article', 'news', 'https://security.googleblog.com/feeds/posts/default', 'atom', 'daily', 1, NULL, NULL, NULL);
