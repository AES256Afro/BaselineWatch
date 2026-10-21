-- Vendor sources (added 2026-10-21, N5 of the night plan). Microsoft's Security Update Guide is
-- read through its CVRF API: one row per CVE here, with the KB that fixes it on each product and
-- Microsoft's own word on severity and exploitation, so the Fix panel can say "KB5127648 for
-- Windows 11 24H2" and the table can mark what Microsoft says is exploited. Apple and Mozilla
-- publish no feeds; their index pages are read by adapters. The rest are plain feeds.
CREATE TABLE msrc_vulns (
  cve_id         TEXT PRIMARY KEY,
  release_id     TEXT NOT NULL,                   -- '2026-Oct': the monthly document it came from
  title          TEXT NOT NULL,
  family         TEXT,                            -- Microsoft's product tag: 'Windows Kernel', 'Microsoft Office Excel', 'Mariner'
  vendor         TEXT,                            -- 'Microsoft', or the upstream of a republished CVE: 'Chrome', 'Linux', 'apache'
  severity       TEXT,                            -- Microsoft's own: Critical, Important, Moderate, Low
  exploited      INTEGER NOT NULL DEFAULT 0 CHECK (exploited IN (0, 1)),
  disclosed      INTEGER NOT NULL DEFAULT 0 CHECK (disclosed IN (0, 1)),
  exploitability TEXT,                            -- 'Exploitation More Likely', as the guide words it
  cvss_score     REAL,
  cvss_vector    TEXT,
  description    TEXT,
  fixes_json     TEXT NOT NULL,                   -- [{kb, url, label, products, fixedBuild, restart}]
  released_at    TEXT,
  revised_at     TEXT,
  seen_at        TEXT NOT NULL
);
CREATE INDEX msrc_vulns_by_release ON msrc_vulns (release_id);
CREATE INDEX msrc_vulns_flagged ON msrc_vulns (exploited, disclosed);

INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('msrc', 'Microsoft Security Update Guide', 'vulnerability', 'vulnerabilities', 'https://api.msrc.microsoft.com/cvrf/v3.0/updates', 'json', 'daily', 1, 'Microsoft Security Update Guide API, free without a key; Microsoft''s terms of use', 'Microsoft Security Response Center', 'The monthly CVRF documents: every CVE Microsoft publishes, with its severity, exploit status, CVSS and the KB per product. One Wire item per monthly release; the CVEs feed the Fix panel and the exploited mark.'),
('apple-security', 'Apple security releases', 'article', 'vulnerabilities', 'https://support.apple.com/en-us/100100', 'html', 'daily', 1, 'Apple Support content; titles, dates and links only', 'Apple', 'The table of every Apple update with security content, read from the page: each row is one item linking to its support article.'),
('mozilla-mfsa', 'Mozilla Foundation Security Advisories', 'article', 'vulnerabilities', 'https://www.mozilla.org/en-US/security/advisories/', 'html', 'daily', 1, 'CC BY-SA 3.0 (mozilla.org)', 'Mozilla', 'The MFSA index, read from the page: each advisory is one item with its impact rating and the product and version it fixes.'),
('zdi-published', 'Zero Day Initiative: published advisories', 'article', 'vulnerabilities', 'https://www.zerodayinitiative.com/rss/published/', 'rss', 'daily', 1, NULL, 'Trend Micro Zero Day Initiative', 'ZDI advisories as they are published, each naming its CVE and vendor.'),
('zdi-upcoming', 'Zero Day Initiative: upcoming advisories', 'article', 'vulnerabilities', 'https://www.zerodayinitiative.com/rss/upcoming/', 'rss', 'daily', 1, NULL, 'Trend Micro Zero Day Initiative', 'Flaws ZDI has reported to a vendor and will publish: the vendor named, the details not yet. No other source carries what is coming.'),
('hashicorp-security', 'HashiCorp security bulletins', 'article', 'vulnerabilities', 'https://discuss.hashicorp.com/c/security/52.rss', 'rss', 'daily', 1, NULL, 'HashiCorp', 'HCSEC bulletins for Vault, Terraform, Consul, Nomad and the rest, from the Discourse category feed.'),
('aws-security-bulletins', 'AWS Security Bulletins', 'article', 'vulnerabilities', 'https://aws.amazon.com/security/security-bulletins/rss/feed/', 'rss', 'daily', 1, NULL, 'Amazon Web Services', 'AWS security bulletins; each names its CVEs.'),
('cisco-talos', 'Cisco Talos blog', 'article', 'news', 'https://blog.talosintelligence.com/rss/', 'rss', 'hourly', 1, NULL, 'Cisco Talos', 'Threat research and vulnerability reports from Talos.');
