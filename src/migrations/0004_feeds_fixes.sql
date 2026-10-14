-- Fixes from the first live fetch on 2026-10-14.

-- Reddit answers 403 to the JSON listing for anything but a browser or an OAuth app, but serves
-- the Atom feed to an identified client.
UPDATE sources SET url = 'https://www.reddit.com/r/netsec/new.rss?limit=50', format = 'atom' WHERE id = 'reddit-netsec';
UPDATE sources SET url = 'https://www.reddit.com/r/cybersecurity/new.rss?limit=50', format = 'atom' WHERE id = 'reddit-cybersecurity';
UPDATE sources SET url = 'https://www.reddit.com/r/blueteamsec/new.rss?limit=50', format = 'atom' WHERE id = 'reddit-blueteamsec';

-- The MSRC blog moved to microsoft.com/en-us/msrc/blog with no feed. The Security Update Guide
-- feed exists but lists every Microsoft CVE (thousands of entries), which is vulnerability data
-- for M2, not news for the Wire. Kept, pointed at the feed, and switched off until M2 reads it
-- as a vulnerability source.
UPDATE sources SET name = 'MSRC Security Update Guide', url = 'https://api.msrc.microsoft.com/update-guide/rss', format = 'rss',
  kind = 'vulnerability', group_name = 'vulnerabilities', enabled = 0,
  notes = 'Every Microsoft CVE and update, thousands of entries. Joins the Vulnerabilities view in M2. The MSRC blog itself no longer offers a feed.'
  WHERE id = 'msrc-blog';
