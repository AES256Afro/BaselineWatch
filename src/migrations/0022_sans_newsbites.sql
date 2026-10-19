-- SANS NewsBites, the twice-weekly news digest. SANS publishes no feed for it (the ISC diaries
-- feed already carried is separate), so the adapter parses the newsletter web pages themselves:
-- the index for the newest issues, then each new issue page once, one item per story.
INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('sans-newsbites', 'SANS NewsBites', 'article', 'news', 'https://www.sans.org/newsletters/newsbites', 'html', 'daily', 1, NULL, NULL, 'Parsed from the newsletter web pages, because SANS publishes no NewsBites feed; each issue page is fetched once.');
