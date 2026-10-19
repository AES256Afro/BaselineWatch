-- The three subreddits seeded in 0019 copied 0002's JSON listing form, which Reddit refuses to
-- anything but a browser or an OAuth app (HTTP 403, immediately and every time). The three older
-- subreddits were moved to the Atom feed in 0004 for exactly this reason; these follow.
UPDATE sources SET url = 'https://www.reddit.com/r/asknetsec/new.rss?limit=50', format = 'atom' WHERE id = 'reddit-asknetsec';
UPDATE sources SET url = 'https://www.reddit.com/r/malware/new.rss?limit=50', format = 'atom' WHERE id = 'reddit-malware';
UPDATE sources SET url = 'https://www.reddit.com/r/reverseengineering/new.rss?limit=50', format = 'atom' WHERE id = 'reddit-reverseengineering';
UPDATE sources SET last_status = NULL, last_error = NULL WHERE id IN ('reddit-asknetsec', 'reddit-malware', 'reddit-reverseengineering');
