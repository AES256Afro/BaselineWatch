-- Reddit has refused this product's feed requests since 2026-11-17: on the public instance every
-- subreddit's newest item was fetched that day between 11:36 and 17:42 UTC and none since, while
-- every other source kept arriving, and from GitHub's runners and a home connection alike Reddit
-- answers 429 or an Atom "Not Found" 404 to any subreddit, at random. An hourly request to each of
-- fourteen feeds that all fail is noise in the log and the nightly probe. Stopped rather than
-- deleted: the items they brought in stay, and the owner can turn one back on from the Sources page.
UPDATE sources
   SET enabled = 0,
       notes = trim(coalesce(notes, '') || ' Stopped by migration 0080: Reddit refused every feed request from 2026-11-17.')
 WHERE id LIKE 'reddit-%' AND enabled = 1;
