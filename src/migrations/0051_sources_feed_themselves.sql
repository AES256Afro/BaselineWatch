-- M20's thin slice: a source the owner adds on the running instance, a source that declares where
-- else its document lives, and a repair the instance found for a failing one, so that keeping the
-- data current stops needing a migration written in a coding session.

-- Where a row came from: seeded by a migration, or added by the owner on the Sources page. Later
-- migrations guard their updates on the old value, so an owner's edit to a seeded row is left alone.
ALTER TABLE sources ADD COLUMN origin TEXT NOT NULL DEFAULT 'seed' CHECK (origin IN ('seed', 'owner'));

-- A JSON array of other addresses that serve the same document, tried in order when the source's
-- own address fails. The one that answered, and what the source's own address said, are kept
-- until the source's own address answers again.
ALTER TABLE sources ADD COLUMN fallback_urls TEXT;
ALTER TABLE sources ADD COLUMN answered_from TEXT;
ALTER TABLE sources ADD COLUMN primary_error TEXT;

-- When the instance last looked for a repair to this source's failure; it looks once a day at most.
ALTER TABLE sources ADD COLUMN repair_checked_at TEXT;

-- Addresses the instance found that answer with the document a failing source expects: probed,
-- parsed, and kept until the owner uses one or the source answers again.
CREATE TABLE source_repairs (
  id         INTEGER PRIMARY KEY,
  source_id  TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  url        TEXT NOT NULL,
  how        TEXT NOT NULL,     -- how it was found, in words: "linked from https://example.com/"
  items      INTEGER NOT NULL,  -- how many entries the probe parsed
  sample     TEXT,              -- the first entry's title, so the owner can see it is the right feed
  found_at   TEXT NOT NULL,
  UNIQUE (source_id, url)
);

-- Every change the owner makes to a source from the Sources page, with what it was before.
CREATE TABLE source_log (
  id         INTEGER PRIMARY KEY,
  source_id  TEXT NOT NULL,
  at         TEXT NOT NULL,
  action     TEXT NOT NULL,     -- 'added', 'address', 'enabled', 'disabled'
  before     TEXT,
  after      TEXT
);
CREATE INDEX source_log_at ON source_log (at);

-- The malware canaries read malware-filter's copy of URLhaus on GitLab Pages (0050); the project
-- publishes the same file on GitHub Pages and Cloudflare Pages too, which are the fallbacks.
UPDATE sources SET fallback_urls = '["https://curbengh.github.io/malware-filter/urlhaus-filter-hosts.txt","https://malware-filter.pages.dev/urlhaus-filter-hosts.txt"]'
WHERE id = 'canary-malware' AND fallback_urls IS NULL;
