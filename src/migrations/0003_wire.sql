-- M1 Wire: conditional requests, duplicate detection across sources, full-text search,
-- and the feed URLs confirmed on 2026-10-14.

ALTER TABLE sources ADD COLUMN etag TEXT;
ALTER TABLE sources ADD COLUMN last_modified TEXT;
ALTER TABLE sources ADD COLUMN last_duration_ms INTEGER;
ALTER TABLE sources ADD COLUMN fetch_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE items ADD COLUMN canonical_url TEXT;
CREATE INDEX items_canonical ON items (canonical_url);

-- CISA publishes RSS after all; the listing page is no longer needed.
UPDATE sources SET url = 'https://www.cisa.gov/cybersecurity-advisories/all.xml', format = 'rss', kind = 'article',
  notes = 'All CISA advisories, alerts, ICS advisories and analysis reports in one feed.'
  WHERE id = 'cisa-advisories';
UPDATE sources SET url = 'https://hn.algolia.com/api/v1/search_by_date?tags=story&query=security&numericFilters=points%3E10&hitsPerPage=50',
  notes = 'Stories matching "security" with more than 10 points.'
  WHERE id = 'hn-algolia';
UPDATE sources SET url = 'https://www.reddit.com/r/netsec/new.json?limit=50&raw_json=1' WHERE id = 'reddit-netsec';
UPDATE sources SET url = 'https://www.reddit.com/r/cybersecurity/new.json?limit=50&raw_json=1' WHERE id = 'reddit-cybersecurity';
UPDATE sources SET url = 'https://www.reddit.com/r/blueteamsec/new.json?limit=50&raw_json=1' WHERE id = 'reddit-blueteamsec';

-- Full-text search over the timeline, kept in step by triggers.
CREATE VIRTUAL TABLE items_fts USING fts5(title, summary, content='items', content_rowid='id', tokenize='unicode61');
CREATE TRIGGER items_fts_insert AFTER INSERT ON items BEGIN
  INSERT INTO items_fts (rowid, title, summary) VALUES (new.id, new.title, new.summary);
END;
CREATE TRIGGER items_fts_delete AFTER DELETE ON items BEGIN
  INSERT INTO items_fts (items_fts, rowid, title, summary) VALUES ('delete', old.id, old.title, old.summary);
END;
CREATE TRIGGER items_fts_update AFTER UPDATE OF title, summary ON items BEGIN
  INSERT INTO items_fts (items_fts, rowid, title, summary) VALUES ('delete', old.id, old.title, old.summary);
  INSERT INTO items_fts (rowid, title, summary) VALUES (new.id, new.title, new.summary);
END;
