-- Article images for the News page, pulled passively at ingest: from the feed's own media
-- (enclosure, media:content, an <img> in content:encoded) or, when a feed carries none, the
-- article page's og:image fetched once. The bytes live in the content-addressed blob store;
-- only hashes recorded here are ever served (at /img/<hash>), so snapshots stay private.
ALTER TABLE items ADD COLUMN image_blob TEXT;
ALTER TABLE items ADD COLUMN image_type TEXT;
ALTER TABLE items ADD COLUMN image_origin TEXT CHECK (image_origin IN ('enclosure', 'body', 'og'));
CREATE INDEX items_image_blob ON items (image_blob) WHERE image_blob IS NOT NULL;
