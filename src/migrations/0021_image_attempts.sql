-- Remembers when an item's image was looked for and not found, so neither ingest nor the
-- backfill asks the same page twice for a picture it does not have.
ALTER TABLE items ADD COLUMN image_checked_at TEXT;
