-- When an item last came back to the owner's attention: set when a story already read is made
-- unread again because what it reports changed. "Mark all read" is bounded by the moment the page
-- was drawn, so an item that resurfaced after that is not marked read unseen.
ALTER TABLE items ADD COLUMN surfaced_at TEXT;
