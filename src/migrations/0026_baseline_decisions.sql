-- Baseline decisions: the owner's decision on each item of a platform's baseline, beside the publisher's
-- recommendation. No row means the recommendation stands: apply it as published. "modify" keeps
-- the item with the organisation's own value; "exclude" drops it from the baseline, its exports
-- and its test plan. Item ids are the builder's (stig:<rule ref>, mscp:<rule id>, sct:<ref>,
-- control:<ref>), which hold across releases of the same STIG or branch.
CREATE TABLE baseline_decisions (
  platform   TEXT NOT NULL,
  item_id    TEXT NOT NULL,
  decision   TEXT NOT NULL CHECK (decision IN ('apply', 'modify', 'exclude')),
  value      TEXT,
  reason     TEXT,
  owner      TEXT,
  decided_at TEXT NOT NULL,
  PRIMARY KEY (platform, item_id)
);
