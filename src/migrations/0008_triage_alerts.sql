-- M6: triage on anything, alerts sent, and digests kept.

-- Triage can sit on a timeline item, a CVE, or one requirement in one release. The table is
-- empty before this migration, so it is simply rebuilt with a text key for the last case.
DROP TABLE triage;
CREATE TABLE triage (
  id           INTEGER PRIMARY KEY,
  subject_kind TEXT NOT NULL CHECK (subject_kind IN ('item', 'vuln', 'control')),
  subject_id   INTEGER NOT NULL,                -- items.id, vulns.id, or documents.id
  subject_key  TEXT NOT NULL DEFAULT '',        -- the requirement ref for a control, else ''
  state        TEXT NOT NULL CHECK (state IN ('new', 'reviewing', 'affects', 'done', 'dismissed')),
  note         TEXT,
  due_at       TEXT,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  UNIQUE (subject_kind, subject_id, subject_key)
);
CREATE INDEX triage_by_state ON triage (state, updated_at DESC);

-- Every notification BaselineWatch sent (or failed to send), so the Today view can show them.
CREATE TABLE alerts (
  id         INTEGER PRIMARY KEY,
  kind       TEXT NOT NULL,                     -- 'kev', 'release', 'watch', 'digest'
  title      TEXT NOT NULL,
  body       TEXT,
  url        TEXT,
  sent_at    TEXT NOT NULL,
  status     TEXT NOT NULL,                     -- 'sent', 'failed', 'unconfigured'
  error      TEXT
);
CREATE INDEX alerts_recent ON alerts (sent_at DESC);

CREATE TABLE digests (
  id           INTEGER PRIMARY KEY,
  period       TEXT NOT NULL,                   -- 'daily' | 'weekly'
  covers_from  TEXT NOT NULL,
  covers_to    TEXT NOT NULL,
  generated_at TEXT NOT NULL,
  text         TEXT NOT NULL
);
