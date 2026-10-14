-- BaselineWatch schema v1.
-- One pipeline for every source: snapshot -> document (normalised) -> changes -> explanations.
-- The timeline (items) and the user's own state (triage, watchlist) sit beside it.
-- Timestamps are ISO 8601 text in UTC.

CREATE TABLE sources (
  id            TEXT PRIMARY KEY,                 -- 'nist-sp-800-53', 'cisa-kev', 'bleeping'
  name          TEXT NOT NULL,
  kind          TEXT NOT NULL CHECK (kind IN ('article', 'vulnerability', 'requirement-set', 'setting-set', 'listing')),
  group_name    TEXT NOT NULL CHECK (group_name IN ('standards', 'vulnerabilities', 'news')),
  url           TEXT NOT NULL,
  format        TEXT NOT NULL,                    -- 'rss', 'atom', 'json', 'csv', 'oscal-json', 'cprt-json', 'xccdf-zip', 'sct-zip', 'pdf-upload', 'git', 'html'
  schedule      TEXT NOT NULL CHECK (schedule IN ('hourly', 'daily', 'weekly', 'manual')),
  enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  licence       TEXT,
  attribution   TEXT,
  notes         TEXT,
  last_fetch_at TEXT,
  last_status   TEXT,                             -- 'ok', 'unchanged', 'error'
  last_error    TEXT,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- The exact bytes of every fetched document, content-addressed on disk under <data>/blobs.
CREATE TABLE snapshots (
  id            INTEGER PRIMARY KEY,
  source_id     TEXT NOT NULL REFERENCES sources(id),
  document_key  TEXT NOT NULL,                    -- which document within the source, e.g. 'NIST_SP-800-53_rev5_catalog.json'
  sha256        TEXT NOT NULL,
  bytes         INTEGER NOT NULL,
  media_type    TEXT,
  blob_path     TEXT NOT NULL,                    -- relative to the data dir: blobs/ab/ab12...
  fetched_at    TEXT NOT NULL,
  etag          TEXT,
  last_modified TEXT,
  UNIQUE (source_id, document_key, sha256)
);
CREATE INDEX snapshots_by_document ON snapshots (source_id, document_key, fetched_at);

-- One parsed, normalised version of a document. A snapshot that parsed gets exactly one document.
CREATE TABLE documents (
  id            INTEGER PRIMARY KEY,
  source_id     TEXT NOT NULL REFERENCES sources(id),
  document_key  TEXT NOT NULL,
  snapshot_id   INTEGER NOT NULL UNIQUE REFERENCES snapshots(id),
  version_label TEXT,                             -- '5.2.0', 'V2R2', '2602'
  title         TEXT,
  published_at  TEXT,
  parsed_at     TEXT NOT NULL
);
CREATE INDEX documents_by_document ON documents (source_id, document_key, published_at);

-- requirement-set shape: a control, a STIG rule, a CIS recommendation, an 800-171 requirement.
CREATE TABLE requirements (
  id             INTEGER PRIMARY KEY,
  document_id    INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  ref            TEXT NOT NULL,                   -- 'si-7.12', 'SV-254238r958472_rule', '1.1.1'
  parent_ref     TEXT,
  family         TEXT,                            -- 'SI', 'SA' for 800-53; section for others
  title          TEXT,
  statement      TEXT,
  guidance       TEXT,                            -- discussion / rationale / check text
  severity       TEXT,                            -- CAT I/II/III, Level 1/2, or NULL
  params_json    TEXT,                            -- organisation-defined parameters
  related_json   TEXT,                            -- related control ids
  baselines_json TEXT,                            -- ['low','moderate','high','privacy']
  extra_json     TEXT,                            -- fix text, CCIs, anything format-specific
  UNIQUE (document_id, ref)
);

-- setting-set shape: Microsoft baseline rows, CIS values.
CREATE TABLE baseline_settings (
  id             INTEGER PRIMARY KEY,
  document_id    INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  ref            TEXT NOT NULL,                   -- policy path + setting name, stable across releases
  scope          TEXT,                            -- 'MS', 'DC', 'User'
  name           TEXT NOT NULL,
  value          TEXT,
  rationale      TEXT,
  extra_json     TEXT,
  UNIQUE (document_id, ref, scope)
);

-- Field-level differences between two consecutive documents of the same document_key.
CREATE TABLE changes (
  id               INTEGER PRIMARY KEY,
  source_id        TEXT NOT NULL REFERENCES sources(id),
  document_key     TEXT NOT NULL,
  from_document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
  to_document_id   INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  ref              TEXT NOT NULL,
  kind             TEXT NOT NULL CHECK (kind IN ('added', 'removed', 'modified')),
  field            TEXT,                          -- 'title', 'statement', 'guidance', 'params', 'related', 'baselines', 'value'; NULL for added/removed
  before_text      TEXT,
  after_text       TEXT,
  computed_at      TEXT NOT NULL
);
CREATE INDEX changes_by_release ON changes (to_document_id, ref);
CREATE INDEX changes_by_source ON changes (source_id, computed_at);

-- Why a change happened. 'publisher' is quoted from the release notes; 'generated' is an LLM summary and is
-- always shown badged; 'none' records that the publisher gave no reason, so the gap is explicit.
CREATE TABLE explanations (
  id             INTEGER PRIMARY KEY,
  change_id      INTEGER REFERENCES changes(id) ON DELETE CASCADE,
  to_document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,   -- release-level rationale when change_id is NULL
  kind           TEXT NOT NULL CHECK (kind IN ('publisher', 'generated', 'none')),
  text           TEXT NOT NULL,
  source_url     TEXT,
  created_at     TEXT NOT NULL,
  CHECK (change_id IS NOT NULL OR to_document_id IS NOT NULL)
);
CREATE INDEX explanations_by_change ON explanations (change_id);
CREATE INDEX explanations_by_release ON explanations (to_document_id);

-- The timeline: an article, a vulnerability event, a KEV addition, a standard's release.
CREATE TABLE items (
  id           INTEGER PRIMARY KEY,
  source_id    TEXT NOT NULL REFERENCES sources(id),
  kind         TEXT NOT NULL CHECK (kind IN ('article', 'vulnerability', 'kev', 'release')),
  external_id  TEXT NOT NULL,                     -- feed guid, CVE id, or document_key@version
  title        TEXT NOT NULL,
  url          TEXT,
  summary      TEXT,
  published_at TEXT,
  fetched_at   TEXT NOT NULL,
  signals_json TEXT,                              -- {"cvss":9.8,"epss":0.94,"kev":true,"products":["fortios"]}
  read         INTEGER NOT NULL DEFAULT 0 CHECK (read IN (0, 1)),
  starred      INTEGER NOT NULL DEFAULT 0 CHECK (starred IN (0, 1)),
  UNIQUE (source_id, external_id)
);
CREATE INDEX items_timeline ON items (published_at DESC, id DESC);
CREATE INDEX items_unread ON items (read, published_at DESC);

-- The user's state on any item or change.
CREATE TABLE triage (
  id           INTEGER PRIMARY KEY,
  subject_kind TEXT NOT NULL CHECK (subject_kind IN ('item', 'change')),
  subject_id   INTEGER NOT NULL,
  state        TEXT NOT NULL CHECK (state IN ('new', 'reviewing', 'affects', 'done', 'dismissed')),
  note         TEXT,
  due_at       TEXT,
  updated_at   TEXT NOT NULL,
  UNIQUE (subject_kind, subject_id)
);

-- What the user owns: products (CPE prefixes or keywords), baselines, control families, free keywords.
CREATE TABLE watchlist (
  id         INTEGER PRIMARY KEY,
  kind       TEXT NOT NULL CHECK (kind IN ('product', 'baseline', 'family', 'keyword')),
  value      TEXT NOT NULL,
  label      TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (kind, value)
);

CREATE TABLE app_settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
