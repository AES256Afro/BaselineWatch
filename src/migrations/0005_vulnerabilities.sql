-- M2 Vulnerabilities: one row per CVE as NVD describes it, joined with CISA KEV and FIRST EPSS,
-- plus the change history BaselineWatch observes between fetches. Vulnerability data is a
-- stream, not a document, so it is normalised on arrival and not kept as raw snapshots.

CREATE TABLE vulns (
  id                INTEGER PRIMARY KEY,
  cve_id            TEXT NOT NULL UNIQUE,
  source_identifier TEXT,
  published_at      TEXT,
  last_modified_at  TEXT NOT NULL,
  vuln_status       TEXT,
  description       TEXT,
  cvss_version      TEXT,              -- '4.0', '3.1', '3.0', '2.0'
  cvss_score        REAL,
  cvss_severity     TEXT,              -- CRITICAL, HIGH, MEDIUM, LOW, NONE
  cvss_vector       TEXT,
  cvss_source       TEXT,              -- who scored it: nvd@nist.gov or the CNA
  ssvc_json         TEXT,              -- CISA SSVC decision point values, when present
  cwes_json         TEXT,              -- ["CWE-78"]
  cpes_json         TEXT,              -- ["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", ...] vulnerable criteria only
  vendors_json      TEXT,              -- ["fortinet"] derived from the CPEs
  products_json     TEXT,              -- ["fortios"]
  references_json   TEXT,              -- [{"url":...,"tags":[...]}]
  kev               INTEGER NOT NULL DEFAULT 0 CHECK (kev IN (0, 1)),
  kev_date_added    TEXT,
  kev_due_date      TEXT,
  kev_ransomware    INTEGER,
  epss              REAL,
  epss_percentile   REAL,
  epss_date         TEXT,
  watch_hit         INTEGER NOT NULL DEFAULT 0 CHECK (watch_hit IN (0, 1)),
  watch_labels_json TEXT,              -- which watchlist entries matched
  first_seen_at     TEXT NOT NULL,
  last_seen_at      TEXT NOT NULL
);
CREATE INDEX vulns_modified ON vulns (last_modified_at DESC);
CREATE INDEX vulns_published ON vulns (published_at DESC);
CREATE INDEX vulns_score ON vulns (cvss_score DESC);
CREATE INDEX vulns_epss ON vulns (epss DESC);
CREATE INDEX vulns_kev ON vulns (kev, kev_date_added DESC);
CREATE INDEX vulns_watch ON vulns (watch_hit, last_modified_at DESC);

-- What changed on a CVE between two sightings, field by field.
CREATE TABLE vuln_changes (
  id              INTEGER PRIMARY KEY,
  cve_id          TEXT NOT NULL,
  observed_at     TEXT NOT NULL,
  nvd_modified_at TEXT,
  field           TEXT NOT NULL,       -- 'new', 'cvss', 'description', 'cpes', 'references', 'cwes', 'status', 'kev', 'epss'
  before_text     TEXT,
  after_text      TEXT
);
CREATE INDEX vuln_changes_by_cve ON vuln_changes (cve_id, observed_at DESC);
CREATE INDEX vuln_changes_recent ON vuln_changes (observed_at DESC);

CREATE VIRTUAL TABLE vulns_fts USING fts5(cve_id, description, vendors, products, content='vulns', content_rowid='id', tokenize='unicode61');
CREATE TRIGGER vulns_fts_insert AFTER INSERT ON vulns BEGIN
  INSERT INTO vulns_fts (rowid, cve_id, description, vendors, products) VALUES (new.id, new.cve_id, new.description, new.vendors_json, new.products_json);
END;
CREATE TRIGGER vulns_fts_delete AFTER DELETE ON vulns BEGIN
  INSERT INTO vulns_fts (vulns_fts, rowid, cve_id, description, vendors, products) VALUES ('delete', old.id, old.cve_id, old.description, old.vendors_json, old.products_json);
END;
CREATE TRIGGER vulns_fts_update AFTER UPDATE OF description, vendors_json, products_json ON vulns BEGIN
  INSERT INTO vulns_fts (vulns_fts, rowid, cve_id, description, vendors, products) VALUES ('delete', old.id, old.cve_id, old.description, old.vendors_json, old.products_json);
  INSERT INTO vulns_fts (rowid, cve_id, description, vendors, products) VALUES (new.id, new.cve_id, new.description, new.vendors_json, new.products_json);
END;

-- The NVD and EPSS sources pull on their own schedule rather than fetching one document.
UPDATE sources SET schedule = 'hourly', notes = 'Incremental: every CVE modified since the last pull, in 120-day windows of 2,000. First run backfills BW_NVD_BACKFILL_DAYS (default 7).' WHERE id = 'nvd-cves';
UPDATE sources SET enabled = 0, notes = 'Change history is computed by BaselineWatch from successive NVD records; this endpoint is not needed yet.' WHERE id = 'nvd-cve-history';
UPDATE sources SET schedule = 'daily', notes = 'Daily bulk scores joined onto every CVE BaselineWatch knows.' WHERE id = 'first-epss';
