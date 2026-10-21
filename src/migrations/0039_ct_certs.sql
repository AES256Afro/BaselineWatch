-- Certificate transparency (added 2026-10-21, Scan 2.0 S3): for each domain the owner listed on
-- the domain check, the certificates the public CT logs hold for it, read from crt.sh once a day.
-- A certificate issued since the last read is one Wire item, which is how a lookalike or a stray
-- issuance is caught the day it happens. The first read of a domain seeds the table in silence.
CREATE TABLE ct_certs (
  domain     TEXT NOT NULL,
  id         INTEGER NOT NULL,                   -- crt.sh's id for the certificate
  issuer     TEXT,
  names      TEXT NOT NULL,                      -- the names on it, newline-separated as crt.sh gives them
  not_before TEXT,
  not_after  TEXT,
  seen_at    TEXT NOT NULL,
  PRIMARY KEY (domain, id)
);

INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('crtsh', 'Certificate transparency (crt.sh)', 'listing', 'news', 'https://crt.sh/', 'json', 'daily', 1, 'crt.sh by Sectigo; the CT logs are public', 'crt.sh', 'For each domain the owner listed on the domain check, the certificates the transparency logs hold for it. A certificate issued since the last read is one Wire item. Reads nothing until a domain is listed.');
