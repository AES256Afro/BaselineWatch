-- M12.3 "This network": the daily LAN scan. Each run is one row in net_scans (the resolver the
-- server discovered, the upstream a resolver-identity query named, the DoH-from-LAN answer, the
-- client count a Pi-hole or AdGuard Home reported when the owner saved a token, and what moved
-- since the previous run as JSON) and one row per canary in net_canaries with the answer verbatim.
-- The canary names come from the Register's blocklist sources at scan time and are only ever
-- resolved, never fetched. The scan is opt-in (app_settings 'netscan.enabled'): it sends packets
-- on the owner's network, so nothing runs until the owner turns it on.

CREATE TABLE net_scans (
  id              INTEGER PRIMARY KEY,
  started_at      TEXT NOT NULL,
  finished_at     TEXT,
  resolver        TEXT,                          -- the address the canaries were resolved through
  resolver_source TEXT,                          -- 'dhcp lease', 'resolv.conf', 'systemd-resolved'
  upstream        TEXT,                          -- what the identity query named, or NULL
  doh             TEXT CHECK (doh IN ('reachable', 'blocked', 'not-tested')),
  clients_seen    INTEGER,                       -- from the Pi-hole or AdGuard Home API, when a token is saved
  clients_source  TEXT,                          -- 'pihole' | 'adguard'
  changes_json    TEXT,                          -- day-over-day: newly resolving, newly sinkholed, resolver changed
  error           TEXT                           -- why a run found nothing (no resolver), never a secret
);

CREATE TABLE net_canaries (
  id        INTEGER PRIMARY KEY,
  scan_id   INTEGER NOT NULL REFERENCES net_scans(id) ON DELETE CASCADE,
  category  TEXT NOT NULL,                       -- 'ads', 'trackers', 'malware', 'phishing', 'adfection'
  source_id TEXT NOT NULL,                       -- the Register source the name came from
  name      TEXT NOT NULL,
  outcome   TEXT NOT NULL CHECK (outcome IN ('resolved', 'sinkholed', 'timeout')),
  answer    TEXT,                                -- the addresses or the error code, verbatim
  UNIQUE (scan_id, category, name)
);
CREATE INDEX net_canaries_by_scan ON net_canaries (scan_id, category);
