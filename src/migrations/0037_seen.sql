-- What this page learned about you (Scan 2.0, S2). The Tor exit list is a source read daily so
-- the panel can say whether the address a visitor came from is a Tor exit; the table holds the
-- current list whole and is replaced on each read. InternetDB is a lookup made on request only,
-- never pulled: declared here so the Sources page names every host this instance may contact.
CREATE TABLE tor_exits (
  ip      TEXT PRIMARY KEY,
  seen_at TEXT NOT NULL
);

INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('tor-exits', 'Tor exit addresses', 'listing', 'news', 'https://check.torproject.org/torbulkexitlist', 'text', 'daily', 1, 'The Tor Project; the list is public', 'The Tor Project', 'The current exit relays, one address per line, read whole once a day so the Scan page can say whether a visitor came through Tor. Nothing about a visitor is stored.'),
('internetdb', 'Shodan InternetDB', 'listing', 'news', 'https://internetdb.shodan.io/', 'json', 'manual', 1, 'Shodan InternetDB, free for non-commercial use, no key', 'Shodan', 'Looked up on request only, for the address a visitor asks about from the Scan page: open ports, hostnames, CPEs and CVEs as Shodan last saw them. Never pulled, never stored.');
