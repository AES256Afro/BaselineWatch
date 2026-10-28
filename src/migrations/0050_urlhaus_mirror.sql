-- URLhaus put every download behind a per-user Auth-Key in October 2026: the host file this source
-- read since 0027 answers 410 Gone, and the source had failed since 21 October. The malware-filter
-- project republishes the same URLhaus hosts in the same hosts format every twelve hours, keyless,
-- under CC0 (URLhaus's own data is CC0), with Tranco's most popular names taken out, which a canary
-- list wants anyway. The derivation is unchanged; only the address, the header and the credit move.
UPDATE sources SET
  name = 'Malware canaries (URLhaus, via malware-filter)',
  url = 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt',
  licence = 'CC0 1.0: URLhaus data by abuse.ch, republished by the malware-filter project (https://gitlab.com/malware-filter/urlhaus-filter#license)',
  attribution = 'URLhaus by abuse.ch, via malware-filter',
  etag = NULL,
  last_modified = NULL,
  notes = 'Twelve malware-hosting names derived from URLhaus''s hosts (the hosts of malware URLs online or added in the last day or two), read from the malware-filter project''s keyless hosts-format copy since URLhaus''s own host file went behind an Auth-Key in October 2026: registrable names only (two labels once a leading www. is dropped; no addresses, no subdomains of shared platforms), the twelve that hash lowest. Checked daily because the list turns over as sites go offline.'
WHERE id = 'canary-malware' AND url = 'https://urlhaus.abuse.ch/downloads/hostfile/';
