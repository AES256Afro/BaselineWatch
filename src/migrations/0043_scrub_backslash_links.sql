-- The audit of 25 October: a link of the form /\example.net passed the "a path on this site"
-- test in items.ts, and a browser reads it the way it reads //example.net — `new URL("/\\x",
-- "https://site/")` is "https://x/" — so a link that looked like one of this site's own paths
-- walked the reader off it. paths.ts refuses a backslash now, as safeBack always did; anything
-- already stored is dropped here, the way 0028 dropped the javascript: and data: forms.
--
-- char(92) is the backslash: LIKE's own escape would otherwise have to be redefined to match it.
UPDATE items SET url = NULL WHERE url LIKE '%' || char(92) || '%';
UPDATE items SET canonical_url = NULL WHERE canonical_url LIKE '%' || char(92) || '%';

-- An exploit index entry is its link; a row without a usable one says nothing, and the next pull
-- of that source writes it again if it was ever real.
DELETE FROM exploits WHERE url LIKE '%' || char(92) || '%';

-- msrc_vulns.fixes_json holds Microsoft's own Remediation.URL, now read through items.ts's
-- safeUrl on the way in. It is rewritten whole by the next daily pull, so it is left alone here.
