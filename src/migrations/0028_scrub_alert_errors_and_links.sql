-- The notifier's address is a credential (a webhook URL, an ntfy topic). A failed send used to
-- record the whole error message, which named the endpoint, and the Digest page showed it.
-- Keep the status alone, as notify.ts now records it.
UPDATE alerts SET error = substr(error, 1, instr(error, ' from ') - 1) WHERE error LIKE 'HTTP % from %';
UPDATE alerts SET error = 'response too large' WHERE error LIKE 'response from %';

-- An item's link is http(s) or one of this site's own paths; anything else a feed sent
-- (javascript:, data:) is not a link and is dropped, as items.ts now drops it on the way in.
UPDATE items
   SET url = NULL
 WHERE url IS NOT NULL
   AND lower(url) NOT LIKE 'http://%'
   AND lower(url) NOT LIKE 'https://%'
   AND NOT (url LIKE '/%' AND url NOT LIKE '//%');
