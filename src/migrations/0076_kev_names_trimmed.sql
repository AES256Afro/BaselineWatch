-- CISA's vendor and product as stored by 0073 and by applyKev before it trimmed them: some of
-- CISA's names end in a space ("Microsoft "), so the stored pair did not equal the one read from a
-- fresh catalogue and every KEV run counted the row as renamed. Trimmed here; an empty name is NULL.
UPDATE vulns SET kev_vendor = nullif(trim(kev_vendor), '') WHERE kev_vendor IS NOT NULL AND kev_vendor <> trim(kev_vendor);
UPDATE vulns SET kev_product = nullif(trim(kev_product), '') WHERE kev_product IS NOT NULL AND kev_product <> trim(kev_product);
