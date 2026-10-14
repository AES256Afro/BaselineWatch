-- M4: where the DISA and Microsoft adapters actually read from (found 2026-10-15).

-- DISA's STIG library page is a Salesforce app; its data comes from one Apex call that answers
-- unauthenticated. The adapter POSTs the method and parameters itself; the URL here is the endpoint.
UPDATE sources SET
  url = 'https://www.cyber.mil/webruntime/api/apex/execute?language=en-US&asGuest=true&htmlEncode=false',
  format = 'xccdf-zip', schedule = 'daily',
  notes = 'The STIG document library, read through the site''s own Apex listing call. Only the STIGs on your watchlist (kind "baseline", a name such as "Windows Server 2025") plus a small default set are downloaded; each release is diffed rule by rule.'
  WHERE id = 'disa-stigs';

-- Microsoft's download page embeds its file list; each baseline zip carries a .PolicyRules file.
UPDATE sources SET
  format = 'sct-zip', schedule = 'daily',
  notes = 'Every "Security Baseline" zip in the Security Compliance Toolkit, diffed setting by setting from its .PolicyRules file (registry values, security template lines, audit subcategories). Licence: Microsoft; snapshots stay local.'
  WHERE id = 'microsoft-sct';
