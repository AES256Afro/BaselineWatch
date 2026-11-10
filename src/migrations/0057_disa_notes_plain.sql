-- The DISA source's note read as a build note ("the site's own Apex listing call", a watchlist
-- kind in quotes). The same facts, for a reader.
UPDATE sources SET notes = 'DISA''s STIG library (public.cyber.mil). The default set is downloaded: Windows 11, Windows Server 2025 and 2022, Red Hat Enterprise Linux 9 and 10, Ubuntu 24.04 and 22.04, macOS 26 and 15, iOS/iPadOS 27 and 26, Android 17 and 16 (Google and Samsung Knox), Edge, Chrome, Firefox, Cisco IOS XE Router, and Application Security and Development. The owner can add others by naming them on the watchlist. Each release is compared with the one before it, rule by rule.'
 WHERE id = 'disa-stigs' AND notes LIKE '%Apex listing call%';
