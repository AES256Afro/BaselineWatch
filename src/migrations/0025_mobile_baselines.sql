-- M11.2: the mobile STIGs join the DISA source's default followed list (Apple iOS/iPadOS 27 and
-- 26, Google Android 17 and 16, Samsung Android 17 and 16 with Knox) and NIST mSCP's ios_26
-- branch joins the followed branches, so iOS, iPadOS and Android get derived checks in the
-- baseline builder and the test plans. Watchlist entries of kind "baseline" still replace the
-- defaults. The notes on the Sources page say so.

UPDATE sources SET
  notes = 'The STIG document library, read through the site''s own Apex listing call. Only the STIGs on your watchlist (kind "baseline", a name such as "Windows Server 2025") or the default set are downloaded: Windows 11, Windows Server 2025 and 2022, Red Hat Enterprise Linux 9 and 10, Ubuntu 24.04 and 22.04, Apple macOS 26 and 15, Apple iOS/iPadOS 27 and 26, Google Android 17 and 16, Samsung Android 17 and 16 with Knox, Microsoft Edge, Google Chrome, Mozilla Firefox, Cisco IOS XE Router, Application Security and Development. Each release is diffed rule by rule.'
  WHERE id = 'disa-stigs';

UPDATE sources SET
  notes = 'One branch per Apple release (tahoe and sequoia for macOS, ios_26 for iOS and iPadOS; a watchlist entry of kind "baseline" written "mscp: <branch>" follows others). Every rule with its check, fix, configuration-profile payload keys, severity and its SP 800-53 r5, 800-171 r3, CCI, STIG and CIS references; which baselines (800-53 High, DISA STIG, CIS Level 1 and 2, CMMC) list it. The branch''s current commit is read from the GitHub API, so an unchanged branch costs one small request.'
  WHERE id = 'nist-mscp';
