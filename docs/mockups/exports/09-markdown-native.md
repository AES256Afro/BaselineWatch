# macOS 26 Security Baseline and Test Report

> **BW-MACOS26-2026-10** · version 1.3 · Final for approval · 17 October 2026  
> 340 managed Macs (Intune fleet 212, Jamf Pro fleet 128), Apple silicon only

| | |
|---|---|
| **Platform** | macOS 26 “Tahoe” |
| **Standards applied** | DISA Apple macOS 26 (Tahoe) STIG, Version 1, Release 4 |
|  | NIST macOS Security Compliance Project, tahoe · 800-53r5 High |
|  | NIST SP 800-53 Rev. 5, High baseline (SP 800-53B) |
| **Assessment period** | 6 – 15 October 2026 |
| **Prepared by** | Jordan Rivera, Endpoint Security Engineer |
| **Organisation** | Example Agency · Endpoint Engineering |

## Approval

| Role | Name | Signature | Date |
|---|---|---|---|
| Prepared | Jordan Rivera, Endpoint Security Engineer | | |
| Reviewed | Alex Chen, Information System Security Manager | | |
| Approved | Morgan Okafor, Authorizing Official’s Designated Representative | | |

## Contents

1. Executive summary
2. Decision register
3. Test plan
4. Findings and exceptions (POA&M)
5. Attribution

## 1. Executive summary

| Baseline | Rules | | Tests | Steps |
|---|---:|---|---|---:|
| Recommended | 212 | | ✅ Pass | 19 |
| Applied | 186 | | ❌ Fail | 3 |
| Modified | 14 | | ➖ N/A | 1 |
| Not applied | 12 | | ⏳ Not tested | 1 |

## 2. Decision register

*10 of 212 decisions shown.*

### BW-101 · Limit consecutive failed logon attempts

`APPL-26-000022` CAT II · `pwpolicy_account_lockout_enforce` · `AC-7`

| Publisher recommends | Our decision |
|---|---|
| Lock the account after 3 consecutive invalid attempts within 15 minutes. | **🟡 Modified** — Lock after 5 attempts; 15-minute lockout. |

> **Why:** Sign-in uses Platform SSO with Entra ID, which has its own lockout. At 3 attempts the pilot had 40+ helpdesk unlocks a week.  
> **Owner:** Endpoint Engineering · **Verified by:** T-AUTH-06

### BW-102 · Enforce smart card authentication

`APPL-26-000060` CAT II · `auth_smartcard_enforce` · `IA-2(1)` `IA-2(2)` `IA-2(12)`

| Publisher recommends | Our decision |
|---|---|
| Require a PIV/CAC smart card for login and authorisation. | **🔴 Not applying** — Platform SSO with a Secure Enclave key (phishing-resistant). |

> **Why:** PIV cards are not issued to macOS users. MFA is met by the Platform SSO Secure Enclave key with Entra ID Conditional Access. Risk accepted: EXC-2026-007.  
> **Owner:** Identity and Access · **Verified by:** T-AUTH-07

### BW-103 · Enforce FileVault and escrow the recovery key

`APPL-26-005020` CAT II · `system_settings_filevault_enforce` · `SC-28` `SC-28(1)`

| Publisher recommends | Our decision |
|---|---|
| Enable FileVault on all volumes; escrow the recovery key to the MDM. | **🟢 Apply** — As recommended; personal recovery key escrowed to Intune or Jamf Pro. |

> **Why:** No deviation.  
> **Owner:** Endpoint Engineering · **Verified by:** T-DISK-01

### BW-104 · Enable the application firewall

`APPL-26-005050` CAT II · `system_settings_firewall_enable` · `SC-7` `SC-7(12)`

| Publisher recommends | Our decision |
|---|---|
| Turn on the macOS application firewall. | **🟢 Apply** — As recommended, plus stealth mode. |

> **Why:** No deviation.  
> **Owner:** Endpoint Engineering · **Verified by:** T-NET-01

### BW-105 · Disable SSH (Remote Login)

`APPL-26-000100` CAT II · `system_settings_ssh_disable` · `CM-7` `AC-17`

| Publisher recommends | Our decision |
|---|---|
| Disable the SSH server unless documented as an operational requirement. | **🟡 Modified** — Off on all endpoints except 14 build hosts, where only the admin group may connect. |

> **Why:** CI agents on the iOS build hosts need SSH. Limited to one Smart Group, key auth only, FIPS ciphers (BW-106), logged to the SIEM.  
> **Owner:** Platform Engineering · **Verified by:** T-NET-04

### BW-106 · Use FIPS-validated SSH ciphers and MACs

`APPL-26-000110` CAT I · `os_sshd_fips_compliant` · `AC-17(2)` `IA-7` `SC-13`

| Publisher recommends | Our decision |
|---|---|
| Limit sshd to FIPS 140-validated ciphers, MACs and key exchange. | **🟢 Apply** — As recommended on the 14 hosts where SSH is enabled. |

> **Why:** SSH is on for build hosts (BW-105).  
> **Owner:** Platform Engineering · **Verified by:** T-NET-03

### BW-107 · Configure audit flags and retention

`APPL-26-001010` CAT II · `audit_flags_lo_configure` · `AU-2` `AU-12` `AU-11`

| Publisher recommends | Our decision |
|---|---|
| Audit logon/logoff, admin and authorisation events; retain locally per policy. | **🟢 Apply** — As recommended; 60-day local retention, forwarded to the SIEM. |

> **Why:** No deviation.  
> **Owner:** Security Operations · **Verified by:** T-LOG-01

### BW-108 · Enforce software update installation

`APPL-26-002050` CAT II · `system_settings_software_update_download_enforce` · `SI-2` `SI-2(2)`

| Publisher recommends | Our decision |
|---|---|
| Download and install security updates automatically. | **🟢 Apply** — Declarative device management enforces minor updates within 7 days. |

> **Why:** No deviation.  
> **Owner:** Endpoint Engineering · **Verified by:** T-UPD-01

### BW-109 · Lock the screen after 15 minutes of inactivity

`APPL-26-000070` CAT II · `system_settings_screensaver_timeout_enforce` · `AC-11` `AC-11(1)`

| Publisher recommends | Our decision |
|---|---|
| Start the screen saver after at most 15 minutes and require a password immediately. | **🟢 Apply** — As recommended (900 seconds, password on wake). |

> **Why:** No deviation.  
> **Owner:** Endpoint Engineering · **Verified by:** T-AUTH-05

### BW-110 · Disable Bluetooth

`APPL-26-002080` CAT II · `system_settings_bluetooth_disable` · `AC-18` `AC-18(3)`

| Publisher recommends | Our decision |
|---|---|
| Turn off Bluetooth unless an approved peripheral requires it. | **🔴 Not applying** — Bluetooth on; sharing and discoverability off. |

> **Why:** Keyboards, headsets and Continuity need Bluetooth. Bluetooth Sharing stays off. Risk accepted: EXC-2026-008.  
> **Owner:** Endpoint Engineering

## 3. Test plan

Applied and modified rules only.

### 3.1 Authentication and SSO

*Platform SSO (Intune and Jamf Pro), Jamf Connect, Kerberos SSO extension, login window, smart card.*

| ID | Step | Procedure | Expected | Result | Evidence | Tester |
|---|---|---|---|---|---|---|
| T-AUTH-01 | Platform SSO registered with Entra ID (Intune fleet) | `app-sso platform -s` | Extension com.microsoft.CompanyPortalMac.ssoextension; registrationCompleted : true; loginType : Secure Enclave key | ✅ Pass | EV-011 (output, 3 hosts) | JR |
| T-AUTH-02 | Platform SSO payload delivered by Jamf Pro | `/usr/bin/profiles show -type configuration \| grep -A4 com.apple.extensiblesso` | Payload present from Jamf Pro; AuthenticationMethod = UserSecureEnclaveKey | ✅ Pass | EV-012 | SP |
| T-AUTH-03 | Jamf Connect login window uses Entra ID (legacy Jamf fleet) | `defaults read /Library/Managed\ Preferences/com.jamf.connect.login OIDCProvider` | EntraID; local account password synced after sign-in | ✅ Pass | EV-013 (screen recording) | SP |
| T-AUTH-04 | Kerberos SSO extension obtains a TGT on the corporate network | `app-sso -i CORP.EXAMPLE.COM && klist` | Realm CORP.EXAMPLE.COM; valid krbtgt ticket listed | ✅ Pass | EV-014 | JR |
| T-AUTH-05 | Login window: name and password, banner, 15-minute screen lock | `/usr/bin/profiles show -type configuration \| grep -E 'SHOWFULLNAME\|idleTime\|askForPasswordDelay'` | SHOWFULLNAME = 1; idleTime = 900; askForPasswordDelay = 0; PolicyBanner present | ✅ Pass | EV-015 | JR |
| T-AUTH-06 | Account locks after 5 failed attempts (modified, BW-101) | `/usr/bin/pwpolicy -getaccountpolicies \| grep -A1 policyAttributeMaximumFailedAuthentications` | <integer>5</integer> | ❌ Fail | EV-016: 10 on 3 Jamf hosts | SP |
| T-AUTH-07 | Smart card pairing and enforcement | `sc_auth identities` | Not tested: control not applied (BW-102, EXC-2026-007) | ➖ N/A | — | JR |

### 3.2 Disk encryption

*FileVault and recovery key escrow.*

| ID | Step | Procedure | Expected | Result | Evidence | Tester |
|---|---|---|---|---|---|---|
| T-DISK-01 | FileVault is on | `fdesetup status` | FileVault is On. | ✅ Pass | EV-021 (MDM report, 340/340) | JR |
| T-DISK-02 | Recovery key escrowed to the MDM | `/usr/bin/profiles show -type configuration \| grep -i FDERecoveryKeyEscrow` | Escrow payload present; key visible in Intune or Jamf Pro inventory | ✅ Pass | EV-022 | SP |
| T-DISK-03 | Recovery key rotates after use | `sudo fdesetup changerecovery -personal (then check MDM)` | New key escrowed within one check-in; old key invalid | ⏳ Not tested | Scheduled 22 Oct | SP |

### 3.3 Network

*SSH tested on build hosts only (BW-105, BW-106).*

| ID | Step | Procedure | Expected | Result | Evidence | Tester |
|---|---|---|---|---|---|---|
| T-NET-01 | Application firewall enabled with stealth mode | `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate --getstealthmode` | Firewall is enabled. (State = 1); Firewall stealth mode is on | ✅ Pass | EV-031 | JR |
| T-NET-02 | Sharing services off (screen, file, internet, Bluetooth sharing) | `launchctl print-disabled system \| grep -E 'screensharing\|smbd\|InternetSharing'` | each service => disabled | ✅ Pass | EV-032 | JR |
| T-NET-03 | SSH uses FIPS ciphers, MACs and KEX (build hosts only) | `/usr/sbin/sshd -G \| grep -E '^(ciphers\|macs\|kexalgorithms)'` | ciphers aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr | ✅ Pass | EV-033 (14/14 hosts) | SP |
| T-NET-04 | Remote Login off on standard endpoints | `sudo /usr/sbin/systemsetup -getremotelogin` | Remote Login: Off | ✅ Pass | EV-034 | JR |

### 3.4 Logging and audit

| ID | Step | Procedure | Expected | Result | Evidence | Tester |
|---|---|---|---|---|---|---|
| T-LOG-01 | Audit flags and retention configured | `grep -E '^(flags\|expire-after)' /etc/security/audit_control` | flags:lo,aa,ad,fd,fm,-all  expire-after:60d | ✅ Pass | EV-041 | JR |
| T-LOG-02 | Audit records reach the SIEM | `Search SIEM for host events in the last 24 h` | Events from every in-scope host | ❌ Fail | EV-042: 12 hosts silent | SP |

### 3.5 Updates

| ID | Step | Procedure | Expected | Result | Evidence | Tester |
|---|---|---|---|---|---|---|
| T-UPD-01 | Software update enforced by declaration | `sw_vers -productVersion; softwareupdate --list` | 26.0.1 or later; No new software available | ✅ Pass | EV-051 | JR |
| T-UPD-02 | Background security responses install automatically | `defaults read /Library/Managed\ Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall` | 1 | ✅ Pass | EV-052 | JR |

### 3.6 MDM enrolment

| ID | Step | Procedure | Expected | Result | Evidence | Tester |
|---|---|---|---|---|---|---|
| T-MDM-01 | Enrolled through Automated Device Enrolment, user approved | `/usr/bin/profiles status -type enrollment` | Enrolled via DEP: Yes; MDM enrollment: Yes (User Approved) | ✅ Pass | EV-061 | SP |
| T-MDM-02 | MDM profile cannot be removed by the user | `/usr/bin/profiles show -type enrollment` | IsSupervised = 1; profile marked non-removable | ✅ Pass | EV-062 | SP |

### 3.7 Browsers

*Entra ID sign-in in Safari, Chrome, Edge and Firefox.*

| ID | Step | Procedure | Expected | Result | Evidence | Tester |
|---|---|---|---|---|---|---|
| T-BRW-01 | Safari: fraudulent website warning and Entra SSO | `defaults read /Library/Managed\ Preferences/com.apple.Safari WarnAboutFraudulentWebsites` | 1; myapps.microsoft.com signs in without a prompt | ✅ Pass | EV-071 | JR |
| T-BRW-02 | Chrome: Microsoft Single Sign On extension forced | `Open chrome://policy and check ExtensionInstallForcelist` | Extension ppnbnpeolgkicgegkbkbjmhlideopiji installed; SSO succeeds | ✅ Pass | EV-072 | JR |
| T-BRW-03 | Edge: work profile signed in automatically | `defaults read /Library/Managed\ Preferences/com.microsoft.Edge` | BrowserSignin = 2; profile signed in on first launch | ✅ Pass | EV-073 | SP |
| T-BRW-04 | Firefox: Entra SSO through enterprise policy | `cat /Applications/Firefox.app/Contents/Resources/distribution/policies.json` | "MicrosoftEntraSSO": true | ❌ Fail | EV-074: policy missing | SP |

## 4. Findings and exceptions (POA&M)

| ID | Item | Controls | Risk | Owner | Milestone | Due | Status |
|---|---|---|---|---|---|---|---|
| POAM-2026-031 | Lockout threshold is 10, not 5, on 3 Jamf hosts | AC-7 | Moderate | S. Patel | Rescope the Jamf password-policy profile | 31 Oct 2026 | Open |
| POAM-2026-032 | 12 hosts not forwarding audit records to the SIEM | AU-6, AU-4(1) | Moderate | Security Operations | Redeploy forwarder; alert on silent hosts | 15 Nov 2026 | Open |
| POAM-2026-033 | Firefox Entra SSO policy not deployed | IA-2 | Low | J. Rivera | Ship policies.json through both MDMs | 30 Nov 2026 | Open |
| EXC-2026-007 | Smart card enforcement not applied | IA-2(12) | Low | Identity and Access | Compensating: Platform SSO Secure Enclave key | Review 17 Apr 2027 | Risk accepted |
| EXC-2026-008 | Bluetooth remains enabled | AC-18(3) | Low | Endpoint Engineering | Compensating: sharing and discoverability off | Review 17 Apr 2027 | Risk accepted |

## 5. Attribution

- DISA Security Technical Implementation Guides are U.S. Government works in the public domain; STIG IDs and severities are DISA’s.
- NIST SP 800-53 Rev. 5 and the macOS Security Compliance Project (mSCP) are NIST publications, not subject to copyright in the United States; rule IDs are mSCP’s.
- Recommendation text is paraphrased from the publishers. No CIS Benchmark text is included.

---

*Mockup with sample data. Names, counts and evidence references are invented. Generated by BaselineWatch 0.24.0 on 2026-10-17.*
