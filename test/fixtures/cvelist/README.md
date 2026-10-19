# cvelist fixtures

Captured 2026-10-19 from the real source.

`releases.json` is the GitHub releases API answer, as served:

    curl 'https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=3' -o releases.json

`delta.zip` is the real `2026-10-19_delta_CVEs_at_1700Z.zip` (6.4 MB, 3,089 records) trimmed to
six unmodified records chosen for variety — CNA CVSS v3.1 + v4.0 (CVE-2026-104679), v3.1 only
(CVE-2026-111058), v4.0 with an ADP container (CVE-2025-71435), no metrics (CVE-2026-100070,
CVE-2026-100072) and a REJECTED record (CVE-2026-77225):

    curl -L 'https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-10-19_1700Z/2026-10-19_delta_CVEs_at_1700Z.zip' -o full.zip
    unzip full.zip 'deltaCves/CVE-2026-104679.json' ... && zip delta.zip deltaCves/*.json
