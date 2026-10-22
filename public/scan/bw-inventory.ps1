#Requires -Version 5.1
<#
bw-inventory.ps1 - what this PC runs, as one report for BaselineWatch's "Is this device
affected?" page (/scan/devices on the instance you downloaded it from).

WHAT IT DOES
  Reads this PC and prints one JSON report between two marker lines:
    os          the Windows version (24H2), edition and full build (10.0.26100.9711), from the registry
    browsers    the versions of Edge, Chrome, Firefox and Brave where installed
  Paste the whole output into /scan/devices. The instance reads the build against Microsoft's
  Security Update Guide (which CVEs the updates not yet on this build fix, and which of those
  Microsoft says are exploited), the browsers against the vendors' releases, and the version
  against endoflife.date. Nothing from the report is stored there.

WHAT IT DOES NOT DO
  It uploads nothing, changes nothing, writes nothing to disk and sends no packet anywhere.
  No advertising domain is fetched: nothing at all is fetched. It needs no administrator
  rights. It reads version numbers, not files, keys or settings.

RUN
  powershell -ExecutionPolicy Bypass -File .\bw-inventory.ps1
  Verify first: Get-FileHash .\bw-inventory.ps1, against /scan/scripts/SHA256SUMS.
#>

$ErrorActionPreference = 'SilentlyContinue'

function Esc([string]$s) { if ($null -eq $s) { return '' }; return $s.Replace('\', '\\').Replace('"', '\"') }

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$display = if ($cv.DisplayVersion) { $cv.DisplayVersion } else { $cv.ReleaseId }
$build = "$($cv.CurrentMajorVersionNumber).$($cv.CurrentMinorVersionNumber).$($cv.CurrentBuild).$($cv.UBR)"
$edition = $cv.EditionID
$name = $cv.ProductName

$browsers = @()
$candidates = @(
  @{ Name = 'Edge';    Paths = @("$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") },
  @{ Name = 'Chrome';  Paths = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "$env:ProgramFiles (x86)\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe") },
  @{ Name = 'Firefox'; Paths = @("$env:ProgramFiles\Mozilla Firefox\firefox.exe", "$env:ProgramFiles (x86)\Mozilla Firefox\firefox.exe", "$env:LOCALAPPDATA\Mozilla Firefox\firefox.exe") },
  @{ Name = 'Brave';   Paths = @("$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe", "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe") }
)
foreach ($c in $candidates) {
  foreach ($p in $c.Paths) {
    if (Test-Path -LiteralPath $p) {
      $v = (Get-Item -LiteralPath $p).VersionInfo.ProductVersion
      if ($v) { $browsers += ('{"name":"' + (Esc $c.Name) + '","version":"' + (Esc ($v -replace '[^0-9.].*$', '')) + '"}'); break }
    }
  }
}

Write-Output 'BW-REPORT-BEGIN'
Write-Output ('{"bw":1,"os":{"family":"windows","name":"' + (Esc $name) + '","version":"' + (Esc $display) + '","build":"' + (Esc $build) + '","display":"' + (Esc $display) + '","edition":"' + (Esc $edition) + '"},"browsers":[' + ($browsers -join ',') + '],"packages":[],"package_source":""}')
Write-Output 'BW-REPORT-END'
