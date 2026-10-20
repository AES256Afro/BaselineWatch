#Requires -Version 5.1
<#
bw-check.ps1 - the BaselineWatch manual check for Windows, as one script.

WHAT IT DOES
  Reads this PC and prints a report in this window, one row per step of the guide at
  /scan/guide/windows on the BaselineWatch instance you downloaded it from:
    resolver   the DNS servers each adapter uses, and whether DNS over HTTPS is set for them
    canary     two ad-domain names resolved through your resolver (a lookup, never a fetch)
    hosts      the hosts file, and any entry that points a name at a real address
    firewall   Windows Firewall per profile, the inbound default and the active network category
    listening  the TCP ports this PC accepts connections on, with the ones worth knowing named
    smb out    whether an enabled rule blocks SMB (TCP 445) leaving this PC
    router     the gateway, whether it hands itself out as the resolver, whether its admin page
               answers over HTTP and redirects to HTTPS, and what it announces over UPnP
    upnp       the port mappings the router's UPnP service lists, if it offers one
    bypass     whether plain DNS to 8.8.8.8 and 1.1.1.1, and DNS over HTTPS to dns.google,
               leave your network past its resolver
    ipv6       whether this PC has a public IPv6 address
    ad id      the advertising ID setting
    dns log    whether the DNS-Client event log is on (off by default, so the past goes unrecorded)

WHAT IT DOES NOT DO
  It uploads nothing, changes nothing and writes nothing to disk. It needs no administrator
  rights. It contacts only your resolver, your router (one HTTP request, one HTTPS request and
  one UPnP search on the LAN) and, for the bypass rows, the public resolvers 8.8.8.8 and 1.1.1.1
  (one lookup each) and dns.google (one HTTPS request). No advertising domain is fetched: the
  canary names are looked up, never loaded. Run with -NoNetwork to skip every row that sends a
  packet beyond this PC.

RUN
  Check the file's SHA-256 against the one shown beside the download link first:
    Get-FileHash .\bw-check.ps1
  Then:
    powershell -ExecutionPolicy Bypass -File .\bw-check.ps1
  Works in Windows PowerShell 5.1 and PowerShell 7. Every check is a few lines below; read them.
#>
[CmdletBinding()]
param(
  [switch]$NoNetwork
)

$BwVersion = '1'
$script:Findings = 0
$Canaries = @('ad.doubleclick.net', 'pagead2.googlesyndication.com')
$ControlName = 'example.com'

function Row {
  param([string]$Label, [string]$State, [string]$Text)
  if ($State -eq 'finding') { $script:Findings += 1 }
  $tag = switch ($State) {
    'ok' { '  ok   ' }
    'finding' { 'FINDING' }
    'info' { ' info  ' }
    default { '   ?   ' }
  }
  Write-Output ('{0,-10} {1}  {2}' -f $Label, $tag, $Text)
}

function Note {
  param([string]$Text)
  Write-Output ('{0,-10} {1}  {2}' -f '', '       ', $Text)
}

# Public resolvers a person might have chosen, by address. Filters: 'ads' (ads and trackers),
# 'malware' (malware only), 'none'. NextDNS is matched by prefix below.
$KnownResolvers = @(
  @{ Name = 'AdGuard DNS, default'; Filters = 'ads'; Addresses = @('94.140.14.14', '94.140.15.15', '2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff') },
  @{ Name = 'AdGuard DNS, family'; Filters = 'ads'; Addresses = @('94.140.14.15', '94.140.15.16', '2a10:50c0::bad1:ff', '2a10:50c0::bad2:ff') },
  @{ Name = 'AdGuard DNS, non-filtering'; Filters = 'none'; Addresses = @('94.140.14.140', '94.140.14.141', '2a10:50c0::1:ff', '2a10:50c0::2:ff') },
  @{ Name = 'Quad9'; Filters = 'malware'; Addresses = @('9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9') },
  @{ Name = 'Quad9, unsecured'; Filters = 'none'; Addresses = @('9.9.9.10', '149.112.112.10', '2620:fe::10', '2620:fe::fe:10') },
  @{ Name = 'Cloudflare 1.1.1.1'; Filters = 'none'; Addresses = @('1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001') },
  @{ Name = 'Cloudflare 1.1.1.2, malware blocking'; Filters = 'malware'; Addresses = @('1.1.1.2', '1.0.0.2', '2606:4700:4700::1112', '2606:4700:4700::1002') },
  @{ Name = 'Cloudflare 1.1.1.3, malware and adult content'; Filters = 'malware'; Addresses = @('1.1.1.3', '1.0.0.3', '2606:4700:4700::1113', '2606:4700:4700::1003') },
  @{ Name = 'Google Public DNS'; Filters = 'none'; Addresses = @('8.8.8.8', '8.8.4.4', '2001:4860:4860::8888', '2001:4860:4860::8844') },
  @{ Name = 'Mullvad DNS, adblock'; Filters = 'ads'; Addresses = @('194.242.2.3', '2a07:e340::3') },
  @{ Name = 'Mullvad DNS, base'; Filters = 'ads'; Addresses = @('194.242.2.4', '2a07:e340::4') },
  @{ Name = 'Mullvad DNS, unfiltered'; Filters = 'none'; Addresses = @('194.242.2.2', '2a07:e340::2') },
  @{ Name = 'OpenDNS'; Filters = 'none'; Addresses = @('208.67.222.222', '208.67.220.220') },
  @{ Name = 'OpenDNS FamilyShield'; Filters = 'malware'; Addresses = @('208.67.222.123', '208.67.220.123') }
)

function Describe-Resolver {
  param([string]$Address, [string]$Gateway)
  foreach ($known in $KnownResolvers) {
    if ($known.Addresses -contains $Address) {
      $what = switch ($known.Filters) {
        'ads' { 'filters ads and trackers' }
        'malware' { 'filters malware only, not ads' }
        default { 'does not filter' }
      }
      return ('{0} ({1})' -f $known.Name, $what)
    }
  }
  if ($Address -like '45.90.28.*' -or $Address -like '45.90.30.*' -or $Address -like '2a07:a8c0:*' -or $Address -like '2a07:a8c1:*') {
    return 'NextDNS (filters whatever the profile says)'
  }
  if ($Gateway -and $Address -eq $Gateway) { return 'the router itself (it forwards to whatever the router is set to, usually the ISP)' }
  if ($Address -eq '127.0.0.1' -or $Address -eq '::1') { return 'a resolver on this PC (a VPN client or a local filter)' }
  if ($Address -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') { return 'a resolver on your network (a Pi-hole, AdGuard Home, or another device)' }
  return 'not a resolver this script knows; check it against the guide'
}

function Is-Sinkhole {
  param([string[]]$Addresses)
  if (-not $Addresses -or $Addresses.Count -eq 0) { return $true }
  foreach ($a in $Addresses) {
    if ($a -ne '0.0.0.0' -and $a -ne '127.0.0.1' -and $a -ne '::' -and $a -ne '::1') { return $false }
  }
  return $true
}

function Is-Private {
  param([string]$Address)
  return ($Address -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|fd|fc)')
}

# Resolve one name for A records, through the system resolver or a named server. Returns a
# hashtable: Kind is 'addresses', 'nxdomain', 'timeout' or 'error'.
function Lookup {
  param([string]$Name, [string]$Server)
  try {
    $parameters = @{ Name = $Name; Type = 'A'; DnsOnly = $true; NoHostsFile = $true; ErrorAction = 'Stop' }
    if ($Server) { $parameters.Server = $Server }
    $answers = Resolve-DnsName @parameters
    $addresses = @($answers | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress })
    return @{ Kind = 'addresses'; Addresses = $addresses }
  } catch {
    $message = $_.Exception.Message
    if ($message -match 'does not exist|NXDOMAIN|non-existent') { return @{ Kind = 'nxdomain'; Addresses = @() } }
    if ($message -match 'timed out|timeout|time out') { return @{ Kind = 'timeout'; Addresses = @() } }
    return @{ Kind = 'error'; Addresses = @(); Error = $message }
  }
}

function Describe-Lookup {
  param($Result)
  switch ($Result.Kind) {
    'nxdomain' { return 'no such name (filtered: the resolver answered NXDOMAIN)' }
    'timeout' { return 'no answer (timed out)' }
    'error' { return ('not answered (' + $Result.Error + ')') }
  }
  if ($Result.Addresses.Count -eq 0) { return 'no address (filtered: an empty answer)' }
  if (Is-Sinkhole $Result.Addresses) { return ('sinkholed to ' + ($Result.Addresses -join ', ') + ' (filtered)') }
  $private = $true
  foreach ($a in $Result.Addresses) { if (-not (Is-Private $a)) { $private = $false } }
  if ($private) { return ('a LAN address, ' + ($Result.Addresses -join ', ') + ' (a local block page: filtered)') }
  return ('a real address, ' + ($Result.Addresses -join ', ') + ' (not filtered)')
}

function Lookup-Is-Filtered {
  param($Result)
  if ($Result.Kind -eq 'nxdomain') { return $true }
  if ($Result.Kind -ne 'addresses') { return $false }
  if ($Result.Addresses.Count -eq 0) { return $true }
  if (Is-Sinkhole $Result.Addresses) { return $true }
  foreach ($a in $Result.Addresses) { if (-not (Is-Private $a)) { return $false } }
  return $true
}

# One HTTP request with redirects left unfollowed, so a 302 to https is read as such, and the
# router's self-signed certificate accepted for the duration. Returns a hashtable with Status
# (0 when nothing answered), Location and Error. HttpWebRequest rather than Invoke-WebRequest,
# because Windows PowerShell 5.1 cannot stop at a redirect without throwing away the response.
function Probe-Http {
  param([string]$Url)
  $previous = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
  try {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    $request = [System.Net.HttpWebRequest]::Create($Url)
    $request.Method = 'GET'
    $request.AllowAutoRedirect = $false
    $request.Timeout = 6000
    $request.ReadWriteTimeout = 6000
    $request.UserAgent = 'bw-check'
    $response = $request.GetResponse()
    try { return @{ Status = [int]$response.StatusCode; Location = [string]$response.Headers['Location']; Error = '' } }
    finally { $response.Close() }
  } catch [System.Net.WebException] {
    $response = $_.Exception.Response
    if ($response) {
      try { return @{ Status = [int]$response.StatusCode; Location = [string]$response.Headers['Location']; Error = '' } }
      finally { $response.Close() }
    }
    return @{ Status = 0; Location = ''; Error = $_.Exception.Message }
  } catch {
    return @{ Status = 0; Location = ''; Error = $_.Exception.Message }
  } finally {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previous
  }
}

# An SSDP search for an Internet Gateway Device: one multicast M-SEARCH, one unicast to the
# gateway, then whatever answers within three seconds. Returns the description URLs.
function Find-Upnp-Locations {
  param([string]$Gateway)
  $locations = @()
  $udp = $null
  try {
    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.ReceiveTimeout = 1500
    $message = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1`r`n`r`n"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($message)
    $multicast = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse('239.255.255.250'), 1900)
    [void]$udp.Send($bytes, $bytes.Length, $multicast)
    if ($Gateway) {
      try {
        $unicast = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($Gateway), 1900)
        [void]$udp.Send($bytes, $bytes.Length, $unicast)
      } catch { }
    }
    $deadline = (Get-Date).AddSeconds(3)
    while ((Get-Date) -lt $deadline) {
      try {
        $from = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any, 0)
        $data = $udp.Receive([ref]$from)
        $text = [System.Text.Encoding]::ASCII.GetString($data)
        if ($text -match '(?im)^LOCATION:\s*(\S+)') { $locations += $Matches[1] }
      } catch { break }
    }
  } catch {
  } finally {
    if ($udp) { $udp.Close() }
  }
  return @($locations | Select-Object -Unique)
}

function Upnp-Call {
  param([string]$ControlUrl, [string]$ServiceType, [string]$Action, [string]$Arguments)
  $body = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:' + $Action + ' xmlns:u="' + $ServiceType + '">' + $Arguments + '</u:' + $Action + '></s:Body></s:Envelope>'
  $headers = @{ 'SOAPAction' = ('"' + $ServiceType + '#' + $Action + '"') }
  $response = Invoke-WebRequest -Uri $ControlUrl -Method Post -Body $body -ContentType 'text/xml; charset="utf-8"' -Headers $headers -TimeoutSec 6 -UseBasicParsing -ErrorAction Stop
  return [string]$response.Content
}

function Xml-Field {
  param([string]$Text, [string]$Field)
  if ($Text -match ('<' + $Field + '>([^<]*)</' + $Field + '>')) { return $Matches[1].Trim() }
  return ''
}

# ---- the report ----------------------------------------------------------------------------

try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12 } catch { }

$os = $null
try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { }
$osName = if ($os) { ('{0} {1}' -f $os.Caption, $os.Version) } else { 'Windows' }
Write-Output ('bw-check {0} - {1} - {2} - {3}' -f $BwVersion, $env:COMPUTERNAME, $osName, (Get-Date -Format 'yyyy-MM-dd HH:mm'))
if ($NoNetwork) { Write-Output 'Run with -NoNetwork: the canary, router, upnp and bypass rows are skipped.' }
Write-Output ''

# Gateway first: the resolver and router rows both need it.
$gateway = ''
try {
  $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
  if ($route) { $gateway = [string]$route.NextHop }
} catch { }

# resolver: every adapter that is up and has a server, with DHCP or manual and the DoH setting.
$resolverAddresses = @()
try {
  $up = @{}
  foreach ($adapter in (Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })) { $up[[int]$adapter.InterfaceIndex] = $adapter.Name }
  $dhcp = @{}
  foreach ($iface in (Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue)) { $dhcp[[int]$iface.InterfaceIndex] = [string]$iface.Dhcp }
  $dohKeys = @{}
  try {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters'
    foreach ($guidKey in (Get-ChildItem -Path $base -ErrorAction SilentlyContinue)) {
      foreach ($serverKey in (Get-ChildItem -Path (Join-Path $guidKey.PSPath 'DohInterfaceSettings\Doh') -ErrorAction SilentlyContinue)) {
        $flags = (Get-ItemProperty -Path $serverKey.PSPath -ErrorAction SilentlyContinue).DohFlags
        if ($flags) { $dohKeys[$serverKey.PSChildName] = [int64]$flags }
      }
    }
  } catch { }
  $rows = 0
  foreach ($entry in (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop)) {
    if (-not $up.ContainsKey([int]$entry.InterfaceIndex)) { continue }
    if (-not $entry.ServerAddresses -or $entry.ServerAddresses.Count -eq 0) { continue }
    $rows += 1
    $how = if ($dhcp[[int]$entry.InterfaceIndex] -eq 'Enabled') { 'DHCP' } else { 'manual' }
    foreach ($address in $entry.ServerAddresses) {
      $resolverAddresses += $address
      $doh = if ($dohKeys.ContainsKey($address)) { ('DoH set, flags ' + $dohKeys[$address]) } else { 'DoH not set' }
      $what = Describe-Resolver -Address $address -Gateway $gateway
      $state = if ($what -like 'the router itself*' -or $what -like '*does not filter*') { 'finding' } else { 'info' }
      Row 'resolver' $state ('{0}: {1} ({2}, {3}): {4}' -f $entry.InterfaceAlias, $address, $how, $doh, $what)
    }
  }
  if ($rows -eq 0) { Row 'resolver' 'unknown' 'no adapter that is up has a DNS server set' }
} catch {
  Row 'resolver' 'unknown' ('could not read the DNS client settings: ' + $_.Exception.Message)
}

# canary: the two ad names through the system resolver, with a control that must resolve.
if (-not $NoNetwork) {
  $control = Lookup -Name $ControlName
  if ($control.Kind -ne 'addresses' -or $control.Addresses.Count -eq 0) {
    Row 'canary' 'unknown' ('the control name {0} did not resolve ({1}), so the canary rows mean nothing; is DNS working?' -f $ControlName, $control.Kind)
  } else {
    $filteredNames = @()
    $realNames = @()
    $otherNames = @()
    foreach ($name in $Canaries) {
      $result = Lookup -Name $name
      if (Lookup-Is-Filtered $result) { $filteredNames += $name } elseif ($result.Kind -eq 'addresses') { $realNames += $name } else { $otherNames += $name }
      Row 'canary' 'info' ('{0}: {1}' -f $name, (Describe-Lookup $result))
    }
    if ($realNames.Count -eq $Canaries.Count) { Row 'canary' 'finding' 'neither ad name was filtered: nothing between this PC and the internet filters ads by DNS' }
    elseif ($filteredNames.Count -eq $Canaries.Count) { Row 'canary' 'ok' 'both ad names were filtered by the resolver this PC uses' }
    elseif ($filteredNames.Count -gt 0) { Row 'canary' 'info' ('filtered by list: {0} filtered, {1} not; the resolver filters, and its list lacks the other name' -f ($filteredNames -join ', '), (($realNames + $otherNames) -join ', ')) }
    else { Row 'canary' 'unknown' 'the canary lookups did not answer' }
  }
}

# hosts: the file, and entries that point a name at a real address.
try {
  $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
  $lines = @(Get-Content -Path $hostsPath -ErrorAction Stop)
  $active = @($lines | Where-Object { $_.Trim() -ne '' -and -not $_.Trim().StartsWith('#') })
  $unusual = @()
  $public = @()
  foreach ($line in $active) {
    $parts = $line.Trim() -split '\s+'
    if ($parts.Count -lt 2) { continue }
    $target = $parts[0]
    if ($target -in @('127.0.0.1', '0.0.0.0', '::1', '::', '255.255.255.255')) { continue }
    $unusual += ($parts[1] + ' -> ' + $target)
    # Private and carrier-grade NAT (100.64/10) targets are a LAN or a VPN client's own entries.
    if (-not (Is-Private $target) -and -not ($target -match '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.')) { $public += ($parts[1] + ' -> ' + $target) }
  }
  if ($public.Count -gt 0) {
    Row 'hosts' 'finding' ('{0} active entries; {1} point a name at a public address: {2}' -f $active.Count, $public.Count, (($public | Select-Object -First 5) -join '; '))
    Note 'a hosts entry can send a name anywhere without DNS; each one should be yours'
  } elseif ($unusual.Count -gt 0) {
    Row 'hosts' 'info' ('{0} active entries; {1} point a name at an address on your network or VPN (a VPN client writes these): {2}' -f $active.Count, $unusual.Count, (($unusual | Select-Object -First 5) -join '; '))
  } else {
    Row 'hosts' 'ok' ('{0} active entries, none pointing a name at a real address ({1})' -f $active.Count, $hostsPath)
  }
} catch {
  Row 'hosts' 'unknown' ('could not read the hosts file: ' + $_.Exception.Message)
}

# firewall: the three profiles and the active network category.
try {
  foreach ($profile in (Get-NetFirewallProfile -ErrorAction Stop)) {
    $enabled = [string]$profile.Enabled
    $inbound = [string]$profile.DefaultInboundAction
    if ($inbound -eq 'NotConfigured') { $inbound = 'Block (default)' }
    $state = if ($enabled -ne 'True' -or $inbound -like 'Allow*') { 'finding' } else { 'ok' }
    $onOff = if ($enabled -eq 'True') { 'on' } else { 'OFF' }
    Row 'firewall' $state ('{0} profile: {1}, inbound default {2}' -f $profile.Name, $onOff, $inbound)
  }
  foreach ($connection in (Get-NetConnectionProfile -ErrorAction SilentlyContinue)) {
    Row 'firewall' 'info' ('{0} ({1}) is a {2} network, so the {2} profile applies to it' -f $connection.Name, $connection.InterfaceAlias, $connection.NetworkCategory)
  }
} catch {
  Row 'firewall' 'unknown' ('could not read the firewall profiles: ' + $_.Exception.Message)
}

# listening: TCP ports with a listener, the known ones named.
$portNames = @{ 21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 80 = 'HTTP'; 135 = 'RPC'; 139 = 'NetBIOS'; 443 = 'HTTPS'; 445 = 'SMB file sharing'; 3389 = 'Remote Desktop'; 5900 = 'VNC'; 5985 = 'WinRM'; 5986 = 'WinRM over HTTPS'; 8080 = 'HTTP alternate' }
try {
  $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
  $byPort = @{}
  foreach ($listener in $listeners) {
    $port = [int]$listener.LocalPort
    $address = [string]$listener.LocalAddress
    $wide = ($address -eq '0.0.0.0' -or $address -eq '::')
    if (-not $byPort.ContainsKey($port)) { $byPort[$port] = $wide } elseif ($wide) { $byPort[$port] = $true }
  }
  $named = @()
  foreach ($port in ($byPort.Keys | Sort-Object)) {
    if ($portNames.ContainsKey($port) -and $byPort[$port]) { $named += ('{0} ({1})' -f $port, $portNames[$port]) }
  }
  $text = '{0} TCP ports have a listener' -f $byPort.Count
  if ($named.Count -gt 0) {
    Row 'listening' 'info' ($text + '; on every address: ' + ($named -join ', ') + ' - reachable from the LAN unless a firewall rule says otherwise')
  } else {
    Row 'listening' 'ok' ($text + '; none of the well-known remote-access or file-sharing ports listens on every address')
  }
  try {
    $rdp = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop).fDenyTSConnections
    if ($rdp -eq 0) { Row 'listening' 'info' 'Remote Desktop is enabled on this PC' } else { Row 'listening' 'ok' 'Remote Desktop is off' }
  } catch { }
} catch {
  Row 'listening' 'unknown' ('could not list the listeners: ' + $_.Exception.Message)
}

# smb out: an enabled outbound block rule for TCP 445.
try {
  $blocks = @(Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True -ErrorAction Stop)
  $smbRules = @()
  foreach ($rule in $blocks) {
    $filters = @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
    foreach ($filter in $filters) {
      if ($filter.Protocol -eq 'TCP' -and (@($filter.RemotePort) -contains '445')) { $smbRules += $rule.DisplayName }
    }
  }
  if ($smbRules.Count -gt 0) { Row 'smb out' 'ok' ('an enabled outbound rule blocks TCP 445: ' + (($smbRules | Select-Object -First 3) -join '; ')) }
  else { Row 'smb out' 'info' 'no enabled outbound rule blocks TCP 445 leaving this PC; the guide says when that matters (laptops on public networks)' }
} catch {
  Row 'smb out' 'unknown' ('could not read the outbound rules: ' + $_.Exception.Message)
}

# router: the gateway, its resolver, its admin page and its UPnP description.
if (-not $gateway) {
  Row 'router' 'unknown' 'no default gateway: not on a network, or on a VPN that owns the route'
} elseif ($NoNetwork) {
  Row 'router' 'info' ('gateway ' + $gateway + ' (its admin page and UPnP were not asked: -NoNetwork)')
} else {
  if ($resolverAddresses -contains $gateway) {
    Row 'router' 'finding' ('gateway {0} hands itself out as the resolver; set the DHCP DNS on the router to your filtering resolver instead' -f $gateway)
  } else {
    Row 'router' 'ok' ('gateway {0}; the resolver this PC uses is not the router' -f $gateway)
  }
  $http = Probe-Http -Url ('http://' + $gateway + '/')
  $https = Probe-Http -Url ('https://' + $gateway + '/')
  if ($http.Status -ge 300 -and $http.Status -lt 400 -and $http.Location -like 'https:*') {
    Row 'router' 'ok' ('admin page: HTTP redirects to HTTPS ({0} -> {1})' -f $http.Status, $http.Location)
  } elseif ($http.Status -ge 200 -and $http.Status -lt 400) {
    Row 'router' 'info' ('admin page answers over plain HTTP ({0}); sign in over https://{1}/ if the router offers it, and turn plain HTTP off if it lets you' -f $http.Status, $gateway)
  } elseif ($http.Status -ne 0) {
    Row 'router' 'info' ('admin page answered HTTP {0} on port 80' -f $http.Status)
  } else {
    Row 'router' 'info' 'nothing answers on port 80 (the admin page may live on another port, or be off)'
  }
  if ($https.Status -ne 0) { Row 'router' 'info' ('admin page answers over HTTPS ({0}); a self-signed certificate is normal on a home router' -f $https.Status) }
  else { Row 'router' 'info' 'nothing answers on port 443' }

  $locations = Find-Upnp-Locations -Gateway $gateway
  if ($locations.Count -eq 0) {
    Row 'upnp' 'ok' 'no UPnP Internet Gateway Device answered the search: UPnP is off, or the router does not offer it on this network'
  } else {
    foreach ($location in $locations) {
      $description = ''
      try { $description = [string](Invoke-WebRequest -Uri $location -TimeoutSec 6 -UseBasicParsing -ErrorAction Stop).Content } catch { }
      if (-not $description) { Row 'upnp' 'info' ('a device answered at {0} but its description could not be read' -f $location); continue }
      $model = @((Xml-Field $description 'manufacturer'), (Xml-Field $description 'modelName'), (Xml-Field $description 'modelNumber')) | Where-Object { $_ }
      $friendly = Xml-Field $description 'friendlyName'
      $modelDescription = Xml-Field $description 'modelDescription'
      $friendlyText = if ($friendly) { ' "' + $friendly + '"' } else { '' }
      $descriptionText = if ($modelDescription) { ' (' + $modelDescription + ')' } else { '' }
      Row 'router' 'info' ('UPnP says the gateway is {0}{1}{2}' -f ($model -join ' '), $friendlyText, $descriptionText)
      Note 'note the firmware version from the admin page and compare it with the vendor; the guide says where to look it up'
      # The WAN connection service, for the mapping table and the public address.
      $serviceType = ''
      $controlPath = ''
      foreach ($match in [regex]::Matches($description, '(?s)<service>(.*?)</service>')) {
        $block = $match.Groups[1].Value
        $type = Xml-Field $block 'serviceType'
        if ($type -match 'WANIPConnection|WANPPPConnection') { $serviceType = $type; $controlPath = Xml-Field $block 'controlURL'; break }
      }
      if (-not $serviceType) { Row 'upnp' 'info' 'UPnP is on, but the gateway lists no WAN connection service, so the mapping table could not be read'; continue }
      $base = New-Object System.Uri ($location)
      $urlBase = Xml-Field $description 'URLBase'
      if ($urlBase) { try { $base = New-Object System.Uri ($urlBase) } catch { } }
      $controlUrl = (New-Object System.Uri ($base, $controlPath)).AbsoluteUri
      try {
        $external = Upnp-Call -ControlUrl $controlUrl -ServiceType $serviceType -Action 'GetExternalIPAddress' -Arguments ''
        $publicAddress = Xml-Field $external 'NewExternalIPAddress'
        if ($publicAddress -and $publicAddress -ne '0.0.0.0') {
          Row 'router' 'info' ('public address {0}; what the internet sees of it: open https://internetdb.shodan.io/{0} by hand' -f $publicAddress)
          if (Is-Private $publicAddress) { Note 'that is a private address: the router sits behind another router or carrier NAT' }
        }
      } catch { }
      $mappings = @()
      for ($index = 0; $index -lt 64; $index++) {
        try {
          $entry = Upnp-Call -ControlUrl $controlUrl -ServiceType $serviceType -Action 'GetGenericPortMappingEntry' -Arguments ('<NewPortMappingIndex>' + $index + '</NewPortMappingIndex>')
        } catch { break }
        $externalPort = Xml-Field $entry 'NewExternalPort'
        if (-not $externalPort) { break }
        $enabledText = if ((Xml-Field $entry 'NewEnabled') -eq '0') { '(disabled) ' } else { '' }
        $mappingDescription = Xml-Field $entry 'NewPortMappingDescription'
        $mappingText = if ($mappingDescription) { '"' + $mappingDescription + '"' } else { '(no description)' }
        $mappings += ('{0} {1} -> {2}:{3} {4}{5}' -f (Xml-Field $entry 'NewProtocol'), $externalPort, (Xml-Field $entry 'NewInternalClient'), (Xml-Field $entry 'NewInternalPort'), $enabledText, $mappingText)
      }
      if ($mappings.Count -eq 0) {
        Row 'upnp' 'finding' 'UPnP is on and the gateway lists no port mappings; any program on the LAN may still ask it to open one, so turn UPnP off unless something you run needs it'
      } else {
        Row 'upnp' 'finding' ('UPnP is on and the gateway lists {0} port mapping(s): {1}' -f $mappings.Count, ($mappings -join '; '))
        Note 'each mapping is a port open from the internet to a device here; know what asked for each, or remove it and turn UPnP off'
      }
    }
  }
}

# bypass: plain DNS to two public resolvers and DNS over HTTPS to one, from this PC.
if (-not $NoNetwork) {
  foreach ($server in @('8.8.8.8', '1.1.1.1')) {
    $result = Lookup -Name $Canaries[0] -Server $server
    if ($result.Kind -eq 'timeout' -or $result.Kind -eq 'error') {
      Row 'bypass' 'ok' ('plain DNS straight to {0}: {1}; port 53 out is blocked or redirected, so a device cannot pick its own resolver' -f $server, (Describe-Lookup $result))
    } elseif (Lookup-Is-Filtered $result) {
      Row 'bypass' 'ok' ('plain DNS straight to {0} came back filtered: the router redirects port 53 to your filter' -f $server)
    } else {
      Row 'bypass' 'info' ('plain DNS straight to {0} was answered with a real address: a device or app that brings its own resolver walks past your network filter' -f $server)
    }
  }
  try {
    $doh = Invoke-RestMethod -Uri ('https://dns.google/resolve?name=' + $Canaries[0] + '&type=A') -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop
    $answered = $false
    try { if ($doh.Answer) { $answered = $true } } catch { }
    if ($answered) { Row 'bypass' 'info' 'DNS over HTTPS to dns.google answered from this PC: an app with its own DoH walks past your network filter unless the router blocks the known DoH endpoints' }
    else { Row 'bypass' 'ok' 'DNS over HTTPS to dns.google answered without an address: the endpoint is intercepted or filtered' }
  } catch {
    Row 'bypass' 'ok' ('DNS over HTTPS to dns.google did not answer (' + $_.Exception.Message + '): blocked from this network')
  }
}

# ipv6: a public address on this PC.
try {
  $global = @(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction Stop | Where-Object { $_.IPAddress -match '^[23]' -and $_.AddressState -eq 'Preferred' } | ForEach-Object { $_.IPAddress })
  if ($global.Count -gt 0) { Row 'ipv6' 'info' ('this PC has a public IPv6 address ({0}); the router''s IPv6 firewall and this firewall are what stand between it and the internet' -f ($global -join ', ')) }
  else { Row 'ipv6' 'info' 'no public IPv6 address on this PC (IPv6 is off here, or the router does not delegate one)' }
} catch {
  Row 'ipv6' 'unknown' ('could not read the IPv6 addresses: ' + $_.Exception.Message)
}

# ad id: the advertising identifier setting for this user.
try {
  $adId = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -ErrorAction Stop).Enabled
  if ($adId -eq 0) { Row 'ad id' 'ok' 'advertising ID off for this user' }
  elseif ($null -eq $adId) { Row 'ad id' 'finding' 'advertising ID not set, which means on (Settings, Privacy & security, General)' }
  else { Row 'ad id' 'finding' 'advertising ID on for this user (Settings, Privacy & security, General)' }
} catch {
  Row 'ad id' 'finding' 'advertising ID not set, which means on (Settings, Privacy & security, General)'
}

# dns log: the DNS-Client operational log.
try {
  $log = Get-WinEvent -ListLog 'Microsoft-Windows-DNS-Client/Operational' -ErrorAction Stop
  if ($log.IsEnabled) { Row 'dns log' 'ok' 'the DNS-Client operational log is on, so lookups are recorded' }
  else { Row 'dns log' 'info' 'the DNS-Client operational log is OFF (the Windows default), so the past is not recorded; the guide says how to turn it on' }
} catch {
  Row 'dns log' 'unknown' ('could not read the log state: ' + $_.Exception.Message)
}

Write-Output ''
if ($script:Findings -eq 0) { Write-Output 'verdict    no finding; a clean result is not a clean bill of health' }
else { Write-Output ('verdict    {0} finding(s); each names the guide step that explains it' -f $script:Findings) }
Write-Output 'nothing was uploaded or changed; keep this report with the device''s record'
