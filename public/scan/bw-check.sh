#!/bin/sh
# bw-check.sh - the BaselineWatch manual check for macOS and Linux, as one script.
#
# WHAT IT DOES
#   Reads this computer and prints a report in this window, one row per step of the guide at
#   /scan/guide/macos or /scan/guide/linux on the BaselineWatch instance you downloaded it from:
#     resolver   the DNS servers this computer uses, and whether a DNS profile or DNS over TLS is set
#     canary     two ad-domain names resolved through your resolver (a lookup, never a fetch)
#     hosts      the hosts file, and any entry that points a name at a real address
#     firewall   macOS: the application firewall and stealth mode (and pf with sudo);
#                Linux: firewalld, ufw and nftables state (the rules themselves with sudo)
#     listening  the TCP ports this computer accepts connections on, with the ones worth knowing named
#     router     the gateway, whether it hands itself out as the resolver, whether its admin page
#                answers over HTTP and redirects to HTTPS, and what it announces over UPnP
#     upnp       the port mappings the router's UPnP service lists, if it offers one
#     bypass     whether plain DNS to 8.8.8.8 and 1.1.1.1, and DNS over HTTPS to dns.google,
#                leave your network past its resolver
#     ipv6       whether this computer has a public IPv6 address
#     lockdown   macOS: Lockdown Mode, the advertising setting, SIP and Gatekeeper
#
# WHAT IT DOES NOT DO
#   It uploads nothing, changes nothing and writes nothing to disk. It needs no root for the
#   default rows; sudo adds the packet-filter and rule rows. It contacts only your resolver, your
#   router (one HTTP request, one HTTPS request and one UPnP search on the LAN) and, for the
#   bypass rows, the public resolvers 8.8.8.8 and 1.1.1.1 (one lookup each) and dns.google (one
#   HTTPS request). No advertising domain is fetched: the canary names are looked up, never loaded.
#   Run with --no-network to skip every row that sends a packet beyond this computer.
#
# RUN
#   Check the file's SHA-256 against the one shown beside the download link first:
#     shasum -a 256 bw-check.sh        (macOS)      sha256sum bw-check.sh        (Linux)
#   Then:
#     sh ./bw-check.sh                 (add sudo for the packet-filter and rule rows)
#   Plain POSIX sh: it runs under macOS's /bin/sh, dash, bash and zsh. It uses dig, host or
#   nslookup when one is present, curl for the router rows, and python3 for the UPnP search.
#   Every check is a few lines below; read them.

BW_VERSION=1
FINDINGS=0
CANARY_1=ad.doubleclick.net
CANARY_2=pagead2.googlesyndication.com
CONTROL_NAME=example.com
NO_NETWORK=0
for arg in "$@"; do
  case "$arg" in
    --no-network) NO_NETWORK=1 ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
  esac
done

OS=$(uname -s 2>/dev/null || echo unknown)

have() { command -v "$1" >/dev/null 2>&1; }

row() {
  # row LABEL STATE TEXT
  if [ "$2" = finding ]; then FINDINGS=$((FINDINGS + 1)); fi
  case "$2" in
    ok) tag='  ok   ' ;;
    finding) tag='FINDING' ;;
    info) tag=' info  ' ;;
    *) tag='   ?   ' ;;
  esac
  printf '%-10s %s  %s\n' "$1" "$tag" "$3"
}

note() { printf '%-10s %s  %s\n' '' '       ' "$1"; }

# describe_resolver ADDRESS -> what the address is, as far as this script knows
describe_resolver() {
  case "$1" in
    94.140.14.14|94.140.15.15|2a10:50c0::ad1:ff|2a10:50c0::ad2:ff) echo 'AdGuard DNS, default (filters ads and trackers)' ;;
    94.140.14.15|94.140.15.16|2a10:50c0::bad1:ff|2a10:50c0::bad2:ff) echo 'AdGuard DNS, family (filters ads and trackers)' ;;
    94.140.14.140|94.140.14.141|2a10:50c0::1:ff|2a10:50c0::2:ff) echo 'AdGuard DNS, non-filtering (does not filter)' ;;
    45.90.28.*|45.90.30.*|2a07:a8c0:*|2a07:a8c1:*) echo 'NextDNS (filters whatever the profile says)' ;;
    9.9.9.9|149.112.112.112|2620:fe::fe|2620:fe::9) echo 'Quad9 (filters malware only, not ads)' ;;
    9.9.9.10|149.112.112.10|2620:fe::10|2620:fe::fe:10) echo 'Quad9, unsecured (does not filter)' ;;
    1.1.1.1|1.0.0.1|2606:4700:4700::1111|2606:4700:4700::1001) echo 'Cloudflare 1.1.1.1 (does not filter)' ;;
    1.1.1.2|1.0.0.2|2606:4700:4700::1112|2606:4700:4700::1002) echo 'Cloudflare 1.1.1.2 (filters malware only, not ads)' ;;
    1.1.1.3|1.0.0.3|2606:4700:4700::1113|2606:4700:4700::1003) echo 'Cloudflare 1.1.1.3 (filters malware and adult content, not ads)' ;;
    8.8.8.8|8.8.4.4|2001:4860:4860::8888|2001:4860:4860::8844) echo 'Google Public DNS (does not filter)' ;;
    194.242.2.3|2a07:e340::3) echo 'Mullvad DNS, adblock (filters ads and trackers)' ;;
    194.242.2.4|2a07:e340::4) echo 'Mullvad DNS, base (filters ads and trackers)' ;;
    194.242.2.2|2a07:e340::2) echo 'Mullvad DNS, unfiltered (does not filter)' ;;
    208.67.222.222|208.67.220.220) echo 'OpenDNS (does not filter)' ;;
    208.67.222.123|208.67.220.123) echo 'OpenDNS FamilyShield (filters malware and adult content, not ads)' ;;
    127.0.0.53|127.0.0.54) echo 'the systemd-resolved stub on this computer (see the servers it forwards to)' ;;
    127.*|::1) echo 'a resolver on this computer (a VPN client or a local filter)' ;;
    *)
      if [ -n "$GATEWAY" ] && [ "$1" = "$GATEWAY" ]; then
        echo 'the router itself (it forwards to whatever the router is set to, usually the ISP)'
      elif is_private "$1"; then
        echo 'a resolver on your network (a Pi-hole, AdGuard Home, or another device)'
      else
        echo 'not a resolver this script knows; check it against the guide'
      fi
      ;;
  esac
}

is_private() {
  case "$1" in
    10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|fd*|fc*) return 0 ;;
    *) return 1 ;;
  esac
}

# lookup NAME [SERVER] -> prints one of: "addr A B C", "nxdomain", "empty", "timeout", "error", "notool"
lookup() {
  lookup_name=$1
  lookup_server=$2
  if have dig; then
    if [ -n "$lookup_server" ]; then
      lookup_out=$(dig +time=3 +tries=1 +noall +answer +comments A "$lookup_name" "@$lookup_server" 2>&1)
    else
      lookup_out=$(dig +time=3 +tries=1 +noall +answer +comments A "$lookup_name" 2>&1)
    fi
    lookup_rc=$?
    case "$lookup_out" in
      *'timed out'*|*'no servers could be reached'*) echo timeout; return ;;
    esac
    if [ $lookup_rc -ne 0 ]; then echo error; return; fi
    case "$lookup_out" in *'status: NXDOMAIN'*) echo nxdomain; return ;; esac
    lookup_addrs=$(printf '%s\n' "$lookup_out" | awk '$4 == "A" { print $5 }' | tr '\n' ' ')
  elif have host; then
    if [ -n "$lookup_server" ]; then
      lookup_out=$(host -W 3 -t A "$lookup_name" "$lookup_server" 2>&1)
    else
      lookup_out=$(host -W 3 -t A "$lookup_name" 2>&1)
    fi
    case "$lookup_out" in
      *'timed out'*|*'no servers could be reached'*) echo timeout; return ;;
      *NXDOMAIN*) echo nxdomain; return ;;
    esac
    lookup_addrs=$(printf '%s\n' "$lookup_out" | awk '/has address/ { print $4 }' | tr '\n' ' ')
  elif have nslookup; then
    if [ -n "$lookup_server" ]; then
      lookup_out=$(nslookup -type=A "$lookup_name" "$lookup_server" 2>&1)
    else
      lookup_out=$(nslookup -type=A "$lookup_name" 2>&1)
    fi
    case "$lookup_out" in
      *'timed out'*|*'no servers could be reached'*) echo timeout; return ;;
      *NXDOMAIN*) echo nxdomain; return ;;
    esac
    lookup_addrs=$(printf '%s\n' "$lookup_out" | awk '/^Name:/ { f = 1; next } f && /^Address/ { print $2 }' | tr '\n' ' ')
  elif [ -z "$lookup_server" ] && have getent; then
    lookup_addrs=$(getent ahostsv4 "$lookup_name" 2>/dev/null | awk '{ print $1 }' | sort -u | tr '\n' ' ')
    if [ -z "$lookup_addrs" ]; then echo nxdomain; return; fi
  elif [ -z "$lookup_server" ] && have dscacheutil; then
    lookup_addrs=$(dscacheutil -q host -a name "$lookup_name" 2>/dev/null | awk '/^ip_address:/ { print $2 }' | tr '\n' ' ')
    if [ -z "$lookup_addrs" ]; then echo nxdomain; return; fi
  else
    echo notool; return
  fi
  lookup_addrs=$(printf '%s' "$lookup_addrs" | sed 's/ *$//')
  if [ -z "$lookup_addrs" ]; then echo empty; else echo "addr $lookup_addrs"; fi
}

# describe_lookup RESULT -> a sentence; filtered_lookup RESULT -> 0 when the answer means filtered
describe_lookup() {
  case "$1" in
    nxdomain) echo 'no such name (filtered: the resolver answered NXDOMAIN)' ;;
    empty) echo 'no address (filtered: an empty answer)' ;;
    timeout) echo 'no answer (timed out)' ;;
    error) echo 'not answered (the lookup failed)' ;;
    notool) echo 'not checked (this needs dig, host or nslookup)' ;;
    addr*)
      describe_addrs=${1#addr }
      if all_sinkhole "$describe_addrs"; then echo "sinkholed to $describe_addrs (filtered)"
      elif all_private "$describe_addrs"; then echo "a LAN address, $describe_addrs (a local block page: filtered)"
      else echo "a real address, $describe_addrs (not filtered)"; fi
      ;;
  esac
}

all_sinkhole() {
  for sink_a in $1; do
    case "$sink_a" in 0.0.0.0|127.0.0.1|::|::1) ;; *) return 1 ;; esac
  done
  return 0
}

all_private() {
  for priv_a in $1; do
    is_private "$priv_a" || return 1
  done
  return 0
}

filtered_lookup() {
  case "$1" in
    nxdomain|empty) return 0 ;;
    addr*)
      filtered_addrs=${1#addr }
      all_sinkhole "$filtered_addrs" && return 0
      all_private "$filtered_addrs" && return 0
      return 1
      ;;
    *) return 1 ;;
  esac
}

# xml_field TEXT FIELD -> the first <FIELD>...</FIELD> value
xml_field() {
  printf '%s' "$1" | tr '\n' ' ' | grep -o "<$2>[^<]*</$2>" | head -1 | sed 's/<[^>]*>//g' | sed 's/^ *//; s/ *$//'
}

# upnp_locations GATEWAY -> description URLs of any Internet Gateway Device that answers
upnp_locations() {
  have python3 || return 1
  python3 - "$1" <<'PY'
import re, socket, sys, time
gateway = sys.argv[1] if len(sys.argv) > 1 else ''
message = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\n'
           'ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n').encode('ascii')
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1.5)
try:
    sock.sendto(message, ('239.255.255.250', 1900))
    if gateway:
        sock.sendto(message, (gateway, 1900))
except OSError:
    pass
seen = []
end = time.time() + 3
while time.time() < end:
    try:
        data, _ = sock.recvfrom(4096)
    except (socket.timeout, OSError):
        break
    found = re.search(rb'(?im)^LOCATION:\s*(\S+)', data)
    if found:
        location = found.group(1).decode('ascii', 'replace')
        if location not in seen:
            seen.append(location)
            print(location)
sock.close()
PY
}

# upnp_call CONTROL_URL SERVICE_TYPE ACTION ARGUMENTS -> the SOAP response body
upnp_call() {
  curl -s -m 6 -X POST -H 'Content-Type: text/xml; charset="utf-8"' -H "SOAPAction: \"$2#$3\"" \
    --data "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:$3 xmlns:u=\"$2\">$4</u:$3></s:Body></s:Envelope>" \
    "$1" 2>/dev/null
}

# ---- the report ----------------------------------------------------------------------------

case "$OS" in
  Darwin) OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null)" ;;
  Linux)
    if [ -r /etc/os-release ]; then
      OS_NAME=$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-Linux}")
    else
      OS_NAME=Linux
    fi
    ;;
  *) OS_NAME="$OS (this script knows macOS and Linux; other systems get a best effort)" ;;
esac
printf 'bw-check %s - %s - %s - %s\n' "$BW_VERSION" "$(hostname 2>/dev/null || echo unknown)" "$OS_NAME" "$(date '+%Y-%m-%d %H:%M')"
if [ "$NO_NETWORK" = 1 ]; then echo 'Run with --no-network: the canary, router, upnp and bypass rows are skipped.'; fi
echo

# Gateway first: the resolver and router rows both need it.
GATEWAY=''
case "$OS" in
  Darwin) GATEWAY=$(route -n get default 2>/dev/null | awk '/gateway:/ { print $2; exit }') ;;
  *) if have ip; then GATEWAY=$(ip route show default 2>/dev/null | awk '/default via/ { print $3; exit }'); fi ;;
esac

# resolver: what the system uses, and how it was set.
RESOLVERS=''
if [ "$OS" = Darwin ]; then
  RESOLVERS=$(scutil --dns 2>/dev/null | awk '/^resolver #1$/ { f = 1; next } /^resolver #/ { f = 0 } f && /nameserver\[/ { print $3 }' | tr '\n' ' ')
  if [ -z "$RESOLVERS" ]; then
    row resolver unknown 'scutil --dns lists no nameserver for resolver #1: is this Mac on a network?'
  else
    for address in $RESOLVERS; do
      what=$(describe_resolver "$address")
      case "$what" in 'the router itself'*|*'does not filter'*) state=finding ;; *) state=info ;; esac
      row resolver "$state" "system resolver $address: $what"
    done
  fi
  if have networksetup; then
    networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | sed 's/^\*//' | while IFS= read -r service; do
      manual=$(networksetup -getdnsservers "$service" 2>/dev/null | grep -v "aren't any" | tr '\n' ' ')
      [ -n "$manual" ] && note "$service has DNS set by hand: $manual"
    done
  fi
  if have profiles; then
    dns_profiles=$(profiles list 2>/dev/null | grep -i -E 'dns|adguard|nextdns|cloudflare|quad9|mullvad' | head -3 | tr '\n' ' ')
    if [ -n "$dns_profiles" ]; then note "a DNS profile is installed for this user: $dns_profiles"
    else note 'no DNS profile for this user (system profiles need sudo profiles list; an encrypted DNS profile is the usual way to set a filter on a Mac)'; fi
  fi
elif have resolvectl && resolvectl status >/dev/null 2>&1; then
  status=$(resolvectl status 2>/dev/null)
  RESOLVERS=$(printf '%s\n' "$status" | awk '/DNS Servers:/ { for (i = 3; i <= NF; i++) print $i } /Current DNS Server:/ { print $4 }' | sort -u | tr '\n' ' ')
  current=$(printf '%s\n' "$status" | awk '/Current DNS Server:/ { print $4; exit }')
  for address in $RESOLVERS; do
    what=$(describe_resolver "$address")
    case "$what" in 'the router itself'*|*'does not filter'*) state=finding ;; *) state=info ;; esac
    if [ "$address" = "$current" ]; then row resolver "$state" "systemd-resolved, in use: $address: $what"
    else row resolver "$state" "systemd-resolved: $address: $what"; fi
  done
  [ -z "$RESOLVERS" ] && row resolver unknown 'systemd-resolved lists no DNS server'
  if printf '%s\n' "$status" | grep -q '+DNSOverTLS'; then note 'DNS over TLS is on (resolved.conf DNSOverTLS)'
  else note 'DNS over TLS is off; resolved.conf can turn it on for a resolver that offers it'; fi
else
  if [ -r /etc/resolv.conf ]; then
    RESOLVERS=$(awk '/^nameserver/ { print $2 }' /etc/resolv.conf | tr '\n' ' ')
    for address in $RESOLVERS; do
      what=$(describe_resolver "$address")
      case "$what" in 'the router itself'*|*'does not filter'*) state=finding ;; *) state=info ;; esac
      row resolver "$state" "/etc/resolv.conf: $address: $what"
    done
    [ -z "$RESOLVERS" ] && row resolver unknown '/etc/resolv.conf names no nameserver'
  else
    row resolver unknown 'no resolvectl and no readable /etc/resolv.conf'
  fi
fi

# canary: the two ad names through the system resolver, with a control that must resolve.
if [ "$NO_NETWORK" = 0 ]; then
  control=$(lookup "$CONTROL_NAME")
  case "$control" in
    addr*)
      filtered_names=''
      real_names=''
      other_names=''
      for name in "$CANARY_1" "$CANARY_2"; do
        result=$(lookup "$name")
        if filtered_lookup "$result"; then filtered_names="$filtered_names$name "
        else case "$result" in addr*) real_names="$real_names$name " ;; *) other_names="$other_names$name " ;; esac; fi
        row canary info "$name: $(describe_lookup "$result")"
      done
      if [ -z "$filtered_names" ] && [ -z "$other_names" ]; then
        row canary finding 'neither ad name was filtered: nothing between this computer and the internet filters ads by DNS'
      elif [ -z "$real_names" ] && [ -z "$other_names" ]; then
        row canary ok 'both ad names were filtered by the resolver this computer uses'
      elif [ -n "$filtered_names" ]; then
        row canary info "filtered by list: ${filtered_names}filtered, ${real_names}${other_names}not; the resolver filters, and its list lacks the other name"
      else
        row canary unknown 'the canary lookups did not answer'
      fi
      ;;
    notool) row canary unknown 'not checked: this needs dig, host, nslookup, getent or dscacheutil' ;;
    *) row canary unknown "the control name $CONTROL_NAME did not resolve ($control), so the canary rows mean nothing; is DNS working?" ;;
  esac
fi

# hosts: the file, and entries that point a name at a real address.
if [ -r /etc/hosts ]; then
  active=$(grep -v '^[[:space:]]*#' /etc/hosts | grep -v '^[[:space:]]*$')
  count=$(printf '%s\n' "$active" | grep -c . 2>/dev/null)
  unusual=$(printf '%s\n' "$active" | awk 'NF >= 2 && $1 !~ /^(127\.|0\.0\.0\.0$|::1$|::$|255\.255\.255\.255$|fe80::1%lo0$)/ { print $2 " -> " $1 }')
  # Private and carrier-grade NAT (100.64/10) targets are a LAN or a VPN client's own entries.
  public=$(printf '%s\n' "$unusual" | awk 'NF == 3 && $3 !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|fd|fc)/')
  if [ -n "$public" ]; then
    row hosts finding "$count active entries; some point a name at a public address: $(printf '%s\n' "$public" | head -5 | tr '\n' ';' | sed 's/;$//; s/;/; /g')"
    note 'a hosts entry can send a name anywhere without DNS; each one should be yours'
  elif [ -n "$unusual" ]; then
    row hosts info "$count active entries; some point a name at an address on your network or VPN (a VPN client writes these): $(printf '%s\n' "$unusual" | head -5 | tr '\n' ';' | sed 's/;$//; s/;/; /g')"
  else
    row hosts ok "$count active entries, none pointing a name at a real address (/etc/hosts)"
  fi
else
  row hosts unknown '/etc/hosts is not readable'
fi

# firewall: what this computer's own firewall says.
if [ "$OS" = Darwin ]; then
  fw=/usr/libexec/ApplicationFirewall/socketfilterfw
  if [ -x "$fw" ]; then
    state_text=$("$fw" --getglobalstate 2>/dev/null)
    stealth_text=$("$fw" --getstealthmode 2>/dev/null)
    case "$state_text" in *enabled*) row firewall ok 'the application firewall is on' ;; *) row firewall finding 'the application firewall is OFF (System Settings, Network, Firewall)' ;; esac
    case "$stealth_text" in *enabled*) row firewall ok 'stealth mode is on' ;; *) row firewall info 'stealth mode is off; on, the Mac does not answer probes it did not ask for' ;; esac
  else
    row firewall unknown 'socketfilterfw is not where this script expects it'
  fi
  if [ "$(id -u)" = 0 ] && have pfctl; then
    pf_status=$(pfctl -s info 2>/dev/null | head -1)
    row firewall info "packet filter: ${pf_status:-not readable}"
  else
    note 'run with sudo to read the packet filter (pfctl -s info) underneath'
  fi
else
  seen_fw=0
  if have systemctl; then
    for unit in firewalld ufw nftables; do
      active=$(systemctl is-active "$unit" 2>/dev/null)
      case "$active" in
        active) row firewall ok "$unit is active"; seen_fw=1 ;;
        inactive|failed) row firewall info "$unit is $active" ;;
      esac
    done
  fi
  if [ "$(id -u)" = 0 ]; then
    if have ufw; then ufw_status=$(ufw status 2>/dev/null | head -1); row firewall info "ufw: ${ufw_status:-not readable}"; fi
    if have nft; then nft_rules=$(nft list ruleset 2>/dev/null | grep -c -E '^[[:space:]]*(ip|ip6|inet) ' ); row firewall info "nftables: $nft_rules table(s) with rules"; fi
    if have iptables; then input_policy=$(iptables -S INPUT 2>/dev/null | head -1); row firewall info "iptables INPUT: ${input_policy:-not readable}"; fi
  else
    note 'run with sudo to read the rules themselves (ufw status, nft list ruleset, iptables -S)'
  fi
  if [ "$seen_fw" = 0 ]; then row firewall finding 'no firewall service is active (firewalld, ufw or nftables): every listener below is reachable from the LAN'; fi
fi

# listening: TCP ports with a listener, the known ones named.
listeners=''
if [ "$OS" = Darwin ]; then
  listeners=$(netstat -an -p tcp 2>/dev/null | awk '$6 == "LISTEN" { print $4 }')
elif have ss; then
  listeners=$(ss -ltnH 2>/dev/null | awk '{ print $4 }')
elif have netstat; then
  listeners=$(netstat -ltn 2>/dev/null | awk '$6 == "LISTEN" { print $4 }')
fi
if [ -n "$listeners" ]; then
  ports=$(printf '%s\n' "$listeners" | sed 's/.*[.:]\([0-9][0-9]*\)$/\1/' | sort -un)
  count=$(printf '%s\n' "$ports" | grep -c .)
  named=''
  for port in $ports; do
    wide=$(printf '%s\n' "$listeners" | grep -E "^(\*|0\.0\.0\.0|\[::\]|::|\*\.\*)[.:]$port$" | head -1)
    [ -z "$wide" ] && continue
    case "$port" in
      21) name=FTP ;; 22) name='SSH, Remote Login' ;; 23) name=Telnet ;; 80) name=HTTP ;; 139) name=NetBIOS ;; 443) name=HTTPS ;;
      445) name='SMB file sharing' ;; 3283) name='Apple Remote Desktop' ;; 3389) name='Remote Desktop' ;; 5900) name='VNC, Screen Sharing' ;;
      8080) name='HTTP alternate' ;; *) continue ;;
    esac
    named="$named$port ($name), "
  done
  named=$(printf '%s' "$named" | sed 's/, $//')
  if [ -n "$named" ]; then
    row listening info "$count TCP ports have a listener; on every address: $named - reachable from the LAN unless the firewall says otherwise"
  else
    row listening ok "$count TCP ports have a listener; none of the well-known remote-access or file-sharing ports listens on every address"
  fi
else
  row listening unknown 'could not list the listeners (this needs netstat or ss)'
fi

# router: the gateway, its resolver, its admin page and its UPnP description.
if [ -z "$GATEWAY" ]; then
  row router unknown 'no default gateway: not on a network, or on a VPN that owns the route'
elif [ "$NO_NETWORK" = 1 ]; then
  row router info "gateway $GATEWAY (its admin page and UPnP were not asked: --no-network)"
else
  router_is_resolver=0
  for address in $RESOLVERS; do [ "$address" = "$GATEWAY" ] && router_is_resolver=1; done
  if [ "$router_is_resolver" = 1 ]; then
    row router finding "gateway $GATEWAY hands itself out as the resolver; set the DHCP DNS on the router to your filtering resolver instead"
  else
    row router ok "gateway $GATEWAY; the resolver this computer uses is not the router"
  fi
  if have curl; then
    http=$(curl -s -o /dev/null -m 6 -w '%{http_code} %{redirect_url}' "http://$GATEWAY/" 2>/dev/null)
    http_code=${http%% *}
    http_redirect=${http#* }
    https_code=$(curl -s -k -o /dev/null -m 6 -w '%{http_code}' "https://$GATEWAY/" 2>/dev/null)
    case "$http_code" in
      301|302|303|307|308)
        case "$http_redirect" in
          https:*) row router ok "admin page: HTTP redirects to HTTPS ($http_code -> $http_redirect)" ;;
          *) row router info "admin page: HTTP redirects to $http_redirect" ;;
        esac
        ;;
      2*|4*) row router info "admin page answers over plain HTTP ($http_code); sign in over https://$GATEWAY/ if the router offers it, and turn plain HTTP off if it lets you" ;;
      000) row router info 'nothing answers on port 80 (the admin page may live on another port, or be off)' ;;
      *) row router info "admin page answered HTTP $http_code on port 80" ;;
    esac
    case "$https_code" in
      000) row router info 'nothing answers on port 443' ;;
      *) row router info "admin page answers over HTTPS ($https_code); a self-signed certificate is normal on a home router" ;;
    esac
  else
    row router unknown 'curl is not installed, so the admin page was not asked'
  fi

  if have python3; then
    locations=$(upnp_locations "$GATEWAY" 2>/dev/null | sort -u)
    if [ -z "$locations" ]; then
      row upnp ok 'no UPnP Internet Gateway Device answered the search: UPnP is off, or the router does not offer it on this network'
    elif ! have curl; then
      row upnp info 'a UPnP device answered, but curl is not installed, so its description was not read'
    else
      for location in $locations; do
        description=$(curl -s -m 6 "$location" 2>/dev/null)
        if [ -z "$description" ]; then row upnp info "a device answered at $location but its description could not be read"; continue; fi
        model="$(xml_field "$description" manufacturer) $(xml_field "$description" modelName) $(xml_field "$description" modelNumber)"
        friendly=$(xml_field "$description" friendlyName)
        model_description=$(xml_field "$description" modelDescription)
        model=$(printf '%s' "$model" | sed 's/  */ /g; s/^ //; s/ $//')
        if [ -n "$friendly" ]; then model="$model \"$friendly\""; fi
        if [ -n "$model_description" ]; then model="$model ($model_description)"; fi
        row router info "UPnP says the gateway is $model"
        note 'note the firmware version from the admin page and compare it with the vendor; the guide says where to look it up'
        service=$(printf '%s' "$description" | tr '\n' ' ' | sed 's/<service>/\n<service>/g' | grep -E 'WANIPConnection|WANPPPConnection' | head -1)
        if [ -z "$service" ]; then row upnp info 'UPnP is on, but the gateway lists no WAN connection service, so the mapping table could not be read'; continue; fi
        service_type=$(xml_field "$service" serviceType)
        control_path=$(xml_field "$service" controlURL)
        url_base=$(xml_field "$description" URLBase)
        origin=$(printf '%s' "${url_base:-$location}" | sed -E 's#^(https?://[^/]+).*#\1#')
        case "$control_path" in
          http*) control_url=$control_path ;;
          /*) control_url="$origin$control_path" ;;
          *) control_url="$(printf '%s' "${url_base:-$location}" | sed -E 's#/[^/]*$#/#')$control_path" ;;
        esac
        external=$(upnp_call "$control_url" "$service_type" GetExternalIPAddress '')
        public_address=$(xml_field "$external" NewExternalIPAddress)
        if [ -n "$public_address" ] && [ "$public_address" != 0.0.0.0 ]; then
          row router info "public address $public_address; what the internet sees of it: open https://internetdb.shodan.io/$public_address by hand"
          is_private "$public_address" && note 'that is a private address: the router sits behind another router or carrier NAT'
        fi
        mappings=''
        mapping_count=0
        index=0
        while [ $index -lt 64 ]; do
          entry=$(upnp_call "$control_url" "$service_type" GetGenericPortMappingEntry "<NewPortMappingIndex>$index</NewPortMappingIndex>")
          external_port=$(xml_field "$entry" NewExternalPort)
          [ -z "$external_port" ] && break
          mapping_description=$(xml_field "$entry" NewPortMappingDescription)
          if [ "$(xml_field "$entry" NewEnabled)" = 0 ]; then enabled_text='(disabled) '; else enabled_text=''; fi
          if [ -n "$mapping_description" ]; then mapping_text="\"$mapping_description\""; else mapping_text='(no description)'; fi
          mappings="$mappings$(xml_field "$entry" NewProtocol) $external_port -> $(xml_field "$entry" NewInternalClient):$(xml_field "$entry" NewInternalPort) $enabled_text$mapping_text; "
          mapping_count=$((mapping_count + 1))
          index=$((index + 1))
        done
        if [ "$mapping_count" = 0 ]; then
          row upnp finding 'UPnP is on and the gateway lists no port mappings; any program on the LAN may still ask it to open one, so turn UPnP off unless something you run needs it'
        else
          row upnp finding "UPnP is on and the gateway lists $mapping_count port mapping(s): $(printf '%s' "$mappings" | sed 's/; $//')"
          note 'each mapping is a port open from the internet to a device here; know what asked for each, or remove it and turn UPnP off'
        fi
      done
    fi
  else
    row upnp unknown 'not checked: the UPnP search needs python3 (the guide says how to read the mappings on the router itself)'
  fi
fi

# bypass: plain DNS to two public resolvers and DNS over HTTPS to one, from this computer.
if [ "$NO_NETWORK" = 0 ]; then
  for server in 8.8.8.8 1.1.1.1; do
    result=$(lookup "$CANARY_1" "$server")
    case "$result" in
      notool) row bypass unknown "plain DNS straight to $server: not checked (this needs dig, host or nslookup)" ;;
      timeout|error) row bypass ok "plain DNS straight to $server: $(describe_lookup "$result"); port 53 out is blocked or redirected, so a device cannot pick its own resolver" ;;
      *)
        if filtered_lookup "$result"; then row bypass ok "plain DNS straight to $server came back filtered: the router redirects port 53 to your filter"
        else row bypass info "plain DNS straight to $server was answered with a real address: a device or app that brings its own resolver walks past your network filter"; fi
        ;;
    esac
  done
  if have curl; then
    doh=$(curl -s -m 8 "https://dns.google/resolve?name=$CANARY_1&type=A" 2>/dev/null)
    case "$doh" in
      *'"Answer"'*) row bypass info 'DNS over HTTPS to dns.google answered from this computer: an app with its own DoH walks past your network filter unless the router blocks the known DoH endpoints' ;;
      '') row bypass ok 'DNS over HTTPS to dns.google did not answer: blocked from this network' ;;
      *) row bypass ok 'DNS over HTTPS to dns.google answered without an address: the endpoint is intercepted or filtered' ;;
    esac
  else
    row bypass unknown 'DNS over HTTPS not checked: curl is not installed'
  fi
fi

# ipv6: a public address on this computer.
if [ "$OS" = Darwin ]; then
  global6=$(ifconfig 2>/dev/null | awk '/inet6/ && $2 ~ /^[23]/ { print $2 }' | tr '\n' ' ')
elif have ip; then
  global6=$(ip -6 addr show scope global 2>/dev/null | awk '/inet6/ { print $2 }' | tr '\n' ' ')
else
  global6=''
fi
if [ -n "$global6" ]; then
  row ipv6 info "this computer has a public IPv6 address ($(printf '%s' "$global6" | sed 's/ *$//')); the router's IPv6 firewall and this firewall are what stand between it and the internet"
else
  row ipv6 info 'no public IPv6 address on this computer (IPv6 is off here, or the router does not delegate one)'
fi

# lockdown and the rest, macOS only.
if [ "$OS" = Darwin ]; then
  ldm=$(defaults read .GlobalPreferences LDMGlobalEnabled 2>/dev/null)
  case "$ldm" in
    1) row lockdown ok 'Lockdown Mode is on' ;;
    *) row lockdown info 'Lockdown Mode is off (System Settings, Privacy & Security); it is for people who may be targeted' ;;
  esac
  ads=$(defaults read com.apple.AdLib allowApplePersonalizedAdvertising 2>/dev/null)
  case "$ads" in
    0) row lockdown ok 'Apple personalized ads are off for this user' ;;
    *) row lockdown finding 'Apple personalized ads are on for this user (System Settings, Privacy & Security, Apple Advertising)' ;;
  esac
  if have csrutil; then
    sip=$(csrutil status 2>/dev/null | head -1)
    case "$sip" in *enabled*) row lockdown ok 'System Integrity Protection is on' ;; *) row lockdown finding "System Integrity Protection: ${sip:-unknown}" ;; esac
  fi
  if have spctl; then
    gatekeeper=$(spctl --status 2>/dev/null | head -1)
    case "$gatekeeper" in *enabled*) row lockdown ok 'Gatekeeper is on' ;; *) row lockdown finding "Gatekeeper: ${gatekeeper:-unknown}" ;; esac
  fi
fi

echo
if [ "$FINDINGS" = 0 ]; then
  echo 'verdict    no finding; a clean result is not a clean bill of health'
else
  echo "verdict    $FINDINGS finding(s); each names the guide step that explains it"
fi
echo "nothing was uploaded or changed; keep this report with the device's record"
