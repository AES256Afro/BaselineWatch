#!/bin/sh
# bw-inventory.sh - what this computer runs, as one report for BaselineWatch's "Is this device
# affected?" page (/scan/devices on the instance you downloaded it from).
#
# WHAT IT DOES
#   Reads this computer and prints one JSON report between two marker lines:
#     os          macOS: the version and build from sw_vers;
#                 Linux: the distribution and release from /etc/os-release
#     browsers    the versions of Safari, Chrome, Chromium, Firefox, Edge, Brave where installed
#     packages    Linux: every installed package and its version, from dpkg, rpm or apk;
#                 macOS: none (Apple's updates carry the system's packages)
#   Paste the whole output into /scan/devices. The instance reads it against the Security
#   Update Guide, the vendors' releases, endoflife.date and OSV, and shows which CVEs apply to
#   the versions you run. Nothing from the report is stored there.
#
# WHAT IT DOES NOT DO
#   It uploads nothing, changes nothing, writes nothing to disk and sends no packet anywhere.
#   No advertising domain is fetched: nothing at all is fetched. It needs no root. It reads
#   version numbers and package names, not files, keys or settings.
#
# RUN
#   sh ./bw-inventory.sh            Verify first: shasum -a 256 bw-inventory.sh (macOS) or
#                                   sha256sum bw-inventory.sh (Linux), against /scan/scripts/SHA256SUMS.

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r'
}

first=1
pair() {
  if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
  printf '{"name":"%s","version":"%s"}' "$(json_escape "$1")" "$(json_escape "$2")"
}

plist_version() {
  # The CFBundleShortVersionString of an app bundle, or nothing.
  [ -f "$1/Contents/Info.plist" ] || return 0
  if command -v defaults >/dev/null 2>&1; then
    defaults read "$1/Contents/Info" CFBundleShortVersionString 2>/dev/null
  fi
}

family=linux
os_name=""; os_version=""; os_build=""; os_id=""; os_version_id=""
if [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
  family=macos
  os_name="macOS"
  os_version=$(sw_vers -productVersion 2>/dev/null)
  os_build=$(sw_vers -buildVersion 2>/dev/null)
elif [ -r /etc/os-release ]; then
  os_id=$(. /etc/os-release 2>/dev/null; printf '%s' "${ID:-}")
  os_name=$(. /etc/os-release 2>/dev/null; printf '%s' "${NAME:-}")
  os_version_id=$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_ID:-}")
  os_version="$os_version_id"
fi

printf 'BW-REPORT-BEGIN\n'
printf '{"bw":1,"os":{"family":"%s","name":"%s","version":"%s","build":"%s","id":"%s","version_id":"%s"},' \
  "$family" "$(json_escape "$os_name")" "$(json_escape "$os_version")" "$(json_escape "$os_build")" "$(json_escape "$os_id")" "$(json_escape "$os_version_id")"

printf '"browsers":['
first=1
if [ "$family" = "macos" ]; then
  v=$(plist_version "/Applications/Safari.app"); [ -n "$v" ] && pair "Safari" "$v"
  v=$(plist_version "/Applications/Google Chrome.app"); [ -n "$v" ] && pair "Chrome" "$v"
  v=$(plist_version "/Applications/Chromium.app"); [ -n "$v" ] && pair "Chromium" "$v"
  v=$(plist_version "/Applications/Firefox.app"); [ -n "$v" ] && pair "Firefox" "$v"
  v=$(plist_version "/Applications/Microsoft Edge.app"); [ -n "$v" ] && pair "Edge" "$v"
  v=$(plist_version "/Applications/Brave Browser.app"); [ -n "$v" ] && pair "Brave" "$v"
else
  for pair_spec in "Chrome:google-chrome" "Chromium:chromium" "Chromium:chromium-browser" "Firefox:firefox" "Edge:microsoft-edge" "Brave:brave-browser"; do
    name=${pair_spec%%:*}; cmd=${pair_spec#*:}
    if command -v "$cmd" >/dev/null 2>&1; then
      v=$("$cmd" --version 2>/dev/null | head -n 1 | grep -o '[0-9][0-9]*\(\.[0-9][0-9]*\)\{1,3\}' | head -n 1)
      [ -n "$v" ] && pair "$name" "$v"
    fi
  done
fi
printf '],'

source=""
printf '"packages":['
first=1
if [ "$family" = "linux" ]; then
  if command -v dpkg-query >/dev/null 2>&1; then
    source=dpkg
    dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | while read -r n v; do [ -n "$n" ] && pair "$n" "$v"; done
  elif command -v rpm >/dev/null 2>&1; then
    source=rpm
    rpm -qa --qf '%{NAME} %|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\n' 2>/dev/null | while read -r n v; do [ -n "$n" ] && pair "$n" "$v"; done
  elif command -v apk >/dev/null 2>&1; then
    source=apk
    apk list -I 2>/dev/null | sed 's/ .*//' | sed 's/-\([0-9][^-]*-r[0-9]*\)$/ \1/' | while read -r n v; do [ -n "$n" ] && pair "$n" "$v"; done
  fi
fi
printf '],"package_source":"%s"}\n' "$source"
printf 'BW-REPORT-END\n'
