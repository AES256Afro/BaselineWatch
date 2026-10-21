import { html, newTab, type Html } from "../html.ts";
import type { LookState } from "../look.ts";
import { scriptsFor, sumsFile, type ScanScript, type ScriptPlatform } from "../scan-scripts.ts";
import { page } from "./layout.ts";

/**
 * The manual guide of the Scan area (M12.2, mockup 07): everything the checks look at, done by
 * hand, one platform at a time. Each step says what to open or run, what a clean result looks
 * like, what a finding means, and links to the vendor page it follows and to the why page's
 * section on it. The wording is this product's; the facts are the vendors'. Nothing is generated
 * by a model. The router and network sections are the same on every platform, because the
 * router is the same router.
 */
export type GuidePlatform = "windows" | "macos" | "linux" | "ios" | "android";

export interface GuidePlatformInfo {
  id: GuidePlatform;
  label: string;
  /** The word the page uses for the device: "this PC", "this Mac". */
  device: string;
  script: ScriptPlatform | null;
}

export const guidePlatforms: readonly GuidePlatformInfo[] = [
  { id: "windows", label: "Windows", device: "this PC", script: "windows" },
  { id: "macos", label: "macOS", device: "this Mac", script: "macos" },
  { id: "linux", label: "Linux", device: "this computer", script: "linux" },
  { id: "ios", label: "iPhone and iPad", device: "this iPhone", script: null },
  { id: "android", label: "Android", device: "this phone", script: null },
];

export function isGuidePlatform(id: string): id is GuidePlatform {
  return guidePlatforms.some((p) => p.id === id);
}

interface Source {
  href: string;
  text: string;
}

interface Step {
  title: string;
  do: Html;
  clean?: Html;
  finding?: Html;
  why?: Html;
  /** An anchor on /scan/why that carries the longer argument. */
  more?: string;
  sources: Source[];
}

interface Section {
  id: string;
  title: string;
  intro?: Html;
  steps: Step[];
}

const c = (text: string): Html => html`<code>${text}</code>`;

/** The primary documents the steps follow. Every href was opened on 2026-10-19. */
const src = {
  adguard: { href: "https://adguard-dns.io/en/public-dns.html", text: "AdGuard DNS, public servers and setup" },
  adguardHome: { href: "https://github.com/AdguardTeam/AdGuardHome/wiki/Getting-Started", text: "AdGuard Home, Getting Started" },
  nextdns: { href: "https://nextdns.io/", text: "NextDNS" },
  quad9: { href: "https://quad9.net/service/service-addresses-and-features/", text: "Quad9, service addresses and features" },
  cloudflareFamilies: { href: "https://developers.cloudflare.com/1.1.1.1/setup/#1111-for-families", text: "Cloudflare, 1.1.1.1 for Families" },
  cloudflareRouter: { href: "https://developers.cloudflare.com/1.1.1.1/setup/router/", text: "Cloudflare, set up 1.1.1.1 on a router" },
  mullvad: { href: "https://mullvad.net/en/help/dns-over-https-and-dns-over-tls", text: "Mullvad, DNS over HTTPS and DNS over TLS" },
  pihole: { href: "https://docs.pi-hole.net/", text: "Pi-hole documentation" },
  piholePost: { href: "https://docs.pi-hole.net/main/post-install/", text: "Pi-hole, Post-Install: point the router's DHCP at the Pi-hole" },
  piholeDevices: { href: "https://discourse.pi-hole.net/t/how-do-i-configure-my-devices-to-use-pi-hole-as-their-dns-server/245", text: "Pi-hole FAQ, configuring devices to use the Pi-hole" },
  easylist: { href: "https://easylist.to/", text: "EasyList" },
  ubo: { href: "https://ublockorigin.com/", text: "uBlock Origin" },
  ubol: { href: "https://github.com/uBlockOrigin/uBOL-home", text: "uBlock Origin Lite, for Chrome and Edge" },
  firefoxDoh: { href: "https://support.mozilla.org/en-US/kb/dns-over-https", text: "Mozilla, DNS over HTTPS in Firefox" },
  chromeDns: { href: "https://support.google.com/chrome/answer/10468685", text: "Google, Manage Chrome safety and security (Use secure DNS)" },
  firefoxAndroid: { href: "https://addons.mozilla.org/en-US/android/", text: "Mozilla, add-ons for Firefox for Android" },
  msDoh: { href: "https://learn.microsoft.com/en-us/windows-server/networking/dns/doh-client-support", text: "Microsoft, DNS over HTTPS for the DNS client" },
  msGetDns: { href: "https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientserveraddress", text: "Microsoft, Get-DnsClientServerAddress" },
  msResolve: { href: "https://learn.microsoft.com/en-us/powershell/module/dnsclient/resolve-dnsname", text: "Microsoft, Resolve-DnsName" },
  msFirewall: { href: "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/", text: "Microsoft, Windows Firewall overview" },
  msFirewallApp: { href: "https://support.microsoft.com/en-us/windows/turn-microsoft-defender-firewall-on-or-off-ec0844f7-aebd-0583-67fe-601ecf5d774f", text: "Microsoft, Firewall & network protection in the Windows Security app" },
  msGetProfile: { href: "https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile", text: "Microsoft, Get-NetFirewallProfile" },
  msGetRule: { href: "https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule", text: "Microsoft, Get-NetFirewallRule" },
  msTcp: { href: "https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection", text: "Microsoft, Get-NetTCPConnection" },
  msIp: { href: "https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress", text: "Microsoft, Get-NetIPAddress" },
  msSmb: { href: "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic", text: "Microsoft, Secure SMB traffic" },
  msSmbRules: { href: "https://support.microsoft.com/en-us/topic/preventing-smb-traffic-from-lateral-connections-and-entering-or-leaving-the-network-c0541db7-2244-0dce-18fd-14a3ddeb282a", text: "Microsoft, Preventing SMB traffic from lateral connections and entering or leaving the network" },
  msPrivacy: { href: "https://support.microsoft.com/en-us/windows/general-privacy-settings-in-windows-7c7f6a09-cebd-5589-c376-7f505e5bf65a", text: "Microsoft, General privacy settings in Windows" },
  msWevtutil: { href: "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil", text: "Microsoft, wevtutil" },
  msGetWinEvent: { href: "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent", text: "Microsoft, Get-WinEvent" },
  appleDns: { href: "https://support.apple.com/guide/mac-help/use-dhcp-or-a-manual-ip-address-on-mac-mchlp2718/mac", text: "Apple, Use DHCP or a manual IP address on Mac (the DNS tab)" },
  appleProfilesMac: { href: "https://support.apple.com/guide/mac-help/configuration-profiles-standardize-settings-mh35561/mac", text: "Apple, Use configuration profiles on Mac" },
  appleFirewall: { href: "https://support.apple.com/guide/mac-help/block-connections-to-your-mac-with-a-firewall-mh34041/mac", text: "Apple, Block connections to your Mac with a firewall" },
  appleSharing: { href: "https://support.apple.com/guide/mac-help/set-up-file-sharing-on-mac-mh17131/mac", text: "Apple, Set up file sharing on Mac (the Sharing settings)" },
  appleLockdown: { href: "https://support.apple.com/en-us/105120", text: "Apple, About Lockdown Mode" },
  appleAds: { href: "https://support.apple.com/en-us/105131", text: "Apple, Control personalized ads on the App Store, Apple News and Stocks" },
  appleTracking: { href: "https://support.apple.com/en-us/102420", text: "Apple, If an app asks to track your activity" },
  appleBsi: { href: "https://support.apple.com/en-us/102657", text: "Apple, About Background Security Improvements" },
  appleUpdate: { href: "https://support.apple.com/guide/iphone/update-ios-iph3e504502/ios", text: "Apple, Update iOS on iPhone" },
  appleProfilesIos: { href: "https://support.apple.com/guide/iphone/install-or-remove-configuration-profiles-iph6c493b19/ios", text: "Apple, Install or remove configuration profiles on iPhone" },
  appleSafariIos: { href: "https://support.apple.com/guide/iphone/get-extensions-iphab0432bf6/ios", text: "Apple, Get extensions to customize Safari on iPhone" },
  appleSafariMac: { href: "https://support.apple.com/guide/safari/get-extensions-sfri32508/mac", text: "Apple, Get extensions to customize Safari on Mac" },
  appleIosAds: { href: "https://support.apple.com/guide/iphone/control-how-apple-delivers-advertising-to-you-iphf60a6a256/ios", text: "Apple, Control how Apple delivers advertising to you on iPhone" },
  androidPrivateDns: { href: "https://support.google.com/android/answer/9654714", text: "Google, Manage advanced network settings on your Android phone (Private DNS)" },
  androidDot: { href: "https://android-developers.googleblog.com/2018/04/dns-over-tls-support-in-android-p.html", text: "Android Developers Blog, DNS over TLS support in Android P" },
  androidAdId: { href: "https://support.google.com/googleplay/answer/3405269", text: "Google Play Help, Advertising ID" },
  androidUpdate: { href: "https://support.google.com/android/answer/7680439", text: "Google, Check and update your Android version" },
  androidBulletin: { href: "https://source.android.com/docs/security/bulletin", text: "Android Security Bulletins" },
  resolvectl: { href: "https://www.freedesktop.org/software/systemd/man/latest/resolvectl.html", text: "systemd, resolvectl" },
  resolvedConf: { href: "https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html", text: "systemd, resolved.conf (DNS= and DNSOverTLS=)" },
  nmcli: { href: "https://networkmanager.dev/docs/api/latest/nmcli.html", text: "NetworkManager, nmcli" },
  ubuntuFw: { href: "https://documentation.ubuntu.com/server/how-to/security/firewalls/", text: "Ubuntu Server, Firewalls (ufw)" },
  firewalld: { href: "https://firewalld.org/documentation/", text: "firewalld documentation" },
  nftables: { href: "https://wiki.nftables.org/", text: "nftables wiki" },
  ss: { href: "https://man7.org/linux/man-pages/man8/ss.8.html", text: "ss(8)" },
  hosts5: { href: "https://man7.org/linux/man-pages/man5/hosts.5.html", text: "hosts(5)" },
  cisaHome: { href: "https://www.cisa.gov/news-events/news/home-network-security", text: "CISA, Home Network Security" },
  certUpnp: { href: "https://www.kb.cert.org/vuls/id/357851", text: "CERT/CC, VU#357851: UPnP requests accepted over router WAN interfaces" },
  igd: { href: "https://openconnectivity.org/developer/specifications/upnp-resources/upnp/internet-gateway-device-igd-v-2-0/", text: "Open Connectivity Foundation, UPnP Internet Gateway Device v2.0" },
  kev: { href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", text: "CISA, Known Exploited Vulnerabilities catalog" },
  internetdb: { href: "https://internetdb.shodan.io/", text: "Shodan, InternetDB" },
  rfc8484: { href: "https://www.rfc-editor.org/rfc/rfc8484", text: "RFC 8484, DNS queries over HTTPS" },
  rfc7858: { href: "https://www.rfc-editor.org/rfc/rfc7858", text: "RFC 7858, DNS over TLS" },
  rfc6092: { href: "https://www.rfc-editor.org/rfc/rfc6092", text: "RFC 6092, simple security in IPv6 residential gateways" },
  mvt: { href: "https://docs.mvt.re/en/latest/", text: "Amnesty International, Mobile Verification Toolkit" },
  mvtIos: { href: "https://docs.mvt.re/en/latest/ios/backup/check/", text: "MVT, checking an iOS backup" },
  mvtAndroid: { href: "https://docs.mvt.re/en/latest/android/methodology/", text: "MVT, Android methodology" },
  accessNow: { href: "https://www.accessnow.org/help/", text: "Access Now, Digital Security Helpline" },
  citizenLab: { href: "https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/", text: "Citizen Lab, how targeted ads became a pipeline for spyware" },
} as const satisfies Record<string, Source>;

/** The step every platform shares: which resolver to filter with, and why. */
function chooseResolverStep(device: string): Step {
  return {
    title: "Decide which resolver filters",
    do: html`AdGuard DNS, NextDNS, Mullvad and Cloudflare's 1.1.1.1 for Families each publish a filtering resolver; Quad9 filters malware domains but not ads. A Pi-hole or AdGuard Home on your own network is the same thing for every device at once, and the router section below hands it out. If ${device} uses a VPN or iCloud Private Relay, that brings its own resolver and wins: set the filter there, or accept that the rows below describe the VPN's resolver.`,
    why: html`A browser blocker protects one browser; the system resolver covers every app that uses it, which is most of them. Apps with their own resolver still bypass it, which the network section tests.`,
    more: "dns",
    sources: [src.adguard, src.nextdns, src.mullvad, src.cloudflareFamilies, src.quad9, src.pihole],
  };
}

/** The content-blocker section, which differs only in which browsers the platform has. */
function blockerSection(platform: GuidePlatform): Section {
  const steps: Step[] = [];
  if (platform === "ios") {
    steps.push({
      title: "Install a content blocker for Safari",
      do: html`Safari on iPhone and iPad takes content blockers from the App Store (AdGuard, 1Blocker, Wipr and others use Apple's content-blocker interface). After installing one, turn it on under Settings, Apps, Safari, Extensions. In-app browsers inside Instagram, Facebook and TikTok carry no blocker at all; open links in Safari.`,
      clean: html`Safari's Extensions list shows the blocker on, and the browser check's ad hiding row reports baits hidden.`,
      finding: html`A page full of ads in Safari with the blocker on usually means its rules need an update inside the blocker's own app.`,
      sources: [src.appleSafariIos, src.easylist],
    });
  } else if (platform === "android") {
    steps.push({
      title: "Use a browser that takes a blocker, or lean on Private DNS",
      do: html`Chrome for Android takes no extensions. Firefox for Android installs uBlock Origin from Mozilla's add-ons site; Brave carries its own blocker. Otherwise the Private DNS step above is the filter for every app, browsers included, and the only one most Android phones have.`,
      clean: html`In Firefox with uBlock Origin, the browser check reports baits hidden and a load difference. In Chrome with Private DNS set to a filtering resolver, the filtering DNS row names the provider and the request row shows a difference while the hiding row stays at "not observed".`,
      finding: html`No difference in any row with Private DNS on means the phone is on a network that overrides it, or a VPN is in the way.`,
      sources: [src.firefoxAndroid, src.ubo],
    });
  } else {
    const safari = platform === "macos" ? html` In Safari, content blockers come from the App Store and are turned on under Safari, Settings, Extensions.` : html``;
    steps.push({
      title: "Install uBlock Origin, or uBlock Origin Lite where the browser requires it",
      do: html`Firefox takes uBlock Origin. Chrome and Edge take uBlock Origin Lite, the build written for their newer extension interface.${safari} The blocker's own lists are EasyList and EasyPrivacy plus the author's; leave the defaults on.`,
      clean: html`The browser check at <a href="/scan">/scan</a> reports baits hidden in the ad hiding row and a load difference in the ad requests row. A blocker that hides nothing but blocks every request (uBlock Origin Lite's default) passes the second row only, which is the better of the two.`,
      finding: html`No difference in the requests row means the blocker is off for this site, or a VPN or extension is sitting in front of it. Reload after changing anything.`,
      sources: platform === "macos" ? [src.ubo, src.ubol, src.appleSafariMac, src.easylist] : [src.ubo, src.ubol, src.easylist],
    });
    steps.push({
      title: "Decide what the browser's own DNS does",
      do: html`Firefox and Chrome can resolve names themselves over DNS over HTTPS, in which case the system resolver from section 1 is not consulted by that browser. Firefox: Settings, Privacy &amp; Security, DNS over HTTPS. Chrome and Edge: Settings, Privacy and security, Security, Use secure DNS. Either point it at the same filtering resolver as the system, or leave it on "use the system resolver".`,
      clean: html`The browser check's filtering DNS row names the provider you chose, the same one the system check in section 1 showed.`,
      finding: html`A provider in that row that differs from section 1 is the browser going its own way.`,
      more: "dns",
      sources: [src.firefoxDoh, src.chromeDns, src.rfc8484],
    });
  }
  return { id: "blocker", title: "A content blocker in the browser", steps };
}

/** The router: the same steps on every platform, because the router is the same router. */
function routerSection(): Section {
  return {
    id: "router",
    title: "The router, from any platform",
    intro: html`Every device on the network trusts the router for its address, its resolver and its path out. These steps are done on the router's own pages; the script's <code>router</code> and <code>upnp</code> rows read what it announces without signing in.`,
    steps: [
      {
        title: "Open the admin page and change the printed password",
        do: html`The gateway address is the one the script's <code>router</code> row names, or the default gateway in your network settings (often 192.168.0.1, 192.168.1.1 or 192.168.8.1). Open it in a browser. If the password is still the one printed on the router, or the vendor's default, change it now: it is the one credential that protects every setting below.`,
        clean: html`The page asks for a password only you know, over HTTPS where the router offers it.`,
        finding: html`A password printed on the device is known to anyone who has seen the device, and vendor defaults are in every list an attacker tries first.`,
        more: "router",
        sources: [src.cisaHome],
      },
      {
        title: "Hand out your filtering resolver by DHCP",
        do: html`In the router's LAN or DHCP settings, set the DNS server that devices receive to your filtering resolver (the Pi-hole's or AdGuard Home's LAN address, or the public resolver from section 1), and leave the router's own address out of the list. A device that takes DHCP then uses the filter without any setup of its own.`,
        clean: html`The script's <code>resolver</code> row, or <code>ipconfig /all</code>, <code>scutil --dns</code> or <code>resolvectl status</code>, shows the filter's address and not the gateway's.`,
        finding: html`The gateway's own address as the resolver means the router forwards to whatever it was set to, usually the ISP, and nothing filters.`,
        more: "dns",
        sources: [src.piholePost, src.adguardHome, src.cloudflareRouter],
      },
      {
        title: "Turn UPnP off unless something you run needs it",
        do: html`Find UPnP (sometimes "automatic port forwarding") in the router's advanced or NAT settings and turn it off. If a game console or a service needs it, leave it on and read the port-mapping table (the script's <code>upnp</code> row, or the router's port-forwarding page) once a month.`,
        clean: html`No UPnP gateway answers the search, or the mapping table is empty.`,
        finding: html`A mapping to a remote-desktop, file-sharing or SSH port that nobody asked for is a hole in the firewall; a program on the LAN opened it without a password.`,
        more: "upnp",
        sources: [src.cisaHome, src.certUpnp, src.igd],
      },
      {
        title: "Turn remote management off, and keep the admin page on HTTPS",
        do: html`Find remote management (also "remote access", "WAN access" or "cloud management") and turn it off, so the admin page answers only from the LAN. Prefer the HTTPS address for the admin page where the router offers one; a self-signed certificate on a home router is normal.`,
        clean: html`From outside the network (a phone on mobile data), the public address does not answer on ports 80, 443 or 8443. The script's <code>router</code> row shows HTTP redirecting to HTTPS.`,
        finding: html`An admin page reachable from the internet is reachable by everyone, and it is where a router's known vulnerabilities are usually exploited.`,
        more: "router",
        sources: [src.cisaHome, src.certUpnp],
      },
      {
        title: "Note the firmware version and look it up",
        do: html`The firmware version is on the router's status or administration page (the script's <code>router</code> row prints the model the router announces over UPnP). Check the vendor's support page for a newer release and turn automatic updates on if the router has them. Then search this site's <a href="/vulnerabilities">Vulnerabilities</a> table for the vendor and model: a CVE marked KEV is one CISA has seen exploited.`,
        clean: html`The installed version is the vendor's newest, and no KEV entry names the model.`,
        finding: html`A router on the KEV list with older firmware is a finding today, not at the next update. The router check planned for this server will do the matching automatically.`,
        more: "router",
        sources: [src.cisaHome, src.kev],
      },
      {
        title: "Wi-Fi: the strongest encryption the router offers, and WPS off",
        do: html`In the wireless settings choose WPA3 Personal, or WPA2 with AES where WPA3 is not offered, turn Wi-Fi Protected Setup (WPS) off, and put guests and smart-home devices on a guest network if the router has one, so a weak device cannot see the rest.`,
        clean: html`The network shows as WPA3 or WPA2 in a device's Wi-Fi details, and WPS is off.`,
        finding: html`WPS and WEP are both ways onto the network that do not need the password.`,
        sources: [src.cisaHome],
      },
    ],
  };
}

/** What the internet sees, and whether DNS can bypass the network's filter: by hand, per platform. */
function networkSection(platform: GuidePlatform): Section {
  const lookupDirect =
    platform === "windows"
      ? c("Resolve-DnsName ad.doubleclick.net -Type A -Server 8.8.8.8 -DnsOnly")
      : platform === "ios" || platform === "android"
        ? html`a computer on the same Wi-Fi: <code>dig +short ad.doubleclick.net @8.8.8.8</code> (a phone has no terminal for this; the browser check's filtering DNS row is the phone's own view)`
        : c("dig +short ad.doubleclick.net @8.8.8.8");
  const doh =
    platform === "windows"
      ? c("Invoke-RestMethod 'https://dns.google/resolve?name=ad.doubleclick.net&type=A'")
      : platform === "ios" || platform === "android"
        ? html`from a computer, <code>curl -s 'https://dns.google/resolve?name=ad.doubleclick.net&amp;type=A'</code>`
        : c("curl -s 'https://dns.google/resolve?name=ad.doubleclick.net&type=A'");
  const ipv6 =
    platform === "windows"
      ? c("Get-NetIPAddress -AddressFamily IPv6 | Where-Object IPAddress -like '2*'")
      : platform === "macos"
        ? c("ifconfig | grep inet6")
        : platform === "linux"
          ? c("ip -6 addr show scope global")
          : html`the Wi-Fi details screen, which lists an IPv6 address when the router delegates one`;
  const ipv6Sources: Source[] = platform === "windows" ? [src.msIp, src.rfc6092] : [src.rfc6092];
  return {
    id: "network",
    title: "The network: what the internet sees, and what walks past the filter",
    intro: html`Two directions. Inbound: the public record of your address, read from a public index rather than scanned. Outbound: whether a device can carry its own resolver past the network's filter.`,
    steps: [
      {
        title: "Read what the internet sees of your address",
        do: html`Find your public address on the router's status page (the script prints it when the router's UPnP service is on), then open <code>https://internetdb.shodan.io/</code> followed by the address. It is a free lookup of what Shodan's own crawlers last saw there: ports, hostnames, CVEs. It is a record, not a live scan, and this site never scans you.`,
        clean: html`"No information available": nothing answered the crawlers.`,
        finding: html`Any port listed is reachable by anyone, and that record is the first thing an attacker reads. Match each port to a UPnP mapping, a port forward or remote management, and close what you did not open.`,
        more: "exposure",
        sources: [src.internetdb],
      },
      {
        title: "Test whether plain DNS can bypass the filter",
        do: html`Ask a public resolver directly, past the network's own: ${lookupDirect}. The script's <code>bypass</code> rows do the same against 8.8.8.8 and 1.1.1.1.`,
        clean: html`A timeout or a sinkholed answer (0.0.0.0, or no such name): the router blocks port 53 outbound or redirects it to the filter, so a device cannot pick its own resolver.`,
        finding: html`A real address means any device or app that brings its own resolver walks past the network filter. The fix is a rule on the router: redirect outbound port 53 to the filter, or block it except from the filter. Pi-hole's FAQ walks through it.`,
        more: "bypass",
        sources: [src.piholeDevices, src.pihole],
      },
      {
        title: "Test whether DNS over HTTPS leaves the network",
        do: html`Ask a public DoH endpoint from a device on the LAN: ${doh}. An answer with an address means the encrypted path is open. Blocking it is a choice: a filtering resolver that offers DoH itself (AdGuard, NextDNS, Mullvad all do) is the better end state, with the known public DoH endpoints blocked on the router for everything else.`,
        clean: html`No answer, or an answer without an address, from the public endpoints you have not chosen; your own filtering resolver answers over DoH.`,
        finding: html`An app with its own DoH walks past the filter the same way plain DNS does, and nothing on the network sees the names it asks for.`,
        more: "bypass",
        sources: [src.rfc8484, src.rfc7858],
      },
      {
        title: "Know whether IPv6 reaches the device",
        do: html`Check for a public IPv6 address on the device: ${ipv6}. An address starting with 2 or 3 is public; the router's IPv6 firewall is what stands between it and the internet, because there is no NAT in the way. In the router's IPv6 settings, confirm the firewall is on and that inbound is blocked by default.`,
        clean: html`No public IPv6 address, or one with the router's IPv6 firewall on.`,
        finding: html`A public IPv6 address behind a router with its IPv6 firewall off is a device on the open internet, whatever the IPv4 side looks like.`,
        sources: ipv6Sources,
      },
    ],
  };
}

function pastStep(platform: GuidePlatform): Step {
  if (platform === "ios") {
    return {
      title: "If you need to know about the past, read a backup with MVT",
      do: html`Amnesty International's Mobile Verification Toolkit reads an encrypted iTunes or Finder backup of the phone against its published indicators. Its documentation is the guide to follow. A clean result is not a clean bill of health: spyware of this grade is built to defeat exactly this kind of check, so a concrete reason to think you were targeted is a reason to use a helpline, not a tool.`,
      more: "device",
      sources: [src.mvtIos, src.mvt, src.accessNow],
    };
  }
  if (platform === "android") {
    return {
      title: "If you need to know about the past, read the phone with MVT",
      do: html`Amnesty International's Mobile Verification Toolkit reads an Android phone over USB debugging, or a backup, against its published indicators. Its methodology page is the guide to follow. A clean result is not a clean bill of health; a concrete reason to think you were targeted is a reason to use a helpline, not a tool.`,
      more: "device",
      sources: [src.mvtAndroid, src.mvt, src.accessNow],
    };
  }
  return {
    title: "If you need to know about the past",
    do: html`Nothing above says whether anything already happened. The device script reads the state of the device today; the browser traces and indicator matching planned for the device scripts come later. For a phone, Amnesty's Mobile Verification Toolkit reads a backup against its indicators. A concrete reason to think you were targeted is a reason to use a helpline, not a tool.`,
    more: "device",
    sources: [src.mvt, src.accessNow, src.citizenLab],
  };
}

function windowsSections(): Section[] {
  return [
    {
      id: "dns",
      title: "Filter DNS for every app on this PC",
      steps: [
        chooseResolverStep("this PC"),
        {
          title: "Set the resolver on the adapter, with DNS over HTTPS on",
          do: html`Settings, Network &amp; internet, then Wi-Fi or Ethernet, then the network's properties. Under DNS server assignment choose Edit, switch to Manual, turn IPv4 on and enter the resolver's two addresses; where the addresses are on Windows' known DoH list the encryption choice appears, so pick Encrypted only. Repeat for IPv6 if the resolver publishes IPv6 addresses. A resolver not on the list can be added with <code>Add-DnsClientDohServerAddress</code>.`,
          clean: html`The adapter shows the resolver's addresses with "Encrypted only" beside them.`,
          finding: html`"Unencrypted only" means every lookup crosses the network in the clear, readable and rewritable by the router or anyone on the path.`,
          more: "dns",
          sources: [src.msDoh],
        },
        {
          title: "Prove it",
          do: html`In PowerShell: ${c("Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses")} lists the resolver per adapter, and ${c("Resolve-DnsName ad.doubleclick.net -Type A -DnsOnly")} asks it for an ad domain. Then run the browser check at <a href="/scan">/scan</a>: the filtering DNS row names AdGuard or NextDNS when either is the resolver.`,
          clean: html`The resolver you chose, and the ad name answered with 0.0.0.0 or "DNS name does not exist".`,
          finding: html`A real address for the ad name means nothing between this PC and the internet filters ads by DNS: the resolver is not a filtering one, or a VPN replaced it. One name filtered and one not is a list difference, not a failure.`,
          more: "dns",
          sources: [src.msGetDns, src.msResolve],
        },
        {
          title: "Read the hosts file",
          do: html`${c("Get-Content $env:SystemRoot\\System32\\drivers\\etc\\hosts")}. Windows ships it with every line commented out. The script's <code>hosts</code> row reads it too.`,
          clean: html`Only comments, or entries you or a program you know (a VPN client, a development tool) wrote.`,
          finding: html`An entry that sends a bank's or a vendor's name to an address you do not recognise bypasses DNS entirely, which is why malware has written them since the file existed.`,
          sources: [src.hosts5],
        },
        {
          title: "Check it stays",
          do: html`A VPN, a new network or a Windows update can replace the resolver. Run the script again after any of them; its <code>resolver</code> and <code>canary</code> rows take ten seconds.`,
          sources: [src.msGetDns],
        },
      ],
    },
    blockerSection("windows"),
    {
      id: "firewall",
      title: "Windows Firewall and what listens",
      steps: [
        {
          title: "Keep all three profiles on, with inbound blocked by default",
          do: html`Windows Security, Firewall &amp; network protection: Domain, Private and Public each say "on". The default for inbound is block, and Microsoft's advice is not to turn the firewall off even for another vendor's product.`,
          clean: html`${c("Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction")} shows True and Block (or NotConfigured, which means Block) for all three.`,
          finding: html`A profile off, or an inbound default of Allow, means every program that listens is reachable from the network that profile applies to.`,
          more: "router",
          sources: [src.msFirewall, src.msFirewallApp, src.msGetProfile],
        },
        {
          title: "Mark untrusted networks Public",
          do: html`Settings, Network &amp; internet, then the network's properties: Public for anything that is not your own home or office network. ${c("Get-NetConnectionProfile")} shows the category of each connection. The Public profile is the one with the fewest holes.`,
          clean: html`Home and office networks Private, everything else Public.`,
          finding: html`A hotel or café network marked Private opens file and printer sharing to everyone on it.`,
          sources: [src.msFirewall],
        },
        {
          title: "Know what listens",
          do: html`${c("Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Format-Table LocalAddress, LocalPort, OwningProcess")}. A local address of 0.0.0.0 or :: means every interface; 127.0.0.1 means this PC only. The script's <code>listening</code> row names the ports worth knowing: 445 (file sharing), 3389 (Remote Desktop), 22 (SSH), 5900 (VNC). Turn off Remote Desktop and file sharing unless you use them, under Settings, System, Remote Desktop and Settings, Network &amp; internet, Advanced network settings, Advanced sharing settings.`,
          clean: html`Only services you use listen on every address, and the firewall rule that allows each is limited to the Private profile.`,
          finding: html`Remote Desktop or SMB listening on every address of a laptop that joins public networks is the way ransomware crews walk in.`,
          sources: [src.msTcp, src.msSmb],
        },
        {
          title: "Block SMB leaving the PC on untrusted networks",
          do: html`Microsoft's guidance is to block TCP 445 outbound to the internet; on a laptop that means an outbound block rule for the Public profile, as in Microsoft's rule templates. ${c("Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True")} lists what exists; the script's <code>smb out</code> row reads it too.`,
          clean: html`An enabled outbound block rule for TCP 445 on the Public profile, or a laptop that never leaves the house.`,
          finding: html`Without it, a link to a share on the internet makes Windows send the user's credential hash to whoever hosts it.`,
          sources: [src.msSmb, src.msSmbRules, src.msGetRule],
        },
      ],
    },
    routerSection(),
    networkSection("windows"),
    {
      id: "adid",
      title: "Take away the advertising identifier",
      steps: [
        {
          title: "Turn the advertising ID off",
          do: html`Settings, Privacy &amp; security, General: turn off "Let apps show me personalized ads by using my advertising ID". ${c("Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo' | Select-Object Enabled")} shows 0 when it is off; the script's <code>ad id</code> row reads the same value.`,
          clean: html`Enabled is 0.`,
          finding: html`Targeted ads are how a target is picked; without the identifier the ad network has less to aim with. It does not remove ads.`,
          more: "harden",
          sources: [src.msPrivacy],
        },
      ],
    },
    {
      id: "past",
      title: "The past",
      steps: [
        {
          title: "Turn the DNS-Client log on, so the next time is recorded",
          do: html`Windows does not record lookups unless the DNS-Client operational log is on. Event Viewer, Applications and Services Logs, Microsoft, Windows, DNS-Client, Operational, then Enable Log; or, as administrator, ${c("wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true")}. ${c("Get-WinEvent -ListLog Microsoft-Windows-DNS-Client/Operational | Select-Object IsEnabled")} shows the state, as does the script's <code>dns log</code> row.`,
          clean: html`IsEnabled is True.`,
          finding: html`Off means that when something does happen, there is no record of which names this PC asked for.`,
          more: "device",
          sources: [src.msWevtutil, src.msGetWinEvent],
        },
        pastStep("windows"),
      ],
    },
  ];
}

function macosSections(): Section[] {
  return [
    {
      id: "dns",
      title: "Filter DNS for every app on this Mac",
      steps: [
        chooseResolverStep("this Mac"),
        {
          title: "Install the resolver's profile, or set the addresses by hand",
          do: html`The resolver's setup page offers a configuration profile that sets encrypted DNS for every network: download it, then System Settings, General, Device Management, where the profile waits to be installed; read the provider and the servers it names before you install, and stop if they do not match the provider's page. Without a profile: System Settings, Network, the connection, Details, DNS, and add the resolver's addresses; that sets plain DNS for that network only.`,
          clean: html`The profile shows under Device Management, or the DNS tab lists the resolver's addresses.`,
          finding: html`A profile from a page you did not choose can set any resolver it likes; the Device Management list is where to look for one you do not remember installing.`,
          more: "dns",
          sources: [src.appleProfilesMac, src.appleDns, src.adguard, src.nextdns],
        },
        {
          title: "Prove it",
          do: html`In Terminal: ${c("scutil --dns | grep nameserver")} shows the resolver in use, and ${c("dig +short ad.doubleclick.net")} asks it for an ad domain. Then run the browser check at <a href="/scan">/scan</a>: the filtering DNS row names AdGuard or NextDNS when either is the resolver. <code>profiles list</code> names the profiles installed for your user.`,
          clean: html`The resolver you chose, and the ad name answered with 0.0.0.0 or nothing.`,
          finding: html`A real address for the ad name means nothing between this Mac and the internet filters ads by DNS: the resolver is not a filtering one, or a VPN or Private Relay replaced it. One name filtered and one not is a list difference, not a failure.`,
          more: "dns",
          sources: [src.appleDns],
        },
        {
          title: "Read the hosts file",
          do: html`${c("cat /etc/hosts")}. macOS ships it with localhost and broadcasthost only. The script's <code>hosts</code> row reads it too.`,
          clean: html`Those two, or entries you or a program you know (a VPN client, a development tool) wrote.`,
          finding: html`An entry that sends a bank's or a vendor's name to an address you do not recognise bypasses DNS entirely.`,
          sources: [src.hosts5],
        },
        {
          title: "Check it stays",
          do: html`A VPN, iCloud Private Relay or a removed profile can replace the resolver. Run the script again after any of them; its <code>resolver</code> and <code>canary</code> rows take ten seconds.`,
          sources: [src.appleDns],
        },
      ],
    },
    blockerSection("macos"),
    {
      id: "firewall",
      title: "The Mac's own firewall and what listens",
      steps: [
        {
          title: "Turn the firewall on, with stealth mode",
          do: html`System Settings, Network, Firewall: on. Under Options, turn stealth mode on and block incoming connections for the apps you do not expect to listen. Prove it with ${c("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate --getstealthmode")}; for the packet filter underneath, ${c("sudo pfctl -s info")}.`,
          clean: html`Both print "enabled". The script's <code>firewall</code> rows read the same.`,
          finding: html`The application firewall stops a program that was not expected to listen from accepting connections from the LAN, which is where a compromised device next door would come from. Off, every listener below is open to the network.`,
          more: "router",
          sources: [src.appleFirewall],
        },
        {
          title: "Turn off sharing you do not use, and know what listens",
          do: html`System Settings, General, Sharing: Screen Sharing, File Sharing, Remote Login and Remote Management off unless you use them. ${c("netstat -an -p tcp | grep LISTEN")} shows what listens; <code>*.22</code> is Remote Login, <code>*.5900</code> Screen Sharing, <code>*.445</code> File Sharing. The script's <code>listening</code> row names them.`,
          clean: html`Only services you use listen on every address.`,
          finding: html`Remote Login or Screen Sharing on a laptop that joins public networks is reachable by everyone on them, password or not.`,
          sources: [src.appleSharing],
        },
      ],
    },
    {
      id: "lockdown",
      title: "Lockdown Mode, if you are a likely target",
      steps: [
        {
          title: "Turn Lockdown Mode on",
          do: html`System Settings, Privacy &amp; Security, Lockdown Mode. It limits what an attack can do if one gets through: message attachments, web technologies, wired accessories, configuration profiles. It is for people who may be targeted by mercenary spyware, and some things stop working. ${c("defaults read .GlobalPreferences LDMGlobalEnabled")} prints 1 when it is on; the script's <code>lockdown</code> row reads it.`,
          clean: html`On, for anyone with a reason to be targeted; off is the default for everyone else.`,
          more: "harden",
          sources: [src.appleLockdown],
        },
      ],
    },
    {
      id: "adid",
      title: "Take away the advertising identifier",
      steps: [
        {
          title: "Turn personalized ads off",
          do: html`System Settings, Privacy &amp; Security, Apple Advertising: Personalized Ads off. ${c("defaults read com.apple.AdLib allowApplePersonalizedAdvertising")} prints 0 when it is off; the script reads the same.`,
          clean: html`0.`,
          finding: html`Targeted ads are how a target is picked; without the identifier the ad network has less to aim with. It does not remove ads.`,
          more: "harden",
          sources: [src.appleAds],
        },
      ],
    },
    routerSection(),
    networkSection("macos"),
    { id: "past", title: "The past", steps: [pastStep("macos")] },
  ];
}

function linuxSections(): Section[] {
  return [
    {
      id: "dns",
      title: "Filter DNS for every app on this computer",
      steps: [
        chooseResolverStep("this computer"),
        {
          title: "Set the resolver where this system keeps it",
          do: html`With systemd-resolved (Ubuntu, Fedora, Debian desktops): in <code>/etc/systemd/resolved.conf</code> set <code>DNS=</code> to the resolver's addresses and <code>DNSOverTLS=yes</code> for one that offers DNS over TLS (AdGuard, NextDNS, Quad9, Mullvad do), then ${c("sudo systemctl restart systemd-resolved")}. With NetworkManager, ${c("nmcli connection modify <name> ipv4.dns <address> ipv4.ignore-auto-dns yes")} sets it per connection. Without either, <code>/etc/resolv.conf</code> is the file.`,
          clean: html`${c("resolvectl status")} lists the resolver under the link in use, with <code>+DNSOverTLS</code> in the protocols line when that is on.`,
          finding: html`A resolver handed out by DHCP that is the router, or the ISP, filters nothing, and plain port 53 is readable and rewritable on the path.`,
          more: "dns",
          sources: [src.resolvedConf, src.resolvectl, src.nmcli, src.rfc7858],
        },
        {
          title: "Prove it",
          do: html`${c("resolvectl status")} or ${c("cat /etc/resolv.conf")} shows the resolver; ${c("dig +short ad.doubleclick.net")} (or <code>host</code>, or <code>nslookup</code>) asks it for an ad domain. Then run the browser check at <a href="/scan">/scan</a>.`,
          clean: html`The resolver you chose, and the ad name answered with 0.0.0.0 or nothing.`,
          finding: html`A real address for the ad name means nothing between this computer and the internet filters ads by DNS. One name filtered and one not is a list difference, not a failure.`,
          more: "dns",
          sources: [src.resolvectl],
        },
        {
          title: "Read the hosts file",
          do: html`${c("cat /etc/hosts")}: localhost, the machine's own name, and whatever you added. The script's <code>hosts</code> row reads it too.`,
          clean: html`Entries you recognise.`,
          finding: html`An entry that sends a vendor's name to an address you do not recognise bypasses DNS entirely.`,
          sources: [src.hosts5],
        },
      ],
    },
    blockerSection("linux"),
    {
      id: "firewall",
      title: "The host firewall and what listens",
      steps: [
        {
          title: "Have a firewall on, with inbound dropped by default",
          do: html`Ubuntu and Debian: ${c("sudo ufw enable")} then ${c("sudo ufw status verbose")}; the default is to deny incoming. Fedora and RHEL: ${c("sudo firewall-cmd --state")} and ${c("sudo firewall-cmd --list-all")}. Anything else: ${c("sudo nft list ruleset")} shows the nftables rules. The script's <code>firewall</code> rows read the service states without root and the rules with sudo.`,
          clean: html`One of them active, with an input policy of drop or reject and allow rules only for services you use.`,
          finding: html`No firewall service active means every listener below is reachable from the LAN. A desktop that only ever sits at home behind the router's NAT is exposed to the devices beside it, which is where a compromised device next door comes from.`,
          more: "router",
          sources: [src.ubuntuFw, src.firewalld, src.nftables],
        },
        {
          title: "Know what listens",
          do: html`${c("ss -ltnup")} lists TCP and UDP listeners with the process. A local address of 0.0.0.0, <code>*</code> or <code>[::]</code> means every interface; 127.0.0.1 means this computer only. The script's <code>listening</code> row names the ports worth knowing: 22 (SSH), 445 (Samba), 5900 (VNC), 3389 (RDP).`,
          clean: html`Only services you use listen on every address, and the firewall allows each from the networks that need it.`,
          finding: html`SSH with password logins on every interface of a laptop that joins public networks will be tried by every scanner on them.`,
          sources: [src.ss],
        },
      ],
    },
    routerSection(),
    networkSection("linux"),
    { id: "past", title: "The past", steps: [pastStep("linux")] },
  ];
}

function iosSections(): Section[] {
  return [
    {
      id: "dns",
      title: "Filter DNS for every app on this iPhone or iPad",
      steps: [
        chooseResolverStep("this iPhone"),
        {
          title: "Install the resolver's encrypted DNS profile",
          do: html`Open the resolver's setup page in Safari (AdGuard DNS and NextDNS both offer a profile; AdGuard's and NextDNS's apps install one for you), download the profile, then Settings, General, VPN &amp; Device Management, where it waits to be installed. Read the provider and the servers it names first, and stop if they do not match the provider's page. A profile sets encrypted DNS for every network the device joins; the per-network DNS setting under Wi-Fi only covers that one network and in the clear. In-app browsers inside Instagram, Facebook and TikTok cannot install a profile; use Safari.`,
          clean: html`The profile shows under VPN &amp; Device Management, and the browser check's filtering DNS row names the provider.`,
          finding: html`A profile you do not remember installing can set any resolver it likes; that list is where to look. A VPN or iCloud Private Relay replaces the resolver for as long as it is on.`,
          more: "dns",
          sources: [src.appleProfilesIos, src.adguard, src.nextdns],
        },
        {
          title: "Prove it",
          do: html`Open <a href="/scan">/scan</a> in Safari and run the check: the filtering DNS row names AdGuard or NextDNS when either is the resolver, and the ad requests row shows a load difference once the resolver filters the test host. Both resolvers also have a self-check on their own pages.`,
          clean: html`The provider you chose in the filtering DNS row.`,
          finding: html`"None seen" with the profile installed means a VPN, Private Relay or the network is overriding it.`,
          more: "dns",
          sources: [src.adguard, src.nextdns],
        },
      ],
    },
    blockerSection("ios"),
    {
      id: "lockdown",
      title: "Lockdown Mode, if you are a likely target",
      steps: [
        {
          title: "Turn Lockdown Mode on",
          do: html`Settings, Privacy &amp; Security, Lockdown Mode. It limits what an attack can do if one gets through: message attachments, web technologies, wired accessories, configuration profiles, and more. It is for people who may be targeted by mercenary spyware, and some things stop working.`,
          clean: html`On, for anyone with a reason to be targeted; off is the default for everyone else.`,
          more: "harden",
          sources: [src.appleLockdown],
        },
        {
          title: "Keep automatic updates and Background Security Improvements on",
          do: html`Settings, General, Software Update, Automatic Updates: everything on. Background Security Improvements patch Safari and WebKit between releases, and WebKit is where ad-delivered exploits land.`,
          clean: html`The device is on the current iOS, with automatic updates on.`,
          finding: html`A device a release behind carries every WebKit bug fixed since.`,
          sources: [src.appleUpdate, src.appleBsi],
        },
      ],
    },
    {
      id: "adid",
      title: "Take away the advertising identifier",
      steps: [
        {
          title: "Stop apps asking to track, and turn personalized ads off",
          do: html`Settings, Privacy &amp; Security, Tracking: Allow Apps to Request to Track off. Settings, Privacy &amp; Security, Apple Advertising: Personalized Ads off.`,
          clean: html`Both off.`,
          finding: html`Targeted ads are how a target is picked; without the identifier the ad network has less to aim with. It does not remove ads.`,
          more: "harden",
          sources: [src.appleTracking, src.appleIosAds, src.appleAds],
        },
      ],
    },
    {
      id: "firewall",
      title: "No firewall to check on the phone",
      steps: [
        {
          title: "The router's firewall is the one that matters here",
          do: html`iOS has no firewall setting. The phone accepts few connections from the network by itself; what stands between it and the internet is the router's firewall, and what stands between it and other devices is the network it joins. Avoid untrusted Wi-Fi, or use a VPN on it, and put untrusted devices at home on the guest network. The router section below is the phone's firewall section.`,
          sources: [src.cisaHome],
        },
      ],
    },
    routerSection(),
    networkSection("ios"),
    { id: "past", title: "The past", steps: [pastStep("ios")] },
  ];
}

function androidSections(): Section[] {
  return [
    {
      id: "dns",
      title: "Filter DNS for every app on this phone",
      steps: [
        chooseResolverStep("this phone"),
        {
          title: "Set Private DNS to the resolver's hostname",
          do: html`Settings, Network &amp; internet, Private DNS (search Settings for it if the path differs; Samsung keeps it under Connections, More connection settings): choose "Private DNS provider hostname" and enter the hostname the resolver publishes, such as <code>dns.adguard-dns.com</code> or the NextDNS profile's hostname. Private DNS is DNS over TLS, so the lookups are encrypted on every network the phone joins. Apps that bring their own resolver still bypass it.`,
          clean: html`Private DNS shows the hostname, and the browser check's filtering DNS row names the provider.`,
          finding: html`"Automatic" means the phone uses whatever the network hands out, encrypted if that resolver offers it, filtered only if the network filters.`,
          more: "dns",
          sources: [src.androidPrivateDns, src.androidDot, src.adguard],
        },
        {
          title: "Prove it",
          do: html`Open <a href="/scan">/scan</a> in Chrome or Firefox and run the check: the filtering DNS row names AdGuard or NextDNS when either is the resolver. Both resolvers also have a self-check on their own pages.`,
          clean: html`The provider you chose in the filtering DNS row.`,
          finding: html`"None seen" with Private DNS set means a VPN is in the way, or the network blocks DNS over TLS (port 853), in which case the phone falls back to the network's resolver.`,
          more: "dns",
          sources: [src.adguard, src.nextdns],
        },
      ],
    },
    blockerSection("android"),
    {
      id: "lockdown",
      title: "Updates, the nearest thing to Lockdown Mode",
      steps: [
        {
          title: "Check the security patch level",
          do: html`Settings, About phone, Android version: the security update line is the month of the last patch level the phone received. Google publishes what each month fixes in the Android Security Bulletins. Install what is offered, and treat a phone whose vendor has stopped sending updates as one to replace.`,
          clean: html`A patch level from the last month or two.`,
          finding: html`A patch level a year old carries every bug the bulletins have listed since, many of them in the browser engine ads are rendered by.`,
          sources: [src.androidUpdate, src.androidBulletin],
        },
      ],
    },
    {
      id: "adid",
      title: "Take away the advertising identifier",
      steps: [
        {
          title: "Delete the advertising ID",
          do: html`Settings, Google, Ads (on older phones, the Google Settings app, then Ads): Delete advertising ID, or Reset advertising ID where delete is not offered, and turn off ad personalization.`,
          clean: html`No advertising ID, or one reset today.`,
          finding: html`Targeted ads are how a target is picked; without the identifier the ad network has less to aim with. It does not remove ads.`,
          more: "harden",
          sources: [src.androidAdId],
        },
      ],
    },
    {
      id: "firewall",
      title: "No firewall to check on the phone",
      steps: [
        {
          title: "The router's firewall is the one that matters here",
          do: html`Android has no user-facing firewall. The phone accepts few connections from the network by itself; what stands between it and the internet is the router's firewall, and what stands between it and other devices is the network it joins. Avoid untrusted Wi-Fi, or use a VPN on it, and put untrusted devices at home on the guest network. The router section below is the phone's firewall section.`,
          sources: [src.cisaHome],
        },
      ],
    },
    routerSection(),
    networkSection("android"),
    { id: "past", title: "The past", steps: [pastStep("android")] },
  ];
}

export function guideSections(platform: GuidePlatform): Section[] {
  switch (platform) {
    case "windows":
      return windowsSections();
    case "macos":
      return macosSections();
    case "linux":
      return linuxSections();
    case "ios":
      return iosSections();
    case "android":
      return androidSections();
  }
}

function sourceLinks(sources: Source[]): Html {
  return html`${sources.map((s, i) => html`${i > 0 ? " · " : ""}<a href="${s.href}" ${newTab}>${s.text}</a>`)}`;
}

function renderStep(step: Step): Html {
  return html`<li>
  <p><b>${step.title}.</b> ${step.do}</p>
  ${step.clean ? html`<p class="small"><b>Clean:</b> ${step.clean}</p>` : ""}
  ${step.finding ? html`<p class="small"><b>A finding:</b> ${step.finding}</p>` : ""}
  ${step.why ? html`<p class="small"><b>Why:</b> ${step.why}${step.more ? html` <a href="/scan/why#${step.more}">More</a>` : ""}</p>` : step.more ? html`<p class="small"><a href="/scan/why#${step.more}">Why this matters</a></p>` : ""}
  <p class="small src">Source${step.sources.length > 1 ? "s" : ""}: ${sourceLinks(step.sources)}</p>
</li>`;
}

function renderSection(section: Section, n: number): Html {
  return html`<section class="box guide-section" id="${section.id}">
  <h2>${n}. ${section.title}</h2>
  ${section.intro ? html`<p class="small">${section.intro}</p>` : ""}
  <ol class="steps">${section.steps.map(renderStep)}</ol>
</section>`;
}

/** The download box: each script for the platform, its sum, and how to verify and run it. */
function scriptBox(scripts: readonly ScanScript[], platform: ScriptPlatform | null, heading = "The script"): Html {
  if (!platform) {
    return html`<div class="box">
  <h2>No script for phones</h2>
  <p class="small">A phone does not let a script read the system. For a filtering check, the browser check at <a href="/scan">/scan</a> is the phone's own view; for the past, Amnesty's Mobile Verification Toolkit reads a backup, and its documentation is the guide to follow.</p>
  <ul class="sources"><li><a href="${src.mvtIos.href}" ${newTab}>${src.mvtIos.text}</a></li><li><a href="${src.mvtAndroid.href}" ${newTab}>${src.mvtAndroid.text}</a></li></ul>
</div>`;
  }
  const mine = scriptsFor(scripts, platform);
  return html`<div class="box">
  <h2>${heading}</h2>
  <p class="small">Every check above, read from the device by one plain script and printed in the window. It uploads nothing, changes nothing and needs no administrator rights; its header says what it contacts. Check the sum, then read the file before you run it.</p>
  ${mine.map(
    (s) => html`<dl class="kv script">
  <dt>File</dt><dd><a href="/scan/scripts/${s.file}" download>${s.file}</a> (${s.bytes} bytes) · <a href="/scan/scripts/${s.file}">view</a></dd>
  <dt>SHA-256</dt><dd><code class="sum">${s.sha256}</code></dd>
  <dt>Verify</dt><dd><code>${s.verify}</code></dd>
  <dt>Run</dt><dd><code>${s.run}</code> (${s.shell})</dd>
</dl>`,
  )}
  <p class="small"><a href="/scan/scripts/${sumsFile}">${sumsFile}</a> carries the same sums for <code>sha256sum -c</code> and <code>shasum -a 256 -c</code>.</p>
</div>`;
}

function platformPicker(current: GuidePlatform | null): Html {
  return html`${guidePlatforms.map((p, i) => html`${i > 0 ? " · " : ""}${p.id === current ? html`<b>${p.label}</b>` : html`<a href="/scan/guide/${p.id}">${p.label}</a>`}`)}`;
}

export interface GuidePageOptions {
  owner: boolean;
  open: boolean;
  look: LookState;
  scripts: readonly ScanScript[];
}

export function renderScanGuide(platform: GuidePlatform, { owner, open, look, scripts }: GuidePageOptions): string {
  const info = guidePlatforms.find((p) => p.id === platform) ?? guidePlatforms[0]!;
  const sections = guideSections(platform);
  const others = guidePlatforms.filter((p) => p.id !== platform);
  const content = html`<section class="scan-guide">
  <p class="crumbs"><a href="/">Home</a><span>›</span><a href="/scan">Scan</a><span>›</span><a href="/scan/guide">Do it by hand</a><span>›</span><b>${info.label}</b></p>
  <h1>Do it by hand <span class="arrow">${info.label}</span></h1>
  <p class="lede">Pick a platform: ${platformPicker(platform)}. Each section is one thing the Scan area checks: how to do it yourself on ${info.device}, what a clean result looks like, what a finding means, and the vendor page each step follows. The router and the network are the same from every platform, so those sections are too.</p>
  <div class="cols">
    <div class="main">
      ${sections.map((s, i) => renderSection(s, i + 1))}
    </div>
    <aside class="side">
      <div class="box">
        <h2>On this page</h2>
        <ol class="small plan">${sections.map((s) => html`<li><a href="#${s.id}">${s.title}</a></li>`)}</ol>
      </div>
      ${scriptBox(scripts, info.script)}
      <div class="box">
        <h2>Prove it in the browser</h2>
        <p class="small">The <a href="/scan">browser check</a> sees this browser only: whether a blocker hides ad slots and stops ad requests, and which filtering resolver this browser uses. Run it after each DNS or blocker step. <a href="/scan/why">Why these checks</a> carries the argument for each, with its sources.</p>
      </div>
      <div class="box">
        <h2>Other platforms</h2>
        <dl class="kv">${others.map((p) => html`<dt><a href="/scan/guide/${p.id}">${p.label}</a></dt><dd>${otherPlatformNote(p.id)}</dd>`)}</dl>
      </div>
      <div class="box">
        <h2>Limits</h2>
        <p class="small">DNS filtering cannot remove ads from Instagram, Facebook, TikTok or YouTube: those come from the same servers as the content. A browser test sees one browser; a script sees one device. None of this says whether anything already happened.</p>
      </div>
    </aside>
  </div>
</section>`;
  return page({ title: `Do it by hand: ${info.label}`, active: "scan", content, owner, open, look });
}

function otherPlatformNote(platform: GuidePlatform): Html {
  switch (platform) {
    case "windows":
      return html`Settings, Network &amp; internet, the adapter's DNS server assignment with DNS over HTTPS on; prove with <code>Get-DnsClientServerAddress</code> and <code>Get-NetFirewallProfile</code>.`;
    case "macos":
      return html`The resolver's profile under System Settings, General, Device Management; the firewall under Network; prove with <code>scutil --dns</code> and <code>socketfilterfw</code>.`;
    case "linux":
      return html`<code>resolvectl status</code> and resolved.conf; <code>ufw status</code>, <code>firewall-cmd</code> or <code>nft list ruleset</code>; <code>ss -ltnup</code>.`;
    case "ios":
      return html`The resolver's profile under Settings, General, VPN &amp; Device Management; Lockdown Mode under Privacy &amp; Security.`;
    case "android":
      return html`Settings, Network &amp; internet, Private DNS, the provider's hostname; the security patch level under About phone.`;
  }
}

/** The index at /scan/guide: the platforms, the scripts, and what the guides cover. */
export function renderScanGuideIndex({ owner, open, look, scripts }: GuidePageOptions): string {
  const content = html`<section class="scan-guide">
  <p class="crumbs"><a href="/">Home</a><span>›</span><a href="/scan">Scan</a><span>›</span><b>Do it by hand</b></p>
  <h1>Do it by hand <span class="arrow">every check, on every platform</span></h1>
  <p class="lede">The browser check sees one browser. These guides do the rest by hand, one platform at a time: the resolver every app uses, the blocker in the browser, the device's own firewall and what listens, the router, what the internet sees of your address and what walks past the filter, the advertising identifier, and the past. Each step names the vendor page it follows. The scripts below do the same checks on a computer in one go.</p>
  <div class="cols">
    <div class="main">
      <div class="checks">
        ${guidePlatforms.map(
          (p, i) => html`<article class="check">
  <span class="n">${String(i + 1).padStart(2, "0")}</span>
  <div>
    <div class="t"><a href="/scan/guide/${p.id}">${p.label}</a></div>
    <p class="d">${otherPlatformNote(p.id)}</p>
  </div>
  <span class="state na">${p.script ? "guide and script" : "guide"}</span>
</article>`,
        )}
      </div>
      <div class="box guide-section" id="what">
        <h2>What every guide covers</h2>
        <ol class="plan">
          <li><b>Filter DNS for every app</b>: which resolver, how to set it, how to prove it with one lookup of an ad domain, and the hosts file.</li>
          <li><b>A content blocker in the browser</b>, and what the browser's own DNS does.</li>
          <li><b>The device's firewall and what listens</b>: profiles, the inbound default, sharing and remote access, SMB leaving the device.</li>
          <li><b>The router</b>: the printed password, the resolver it hands out, UPnP and its mappings, remote management, firmware against this site's CVE table and KEV, Wi-Fi encryption.</li>
          <li><b>The network</b>: what Shodan's index says about your address, whether plain DNS and DNS over HTTPS bypass the filter, and whether IPv6 reaches the device.</li>
          <li><b>Lockdown Mode and the advertising identifier</b>, and <b>the past</b>: logging, and the Mobile Verification Toolkit for phones.</li>
        </ol>
        <p class="small"><a href="/scan/why">Why these checks</a> carries the argument for each, with its sources.</p>
      </div>
    </div>
    <aside class="side">
      ${scriptBox(scripts, "windows", "The Windows script")}
      ${scriptBox(scripts, "macos", "The macOS and Linux script")}
      <div class="box">
        <h2>Before you run anything</h2>
        <ul class="small plan">
          <li>Check the SHA-256 against the one shown here.</li>
          <li>Read the file. Every check is a few lines; nothing is obfuscated and nothing is downloaded by the script.</li>
          <li>A clean result means no finding where the script could look. It is not a clean bill of health.</li>
          <li>With a concrete reason to think you were targeted, use a helpline, not a script: <a href="${src.accessNow.href}" ${newTab}>${src.accessNow.text}</a>.</li>
        </ul>
      </div>
    </aside>
  </div>
</section>`;
  return page({ title: "Do it by hand", active: "scan", content, owner, open, look });
}
