import { html, type Html } from "../../html.ts";
import type { ScriptPlatform } from "../../scan-scripts.ts";

/**
 * What every platform's guide is built from (M12.2): the platforms, the shape of a step and a
 * section, the vendor pages the steps cite, and the sections that are the same on every
 * platform — the resolver choice, the blocker, the router, the network, and the past — because
 * the router is the same router whatever is on the desk.
 */
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

export interface Source {
  href: string;
  text: string;
}

export interface Step {
  title: string;
  do: Html;
  clean?: Html;
  finding?: Html;
  why?: Html;
  /** An anchor on /scan/why that carries the longer argument. */
  more?: string;
  sources: Source[];
}

export interface Section {
  id: string;
  title: string;
  intro?: Html;
  steps: Step[];
}

export const c = (text: string): Html => html`<code>${text}</code>`;

/** The primary documents the steps follow. Every href was opened on 2026-10-19. */
export const src = {
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
export function chooseResolverStep(device: string): Step {
  return {
    title: "Decide which resolver filters",
    do: html`AdGuard DNS, NextDNS, Mullvad and Cloudflare's 1.1.1.1 for Families each publish a filtering resolver; Quad9 filters malware domains but not ads. A Pi-hole or AdGuard Home on your own network is the same thing for every device at once, and the router section below hands it out. If ${device} uses a VPN or iCloud Private Relay, that brings its own resolver and wins: set the filter there, or accept that the rows below describe the VPN's resolver.`,
    why: html`A browser blocker protects one browser; the system resolver covers every app that uses it, which is most of them. Apps with their own resolver still bypass it, which the network section tests.`,
    more: "dns",
    sources: [src.adguard, src.nextdns, src.mullvad, src.cloudflareFamilies, src.quad9, src.pihole],
  };
}

/** The content-blocker section, which differs only in which browsers the platform has. */
export function blockerSection(platform: GuidePlatform): Section {
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
export function routerSection(): Section {
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
export function networkSection(platform: GuidePlatform): Section {
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

export function pastStep(platform: GuidePlatform): Step {
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
