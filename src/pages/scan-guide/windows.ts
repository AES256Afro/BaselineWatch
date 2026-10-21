import { html } from "../../html.ts";
import { blockerSection, c, chooseResolverStep, networkSection, pastStep, routerSection, src, type Section } from "./shared.ts";

/** The windows guide (M12.2): what the Scan area checks, done by hand on this platform, one section at a time. */
export function windowsSections(): Section[] {
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
