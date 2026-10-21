import { html } from "../../html.ts";
import { blockerSection, c, chooseResolverStep, networkSection, pastStep, routerSection, src, type Section } from "./shared.ts";

/** The macos guide (M12.2): what the Scan area checks, done by hand on this platform, one section at a time. */
export function macosSections(): Section[] {
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
