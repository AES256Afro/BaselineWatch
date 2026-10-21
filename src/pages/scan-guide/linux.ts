import { html } from "../../html.ts";
import { blockerSection, c, chooseResolverStep, networkSection, pastStep, routerSection, src, type Section } from "./shared.ts";

/** The linux guide (M12.2): what the Scan area checks, done by hand on this platform, one section at a time. */
export function linuxSections(): Section[] {
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
