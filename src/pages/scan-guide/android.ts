import { html } from "../../html.ts";
import { blockerSection, chooseResolverStep, networkSection, pastStep, routerSection, src, type Section } from "./shared.ts";

/** The android guide (M12.2): what the Scan area checks, done by hand on this platform, one section at a time. */
export function androidSections(): Section[] {
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
