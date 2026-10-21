import { html } from "../../html.ts";
import { blockerSection, chooseResolverStep, networkSection, pastStep, routerSection, src, type Section } from "./shared.ts";

/** The ios guide (M12.2): what the Scan area checks, done by hand on this platform, one section at a time. */
export function iosSections(): Section[] {
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
