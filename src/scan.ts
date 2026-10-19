/**
 * The Scan area (M12): what the server contributes to the browser check at /scan.
 *
 * The page's script (public/scan.js) loads test images from paths that EasyList's request rules
 * match, each between control images with identical bytes, and reads the load difference. The
 * server's part is small: one transparent pixel served at four names, never cached, readable
 * cross-site so a second instance named by BW_PROBE_ORIGIN can serve the cross-site set. The paths
 * are repeated in public/scan.js; test/scan-script.test.ts holds the two lists to each other.
 */

/** The control image: a path no filter list has a reason to touch. */
export const probeControlPath = "/scan/probe/control.gif";

/**
 * The three test paths, each matching one EasyList request rule as read on 2026-10-19:
 * `/ad_images/*$image`, `/adsbanner-$image` and `/ad_skyscraper.gif$image`. The rules carry no
 * third-party option, so a same-site load is filtered the same as a cross-site one.
 */
export const probeTestPaths = ["/scan/probe/ad_images/1.gif", "/scan/probe/adsbanner-1.gif", "/scan/probe/ad_skyscraper.gif"] as const;

export const probePaths: readonly string[] = [probeControlPath, ...probeTestPaths];

/** One transparent GIF pixel, the same 42 bytes at every probe path, so only the path can make a difference. */
export const probeGif: Buffer = Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64");

/**
 * The two resolvers' self-check hosts, the only outside hosts the page's script contacts. AdGuard
 * answers a fresh random name under -dnscheck.adguard-dns.com; NextDNS answers a fresh random name
 * under test.nextdns.io (the bare host only redirects there, without CORS headers, so the script
 * picks the name itself; the bare host stays in the policy for the day that changes).
 */
export const resolverCheckSources = ["https://*.adguard-dns.com", "https://test.nextdns.io", "https://*.test.nextdns.io"] as const;
