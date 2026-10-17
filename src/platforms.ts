/**
 * Platforms a person follows as a whole: "every Apple CVE", "every Windows CVE". A CVE belongs
 * to a platform by its CPE criteria first (the operating system or the browser named), then by
 * the vendor and product NVD derived, and, for a CVE NVD has not analysed yet, by the way the
 * description names the platform ("This issue is fixed in macOS Sequoia 15.6"). The ids are the
 * ones the watchlist takes as kind "platform".
 */

export type PlatformKey = "windows" | "apple" | "linux" | "android" | "chrome" | "firefox" | "edge" | "network";

export const platformList: { id: PlatformKey; label: string; blurb: string }[] = [
  { id: "windows", label: "Windows", blurb: "Windows 10 and 11, Windows Server and the Windows components (kernel, SMB, Print Spooler, Defender)." },
  { id: "apple", label: "Apple", blurb: "macOS, iOS, iPadOS, watchOS, tvOS, visionOS and Safari." },
  { id: "linux", label: "Linux", blurb: "The Linux kernel and the distributions (Red Hat, Ubuntu, Debian, SUSE, Oracle Linux, Fedora)." },
  { id: "android", label: "Android", blurb: "Android and Pixel." },
  { id: "chrome", label: "Chrome", blurb: "Google Chrome and Chromium." },
  { id: "firefox", label: "Firefox", blurb: "Mozilla Firefox and Thunderbird." },
  { id: "edge", label: "Edge", blurb: "Microsoft Edge." },
  { id: "network", label: "Network devices", blurb: "Cisco, Juniper, Fortinet, Palo Alto Networks, F5, Ivanti, Citrix, SonicWall and the other edge devices." },
];

export const platformKeys: PlatformKey[] = platformList.map((p) => p.id);

export function isPlatformKey(value: unknown): value is PlatformKey {
  return typeof value === "string" && (platformKeys as string[]).includes(value);
}

export function platformName(id: PlatformKey): string {
  return platformList.find((p) => p.id === id)?.label ?? id;
}

const networkVendors = new Set(["cisco", "juniper", "fortinet", "paloaltonetworks", "f5", "ivanti", "citrix", "sonicwall", "zyxel", "dlink", "d-link", "netgear", "mikrotik", "arista", "checkpoint", "pulsesecure", "barracuda", "sophos", "watchguard", "arraynetworks", "draytek", "tp-link", "ubiquiti", "hpe", "aruba"]);
const linuxVendors = new Set(["linux", "redhat", "canonical", "debian", "suse", "opensuse", "fedoraproject", "almalinux", "rockylinux", "oraclelinux"]);

/** The platforms one CPE criterion names, from its part, vendor and product. */
function platformsOfCpe(cpe: string): PlatformKey[] {
  const parts = cpe.split(":");
  const part = parts[2] ?? "";
  const vendor = (parts[3] ?? "").toLowerCase();
  const product = (parts[4] ?? "").toLowerCase();
  const out: PlatformKey[] = [];
  if (vendor === "microsoft") {
    if (/^edge/.test(product)) out.push("edge");
    else if (part === "o" && /windows/.test(product)) out.push("windows");
    else if (/^windows/.test(product)) out.push("windows");
  } else if (vendor === "apple") {
    if (/macos|mac_os|iphone_os|ipados|ipad_os|watchos|tvos|visionos|safari/.test(product) || part === "o") out.push("apple");
  } else if (vendor === "google") {
    if (/^chrome|chromium/.test(product)) out.push("chrome");
    else if (/android/.test(product)) out.push("android");
  } else if (vendor === "mozilla") {
    if (/firefox|thunderbird/.test(product)) out.push("firefox");
  } else if (vendor === "oracle") {
    if (/^linux/.test(product)) out.push("linux");
  } else if (linuxVendors.has(vendor)) {
    if (part === "o" || /linux|kernel|enterprise_linux|ubuntu|debian|sles|leap|fedora/.test(product)) out.push("linux");
  } else if (networkVendors.has(vendor)) {
    out.push("network");
  }
  return out;
}

const descriptionHints: { platform: PlatformKey; re: RegExp }[] = [
  { platform: "apple", re: /\b(macOS|iOS|iPadOS|watchOS|tvOS|visionOS)\s+(Sequoia|Sonoma|Ventura|Tahoe|\d{1,2}(\.\d+)*)\b|\bis fixed in (macOS|iOS|iPadOS|watchOS|tvOS|visionOS)\b/ },
  { platform: "windows", re: /\bMicrosoft Windows\b|\bWindows (10|11|Server)\b/ },
  { platform: "linux", re: /\bLinux kernel\b|\bIn the Linux kernel\b/ },
  { platform: "android", re: /\bAndroid\b/ },
  { platform: "chrome", re: /\bGoogle Chrome\b|\bChromium\b/ },
  { platform: "firefox", re: /\bFirefox\b|\bThunderbird\b/ },
];

/**
 * The platforms a CVE belongs to, in order of confidence: CPE criteria, then NVD's vendor and
 * product names, then the description when NVD has attached nothing yet.
 */
export function platformsOf(v: { cpes: string[]; vendors: string[]; products: string[]; description: string | null }): PlatformKey[] {
  const out = new Set<PlatformKey>();
  for (const cpe of v.cpes) for (const p of platformsOfCpe(cpe)) out.add(p);
  if (out.size === 0) {
    const vendors = v.vendors.map((x) => x.toLowerCase());
    const products = v.products.map((x) => x.toLowerCase());
    for (const vendor of vendors) for (const product of products.length ? products : [""]) for (const p of platformsOfCpe(`cpe:2.3:a:${vendor}:${product}`)) out.add(p);
  }
  if (out.size === 0 && v.description) {
    for (const hint of descriptionHints) if (hint.re.test(v.description)) out.add(hint.platform);
  }
  return [...out];
}
