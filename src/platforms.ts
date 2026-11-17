/**
 * Platforms a person follows as a whole: "every Apple CVE", "every Windows CVE". A CVE belongs
 * to a platform by its CPE criteria first (the operating system or the browser named), then by
 * the vendor and product NVD derived, and, for a CVE NVD has not analysed yet, by the way the
 * description names the platform ("This issue is fixed in macOS Sequoia 15.6"). The ids are the
 * ones the watchlist takes as kind "platform".
 */

export type PlatformKey = "windows" | "apple" | "linux" | "android" | "chrome" | "firefox" | "edge" | "network" | "ai";

const platformList: { id: PlatformKey; label: string; blurb: string }[] = [
  { id: "windows", label: "Windows", blurb: "Windows 10 and 11, Windows Server and the Windows components (kernel, SMB, Print Spooler, Defender)." },
  { id: "apple", label: "Apple", blurb: "macOS, iOS, iPadOS, watchOS, tvOS, visionOS and Safari." },
  { id: "linux", label: "Linux", blurb: "The Linux kernel and the distributions (Red Hat, Ubuntu, Debian, SUSE, Oracle Linux, Fedora)." },
  { id: "android", label: "Android", blurb: "Android and Pixel." },
  { id: "chrome", label: "Chrome", blurb: "Google Chrome and Chromium." },
  { id: "firefox", label: "Firefox", blurb: "Mozilla Firefox and Thunderbird." },
  { id: "edge", label: "Edge", blurb: "Microsoft Edge." },
  { id: "network", label: "Network devices", blurb: "Cisco, Juniper, Fortinet, Palo Alto Networks, F5, Ivanti, Citrix, SonicWall and the other edge devices." },
  { id: "ai", label: "AI tooling", blurb: "Model servers and runtimes (Ollama, vLLM, llama.cpp, Triton), agent and RAG frameworks (LangChain, Langflow, Flowise, Dify, LiteLLM), chat front ends (Open WebUI, LibreChat), ML libraries, and MCP servers." },
];

export const platformKeys: PlatformKey[] = platformList.map((p) => p.id);

export function isPlatformKey(value: unknown): value is PlatformKey {
  return typeof value === "string" && (platformKeys as string[]).includes(value);
}

export function platformName(id: PlatformKey): string {
  return platformList.find((p) => p.id === id)?.label ?? id;
}

/**
 * What a reader picks on the Vulnerabilities page: the platforms as people ask about them. The
 * three browsers are one choice there, because "what is hitting the browsers?" is the question;
 * Safari stays with Apple, where src/platforms.ts has always put it.
 */
export type PlatformChoice = PlatformKey | "browsers";

/**
 * `newsTerms` are the words a story uses for the platform, matched as whole words in its headline
 * and summary (the News has no CPEs; a story that names a CVE is placed by the CVE as well).
 * Edge is only ever "Microsoft Edge": "edge devices" is the network's.
 */
export const platformChoices: { id: PlatformChoice; label: string; blurb: string; keys: PlatformKey[]; newsTerms: string[] }[] = [
  { id: "windows", label: "Windows", blurb: "Windows, Windows Server and their components", keys: ["windows"], newsTerms: ["windows", "patch tuesday", "active directory", "exchange server", "sharepoint"] },
  { id: "apple", label: "Apple", blurb: "macOS, iOS, iPadOS and Safari", keys: ["apple"], newsTerms: ["apple", "macos", "ios", "ipados", "iphone", "ipad", "safari", "webkit"] },
  { id: "linux", label: "Linux", blurb: "The kernel and the distributions", keys: ["linux"], newsTerms: ["linux", "ubuntu", "debian", "red hat", "rhel", "fedora", "suse", "glibc", "systemd"] },
  { id: "browsers", label: "Browsers", blurb: "Chrome, Firefox and Edge", keys: ["chrome", "firefox", "edge"], newsTerms: ["chrome", "chromium", "firefox", "microsoft edge", "browser", "browsers"] },
  { id: "android", label: "Android", blurb: "Android and Pixel", keys: ["android"], newsTerms: ["android", "pixel"] },
  {
    id: "ai",
    label: "AI tooling",
    blurb: "Model servers, agent frameworks and MCP servers",
    keys: ["ai"],
    newsTerms: ["ollama", "vllm", "llama.cpp", "langchain", "langflow", "litellm", "open webui", "comfyui", "flowise", "hugging face", "mcp", "model context protocol", "prompt injection"],
  },
  {
    id: "network",
    label: "Network devices",
    blurb: "Firewalls, VPNs and edge gear",
    keys: ["network"],
    newsTerms: ["cisco", "fortinet", "fortigate", "fortios", "palo alto", "pan-os", "juniper", "ivanti", "citrix", "netscaler", "sonicwall", "f5", "big-ip", "zyxel", "mikrotik", "router", "routers", "firewall", "firewalls", "vpn"],
  },
];

/** A choice's words as an FTS5 query: each one quoted, any of them. */
export function newsQuery(choice: PlatformChoice): string {
  const terms = platformChoices.find((c) => c.id === choice)?.newsTerms ?? [];
  return terms.map((t) => `"${t}"`).join(" OR ");
}

export function isPlatformChoice(value: unknown): value is PlatformChoice {
  return value === "browsers" || isPlatformKey(value);
}

/** The platform ids a choice stands for. */
export function platformKeysOf(choice: PlatformChoice): PlatformKey[] {
  return choice === "browsers" ? ["chrome", "firefox", "edge"] : [choice];
}

export function platformChoiceName(choice: PlatformChoice): string {
  return choice === "browsers" ? "Browsers" : platformName(choice);
}

const networkVendors = new Set(["cisco", "juniper", "fortinet", "paloaltonetworks", "f5", "ivanti", "citrix", "sonicwall", "zyxel", "dlink", "d-link", "netgear", "mikrotik", "arista", "checkpoint", "pulsesecure", "barracuda", "sophos", "watchguard", "arraynetworks", "draytek", "tp-link", "ubiquiti", "hpe", "aruba"]);
/**
 * The software people run models and agents with. Vendors whose whole line is AI; then products by
 * name, for the ones a general vendor ships (NVIDIA's Triton, Google's TensorFlow) and for MCP
 * servers, which every vendor now publishes. n8n and Jupyter are left out: automation and notebooks
 * that happen to host AI, and n8n's seventy CVEs would be most of the card.
 */
const aiVendors = new Set(["ollama", "vllm", "ggml", "langchain", "langflow", "llamaindex", "litellm", "openwebui", "comfyanonymous", "flowiseai", "dify", "langgenius", "mintplexlabs", "librechat", "lollms", "oobabooga", "gradio_project", "huggingface", "h2o", "bentoml", "anyscale", "keras", "anthropic", "openai"]);
const aiProducts = /^(ollama|vllm|llama\.cpp|llama-factory|langchain.*|langflow.*|llamaindex|litellm|open_webui|comfyui|flowise|dify|anythingllm|librechat|lollms|gradio|transformers|sglang|tensorrt-llm|triton_inference_server|mlflow|bentoml|openllm|metagpt|pytorch|pytorch_lightning|tensorflow|keras|onnx|onnxruntime|text-generation-webui)$|(^|[_-])mcp([_-]|$)/;

const linuxVendors = new Set(["linux", "redhat", "canonical", "debian", "suse", "opensuse", "fedoraproject", "almalinux", "rockylinux", "oraclelinux"]);
/**
 * A Linux vendor's product that is the system or a part of it, as a CPE slug ("enterprise_linux")
 * or in CISA's words ("Automatic Bug Reporting Tool"): the kernel, the distributions, and the
 * components Red Hat ships under its own name (Polkit, libuser, ABRT). JBoss is not.
 */
const linuxProducts = /linux|kernel|ubuntu|debian|sles|leap|fedora|polkit|libuser|bug[ _]reporting/;

/** The platforms one CPE criterion names, from its part, vendor and product. */
function platformsOfCpe(cpe: string): PlatformKey[] {
  const parts = cpe.split(":");
  const part = parts[2] ?? "";
  const vendor = (parts[3] ?? "").toLowerCase();
  const product = (parts[4] ?? "").toLowerCase();
  const out: PlatformKey[] = [];
  if (aiVendors.has(vendor) || aiProducts.test(product)) out.push("ai");
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
    if (part === "o" || linuxProducts.test(product)) out.push("linux");
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
  { platform: "ai", re: /\b(Ollama|vLLM|llama\.cpp|LangChain|Langflow|LlamaIndex|LiteLLM|Open WebUI|ComfyUI|Flowise|Dify|AnythingLLM|LibreChat|MLflow|BentoML|SGLang|PyTorch|TensorFlow|Triton Inference Server|MCP server|Model Context Protocol)\b/ },
];

/** The platforms a CVE's CPE criteria name. */
export function platformsOfCpes(cpes: readonly string[]): PlatformKey[] {
  const out = new Set<PlatformKey>();
  for (const cpe of cpes) for (const p of platformsOfCpe(cpe)) out.add(p);
  return [...out];
}

/** The platforms a CVE's vendor and product names name, read as CPE slugs ("apple", "macos"). */
export function platformsOfNames(vendors: readonly string[], products: readonly string[]): PlatformKey[] {
  const out = new Set<PlatformKey>();
  const ps = products.map((x) => x.toLowerCase());
  for (const vendor of vendors.map((x) => x.toLowerCase())) for (const product of ps.length ? ps : [""]) for (const p of platformsOfCpe(`cpe:2.3:a:${vendor}:${product}`)) out.add(p);
  return [...out];
}

/** The platforms a CVE's description names in so many words ("Microsoft Windows", "In the Linux kernel"). */
export function platformsOfDescription(description: string | null): PlatformKey[] {
  if (!description) return [];
  return descriptionHints.filter((hint) => hint.re.test(description)).map((hint) => hint.platform);
}

/**
 * A Microsoft application CPE (Exchange, SharePoint, Office, 365 Apps, SQL Server, the Defender
 * engine): NVD placed the CVE on Microsoft software that is not Windows, and that is a reading.
 */
export function isMicrosoftApplicationCpe(cpe: string): boolean {
  const parts = cpe.split(":");
  return parts[2] === "a" && (parts[3] ?? "").toLowerCase() === "microsoft" && platformsOfCpe(cpe).length === 0;
}

/**
 * The platforms NVD's own data names, in order of confidence: CPE criteria, then NVD's vendor and
 * product names, then the description when NVD has attached nothing yet. A building block: the
 * reading of a stored row, CISA's names included, is rowPlatforms in src/vulns.ts.
 */
export function platformsOf(v: { cpes: string[]; vendors: string[]; products: string[]; description: string | null }): PlatformKey[] {
  const byCpe = platformsOfCpes(v.cpes);
  if (byCpe.length) return byCpe;
  const byName = platformsOfNames(v.vendors, v.products);
  if (byName.length) return byName;
  // Only when NVD has attached nothing: a CVE whose CPE names another product is that product's,
  // however its description travels. "Ray … exploitable via Firefox and Safari" is a Ray flaw,
  // and filing it under the browsers put it first on "what is affecting the browsers?".
  return v.cpes.length === 0 && v.vendors.length === 0 ? platformsOfDescription(v.description) : [];
}

/**
 * CISA's Microsoft product words that are not "patch Windows": the old browser engines, Office,
 * and the servers. "Exchange" is the server ("Exchange", "Exchange Server"), never Windows' own
 * "Internet Key Exchange (IKE) Service Extensions".
 */
const microsoftBrowsers = /\b(edge|internet explorer|mshtml|scripting engine|silverlight)\b/i;
const microsoftOffice = /\b(office|word|excel|powerpoint|outlook|publisher|project|visio|access|wordpad|visual basic|vba|mscomctl)\b/i;
export const microsoftServers = /(?<!key )\bexchange\b|sharepoint|sql server|configuration manager|partner center|power pages|skype|lync|dynamics|azure|forefront|open management|\bomi\b|\.net|visual studio|internet information|\biis\b/i;

/**
 * What a KEV entry is about, read once from CISA's own vendor and product words ("Microsoft |
 * Win32k", "Palo Alto Networks | PAN-OS", "Oracle | Solaris") through the same vendor tables a
 * CVE's CPEs are read with. The CVE table (kevPlatformKeys) and the STIG pages (kevPlatform in
 * src/stigs.ts) each file a reading under their own groups; beside the platforms, the readings the
 * table has no platform for and the STIG pages do:
 * - "microsoft-browser": Internet Explorer, MSHTML, the scripting engines, Silverlight;
 * - "microsoft-application": Office and the servers (Exchange, SharePoint, SQL Server, .NET);
 * - "unix": Solaris, which is UNIX and not Linux;
 * - "application": a system vendor's other software (JBoss, WebLogic, Java).
 */
export type KevReading = PlatformKey | "microsoft-browser" | "microsoft-application" | "unix" | "application";

/**
 * The CPE vendor names a KEV vendor stands for: "Palo Alto Networks" is paloaltonetworks,
 * "Barracuda Networks" barracuda, "Hewlett Packard Enterprise (HPE)" hpe, "D-Link and TRENDnet"
 * d-link and trendnet. Lower case, with the spaces CISA writes and NVD does not taken out.
 */
function kevVendorNames(vendor: string | null | undefined): string[] {
  const v = (vendor ?? "").trim().toLowerCase();
  if (!v) return [];
  const out = new Set<string>();
  const short = /\(([^)]+)\)$/.exec(v)?.[1];
  if (short) out.add(short.replace(/\s+/g, ""));
  for (const name of v.replace(/\s*\([^)]*\)$/, "").split(/\s+and\s+/)) {
    out.add(name.replace(/\s+/g, ""));
    out.add(name.replace(/\s+networks$/, "").replace(/\s+/g, ""));
  }
  return [...out];
}

/** One KEV entry's reading; null when no table here names its vendor or product. */
export function kevReading(vendor: string | null | undefined, product: string | null | undefined): KevReading | null {
  const names = kevVendorNames(vendor);
  if (names.length === 0) return null;
  const p = (product ?? "").trim().toLowerCase();
  const is = (name: string) => names.includes(name);
  if (is("microsoft")) {
    // "Multiple Products" names no product (kevPairUsable): Office, Exchange and Windows alike, so
    // it is not read as Windows; nor is a product left empty or given as the vendor's own name.
    if (!p || /^multiple\b/.test(p) || names.includes(p.replace(/\s+/g, ""))) return null;
    if (/\bedge\b/.test(p)) return "edge";
    if (microsoftBrowsers.test(p)) return "microsoft-browser";
    if (microsoftOffice.test(p) || microsoftServers.test(p)) return "microsoft-application";
    return "windows";
  }
  if (is("apple")) return "apple";
  if (is("google")) {
    if (/chrom/.test(p)) return "chrome";
    if (/android|pixel/.test(p)) return "android";
  }
  if (is("android") || is("samsung")) return "android";
  if (is("mozilla")) return "firefox";
  if (is("oracle")) return /linux/.test(p) ? "linux" : /solaris/.test(p) ? "unix" : "application";
  if (names.some((n) => linuxVendors.has(n))) return linuxProducts.test(p) ? "linux" : "application";
  if (names.some((n) => networkVendors.has(n))) return "network";
  if (names.some((n) => aiVendors.has(n)) || aiProducts.test(p.replace(/\s+/g, "_"))) return "ai";
  return null;
}

/**
 * The platforms of a KEV entry, for a row the catalogue made before NVD sent the CVE: CISA's
 * words match nothing in platformsOfCpe. Windows only for what the STIG pages also call Windows:
 * Exchange, Office, SQL Server and Internet Explorer are not "patch Windows" (and NVD's own rows
 * for them carry no platform).
 */
export function kevPlatformKeys(vendor: string | null | undefined, product: string | null | undefined): PlatformKey[] {
  const reading = kevReading(vendor, product);
  return isPlatformKey(reading) ? [reading] : [];
}
