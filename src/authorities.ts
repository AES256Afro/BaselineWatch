/**
 * Where a rule comes from: the bodies that publish security standards, the rung of the ladder each
 * one sits on, and what derives from what. The ladder (`/guide#ladder`) names the four words; this
 * registry answers the next question, which is who wrote the rulebook and under whose authority —
 * a law obliges a policy, a policy directs a framework, a framework structures a control catalogue,
 * a catalogue is cut down to a baseline, a baseline becomes settings on a device, and a check
 * proves it. `/learn` draws it.
 *
 * This is committed knowledge, not fetched content: every entry is public information about a
 * publisher, with the address its own words live at and what it takes to read them. Nothing here is
 * a secret, and nothing here is quoted from a restricted document — an agency-only link says so and
 * leads to the sign-in page, because knowing where a standard lives is public even when the
 * standard is not. Where this instance actually tracks a body, `tracked` names the source, so the
 * page can show the version on hand beside the publisher's own address.
 */

/** The rungs, in the order a rule travels down them. */
export type Rung = "law" | "policy" | "framework" | "catalog" | "baseline" | "setting" | "check";

/** Who a body writes for. One body often writes for several. */
export type Sector = "us-federal" | "us-dod" | "nasa" | "industry" | "international";

/** What it takes to read the publisher's own words. */
export type Access = "public" | "registration" | "agency" | "licence";

export interface AuthorityLink {
  label: string;
  href: string;
  access: Access;
  /** A crosswalk is somebody's published mapping between two bodies, not the body's own text. */
  kind?: "source" | "crosswalk";
  note?: string;
}

export interface Authority {
  id: string;
  /** The name as the field uses it: "NIST SP 800-53", "DISA STIGs". */
  name: string;
  /** Who publishes it, spelled out once. */
  publisher: string;
  rung: Rung;
  sectors: Sector[];
  /** One line: what this thing is. */
  what: string;
  /** One line: what obliges or motivates it, and for whom. */
  because: string;
  /** The bodies this one is built on, by id. */
  derivesFrom: string[];
  links: AuthorityLink[];
  /** The source id in this instance, when the pipeline follows this body. */
  tracked?: string;
}

export const rungs: { id: Rung; label: string; line: string }[] = [
  { id: "law", label: "Law and contract", line: "what obliges anyone to do this at all" },
  { id: "policy", label: "Policy", line: "what the government or agency directs, under that law" },
  { id: "framework", label: "Framework", line: "how the work is structured: categorise, select, assess, authorise" },
  { id: "catalog", label: "Control catalogue", line: "the controls themselves, written once for everyone" },
  { id: "baseline", label: "Baseline", line: "the controls chosen for one kind of system" },
  { id: "setting", label: "Configuration setting", line: "how a control is enforced on a real device" },
  { id: "check", label: "Check and evidence", line: "how conformance is expressed, measured and proved" },
];

export const sectors: { id: Sector; label: string; line: string }[] = [
  { id: "us-federal", label: "US federal civilian", line: "agencies under FISMA and OMB, and their cloud providers" },
  { id: "us-dod", label: "US defense", line: "DoD systems and national security systems" },
  { id: "nasa", label: "NASA", line: "an agency's own layer above NIST" },
  { id: "industry", label: "Private business", line: "adopted by contract or by choice, never by FISMA" },
  { id: "international", label: "Outside the US", line: "the same job, done by another country's body" },
];

export const accessLabels: Record<Access, { label: string; line: string }> = {
  public: { label: "public", line: "anyone can read it, no account" },
  registration: { label: "free account", line: "readable after a free registration" },
  agency: { label: "agency sign-in", line: "the publisher's own staff and contractors; the address is public, the document is not" },
  licence: { label: "your own licence", line: "licensed content — this site shows your copy and never redistributes it" },
};

/**
 * The bodies. Ordered by rung, and within a rung roughly by how far upstream they sit, because
 * the page reads top to bottom and a reader should meet a parent before its children.
 */
export const authorities: Authority[] = [
  // ── Law and contract ────────────────────────────────────────────────────────────────────────
  {
    id: "fisma",
    name: "FISMA 2014",
    publisher: "US Congress (44 U.S.C. ch. 35)",
    rung: "law",
    sectors: ["us-federal", "us-dod", "nasa"],
    what: "The statute that makes every federal agency run an information security programme, and makes NIST's standards mandatory for the systems it covers.",
    because: "This is the root of nearly every rule on this site. A federal control exists because FISMA says the agency must have one, not because a vendor recommends it.",
    derivesFrom: [],
    links: [
      { label: "The Act (S.2521, 113th Congress)", href: "https://www.congress.gov/bill/113th-congress/senate-bill/2521", access: "public" },
      { label: "NIST's FISMA background", href: "https://csrc.nist.gov/projects/risk-management/fisma-background", access: "public" },
    ],
  },
  {
    id: "far-52-204-21",
    name: "FAR 52.204-21",
    publisher: "US federal acquisition (FAR Council)",
    rung: "law",
    sectors: ["industry"],
    what: "Fifteen basic safeguarding requirements written into almost every federal contract that touches federal contract information.",
    because: "The smallest legal floor a private company can be held to by a US federal contract — and the first place a business discovers that a 'voluntary' framework is not voluntary for them.",
    derivesFrom: [],
    links: [{ label: "FAR 52.204-21", href: "https://www.acquisition.gov/far/52.204-21", access: "public" }],
  },
  {
    id: "dfars-7012",
    name: "DFARS 252.204-7012",
    publisher: "US Department of Defense (DFARS)",
    rung: "law",
    sectors: ["industry", "us-dod"],
    what: "The defense contract clause that flows NIST SP 800-171 down to any contractor holding controlled unclassified information, with incident reporting attached.",
    because: "This clause is why a machine shop in Ohio has to care about a NIST publication. It is the normalisation path from federal rules to private business.",
    derivesFrom: [],
    links: [
      { label: "DFARS 252.204-7012", href: "https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting.", access: "public" },
    ],
  },

  // ── Policy ──────────────────────────────────────────────────────────────────────────────────
  {
    id: "omb-a130",
    name: "OMB Circular A-130",
    publisher: "US Office of Management and Budget",
    rung: "policy",
    sectors: ["us-federal", "nasa"],
    what: "The circular that tells agencies how to manage information as a resource, security and privacy included, and binds them to the NIST framework.",
    because: "FISMA says an agency must have a programme; A-130 is what that programme has to look like.",
    derivesFrom: ["fisma"],
    links: [{ label: "Circular A-130", href: "https://www.cio.gov/policies-and-priorities/circular-a-130/", access: "public" }],
  },
  {
    id: "cisa-directives",
    name: "CISA directives",
    publisher: "CISA (Cybersecurity and Infrastructure Security Agency)",
    rung: "policy",
    sectors: ["us-federal"],
    what: "Binding Operational Directives and Emergency Directives: orders to federal civilian agencies to do one specific thing by one specific date.",
    because: "The fastest-moving rung. A directive can oblige an agency to patch a named flaw in two weeks, which no control catalogue can do.",
    derivesFrom: ["fisma"],
    links: [
      { label: "Directives", href: "https://www.cisa.gov/news-events/directives", access: "public" },
      { label: "Known Exploited Vulnerabilities catalogue", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", access: "public", note: "BOD 22-01's list, and the due dates it sets" },
    ],
    tracked: "cisa-directives",
  },
  {
    id: "dodi-8500",
    name: "DoDI 8500.01 and 8510.01",
    publisher: "US Department of Defense CIO",
    rung: "policy",
    sectors: ["us-dod"],
    what: "DoD's cybersecurity instruction and its adoption of the Risk Management Framework, which together put DISA's content in force across the department.",
    because: "A STIG is not advice inside the DoD; it is policy, through these two instructions.",
    derivesFrom: ["fisma", "cnss"],
    links: [{ label: "DoD issuances (8500 series)", href: "https://www.esd.whs.mil/DD/issuances/dodi/", access: "public" }],
  },
  {
    id: "cnss",
    name: "CNSS policy",
    publisher: "Committee on National Security Systems",
    rung: "policy",
    sectors: ["us-dod"],
    what: "The policy and instruction set for national security systems — classified and intelligence systems — above and apart from the civilian FISMA line.",
    because: "This is why DoD and intelligence baselines differ from a civilian agency's: a different committee decides, and it adds overlays civilian systems never see.",
    derivesFrom: [],
    links: [{ label: "CNSS issuances", href: "https://www.cnss.gov/CNSS/issuances/Instructions.cfm", access: "public", note: "some instructions are restricted; the index is public" }],
  },
  {
    id: "npr-2810",
    name: "NPR 2810.1",
    publisher: "NASA Office of the CIO",
    rung: "policy",
    sectors: ["nasa"],
    what: "NASA's own procedural requirements for the security of information and information systems, in the NODIS directives library.",
    because: "An agency's own layer sits between NIST and the machine. NASA's requirements are NASA's, and they are stricter in places than the NIST publication they rest on.",
    derivesFrom: ["fisma", "omb-a130"],
    links: [
      { label: "NODIS directives library", href: "https://nodis3.gsfc.nasa.gov/", access: "public" },
      { label: "NASA cybersecurity policy", href: "https://www.nasa.gov/cybersecurity-policies/", access: "public", note: "the quarterly reference that enumerates every NASA document" },
    ],
    tracked: "nasa-cyber-ref",
  },

  // ── Framework ───────────────────────────────────────────────────────────────────────────────
  {
    id: "fips-199-200",
    name: "FIPS 199 and FIPS 200",
    publisher: "NIST",
    rung: "framework",
    sectors: ["us-federal", "us-dod", "nasa"],
    what: "FIPS 199 categorises a system low, moderate or high against confidentiality, integrity and availability; FIPS 200 sets the minimum requirements that follow.",
    because: "The hinge of the whole federal chain: the category a system is given here is what decides which baseline it gets later.",
    derivesFrom: ["fisma"],
    links: [
      { label: "FIPS 199", href: "https://csrc.nist.gov/pubs/fips/199/final", access: "public" },
      { label: "FIPS 200", href: "https://csrc.nist.gov/pubs/fips/200/final", access: "public" },
    ],
  },
  {
    id: "rmf",
    name: "NIST SP 800-37 (RMF)",
    publisher: "NIST",
    rung: "framework",
    sectors: ["us-federal", "us-dod", "nasa"],
    what: "The Risk Management Framework: seven steps from preparing and categorising through selecting, implementing, assessing, authorising and monitoring controls.",
    because: "The framework is the verb and the catalogue is the noun. RMF is how a control gets selected, assessed and signed off by somebody with a name.",
    derivesFrom: ["fisma", "omb-a130", "fips-199-200"],
    links: [{ label: "SP 800-37 Rev. 2", href: "https://csrc.nist.gov/pubs/sp/800/37/r2/final", access: "public" }],
  },
  {
    id: "csf",
    name: "NIST CSF 2.0",
    publisher: "NIST",
    rung: "framework",
    sectors: ["industry", "us-federal", "international"],
    what: "The Cybersecurity Framework: six functions — govern, identify, protect, detect, respond, recover — with no control text of its own, and informative references out to the catalogues that have it.",
    because: "The usual entry point for a private business, because it obliges nothing and organises everything. It is a map, not a rulebook.",
    derivesFrom: [],
    links: [
      { label: "The framework", href: "https://www.nist.gov/cyberframework", access: "public" },
      { label: "CSF 2.0 (CSWP 29)", href: "https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-20/final", access: "public" },
      { label: "CPRT: CSF mapped to SP 800-53", href: "https://csrc.nist.gov/projects/cprt", access: "public", kind: "crosswalk" },
    ],
  },
  {
    id: "cmmc",
    name: "CMMC",
    publisher: "US Department of Defense CIO",
    rung: "framework",
    sectors: ["industry", "us-dod"],
    what: "Cybersecurity Maturity Model Certification: the assessment and certification programme that turns SP 800-171 from a promise in a contract into an audited level.",
    because: "The answer to 'who checks?' in private business. Level 2 is the SP 800-171 requirement set, assessed by a third party rather than self-attested.",
    derivesFrom: ["dfars-7012", "sp-800-171"],
    links: [{ label: "CMMC at DoD CIO", href: "https://dodcio.defense.gov/CMMC/", access: "public" }],
  },
  {
    id: "cis-controls",
    name: "CIS Critical Security Controls",
    publisher: "Center for Internet Security",
    rung: "framework",
    sectors: ["industry", "international"],
    what: "Eighteen controls in three implementation groups, ordered by what stops the most attacks for the least work.",
    because: "The private-sector counterpart to a federal catalogue: prioritised rather than complete, and written to be started on a Monday.",
    derivesFrom: [],
    links: [
      { label: "CIS Controls", href: "https://www.cisecurity.org/controls", access: "registration" },
      { label: "Mappings to 800-53, CSF, ISO 27001", href: "https://www.cisecurity.org/insights/white-papers/cis-controls-v8-1-mappings", access: "registration", kind: "crosswalk" },
    ],
  },
  {
    id: "iso-27001",
    name: "ISO/IEC 27001 and 27002",
    publisher: "ISO and IEC",
    rung: "framework",
    sectors: ["international", "industry"],
    what: "27001 is the certifiable management system; 27002 is its control guidance. The pair is what most of the world outside US government means by 'the standard'.",
    because: "The one on this page a company is certified against rather than assessed under, and the one a customer in Europe or Asia is most likely to ask for.",
    derivesFrom: [],
    links: [
      { label: "ISO/IEC 27001", href: "https://www.iso.org/standard/27001", access: "licence", note: "ISO sells its standards; the abstract is public" },
      { label: "CPRT: 800-53 to ISO/IEC 27001", href: "https://csrc.nist.gov/projects/cprt", access: "public", kind: "crosswalk" },
    ],
  },
  {
    id: "e8",
    name: "Essential Eight and the ISM",
    publisher: "Australian Signals Directorate — ACSC",
    rung: "framework",
    sectors: ["international"],
    what: "Eight mitigation strategies at three maturity levels, over the Information Security Manual's full control set.",
    because: "The clearest example of another country doing the same job differently: where NIST publishes a thousand controls and lets you tailor, the ACSC publishes eight and tells you how far to take each.",
    derivesFrom: [],
    links: [
      { label: "Essential Eight", href: "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight", access: "public" },
      { label: "Information Security Manual", href: "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism", access: "public" },
    ],
  },
  {
    id: "ncsc-caf",
    name: "Cyber Assessment Framework",
    publisher: "UK National Cyber Security Centre",
    rung: "framework",
    sectors: ["international"],
    what: "Fourteen outcome-based principles assessed on a scale, with Cyber Essentials underneath it as the small-organisation floor.",
    because: "Outcomes rather than controls: the CAF asks whether you achieved the objective, where a STIG asks whether a registry value is set.",
    derivesFrom: [],
    links: [{ label: "The CAF", href: "https://www.ncsc.gov.uk/collection/cyber-assessment-framework", access: "public" }],
  },

  // ── Control catalogue ───────────────────────────────────────────────────────────────────────
  {
    id: "sp-800-53",
    name: "NIST SP 800-53",
    publisher: "NIST",
    rung: "catalog",
    sectors: ["us-federal", "us-dod", "nasa"],
    what: "The control catalogue: roughly a thousand controls and enhancements in twenty families, each a statement of what must be true, with discussion and related controls.",
    because: "The single most derived-from document in this whole registry. STIGs, FedRAMP, 800-171, CNSSI 1253, the mSCP and NASA's own specifications all cut their rules out of this one.",
    derivesFrom: ["fisma", "fips-199-200"],
    links: [
      { label: "SP 800-53 Rev. 5", href: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final", access: "public" },
      { label: "Release search (the controls themselves)", href: "https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search", access: "public" },
      { label: "OSCAL content on GitHub", href: "https://github.com/usnistgov/oscal-content", access: "public", note: "the machine-readable catalogue this instance reads" },
    ],
    tracked: "nist-sp-800-53",
  },
  {
    id: "sp-800-53a",
    name: "NIST SP 800-53A",
    publisher: "NIST",
    rung: "catalog",
    sectors: ["us-federal", "us-dod", "nasa"],
    what: "The assessment procedures for the catalogue: for each control, what an assessor examines, interviews and tests.",
    because: "The half of the catalogue people forget. A control says what must be true; 800-53A says what would convince somebody that it is.",
    derivesFrom: ["sp-800-53"],
    links: [{ label: "SP 800-53A Rev. 5", href: "https://csrc.nist.gov/pubs/sp/800/53/a/r5/final", access: "public" }],
    tracked: "nist-sp-800-53a",
  },
  {
    id: "sp-800-171",
    name: "NIST SP 800-171",
    publisher: "NIST",
    rung: "catalog",
    sectors: ["industry", "us-dod"],
    what: "The requirements for protecting controlled unclassified information in systems that are not federal — tailored out of the moderate baseline, with the federal-only parts removed.",
    because: "This is the normalisation, written down: SP 800-53 for government, SP 800-171 for everyone the government buys from. CMMC Level 2 is this set.",
    derivesFrom: ["sp-800-53b", "dfars-7012"],
    links: [
      { label: "SP 800-171 Rev. 3", href: "https://csrc.nist.gov/pubs/sp/800/171/r3/final", access: "public" },
      { label: "SP 800-171A (assessment)", href: "https://csrc.nist.gov/pubs/sp/800/171/a/r3/final", access: "public" },
    ],
    tracked: "nist-sp-800-171",
  },

  // ── Baseline ────────────────────────────────────────────────────────────────────────────────
  {
    id: "sp-800-53b",
    name: "NIST SP 800-53B",
    publisher: "NIST",
    rung: "baseline",
    sectors: ["us-federal", "nasa"],
    what: "The low, moderate and high control baselines, plus the privacy baseline, and the tailoring and overlay rules for adjusting them.",
    because: "Where categorisation turns into a list. FIPS 199 says 'moderate'; 800-53B says which of the thousand controls that means.",
    derivesFrom: ["sp-800-53", "fips-199-200"],
    links: [{ label: "SP 800-53B", href: "https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final", access: "public" }],
    tracked: "nist-sp-800-53b",
  },
  {
    id: "cnssi-1253",
    name: "CNSSI 1253",
    publisher: "Committee on National Security Systems",
    rung: "baseline",
    sectors: ["us-dod"],
    what: "Security categorisation and control selection for national security systems: the 800-53 catalogue with its own baselines and overlays.",
    because: "The fork in the road. Two systems can hold the same data and get different control sets, because one is a national security system and the other is not.",
    derivesFrom: ["sp-800-53", "cnss"],
    links: [{ label: "CNSS instructions", href: "https://www.cnss.gov/CNSS/issuances/Instructions.cfm", access: "public" }],
  },
  {
    id: "fedramp",
    name: "FedRAMP baselines",
    publisher: "FedRAMP (GSA)",
    rung: "baseline",
    sectors: ["us-federal", "industry"],
    what: "The low, moderate and high baselines a cloud service must meet to be authorised for federal use, as 800-53 controls plus FedRAMP's own parameters.",
    because: "The other normalisation path into private business: not a contract clause but a market. A vendor meets FedRAMP once and sells to every agency.",
    derivesFrom: ["sp-800-53b", "omb-a130"],
    links: [
      { label: "FedRAMP documents", href: "https://www.fedramp.gov/documents-templates/", access: "public" },
      { label: "The rules, machine-readable", href: "https://github.com/FedRAMP/rules", access: "public", note: "what this instance reads" },
    ],
    tracked: "fedramp-rules",
  },
  {
    id: "disa-srg",
    name: "DISA Security Requirements Guides",
    publisher: "DISA (Defense Information Systems Agency)",
    rung: "baseline",
    sectors: ["us-dod"],
    what: "Technology-class requirements — an operating system SRG, a web server SRG, a mobile policy SRG — written from the catalogue but not yet about any one product.",
    because: "The missing middle most people skip. An SRG is where 'AC-11 Device Lock' becomes 'an operating system must lock after 15 minutes', before any vendor is named.",
    derivesFrom: ["sp-800-53", "cnssi-1253", "dodi-8500"],
    links: [{ label: "SRGs and STIGs", href: "https://www.cyber.mil/stigs/downloads/", access: "public" }],
  },
  {
    id: "nasa-ascs",
    name: "NASA-SPEC-2600 (ASCS)",
    publisher: "NASA OCIO — Cybersecurity Standards and Engineering Team (CSET)",
    rung: "baseline",
    sectors: ["nasa"],
    what: "The enumeration of NASA's Agency Security Configuration Standards: the agency's own per-platform hardening specifications, taken from NIST checklists, CIS Benchmarks, DISA STIGs and vendor guidance.",
    because: "The worked example of an agency layer. NASA does not simply adopt a STIG; CSET reconciles the sources and issues a NASA-approved specification, and that is what a NASA machine is built to.",
    derivesFrom: ["npr-2810", "sp-800-53", "disa-stig", "cis-benchmarks"],
    links: [
      { label: "CSET (the specifications)", href: "https://cset.nasa.gov", access: "agency", note: "NASA sign-in; the specifications themselves are internal" },
      { label: "NTSS (NASA standards)", href: "https://standards.nasa.gov/", access: "agency" },
      { label: "Cybersecurity Policy Reference", href: "https://www.nasa.gov/cybersecurity-policies/", access: "public", note: "the public quarterly list of every NASA document, tracked here" },
    ],
    tracked: "nasa-cyber-ref",
  },
  {
    id: "mscp",
    name: "macOS Security Compliance Project",
    publisher: "NIST, with DISA, NASA and the Los Alamos National Laboratory",
    rung: "baseline",
    sectors: ["us-federal", "us-dod", "nasa", "industry"],
    what: "One rule set per macOS release, each rule carrying its references to 800-53, 800-171, the STIG, CIS and CMMC, from which any of those baselines can be generated.",
    because: "The cleanest answer on this page to 'how are these normalised?'. One rule, many citations, and a build step that emits whichever baseline you asked for.",
    derivesFrom: ["sp-800-53", "sp-800-171", "cis-benchmarks", "disa-stig", "cnssi-1253"],
    links: [{ label: "macos_security on GitHub", href: "https://github.com/usnistgov/macos_security", access: "public" }],
    tracked: "nist-mscp",
  },

  // ── Configuration setting ───────────────────────────────────────────────────────────────────
  {
    id: "disa-stig",
    name: "DISA STIGs",
    publisher: "DISA (Defense Information Systems Agency)",
    rung: "setting",
    sectors: ["us-dod", "us-federal", "nasa", "industry"],
    what: "Security Technical Implementation Guides: per-product rules, each with a severity (CAT I, II, III), the exact check text and the exact fix text.",
    because: "The most concrete rung there is, and the reason this site exists. A STIG rule tells you the command to run, which no catalogue ever does — and because it is free and public, it is read far outside the DoD.",
    derivesFrom: ["disa-srg"],
    links: [
      { label: "STIG downloads", href: "https://www.cyber.mil/stigs/downloads/", access: "public" },
      { label: "STIG Viewer and tools", href: "https://www.cyber.mil/stigs/srg-stig-tools/", access: "public" },
    ],
    tracked: "disa-stigs",
  },
  {
    id: "disa-gpo",
    name: "DISA STIG GPO package",
    publisher: "DISA",
    rung: "setting",
    sectors: ["us-dod", "us-federal"],
    what: "The same STIG rules as Windows Group Policy objects, ready to import into a domain.",
    because: "A rung below the rule: the policy file that actually sets the registry value the rule asks about.",
    derivesFrom: ["disa-stig"],
    links: [{ label: "GPO package", href: "https://www.cyber.mil/stigs/gpo/", access: "public" }],
    tracked: "disa-gpo",
  },
  {
    id: "disa-intune",
    name: "DISA STIG Intune package",
    publisher: "DISA",
    rung: "setting",
    sectors: ["us-dod", "us-federal"],
    what: "The STIG rules expressed as Microsoft Intune settings-catalogue policies, for devices managed from the cloud rather than a domain.",
    because: "The same control, the same rule, a third shape — which is what a configuration setting being platform-specific actually means in practice.",
    derivesFrom: ["disa-stig"],
    links: [{ label: "STIG downloads", href: "https://www.cyber.mil/stigs/downloads/", access: "public" }],
    tracked: "disa-intune",
  },
  {
    id: "microsoft-baselines",
    name: "Microsoft security baselines",
    publisher: "Microsoft",
    rung: "setting",
    sectors: ["industry", "us-federal", "us-dod", "nasa"],
    what: "The vendor's own recommended settings for each Windows and Office release, shipped as GPO backups and policy rules in the Security Compliance Toolkit.",
    because: "The vendor is a publisher too, and often the first one: Microsoft's baseline for a new Windows release lands months before the STIG for it does.",
    derivesFrom: [],
    links: [
      { label: "Windows security baselines", href: "https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines", access: "public" },
      { label: "Security Compliance Toolkit", href: "https://www.microsoft.com/en-us/download/details.aspx?id=55319", access: "public", note: "what this instance reads" },
    ],
    tracked: "microsoft-sct",
  },
  {
    id: "cis-benchmarks",
    name: "CIS Benchmarks",
    publisher: "Center for Internet Security",
    rung: "setting",
    sectors: ["industry", "international", "us-federal", "nasa"],
    what: "Consensus hardening benchmarks per platform at two levels, each recommendation with its audit and remediation steps and its rationale.",
    because: "The private sector's STIG. Free to read under CIS's own terms, licensed for use, and the thing most non-government hardening actually derives from.",
    derivesFrom: ["cis-controls"],
    links: [
      { label: "CIS Benchmarks", href: "https://www.cisecurity.org/cis-benchmarks", access: "registration" },
      { label: "CIS WorkBench", href: "https://workbench.cisecurity.org/", access: "registration", note: "where the owner's own PDF copy comes from" },
    ],
    tracked: "cis-benchmarks",
  },
  {
    id: "nsa-csi",
    name: "NSA Cybersecurity Information Sheets",
    publisher: "US National Security Agency",
    rung: "setting",
    sectors: ["us-dod", "us-federal", "industry"],
    what: "Short, specific hardening guidance on one subject at a time — network infrastructure, Kubernetes, PowerShell, cloud identity — often with other countries' agencies as co-signers.",
    because: "The gap-filler. When something new needs hardening and no catalogue or benchmark covers it yet, this is usually the first public guidance to exist.",
    derivesFrom: [],
    links: [{ label: "Advisories and guidance", href: "https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/", access: "public" }],
  },

  // ── Check and evidence ──────────────────────────────────────────────────────────────────────
  {
    id: "disa-cci",
    name: "Control Correlation Identifiers",
    publisher: "DISA",
    rung: "check",
    sectors: ["us-dod", "us-federal", "nasa"],
    what: "A list that breaks each 800-53 control statement into single testable assertions, each with a CCI number that a STIG rule then cites.",
    because: "The joint in the whole machine. A CCI is how 'this registry value' gets back to 'AC-11', and so how a pile of STIG findings becomes an answer about controls.",
    derivesFrom: ["sp-800-53"],
    links: [{ label: "CCI list", href: "https://www.cyber.mil/stigs/cci/", access: "public" }],
    tracked: "disa-cci",
  },
  {
    id: "oscal",
    name: "OSCAL",
    publisher: "NIST",
    rung: "check",
    sectors: ["us-federal", "us-dod", "industry", "nasa"],
    what: "The Open Security Controls Assessment Language: catalogues, profiles, baselines, implementation statements and assessment results as JSON, XML or YAML.",
    because: "The format that makes any of this computable. A baseline as an OSCAL profile is a document that says 'this catalogue, these controls, these parameters' — which a program can resolve, and a person cannot be trusted to.",
    derivesFrom: ["sp-800-53"],
    links: [
      { label: "OSCAL", href: "https://pages.nist.gov/OSCAL/", access: "public" },
      { label: "NIST's OSCAL content", href: "https://github.com/usnistgov/oscal-content", access: "public" },
    ],
  },
  {
    id: "scap-ncp",
    name: "SCAP and the National Checklist Program",
    publisher: "NIST",
    rung: "check",
    sectors: ["us-federal", "us-dod", "industry", "nasa"],
    what: "XCCDF for the checklist, OVAL for the test, CPE for the product, and the NCP repository that holds the published checklists for each platform.",
    because: "This is what a scanner reads. The same STIG exists as prose for a person and as SCAP content for a tool, and the NCP is the public shelf both come off.",
    derivesFrom: ["sp-800-53"],
    links: [
      { label: "National Checklist Program repository", href: "https://ncp.nist.gov/repository", access: "public" },
      { label: "SCAP", href: "https://csrc.nist.gov/projects/security-content-automation-protocol", access: "public" },
    ],
  },
  {
    id: "cisa-cset",
    name: "CSET (CISA's assessment tool)",
    publisher: "CISA",
    rung: "check",
    sectors: ["us-federal", "industry"],
    what: "A free self-assessment tool that walks an organisation through a chosen standard — CSF, 800-53, 800-171, CIS Controls, ICS standards — and reports the gaps.",
    because: "The one entry here that is software rather than a document, and the easiest way for a small organisation to assess itself against a catalogue it did not write.",
    derivesFrom: ["csf", "sp-800-53", "cis-controls"],
    links: [
      { label: "CSET", href: "https://www.cisa.gov/resources-tools/services/cyber-security-evaluation-tool-cset", access: "public" },
      { label: "cisagov/cset on GitHub", href: "https://github.com/cisagov/cset", access: "public" },
    ],
  },
];

const byId = new Map(authorities.map((a) => [a.id, a]));

export function authorityById(id: string): Authority | undefined {
  return byId.get(id);
}

/** The body a tracked source belongs to, for the header of a standard's own page. */
export function authorityForSource(sourceId: string): Authority | undefined {
  return authorities.find((a) => a.tracked === sourceId);
}

/** The bodies built on this one: the reverse of derivesFrom. */
export function feedsInto(id: string): Authority[] {
  return authorities.filter((a) => a.derivesFrom.includes(id));
}

/** Every body on a rung, optionally narrowed to one sector. */
export function onRung(rung: Rung, sector?: Sector): Authority[] {
  return authorities.filter((a) => a.rung === rung && (sector === undefined || a.sectors.includes(sector)));
}

/** The other bodies doing the same job: the same rung, somebody else's answer. */
export function peers(id: string): Authority[] {
  const a = byId.get(id);
  if (!a) return [];
  return authorities.filter((b) => b.id !== id && b.rung === a.rung);
}

/**
 * Every ancestor of a body, nearest first, with each rung's step kept whole: walking up from a STIG
 * rule reaches the SRG, the catalogue, FIPS 200 and FISMA, which is the sentence a reader wants.
 */
export function ancestors(id: string): Authority[] {
  const seen = new Set<string>([id]);
  const out: Authority[] = [];
  let frontier = byId.get(id)?.derivesFrom ?? [];
  while (frontier.length > 0) {
    const next: string[] = [];
    for (const parentId of frontier) {
      if (seen.has(parentId)) continue;
      seen.add(parentId);
      const parent = byId.get(parentId);
      if (!parent) continue;
      out.push(parent);
      next.push(...parent.derivesFrom);
    }
    frontier = next;
  }
  return out;
}

export function isSector(value: string): value is Sector {
  return sectors.some((s) => s.id === value);
}

export function isRung(value: string): value is Rung {
  return rungs.some((r) => r.id === value);
}

/**
 * A worked trace down the ladder, end to end, for one kind of system. A step names the body it
 * passes through where this registry has one, so the reader can leave the trace and read the source.
 */
export interface ChainStep {
  rung: Rung;
  /** The body this step passes through, where there is one. */
  authority?: string;
  /** What the rule says at this rung, in concrete words. */
  says: string;
}

export interface Chain {
  id: string;
  title: string;
  sector: Sector;
  line: string;
  steps: ChainStep[];
}

/**
 * The same control — a device locking itself after a period of inactivity — traced down three
 * different chains, because that is the answer to "how are these normalised for private business or
 * a government agency": the control is the same, and everything above and below it differs.
 */
export const chains: Chain[] = [
  {
    id: "federal",
    title: "A federal civilian system",
    sector: "us-federal",
    line: "The plain FISMA chain: obliged by statute, categorised, baselined, enforced, assessed.",
    steps: [
      { rung: "law", authority: "fisma", says: "The agency must run an information security programme, and NIST's standards are mandatory for this system." },
      { rung: "policy", authority: "omb-a130", says: "OMB tells the agency what that programme looks like and binds it to the NIST framework." },
      { rung: "framework", authority: "fips-199-200", says: "The system is categorised moderate for confidentiality, integrity and availability." },
      { rung: "catalog", authority: "sp-800-53", says: "AC-11 Device Lock: prevent further access by initiating a device lock after a period of inactivity." },
      { rung: "baseline", authority: "sp-800-53b", says: "The moderate baseline includes AC-11, and the agency's parameter sets the period at 15 minutes." },
      { rung: "setting", authority: "mscp", says: "On macOS: a screensaver idle time of 900 seconds, with the lock delay at zero, in a configuration profile." },
      { rung: "check", authority: "sp-800-53a", says: "The assessor examines the profile and tests a machine; the result goes in the assessment that supports the authorisation." },
    ],
  },
  {
    id: "dod",
    title: "A DoD system",
    sector: "us-dod",
    line: "The same control, a different committee, and a rule concrete enough to run.",
    steps: [
      { rung: "law", authority: "fisma", says: "FISMA applies, and for a national security system CNSS policy applies instead of the civilian line." },
      { rung: "policy", authority: "dodi-8500", says: "DoD adopts the RMF and puts DISA's content in force: the STIG is policy, not advice." },
      { rung: "framework", authority: "rmf", says: "Categorise, select, implement, assess, authorise, monitor — with an authorising official who signs." },
      { rung: "catalog", authority: "cnssi-1253", says: "The 800-53 catalogue with the national security baselines and overlays applied, so the selected set differs from the civilian one." },
      { rung: "baseline", authority: "disa-srg", says: "The Operating System SRG: the OS must initiate a session lock after a period of inactivity." },
      { rung: "setting", authority: "disa-stig", says: "A named rule for this exact Windows release, CAT II, with check text and fix text — the registry value, and the command to set it." },
      { rung: "check", authority: "disa-cci", says: "The rule cites a CCI, the CCI points back at AC-11, and a scanner's XCCDF result rolls the finding up to the control." },
    ],
  },
  {
    id: "business",
    title: "A private business",
    sector: "industry",
    line: "Nothing here is obliged by FISMA. It arrives by contract, by market, or by choice.",
    steps: [
      { rung: "law", authority: "dfars-7012", says: "A defense contract flows SP 800-171 down — or no contract does, and everything below is voluntary." },
      { rung: "policy", says: "There is no rung here. No OMB circular reaches a private company; its own policy is the only policy." },
      { rung: "framework", authority: "csf", says: "CSF 2.0 organises the work by function, or CIS Controls prioritises it, or ISO 27001 certifies it — whichever the customer asks for." },
      { rung: "catalog", authority: "sp-800-171", says: "3.1.10: use session lock with pattern-hiding displays to prevent access after a period of inactivity." },
      { rung: "baseline", authority: "cis-benchmarks", says: "The CIS Benchmark for the platform, Level 1 for a workstation, Level 2 where the data warrants it." },
      { rung: "setting", authority: "microsoft-baselines", says: "The vendor's own baseline sets the machine inactivity limit, imported as a GPO or an Intune policy." },
      { rung: "check", authority: "cmmc", says: "A CMMC assessment, a customer's questionnaire, or an ISO audit — somebody outside the company asks for the evidence." },
    ],
  },
];

/**
 * Names that collide, which is most of why this field is hard to learn. Each reading is real and
 * public; the page names all of them rather than guessing which one a reader meant.
 */
export interface Collision {
  name: string;
  readings: { who: string; what: string; href: string; access: Access }[];
}

export const collisions: Collision[] = [
  {
    name: "CSET",
    readings: [
      { who: "NASA OCIO", what: "the Cybersecurity Standards and Engineering Team, which writes NASA's own configuration specifications (the ASCS set)", href: "https://cset.nasa.gov", access: "agency" },
      { who: "CISA", what: "the Cyber Security Evaluation Tool, free software for assessing yourself against a chosen standard", href: "https://www.cisa.gov/resources-tools/services/cyber-security-evaluation-tool-cset", access: "public" },
      { who: "Georgetown University", what: "the Center for Security and Emerging Technology, a policy research centre — no controls, no baselines", href: "https://cset.georgetown.edu/", access: "public" },
    ],
  },
  {
    name: "FISMA, not FISA",
    readings: [
      { who: "FISMA", what: "the Federal Information Security Modernization Act: the statute behind every federal control on this site", href: "https://csrc.nist.gov/projects/risk-management/fisma-background", access: "public" },
      { who: "FISA", what: "the Foreign Intelligence Surveillance Act: surveillance authority law. It publishes no controls, baselines or standards, and nothing on this site derives from it", href: "https://www.congress.gov/bill/95th-congress/senate-bill/1566", access: "public" },
    ],
  },
  {
    name: "CSI",
    readings: [
      { who: "NSA", what: "a Cybersecurity Information Sheet: short hardening guidance on one subject", href: "https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/", access: "public" },
      { who: "CIS", what: "the Center for Internet Security — the Controls and the Benchmarks. Easy to type as CSI and mean something else entirely", href: "https://www.cisecurity.org/", access: "public" },
    ],
  },
  {
    name: "NIST, CSRC and NVD",
    readings: [
      { who: "NIST", what: "the institute itself, which publishes the standards", href: "https://www.nist.gov/", access: "public" },
      { who: "CSRC", what: "the Computer Security Resource Center: where the publications live", href: "https://csrc.nist.gov/publications", access: "public" },
      { who: "NVD", what: "the National Vulnerability Database: CVEs and their scores, run by NIST but nothing to do with the standards", href: "https://nvd.nist.gov/", access: "public" },
    ],
  },
  {
    name: "800-53, 800-53A, 800-53B",
    readings: [
      { who: "SP 800-53", what: "the control catalogue: what must be true", href: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final", access: "public" },
      { who: "SP 800-53A", what: "the assessment procedures: how an assessor would be convinced", href: "https://csrc.nist.gov/pubs/sp/800/53/a/r5/final", access: "public" },
      { who: "SP 800-53B", what: "the baselines: which controls a low, moderate or high system gets", href: "https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final", access: "public" },
    ],
  },
];
