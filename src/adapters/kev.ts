import { isoDate, plainText, type Adapter, type ParsedItem } from "./types.ts";

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
  cwes?: string[];
}

interface KevCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevEntry[];
}

/**
 * CISA's Known Exploited Vulnerabilities catalog. Every entry becomes a `kev` item dated by
 * dateAdded, so an addition surfaces at the top of the Wire and carries its due date.
 */
export const kevAdapter: Adapter = {
  id: "kev",
  headers: { accept: "application/json" },
  parse(bytes) {
    const catalog = JSON.parse(new TextDecoder("utf-8").decode(bytes)) as KevCatalog;
    if (!Array.isArray(catalog.vulnerabilities)) throw new Error("KEV JSON has no vulnerabilities array");
    const items: ParsedItem[] = catalog.vulnerabilities.map((v) => ({
      kind: "kev",
      externalId: v.cveID,
      title: `${v.vendorProject} ${v.product}: ${v.vulnerabilityName}`.replace(/\s+/g, " ").trim(),
      url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      summary: plainText(`${v.shortDescription} Required action: ${v.requiredAction}`, 800),
      publishedAt: isoDate(v.dateAdded),
      signals: {
        kev: true,
        cves: [v.cveID],
        vendor: v.vendorProject,
        product: v.product,
        dueDate: v.dueDate,
        ransomware: v.knownRansomwareCampaignUse === "Known",
        ...(v.cwes?.length ? { cwes: v.cwes } : {}),
        ...(v.notes ? { notes: v.notes } : {}),
      },
    }));
    return { items, documentKey: "known_exploited_vulnerabilities.json", versionLabel: catalog.catalogVersion ?? null };
  },
};
