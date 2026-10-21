import { extractPlanningNote } from "../explain.ts";
import { normalizeCatalog, normalizeProfile, type OscalCatalog, type OscalProfile } from "../oscal.ts";
import { latestDocument, loadRequirements } from "../register.ts";
import type { Adapter, DocumentTarget, ParsedDocument, SourceRow } from "./types.ts";
import { isoDate } from "./types.ts";

/** Where NIST explains a release of SP 800-53: the publication page's Planning Note. */
const publicationPage = "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final";

const repo = "https://raw.githubusercontent.com/usnistgov/oscal-content";
const dir = "nist.gov/SP800-53/rev5/json";

/** Commits of usnistgov/oscal-content that published each release of the Rev 5 catalog. */
const releases = [
  { sha: "941c978d14", note: "Release 5.1.1", rationale: null },
  {
    sha: "bc8a528770",
    note: "Release 5.2.0",
    rationale: {
      text:
        "On August 27, 2025, NIST issued a minor release of SP 800-53 (Release 5.2.0) that includes: " +
        "New Control/Control Enhancements: SA-15(13), SA-24, SI-02(07). " +
        "Revisions to Existing Controls: SI-07(12). " +
        "Updates to Control Discussion: SA-04, SA-05, SA-08, SA-08(14), SI-02, SI-02(05). " +
        "Updates to Related Controls: All -01 Controls, AU-02, AU-03, CA-07, IR-04, IR-06, IR-08, SA-15, SI-02, SI-07.",
      url: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    },
  },
] as const;

const baselines = ["LOW", "MODERATE", "HIGH", "PRIVACY"] as const;

function decode(bytes: Uint8Array): unknown {
  return JSON.parse(new TextDecoder("utf-8").decode(bytes));
}

/** NIST SP 800-53 (with the 800-53A objectives) as the OSCAL catalog. */
export const nistCatalogAdapter: Adapter = {
  id: "oscal-catalog",
  headers: { accept: "application/json" },
  documents(source: SourceRow): DocumentTarget[] {
    return [{ key: "catalog", url: source.url }];
  },
  history(): DocumentTarget[] {
    return releases.map((r) => ({ key: "catalog", url: `${repo}/${r.sha}/${dir}/NIST_SP-800-53_rev5_catalog.json`, rationale: r.rationale }));
  },
  async parseDocument(bytes, target, ctx): Promise<ParsedDocument> {
    const doc = normalizeCatalog(decode(bytes) as OscalCatalog);
    let rationale: ParsedDocument["rationale"] = null;
    if (!target.rationale) {
      // A release the history does not already explain: read NIST's Planning Note from the publication page.
      try {
        const page = await ctx.http(publicationPage, { headers: { accept: "text/html" }, timeoutMs: 60_000 });
        const note = extractPlanningNote(new TextDecoder("utf-8").decode(page.bytes));
        if (note) rationale = { text: `Planning Note${note.date ? ` (${note.date})` : ""}: ${note.text}`, url: publicationPage };
      } catch {
        // The catalog still loads; the release is marked as having no captured reason.
      }
    }
    return { title: doc.title, versionLabel: doc.version, publishedAt: isoDate(doc.lastModified), requirements: doc.requirements, rationale };
  },
};

/**
 * NIST SP 800-171 Revision 3: the requirements for protecting CUI in nonfederal systems (CMMC
 * Level 2 is this set), from NIST's OSCAL. The same normaliser as 800-53, then the names people
 * use: the requirement number (03.01.01) as ref and label, the family as "03.01 Access Control",
 * and statement items lettered a., b. instead of the file's SR-03.01.01.a ids.
 *
 * No backfill: NIST's OSCAL 1.0.0 of Revision 3 (August 2025) left 29 statements empty, which
 * 1.1.0 (May 2026) filled in, so a diff against 1.0.0 would show a conversion fix as a change to
 * the publication. Tracking starts at the current file.
 */
export const nist171Adapter: Adapter = {
  id: "oscal-171",
  headers: { accept: "application/json" },
  documents(source: SourceRow): DocumentTarget[] {
    return [{ key: "catalog", url: source.url }];
  },
  async parseDocument(bytes): Promise<ParsedDocument> {
    const raw = decode(bytes) as OscalCatalog & { catalog: { groups?: { id?: string; title?: string; props?: { name: string; value: string }[] }[] } };
    const doc = normalizeCatalog(raw);
    const families = new Map<string, string>();
    for (const group of raw.catalog.groups ?? []) {
      const sortId = (group.props ?? []).find((p) => p.name === "sort-id")?.value;
      families.set((group.id ?? "").toUpperCase(), `${sortId ? `${sortId} ` : ""}${group.title ?? group.id ?? ""}`.trim());
    }
    const requirements = doc.requirements.map((r) => ({
      ...r,
      ref: r.sortKey.toLowerCase(),
      label: r.sortKey,
      family: families.get(r.family ?? "") ?? r.family,
      statement: r.statement?.replace(/^SR-\d{2}\.\d{2}\.\d{2}\.([a-z](?:\.\d{2})*)\s+/gm, "$1. ") ?? null,
    }));
    return { title: "NIST SP 800-171 Revision 3", versionLabel: `OSCAL ${doc.version}`, publishedAt: isoDate(doc.lastModified), requirements, rationale: null };
  },
};

/** NIST SP 800-53B: the four baseline profiles, diffed as control membership. */
export const nistBaselinesAdapter: Adapter = {
  id: "oscal-profiles",
  headers: { accept: "application/json" },
  documents(source: SourceRow): DocumentTarget[] {
    return baselines.map((b) => ({ key: `profile:${b.toLowerCase()}`, url: `${source.url}NIST_SP-800-53_rev5_${b}-baseline_profile.json` }));
  },
  history(): DocumentTarget[] {
    return releases.flatMap((r) =>
      baselines.map((b) => ({ key: `profile:${b.toLowerCase()}`, url: `${repo}/${r.sha}/${dir}/NIST_SP-800-53_rev5_${b}-baseline_profile.json`, rationale: null })),
    );
  },
  parseDocument(bytes, target, ctx) {
    const titles = new Map<string, string>();
    const catalog = latestDocument(ctx.db, "nist-sp-800-53", "catalog");
    if (catalog) for (const r of loadRequirements(ctx.db, catalog.id)) titles.set(r.ref, r.title);
    const doc = normalizeProfile(decode(bytes) as OscalProfile, titles);
    const baseline = target.key.replace("profile:", "");
    return {
      title: `${doc.title} (${baseline})`,
      versionLabel: doc.version,
      publishedAt: isoDate(doc.lastModified),
      requirements: doc.requirements,
    };
  },
};
