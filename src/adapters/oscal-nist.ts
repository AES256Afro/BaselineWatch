import { extractPlanningNote } from "../explain.ts";
import { normalizeCatalog, normalizeProfile, type OscalCatalog, type OscalProfile } from "../oscal.ts";
import { latestDocument, loadRequirements } from "../register.ts";
import type { Adapter, DocumentTarget, ParsedDocument, SourceRow } from "./types.ts";
import { isoDate } from "./types.ts";

/** Where NIST explains a release of SP 800-53: the publication page's Planning Note. */
const publicationPage = "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final";

const repo = "https://raw.githubusercontent.com/usnistgov/oscal-content";
const dir = "nist.gov/SP800-53/rev5/json";

interface Release {
  /** The commit of usnistgov/oscal-content that published this file. */
  sha: string;
  /**
   * What to call this version. Explicit rather than taken from the file, because the files are not
   * consistent: the moderate profile of August 2022 calls itself "Final", and the one shipped with
   * 5.1.1+u3 still calls itself 5.1.1+u2.
   */
  versionLabel: string;
  /** NIST's publication date, where the file's last-modified is the conversion's date instead. */
  publishedAt?: string;
  /** The publisher's own words, quoted. `null` leaves the release with no captured reason. */
  rationale: { text: string; url: string | null } | null;
}

/**
 * The releases of the Rev 5 catalog this instance keeps, oldest first, each pinned to the commit
 * of usnistgov/oscal-content that published it.
 *
 * Two numbering schemes run through these files and they do not even run in the same direction.
 * NIST has published three releases of Revision 5 — September 2020 with its December 2020 errata,
 * Patch Release 5.1.1 of October 2023, and Release 5.2.0 of August 2025 — while the OSCAL
 * conversion has published a dozen versions of those three, and OSCAL's 5.1.2 of August 2022 is
 * NIST's errata'd Revision 5, a year *older* than NIST's own 5.1.1. So each file is pinned where
 * the conversion settled, every content update of a release is kept as its own version so that the
 * diff at each step matches the note the publisher wrote for that step, and `versionLabel` names
 * the NIST release where the file's version string would mislead.
 *
 * Earlier conversions are deliberately not loaded, and that is the honest part. The first one
 * (November 2020) carries no withdrawal status at all and incomplete control statements, so
 * starting there would claim 182 withdrawals and 282 rewritten controls that NIST never made; the
 * 2021 and 2022 files then gain the SP 800-53A assessment procedures, which triples the file and
 * reads as a change to every control. A conversion catching up with the PDF is not the standard
 * changing, and the floor below is the earliest file complete enough to compare against.
 */
const releases: Release[] = [
  {
    sha: "601b282bee",
    versionLabel: "Revision 5 (Dec 2020 errata)",
    publishedAt: "2020-12-10T00:00:00.000Z",
    rationale: {
      text: "From the publication page: Date Published: September 2020 (includes updates as of Dec. 10, 2020). Supersedes: SP 800-53 Rev. 5 (09/23/2020).",
      url: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    },
  },
  {
    sha: "bae69b5a53",
    versionLabel: "5.1.1",
    rationale: {
      // NIST's note for 5.1.1 runs on to describe the content of the later updates, which these
      // bytes do not carry; the rest of it is quoted on 5.1.1+u2 below, where the content lands.
      text:
        'OSCAL release note (5.1.1, 12 October 2023): "This OSCAL version of the SP 800-53 Revision 5.1.1 catalog restores the non-padded ' +
        'prop/@name=“label” for all controls, for backwards compatibility and adds prop/@name=“label” with class=“zero-padded” to support and ' +
        "encourage users' transission to zero-padded control IDs.”",
      url: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    },
  },
  {
    sha: "1763607deb",
    versionLabel: "5.1.1+u2",
    rationale: {
      text:
        'OSCAL release note (5.1.1+u2, 4 December 2023): "This revision of the OSCAL representation of the NIST SP 800-53 Revision 5.1.1 ' +
        'published on November, 7, 2023, provides enhancements to data representation per community’s suggestions." NIST’s note for Patch ' +
        'Release 5.1.1 describes the content this file carries: "…one new control (IA-13), three control enhancements, minor grammatical ' +
        'edits/clarifications that do not impact the implementation or outcome of the controls…"',
      url: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    },
  },
  {
    sha: "b517381112",
    versionLabel: "5.1.1+u3",
    rationale: {
      text:
        'OSCAL release note (5.1.1+u3, 13 December 2023): "This revision of the OSCAL representation of the NIST SP 800-53 Revision 5.1.1 ' +
        'published on November, 7, 2023, provides enhancements to data representation per community’s suggestions."',
      url: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    },
  },
  {
    sha: "941c978d14",
    versionLabel: "5.1.1+u4",
    rationale: {
      text:
        'OSCAL release note (5.1.1+u4, 4 February 2024): "This revision of the OSCAL representation of the NIST SP 800-53 Revision 5.1.1 ' +
        'published on November, 7, 2023, provides a bug fix in SI-03(09) control lines 77352-77359."',
      url: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    },
  },
  {
    sha: "bc8a528770",
    versionLabel: "5.2.0",
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
];

/**
 * Revision 4, kept under its own document key because a revision is not a release: diffing the
 * 922 controls of Rev 4 into the 1,196 of Rev 5 as one more step would read as the publication
 * changing its mind overnight, when what happened was a new book. Held so that a control page can
 * say which revision introduced it, and so the 21 controls of the PT family can be shown for what
 * they are — Rev 4 has no privacy family at all, only Appendix J.
 *
 * It is loaded once and is not expected to move: NIST withdrew it in September 2021.
 */
const rev4 = {
  key: "catalog-rev4",
  url: `${repo}/f0de6d8d8c/nist.gov/SP800-53/rev4/json/NIST_SP-800-53_rev4_catalog.json`,
  versionLabel: "Revision 4",
  publishedAt: "2015-01-22T00:00:00.000Z",
  rationale: {
    text:
      "Planning Note (09/23/2021): This publication was officially withdrawn on September 23, 2021, one year after the publication of " +
      "Revision 5 (September 23, 2020). Date Published: April 2013 (Updated 1/22/2015).",
    url: "https://csrc.nist.gov/pubs/sp/800/53/r4/upd3/final",
  },
};

/** A pinned historical file carries the publisher's words already; only the live catalog needs the page read. */
function pinnedUrl(url: string): boolean {
  return url === rev4.url || releases.some((r) => url.startsWith(`${repo}/${r.sha}/`));
}

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
    return [
      { key: rev4.key, url: rev4.url, versionLabel: rev4.versionLabel, publishedAt: rev4.publishedAt, rationale: rev4.rationale },
      ...releases.map((r) => ({
        key: "catalog",
        url: `${repo}/${r.sha}/${dir}/NIST_SP-800-53_rev5_catalog.json`,
        versionLabel: r.versionLabel,
        ...(r.publishedAt === undefined ? {} : { publishedAt: r.publishedAt }),
        rationale: r.rationale,
      })),
    ];
  },
  async parseDocument(bytes, target, ctx): Promise<ParsedDocument> {
    const doc = normalizeCatalog(decode(bytes) as OscalCatalog);
    let rationale: ParsedDocument["rationale"] = null;
    if (!target.rationale && !pinnedUrl(target.url)) {
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
    // The same pinned releases as the catalog, so membership and text move on the same dates.
    return releases.flatMap((r) =>
      baselines.map((b) => ({
        key: `profile:${b.toLowerCase()}`,
        url: `${repo}/${r.sha}/${dir}/NIST_SP-800-53_rev5_${b}-baseline_profile.json`,
        versionLabel: r.versionLabel,
        ...(r.publishedAt === undefined ? {} : { publishedAt: r.publishedAt }),
        rationale: null,
      })),
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
