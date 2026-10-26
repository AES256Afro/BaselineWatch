import type { SourceRow } from "./adapters/types.ts";
import { authorityForSource, type Access } from "./authorities.ts";
import type { NormalizedRequirement } from "./oscal.ts";
import type { DocumentRow } from "./register.ts";

/**
 * Where to read a control in the publisher's own words. Every page that shows a control, a STIG
 * rule, a CIS recommendation or a configuration setting ends here rather than at the page's own
 * text: the rule at the publisher when the publisher gives it an address of its own, the exact
 * document this instance read, and the body that wrote it.
 *
 * Three rules keep it honest. A deep link is built only from a pattern that has been checked
 * against the publisher's site, and only when the label has the shape that pattern takes — a
 * guessed address is worse than none. The document link is the byte-for-byte copy the snapshot
 * was taken from, so the words on the page and the words at the end of the link are the same
 * ones. And a restricted source's own entries are never linked or named here; only the
 * publisher's public address is, which is public knowledge either way (`access: "licence"` says
 * what it takes to read it).
 */

export interface SourceLink {
  href: string;
  /** What the link is, in the page's own words: "AC-02 at NIST (CPRT)". */
  label: string;
  /** The same thing in a table cell, where the standard's name is already in the row beside it. */
  short?: string;
  access: Access;
  /** One line: what a reader finds there. */
  note?: string;
}

const isHttp = (value: unknown): value is string => typeof value === "string" && /^https?:\/\//i.test(value);

/**
 * NIST's Cybersecurity and Privacy Reference Tool holds the control catalogues, one addressable
 * element per control; SP 800-53A's assessment procedures and SP 800-53B's baselines are tabs and
 * rows of the SP 800-53 element rather than frameworks of their own, so all three lead there.
 * Checked 2026-10-25: the element id is the label this instance already stores (AC-02, AC-02(01),
 * 03.01.01).
 */
const cprtBase = "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version";

/** The framework version, from the version this instance holds where the publisher numbers it the same way. */
function cprtVersion(sourceId: string, versionLabel: string | null): string | null {
  switch (sourceId) {
    case "nist-sp-800-53":
    case "nist-sp-800-53a":
    case "nist-sp-800-53b":
      // The OSCAL release number is CPRT's own: 5.2.0 → SP_800_53_5_2_0.
      return versionLabel && /^\d+\.\d+\.\d+$/.test(versionLabel) ? `SP_800_53_${versionLabel.replace(/\./g, "_")}` : null;
    case "nist-sp-800-171":
      // The OSCAL file states its own schema version, not the publication's, so the revision this
      // source follows is named here; a Rev 4 would be a new line.
      return "SP_800_171_3_0_0";
    default:
      return null;
  }
}

/** Whether the label is the shape CPRT addresses an element by, so no address is invented for a row that is not a control. */
function cprtElement(sourceId: string, label: string): string | null {
  if (sourceId === "nist-sp-800-171") return /^\d{2}\.\d{2}\.\d{2}$/.test(label) ? label : null;
  return /^[A-Z]{2}-\d{2}(\(\d{2}\))?$/.test(label) ? label : null;
}

/** macOS and iOS Security Compliance Project rules are files in the branch this instance read, at its exact commit. */
function mscpRuleHref(doc: DocumentRow, requirement: NormalizedRequirement): string | null {
  const section = requirement.extra.section;
  if (typeof section !== "string" || section === "") return null;
  const zip = /^https?:\/\/codeload\.github\.com\/([^/]+)\/([^/]+)\/zip\/([0-9a-f]{7,40})$/i.exec(doc.source_url ?? "");
  if (!zip) return null;
  return `https://github.com/${zip[1]}/${zip[2]}/blob/${zip[3]}/rules/${section}/${requirement.ref}.yaml`;
}

/**
 * The publisher's page for this one rule, when the publisher gives it one. Null is the honest
 * answer for a rule that only exists inside a package (a STIG rule, a DISA checklist row, an
 * Intune setting) — the document link below covers those.
 */
export function controlAtPublisher(source: SourceRow, doc: DocumentRow, requirement: NormalizedRequirement): SourceLink | null {
  const version = cprtVersion(source.id, doc.version_label);
  const element = version ? cprtElement(source.id, requirement.label) : null;
  if (version && element) {
    return {
      href: `${cprtBase}/${version}/home?element=${encodeURIComponent(element)}`,
      label: `${requirement.label} at NIST (CPRT)`,
      access: "public",
      note: "the control as NIST publishes it, with its baselines and assessment procedure",
    };
  }
  if (source.id === "nist-mscp") {
    const href = mscpRuleHref(doc, requirement);
    if (href) return { href, label: `${requirement.label} in the mSCP repository`, access: "public", note: "the rule file at the commit this version was read from" };
  }
  // An adapter that read the entry from a page of its own keeps that address on the requirement:
  // NASA's policy reference carries the NODIS link per directive, FedRAMP's rules a reference URL.
  const stated = isHttp(requirement.extra.url) ? requirement.extra.url : isHttp(requirement.extra.reference) ? requirement.extra.reference : null;
  if (stated) return { href: stated, label: `${requirement.label} at the publisher`, access: source.restricted === 1 ? "licence" : "public", note: "the address the publisher's own list gives for it" };
  return null;
}

/** The document this version was parsed from, byte for byte: the copy the page's words come from. */
export function documentAtPublisher(source: SourceRow, doc: DocumentRow): SourceLink | null {
  const href = doc.source_url;
  if (!isHttp(href)) return null;
  return {
    href,
    label: `${source.name}${doc.version_label ? ` ${doc.version_label}` : ""} as published`,
    short: "as published",
    access: source.restricted === 1 ? "licence" : "public",
    note: "the exact file this version was read from",
  };
}

/** The body that wrote it: its own addresses from the authority registry, else the source's home page. */
export function publisherLinks(source: SourceRow): SourceLink[] {
  const authority = authorityForSource(source.id);
  const own = (authority?.links ?? []).filter((l) => (l.kind ?? "source") === "source");
  if (own.length) return own.map((l) => ({ href: l.href, label: l.label, access: l.access, ...(l.note ? { note: l.note } : {}) }));
  if (isHttp(source.url)) return [{ href: source.url, label: `${source.name} at the publisher`, access: source.restricted === 1 ? "licence" : "public" }];
  return [];
}

/**
 * Every address a reader can follow from one control, best first and never empty while the
 * publisher has a public page: the rule itself, the document it is in, then the publisher.
 */
export function requirementSources(source: SourceRow, doc: DocumentRow, requirement: NormalizedRequirement): SourceLink[] {
  const links = [controlAtPublisher(source, doc, requirement), documentAtPublisher(source, doc), ...publisherLinks(source)];
  const seen = new Set<string>();
  return links.filter((l): l is SourceLink => {
    if (!l || seen.has(l.href)) return false;
    seen.add(l.href);
    return true;
  });
}

/**
 * The same for a whole version, for the pages that list a standard rather than one rule: the
 * document as published, then the publisher.
 */
export function documentSources(source: SourceRow, doc: DocumentRow): SourceLink[] {
  const links = [documentAtPublisher(source, doc), ...publisherLinks(source)];
  const seen = new Set<string>();
  return links.filter((l): l is SourceLink => {
    if (!l || seen.has(l.href)) return false;
    seen.add(l.href);
    return true;
  });
}
