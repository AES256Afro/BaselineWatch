import { canonicalEcosystem, distroEcosystem } from "./ecosystems.ts";
import { parseJson } from "./json.ts";

/**
 * An SBOM into watchlist entries (N6): a CycloneDX or SPDX JSON document's components, each
 * read as a package URL (purl) and turned into the `ecosystem:name` the watchlist's package
 * entries use, so the advisories OSV and GitHub publish for what a system actually ships mark
 * the owner's stack. Versions are not kept: a watchlist entry names a package, and the advisory
 * says which versions. Nothing from the SBOM but the names is stored.
 */

export interface SbomPackage {
  /** The watchlist value: `npm:express`, `Maven:org.apache.logging.log4j:log4j-core`, `Debian:12:openssl`. */
  value: string;
  /** The component's own name, for the entry's label. */
  name: string;
}

export interface SbomReading {
  /** The document's own name, from CycloneDX's metadata.component or SPDX's name. */
  name: string | null;
  format: "cyclonedx" | "spdx";
  packages: SbomPackage[];
  /** Components that carried no purl, or one of a type the watchlist cannot match. */
  skipped: number;
}

/** purl types that are package ecosystems OSV carries; the name is OSV's (src/ecosystems.ts). */
const ecosystemTypes = new Set(["npm", "pypi", "maven", "golang", "cargo", "nuget", "gem", "composer", "hex", "pub", "cran", "hackage", "swift", "cocoapods", "conan", "bitnami", "github"]);

/** Distribution purl types as os-release ids; the release comes from the `distro` qualifier (`debian-12`, `alpine-3.20`). */
const distributions: Record<string, string> = { deb: "debian", apk: "alpine", rpm: "rhel" };

const maxPackages = 5000;

/** One purl into a watchlist value, or null when the type is not one an advisory feed covers. */
export function purlToWatch(purl: string): string | null {
  const match = /^pkg:([a-z0-9.+-]+)\/(.+?)(?:@[^?#]*)?(?:\?([^#]*))?(?:#.*)?$/i.exec(purl.trim());
  if (!match) return null;
  const type = match[1]!.toLowerCase();
  const path = decodeURIComponent(match[2]!);
  const qualifiers = new URLSearchParams(match[3] ?? "");
  const parts = path.split("/").filter((p) => p);
  if (parts.length === 0) return null;
  const name = parts[parts.length - 1]!;
  const namespace = parts.slice(0, -1).join("/");
  const distribution = type === "deb" && /^ubuntu$/i.test(namespace) ? "ubuntu" : distributions[type];
  if (distribution) {
    const release = /^[a-z]+-(\d+(?:\.\d+)*)/i.exec(qualifiers.get("distro") ?? "")?.[1];
    // Without a release the entry names every release of the distribution: `Debian:openssl`.
    const ecosystem = distroEcosystem(distribution, release ?? "") ?? "";
    return `${release ? ecosystem : ecosystem.split(":")[0]}:${name}`;
  }
  if (!ecosystemTypes.has(type)) return null;
  const ecosystem = canonicalEcosystem(type);
  if (type === "maven") return namespace ? `Maven:${namespace}:${name}` : null;
  if (type === "golang" || type === "composer" || type === "github" || type === "swift") return `${ecosystem}:${namespace ? `${namespace}/${name}` : name}`;
  // npm scopes come through the purl namespace: pkg:npm/%40scope/name.
  if (type === "npm" && namespace) return `npm:${namespace}/${name}`;
  return `${ecosystem}:${name}`;
}

interface CycloneDx {
  bomFormat?: string;
  metadata?: { component?: { name?: string } };
  components?: { name?: string; purl?: string; components?: unknown[] }[];
}
interface Spdx {
  spdxVersion?: string;
  name?: string;
  packages?: { name?: string; externalRefs?: { referenceType?: string; referenceLocator?: string }[] }[];
}

/** Reads a CycloneDX or SPDX JSON document; anything else is refused with the reason. */
export function readSbom(text: string): SbomReading {
  const doc = parseJson<CycloneDx & Spdx>(text, {});
  const packages: SbomPackage[] = [];
  const seen = new Set<string>();
  let skipped = 0;
  const add = (purl: string | undefined, name: string | undefined): void => {
    const value = purl ? purlToWatch(purl) : null;
    if (!value) {
      skipped += 1;
      return;
    }
    const key = value.toLowerCase();
    if (seen.has(key) || packages.length >= maxPackages) return;
    seen.add(key);
    packages.push({ value, name: (name ?? value.split(":").pop() ?? value).slice(0, 60) });
  };
  if (doc.bomFormat === "CycloneDX" && Array.isArray(doc.components)) {
    // Components nest (an application's libraries, a library's); thirty-two levels is more than any real
    // document and a hostile one cannot run the stack out.
    const walk = (list: unknown[], depth: number): void => {
      if (depth > 32) return;
      for (const raw of list) {
        const c = raw as { name?: string; purl?: string; components?: unknown[] };
        add(c.purl, c.name);
        if (Array.isArray(c.components)) walk(c.components, depth + 1);
      }
    };
    walk(doc.components, 0);
    return { name: doc.metadata?.component?.name ?? null, format: "cyclonedx", packages, skipped };
  }
  if (typeof doc.spdxVersion === "string" && Array.isArray(doc.packages)) {
    for (const p of doc.packages) {
      const purl = p.externalRefs?.find((r) => r.referenceType === "purl")?.referenceLocator;
      add(purl, p.name);
    }
    return { name: doc.name ?? null, format: "spdx", packages, skipped };
  }
  throw new Error("Not a CycloneDX or SPDX JSON document: no bomFormat with components, no spdxVersion with packages.");
}
