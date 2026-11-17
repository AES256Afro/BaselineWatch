/**
 * OSV's ecosystem names, in one place: the watchlist's package entries, an SBOM's purls, a device
 * reading's distribution and the OSV adapter all spell an ecosystem the way OSV does, or a package
 * named one way never meets an advisory filed under the other (Ubuntu 24.04 is `Ubuntu:24.04:LTS`).
 */

/** OSV's names, keyed by the way people type them. */
const names: Record<string, string> = {
  npm: "npm", pypi: "PyPI", go: "Go", golang: "Go", maven: "Maven", "crates.io": "crates.io", crates: "crates.io", cargo: "crates.io", rubygems: "RubyGems", gem: "RubyGems",
  nuget: "NuGet", packagist: "Packagist", composer: "Packagist", pub: "Pub", hex: "Hex", hackage: "Hackage", cran: "CRAN", conancenter: "ConanCenter", conan: "ConanCenter",
  "github actions": "GitHub Actions", github: "GitHub Actions", swifturl: "SwiftURL", swift: "SwiftURL", cocoapods: "CocoaPods", bitnami: "Bitnami", linux: "Linux", "oss-fuzz": "OSS-Fuzz",
  debian: "Debian", ubuntu: "Ubuntu", alpine: "Alpine", "rocky linux": "Rocky Linux", almalinux: "AlmaLinux", mageia: "Mageia", opensuse: "openSUSE", suse: "SUSE",
  "red hat": "Red Hat", chainguard: "Chainguard", wolfi: "Wolfi", "photon os": "Photon OS", openeuler: "openEuler",
};

/** Ecosystems whose name carries a release after a colon (Debian:12, Ubuntu:24.04:LTS, Alpine:v3.20). */
const withRelease = new Set(["debian", "ubuntu", "alpine", "rocky linux", "almalinux", "mageia", "opensuse", "suse", "red hat", "chainguard", "wolfi", "photon os", "openeuler"]);

/**
 * `pypi` → `PyPI`, `debian:12` → `Debian:12`, `ubuntu:24.04` → `Ubuntu:24.04:LTS`; anything unknown
 * passes through as typed.
 */
export function canonicalEcosystem(name: string): string {
  const [head = "", ...rest] = name.split(":");
  const canonical = names[head.trim().toLowerCase()] ?? head.trim();
  if (canonical === "Ubuntu" && rest.length === 1 && ubuntuLts(rest[0]!)) rest.push("LTS");
  return [canonical, ...rest].join(":");
}

/** Ubuntu's even-year April releases are LTS, and OSV files them with the suffix. */
function ubuntuLts(release: string): boolean {
  const [y, m] = release.split(".");
  return Number(y) % 2 === 0 && m === "04";
}

/** Whether an ecosystem's name carries a release between it and the package (`Debian:12:openssl`). */
export function hasRelease(ecosystem: string): boolean {
  return withRelease.has(ecosystem.trim().toLowerCase());
}

/**
 * The OSV ecosystem for a distribution as /etc/os-release names it (`ubuntu`, `24.04`); null for one
 * OSV does not carry.
 */
export function distroEcosystem(id: string, versionId: string): string | null {
  const major = versionId.split(".")[0]!;
  switch (id.toLowerCase()) {
    case "debian":
      return `Debian:${major}`;
    case "ubuntu":
      return `Ubuntu:${versionId}${ubuntuLts(versionId) ? ":LTS" : ""}`;
    case "alpine":
      return `Alpine:v${versionId.split(".").slice(0, 2).join(".")}`;
    case "almalinux":
      return `AlmaLinux:${major}`;
    case "rocky":
      return `Rocky Linux:${major}`;
    case "rhel":
    case "redhat":
      return "Red Hat";
    default:
      return null;
  }
}

/**
 * Whether an advisory's ecosystem is the one a watchlist entry names, compared a colon-separated part
 * at a time: `Debian` takes every Debian release, `Ubuntu:24.04` takes `Ubuntu:24.04:LTS`, and
 * `Alpine:v3.2` does not take `Alpine:v3.20`.
 */
export function ecosystemCovers(wanted: string, held: string): boolean {
  const want = wanted.toLowerCase().split(":");
  const have = held.toLowerCase().split(":");
  return want.length <= have.length && want.every((part, i) => part === have[i]);
}
