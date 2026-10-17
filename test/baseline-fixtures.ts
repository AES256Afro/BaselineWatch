import { zipSync } from "fflate";
import { expect } from "vitest";
import { cciListUrl } from "../src/adapters/cci.ts";
import { packageTarget, type DisaListingItem } from "../src/adapters/disa.ts";
import { gpoPackageKey } from "../src/adapters/disa-gpo.ts";
import { intunePackageKey } from "../src/adapters/disa-intune.ts";
import { branchCommitUrl, branchZipUrl } from "../src/adapters/mscp.ts";
import { nistBaselinesAdapter, nistCatalogAdapter } from "../src/adapters/oscal-nist.ts";
import { parseSctListing } from "../src/adapters/sct.ts";
import { getSource, ingestDocumentTarget, ingestSource } from "../src/ingest.ts";
import { latestDocument } from "../src/register.ts";
import { fakeHttp, fixture, type TestApp } from "./helpers.ts";
import { mscpZip } from "./mscp.test.ts";

const text = (name: string) => new TextDecoder().decode(fixture(name));

/**
 * Loads everything the baseline builder reads, from the fixtures: three STIGs (Windows 11, macOS 26
 * and the Server 2025 fixture retitled as RHEL 9), the CCI list, DISA's Intune package and
 * checklist, mSCP tahoe, the SCT baselines, the SP 800-53 catalog and (standing in for High) the
 * moderate profile.
 */
export async function loadBaselineFixtures(app: TestApp, at: Date): Promise<{ win11Doc: number; macDoc: number }> {
  const listing = (): DisaListingItem[] => (JSON.parse(text("disa-listing.json")) as { returnValue: DisaListingItem[] }).returnValue;
  const linkFor = (re: RegExp) => listing().find((i) => re.test(i.FileName.split(String.fromCharCode(0x200b)).join("")))!.DownloadLink;
  const sha = "cf656e844a4091868b2eeb8e6405f8f83952d08f";
  const disa = getSource(app.db, "disa-stigs")!;
  const routes: Record<string, { bytes?: Uint8Array; text?: string }> = {
    [disa.url]: { bytes: fixture("disa-listing.json") },
    [linkFor(/Microsoft Windows 11 STIG - Ver/)]: { bytes: new Uint8Array(zipSync({ "U_MS_Windows_11_V2R11_Manual_STIG/U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml": fixture("stig-win11.xccdf.xml") })) },
    [linkFor(/Apple macOS 26 \(Tahoe\) STIG - Ver/)]: { bytes: new Uint8Array(zipSync({ "U_Apple_macOS_26_V1R4_Manual_STIG/U_Apple_macOS_26_V1R4_STIG_Manual-xccdf.xml": fixture("stig-macos.xccdf.xml") })) },
    // The Server 2025 fixture, retitled, stands in for a Linux STIG.
    [linkFor(/Red Hat Enterprise Linux 9 STIG - Ver/)]: { bytes: new Uint8Array(zipSync({ "U_RHEL_9_V2R10_Manual_STIG/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml": new TextEncoder().encode(text("stig.xccdf.xml").replace("Microsoft Windows Server 2025 Security Technical Implementation Guide", "Red Hat Enterprise Linux 9 Security Technical Implementation Guide")) })) },
    [cciListUrl]: { bytes: new Uint8Array(zipSync({ "CCI_List.xml": fixture("cci/CCI_List.xml") })) },
    [packageTarget(listing(), intunePackageKey, /^Intune Policy - (.+)$/i)!.url]: { bytes: new Uint8Array(zipSync({ "Intune Policies/Settings Catalog/DoD Windows 11 STIG v2r11 Settings Catalog.json": fixture("disa-intune/DoD Windows 11 STIG v2r11 Settings Catalog.json") })) },
    [packageTarget(listing(), gpoPackageKey, /^Group Policy Objects \(GPOs\) - (.+)$/i)!.url]: { bytes: new Uint8Array(zipSync({ "Support Files/Checklist Files/DoD Windows 11 STIG v2r11.ckl": fixture("disa-gpo/DoD Windows 11 STIG v2r11.ckl") })) },
    [branchCommitUrl("tahoe")]: { text: JSON.stringify({ sha, html_url: "https://github.com/usnistgov/macos_security/commit/x", commit: { message: "Tahoe fixes", committer: { date: "2026-06-25T13:21:01Z" } } }) },
    [branchZipUrl(sha)]: { bytes: mscpZip(`macos_security-${sha}`) },
    "https://www.microsoft.com/en-us/download/details.aspx?id=55319": { bytes: fixture("sct-listing.html") },
  };
  for (const file of parseSctListing(text("sct-listing.html"))) {
    routes[file.url] = { bytes: new Uint8Array(zipSync({ "Windows 11 v25H2 Security Baseline/Documentation/MSFT-Win11-v25H2.PolicyRules": fixture("sct.PolicyRules") })) };
  }
  const http = fakeHttp(routes);
  for (const name of ["Microsoft Windows 11", "Apple macOS 26", "Red Hat Enterprise Linux 9", "mscp: tahoe"]) {
    app.db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('baseline', ?, NULL, ?)").run(name, at.toISOString());
  }
  for (const id of ["disa-stigs", "disa-cci", "disa-intune", "disa-gpo", "nist-mscp", "microsoft-sct"]) {
    const result = await ingestSource(app.db, app.dataDir, getSource(app.db, id)!, { http, now: () => at });
    expect(result.status, `${id}: ${result.error ?? result.detail}`).toBe("ok");
  }
  const nist = getSource(app.db, "nist-sp-800-53")!;
  const nistHttp = fakeHttp({ [nistCatalogAdapter.history!(nist)[1]!.url]: { bytes: fixture("oscal-catalog-5.2.0.json") } });
  await ingestDocumentTarget(app.db, app.dataDir, nist, nistCatalogAdapter, nistCatalogAdapter.history!(nist)[1]!, { http: nistHttp, now: () => at });
  const b = getSource(app.db, "nist-sp-800-53b")!;
  const high = { key: "profile:high", url: "https://example.test/high.json" };
  await ingestDocumentTarget(app.db, app.dataDir, b, nistBaselinesAdapter, high, { http: fakeHttp({ [high.url]: { bytes: fixture("oscal-profile-moderate-5.2.0.json") } }), now: () => at });
  return { win11Doc: latestDocument(app.db, "disa-stigs", "stig:microsoft-windows-11")!.id, macDoc: latestDocument(app.db, "disa-stigs", "stig:apple-macos-26-tahoe")!.id };
}
