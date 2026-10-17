# What comparable tools do, and what BaselineWatch takes from each

*Written 2026-10-17 for M9. A survey from public documentation and use, not a benchmark.*

BaselineWatch's aim is one place for a practitioner: alerts, news, CVEs, suggestions, guides,
baselines and controls, read-only, with every line traceable to its publisher. The tools below
each do one or two of those well. One sentence each on what to borrow, and what to leave alone.

## Vulnerability intelligence

**OpenCVE** (open source CVE tracker with subscriptions per vendor and product, change history
per CVE, and alerts): borrow the per-vendor subscription that produces an alert the moment a
CVE touching it appears or changes (M9.5's platform entries do this for whole platforms);
deliberately do not copy its account-per-user model, since cybercard.net is one owner and
public readers.

**Vulners** (an aggregated vulnerability database with a search language, exploit and patch
correlation, and paid API tiers): borrow the idea that a CVE page should show the published
exploit and the published patch side by side (the Fix panel quotes patch, advisory and
mitigation references); do not build a query language or a metered API, since the read-only
JSON and MCP already serve scripts.

**Feedly Threat Intelligence** (news and CVE feeds enriched by models that tag threat actors,
malware and CVEs, with "insights" generated per article): borrow the habit of putting the CVE
ids and the affected products on the story itself as chips; deliberately do not generate
summaries or tags with a model in the guidance path, which is the rule for all of M9.

**CISA KEV and its directives** (the Known Exploited Vulnerabilities catalog with due dates
and required actions, and the Binding Operational and Emergency Directives that set deadlines
for federal agencies): borrow all of it as data, which BaselineWatch already does for KEV and
M9.2 adds for the directives, quoting the required action beside each CVE; do not paraphrase
CISA, since its text is the authority and is public domain.

## Platform baselines

**NIST macOS Security Compliance Project** (mSCP: YAML rules per macOS release with check and
fix, mobileconfig payloads, and references to 800-53, 800-171, STIG, CIS and CMMC, from which
a script generates guides, profiles and compliance scripts): borrow the rule model wholesale,
because it is the best-structured baseline source that exists, and ingest it as a source so
the macOS profile and its Jamf flavour come straight from it; do not re-implement its
generator, since the exports here are guides for a person, not scripts for a host.

**Jamf Compliance Editor** (a Mac app that takes mSCP, lets an administrator pick a baseline,
tailor rules and organisation-defined values, and produce profiles and a compliance script for
Jamf Pro): borrow the "pick a baseline, untick what you cannot do, export" flow, which is the
baseline builder, with ordinary HTML forms instead of a native app; do not produce signed
profiles or scripts, since that is Jamf's job and the export names the mSCP rule ids and
payload keys it needs.

**Microsoft Intune security baselines** (Microsoft's recommended settings for Windows, Edge,
Defender and Microsoft 365 Apps, versioned, applied as Intune profiles with per-setting
comparison between versions): borrow the per-setting "what changed between versions" view,
which the Register already draws for the Security Compliance Toolkit baselines and M9.3 draws
for the strict profile; do not attempt to publish Intune profiles, since Microsoft's baseline
content is licensed and DISA already ships settings-catalog JSON for its STIGs.

**Microsoft Secure Score** (a tenant-level score from Defender and Microsoft 365 configuration,
with recommended actions and points per action): borrow the idea that a recommendation says
what to do and where in the console; deliberately do not score, because a number invites
gaming and the publishers do not rank their own rules beyond CAT or Level.

**CIS WorkBench and CIS-CAT** (the community site where benchmarks are drafted and published
with change logs, and the assessor that checks a host against them): borrow the change-log
habit (the Register's reason for being) and the per-recommendation level; do not redistribute
CIS content or assess hosts, since the licence forbids the first and the second is a scanner.

## Compliance and policy platforms

**Tenable and Qualys policy compliance** (audit files per benchmark run by a scanner, with
pass and fail per host and mappings to frameworks): borrow the framework mappings as a thing
people expect to see beside each rule (the CCI join does this for 800-53); deliberately do
not scan, since BaselineWatch knows no hosts and should keep knowing none.

**Wiz** (cloud security posture with a policy library mapped to frameworks and findings per
resource): borrow the "one control, many frameworks" view, which the control page gets in
M9.2 as its STIG rules; do not model resources or findings, since that is an inventory
product.

**Vanta and the policy libraries of its kind** (compliance automation with policy templates,
framework crosswalks and evidence collection): borrow the crosswalk (800-53 to 800-171 to STIG
to CIS, which mSCP's references and DISA's CCIs give for free); do not collect evidence or
track audits, since triage with a note is as far as BaselineWatch goes into workflow.

**ComplianceAsCode and OpenSCAP** (open-source profiles for STIG, CIS and PCI as rules with
remediations in Bash, Ansible and Kubernetes): borrow the idea of a fix in the operator's
own tongue (the Linux flavour quotes the STIG fix procedure); do not generate remediation
scripts of our own, since the publisher's words are the ones a reader can be held to.

## What this adds up to

BaselineWatch keeps what the others leave out: the standards as living documents with their
diffs and reasons, one timeline across news, CVEs and releases, and guidance that is a quote
with a link rather than a model's paraphrase. It leaves to the others what needs agents on
hosts, accounts per user, or a licence to redistribute.
