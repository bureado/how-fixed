---
name: azurelinux-cve-analysis
description: Analyze how CVEs are addressed in Azure Linux 3.0. Given a CVE ID, fetches vulnerability details from CISA Vulnrichment and NVD (including SSVC, CWE, CVSS, advisory URLs and fix commits), Azure Linux OVAL data, RPM specs, actual patch file contents, and compares patches to upstream fixes to explain the remediation mechanism.
license: MIT
compatibility: Requires curl, git, jq, and network access to GitHub, NVD, and packages.microsoft.com
metadata:
  author: microsoft
  version: "1.2"
  target-distro: azurelinux-3.0
---

# Azure Linux CVE Analysis Skill

This skill helps users understand how a specific CVE is addressed in Azure Linux 3.0 by gathering and correlating information from multiple authoritative sources, including comparing actual patch contents to upstream fixes.

## When to Use

- User asks about a CVE's status in Azure Linux
- User wants to know if Azure Linux is affected by a vulnerability
- User wants to understand how a patch was applied (upgrade vs backport)
- User wants to compare Azure Linux patches to upstream fixes
- User is investigating security posture of Azure Linux packages

## Workflow

> **Parallel Execution:** Steps 1-3 can be executed in parallel since they are independent data fetches. Only Step 4+ requires results from earlier steps.

### Step 1: Gather CVE Details (Run in Parallel)

Fetch from **multiple sources simultaneously**:

#### 1a. CISA Vulnrichment (Preferred - richer data)

CISA's enriched CVE data includes SSVC scoring, CWE, CVSS, and KEV status:

```bash
# Path pattern: {YEAR}/{NNxxx}/CVE-{YEAR}-{NNNNN}.json
# Example: CVE-2026-24882 → 2026/24xxx/CVE-2026-24882.json
CVE_ID="CVE-2026-24882"
YEAR=$(echo $CVE_ID | cut -d'-' -f2)
NUM=$(echo $CVE_ID | cut -d'-' -f3)
PREFIX="${NUM:0:2}xxx"

curl -sf "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/${YEAR}/${PREFIX}/${CVE_ID}.json" | jq '{
  id: .cveMetadata.cveId,
  ssvc: .containers.adp[0].metrics[0].other.content.options,
  cvss: .containers.cna.metrics[0].cvssV3_1,
  cwe: .containers.cna.problemTypes[0].descriptions[0],
  affected: .containers.cna.affected,
  references: .containers.cna.references,
  description: .containers.cna.descriptions[0].value
}'
```

**CISA Vulnrichment provides:**
- **SSVC Decision Points:** Exploitation status, Automatable, Technical Impact
- **CWE:** Specific weakness identifier (e.g., CWE-121 Stack-based Buffer Overflow)
- **CVSS 3.1:** Full scoring with vector string
- **KEV Status:** Whether on CISA's Known Exploited Vulnerabilities list
- **CPE:** Affected product identifiers

#### 1b. NVD API (Fallback/Additional)

If CISA Vulnrichment entry doesn't exist or for additional references:

```bash
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXXX" | jq '{
  id: .vulnerabilities[0].cve.id,
  published: .vulnerabilities[0].cve.published,
  description: .vulnerabilities[0].cve.descriptions[0].value,
  severity: (.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // "Unknown"),
  score: (.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore // null),
  references: [.vulnerabilities[0].cve.references[] | {url: .url, tags: .tags}]
}'
```

**Mine reference URLs for:**
- Upstream security advisories (e.g., `openssl-library.org/news/secadv/`)
- Bug tracker links (e.g., `dev.gnupg.org/T8045`)
- Fix commits (e.g., `github.com/.../commit/...`)

### Step 2: Check Azure Linux OVAL Data (Run in Parallel with Step 1)

```bash
curl -sL "https://raw.githubusercontent.com/microsoft/AzureLinuxVulnerabilityData/main/azurelinux-3.0-oval.xml" -o azurelinux-3.0-oval.xml
grep -B 5 -A 15 "ref_id=\"CVE-XXXX-XXXXX\"" azurelinux-3.0-oval.xml
```

Extract:
- Affected package name(s) - note CVEs can affect multiple packages
- Fixed version (if patchable=true)
- Severity rating
- Advisory date

### Step 3: Check GitHub Security Advisories (Run in Parallel with Steps 1-2)

Search for additional context and fix commits:
- URL: `https://github.com/advisories?query=CVE-XXXX-XXXXX`
- Extract linked commit SHAs for later comparison

### Step 4: Examine RPM Spec and Fetch Actual Patches

**Important:** Don't just check if patches exist - fetch and analyze their contents.

1. **Find and fetch the spec file:**
   ```bash
   PACKAGE="openssl"
   curl -s "https://raw.githubusercontent.com/microsoft/azurelinux/3.0/SPECS/${PACKAGE}/${PACKAGE}.spec"
   ```

2. **Extract patch filenames from spec:**
   ```bash
   grep -E "^Patch[0-9]+:" ${PACKAGE}.spec | awk '{print $2}'
   ```

3. **Fetch each relevant patch file:**
   ```bash
   PATCH_NAME="CVE-XXXX-XXXXX.patch"
   curl -s "https://raw.githubusercontent.com/microsoft/azurelinux/3.0/SPECS/${PACKAGE}/${PATCH_NAME}"
   ```
   
   **Direct link format:**
   ```
   https://github.com/microsoft/azurelinux/blob/3.0/SPECS/{package}/{patch-file}
   ```

4. **Analyze patch contents for:**
   - `From:` line with original commit SHA and author
   - `Subject:` describing the fix
   - `Upstream-reference:` or similar headers linking to upstream commit
   - Actual code changes (diff hunks)

### Step 5: Compare Patches to Upstream Fixes

This is critical for verification:

1. **Extract upstream commit SHA from:**
   - NVD references (github.com/.../commit/...)
   - GitHub Security Advisory links
   - Patch file headers (`From:` line or `Upstream-reference:`)
   - Upstream security advisories

2. **Fetch upstream commit as patch:**
   ```bash
   # Example for OpenSSL
   curl -s "https://github.com/openssl/openssl/commit/COMMIT_SHA.patch"
   ```

3. **Compare the patches:**
   - Are the code changes identical or equivalent?
   - Does the Azure Linux patch cover all affected files?
   - Are there any Azure Linux-specific adaptations?

4. **Document comparison:**
   | Aspect | Upstream | Azure Linux |
   |--------|----------|-------------|
   | Commit SHA | abc123... | Backported from abc123 |
   | Files changed | 3 | 3 |
   | Lines added | 15 | 15 |
   | Differences | N/A | None / Minor adaptations |

### Step 6: Verify Package Availability

Confirm the fixed package is published:

1. **Check package repository:**
   ```bash
   # List available versions
   curl -s "https://packages.microsoft.com/azurelinux/3.0/prod/base/x86_64/repodata/primary.xml.gz" | \
     gunzip | grep -A 5 "<name>{package-name}</name>"
   ```

2. **Alternative: Check security updates repo:**
   ```bash
   curl -s "https://packages.microsoft.com/azurelinux/3.0/prod/security/x86_64/repodata/primary.xml.gz" | \
     gunzip | grep -A 5 "<name>{package-name}</name>"
   ```

### Step 7: Summarize Findings

Provide a clear summary including data from all sources:

| Field | Value | Source |
|-------|-------|--------|
| CVE ID | CVE-XXXX-XXXXX | - |
| Description | {brief description} | CISA/NVD |
| CWE | {CWE-XXX: description} | CISA Vulnrichment |
| CVSS Score | {score} ({severity}) | CISA/NVD |
| SSVC Exploitation | {none/poc/active} | CISA Vulnrichment |
| SSVC Automatable | {yes/no} | CISA Vulnrichment |
| SSVC Technical Impact | {partial/total} | CISA Vulnrichment |
| Affected Package | {package-name} | Azure Linux OVAL |
| Azure Linux Status | {Affected/Fixed/Not Affected} | Azure Linux OVAL |
| Remediation Type | {Upgrade/Backport/N/A} | RPM Spec analysis |
| Fixed Version | {version-release} | Azure Linux OVAL |
| Upstream Fix | {commit SHA or version} | NVD references |
| Patch Link | https://github.com/microsoft/azurelinux/blob/3.0/SPECS/{pkg}/{patch} | RPM Spec |
| Patch Matches Upstream | {Yes/No/Partial - explanation} | Patch comparison |

## Remediation Types

### Upgrade
The package was upgraded to a new upstream version that includes the fix.
- Spec file shows new `Version:`
- Changelog mentions "upgrade" or "update"

### Backport
Security patches were extracted from upstream and applied to the existing version.
- Spec file shows same `Version:` but incremented `Release:`
- `Patch*:` entries added for CVE fixes
- Changelog mentions "Patch CVE-..."

### Not Affected
Azure Linux is not vulnerable because:
- Feature is disabled at compile time
- Vulnerable code path is not present
- Package version predates the vulnerability introduction

## Example Analysis

See [references/EXAMPLE-ANALYSIS.md](references/EXAMPLE-ANALYSIS.md) for a complete walkthrough.

## Data Sources

| Priority | Source | URL | Purpose |
|----------|--------|-----|---------|
| 1 | CISA Vulnrichment | https://github.com/cisagov/vulnrichment | SSVC, CWE, CVSS, KEV status |
| 2 | NVD | https://nvd.nist.gov | CVE details, references |
| 3 | GitHub Advisories | https://github.com/advisories | Fix commits, patches |
| 4 | Azure Linux OVAL | https://github.com/microsoft/AzureLinuxVulnerabilityData | Package vuln status |
| 5 | Azure Linux Specs | https://github.com/microsoft/azurelinux | RPM specs, patches |
| 6 | Package Repo | https://packages.microsoft.com/azurelinux/ | Published RPMs |

## Tips

- **Run fetches in parallel** - Steps 1-3 are independent and can execute simultaneously
- **CISA Vulnrichment first** - Often has richer data than NVD (SSVC, CWE)
- **OVAL `patchable=true`** means a fix is available in Azure Linux
- **For Azure Linux 3.0**, use `azurelinux-3.0-oval.xml` (consistent naming)
- **Backported patches** often have `Upstream-reference:` headers linking to original commits
- **Security patches** typically increment only the release number (e.g., 3.3.5-2 → 3.3.5-3)
- **Look for `[AutoPR-Security]`** in commit messages for automated security fixes
- **One CVE can affect multiple packages** (e.g., libpcap AND nmap for CVE-2025-11961)
