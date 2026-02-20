---
name: azurelinux-cve-analysis
description: Analyze how CVEs are addressed in Azure Linux 3.0. Given a CVE ID, fetches vulnerability details from NVD, related fix commits, Azure Linux OVAL data, RPM specs, patches, and package availability to explain the remediation mechanism (upgrade, backport, or not-affected).
license: MIT
compatibility: Requires curl, git, jq, and network access to NVD, GitHub, and packages.microsoft.com
metadata:
  author: microsoft
  version: "1.0"
  target-distro: azurelinux-3.0
---

# Azure Linux CVE Analysis Skill

This skill helps users understand how a specific CVE is addressed in Azure Linux 3.0 by gathering and correlating information from multiple authoritative sources.

## When to Use

- User asks about a CVE's status in Azure Linux
- User wants to know if Azure Linux is affected by a vulnerability
- User wants to understand how a patch was applied (upgrade vs backport)
- User is investigating security posture of Azure Linux packages

## Workflow

### Step 1: Gather CVE Details

Fetch vulnerability information from multiple sources:

1. **NVD (National Vulnerability Database)**
   ```bash
   curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXXX" | jq .
   ```

2. **GitHub Security Advisories**
   - Search: `https://github.com/advisories?query=CVE-XXXX-XXXXX`
   - Look for linked fix commits

3. **Upstream Project**
   - Check the affected project's security advisories
   - Find the commits that fix the vulnerability

### Step 2: Check Azure Linux OVAL Data

The OVAL (Open Vulnerability and Assessment Language) file contains the official vulnerability status:

1. **Fetch latest OVAL file:**
   ```bash
   curl -sL "https://raw.githubusercontent.com/microsoft/AzureLinuxVulnerabilityData/main/cbl-mariner-3.0-oval.xml" -o azurelinux-3.0-oval.xml
   ```
   
   Or for Azure Linux 3.0:
   ```bash
   curl -sL "https://raw.githubusercontent.com/microsoft/AzureLinuxVulnerabilityData/main/azurelinux-3.0-oval.xml" -o azurelinux-3.0-oval.xml
   ```

2. **Search for CVE:**
   ```bash
   grep -A 20 "CVE-XXXX-XXXXX" azurelinux-3.0-oval.xml
   ```

3. **Extract key information:**
   - Affected package name
   - Fixed version (if patchable=true)
   - Severity rating
   - Advisory date

### Step 3: Examine RPM Spec and Patches

Check how the fix was implemented in Azure Linux:

1. **Find the spec file:**
   - Repository: `https://github.com/microsoft/azurelinux`
   - Branch: `3.0`
   - Path: `SPECS/{package-name}/{package-name}.spec`

2. **Review the spec file for:**
   - Current `Version:` and `Release:`
   - `Patch*:` entries (indicates backported fixes)
   - `%changelog` entries mentioning the CVE

3. **Examine patch files:**
   - Look in `SPECS/{package-name}/` for `.patch` files
   - Check if patches reference upstream commits
   - Verify the patch addresses the specific CVE

4. **Check recent commits:**
   - Search commits on `3.0` branch mentioning the CVE
   - Look for "[AutoPR-Security]" or similar automated security patches

### Step 4: Verify Package Availability

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

### Step 5: Summarize Findings

Provide a clear summary including:

| Field | Value |
|-------|-------|
| CVE ID | CVE-XXXX-XXXXX |
| Affected Package | {package-name} |
| Severity | {severity} |
| Azure Linux Status | {Affected/Fixed/Not Affected} |
| Remediation Type | {Upgrade/Backport/N/A} |
| Fixed Version | {version-release} |
| Fix Mechanism | {description of how fix was applied} |

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

| Source | URL | Purpose |
|--------|-----|---------|
| NVD | https://nvd.nist.gov | Official CVE details |
| GitHub Advisories | https://github.com/advisories | Fix commits, CVSS |
| Azure Linux OVAL | https://github.com/microsoft/AzureLinuxVulnerabilityData | Official vuln status |
| Azure Linux Specs | https://github.com/microsoft/azurelinux | Package sources |
| Package Repo | https://packages.microsoft.com/azurelinux/ | Published RPMs |

## Tips

- OVAL `patchable=true` means a fix is available
- Check both `cbl-mariner-3.0-oval.xml` and `azurelinux-3.0-oval.xml` (naming transition)
- Backported patches often reference upstream commit SHAs
- Security patches typically increment the release number (e.g., 3.3.5-2 → 3.3.5-3)
- Look for `[AutoPR-Security]` in commit messages for automated security fixes
