# Azure Linux Data Sources Reference

## Data Source Priority

When analyzing CVEs, fetch from multiple sources **in parallel** for efficiency:

| Priority | Source | Best For |
|----------|--------|----------|
| 1 | CISA Vulnrichment | SSVC scoring, CWE, CVSS, KEV status |
| 2 | NVD | Reference URLs, publication date |
| 3 | Azure Linux OVAL | Package status, fixed versions |
| 4 | GitHub Advisories | Fix commit links |

## CISA Vulnrichment (Preferred)

CISA's Authorized Data Publisher (ADP) enriches CVE records with additional context.

### Repository
- **URL:** https://github.com/cisagov/vulnrichment
- **Format:** JSON (CVE Record Format 5.x)

### File Path Pattern
```
{YEAR}/{NNxxx}/CVE-{YEAR}-{NNNNN}.json

Examples:
  CVE-2026-24882 → 2026/24xxx/CVE-2026-24882.json
  CVE-2025-11961 → 2025/11xxx/CVE-2025-11961.json
```

### Fetching
```bash
CVE_ID="CVE-2026-24882"
YEAR=$(echo $CVE_ID | cut -d'-' -f2)
NUM=$(echo $CVE_ID | cut -d'-' -f3)
PREFIX="${NUM:0:2}xxx"

curl -s "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/${YEAR}/${PREFIX}/${CVE_ID}.json"
```

### Data Structure
```json
{
  "containers": {
    "adp": [{
      "title": "CISA ADP Vulnrichment",
      "metrics": [{
        "other": {
          "type": "ssvc",
          "content": {
            "options": [
              {"Exploitation": "none|poc|active"},
              {"Automatable": "yes|no"},
              {"Technical Impact": "partial|total"}
            ]
          }
        }
      }]
    }],
    "cna": {
      "metrics": [{"cvssV3_1": {...}}],
      "problemTypes": [{"descriptions": [{"cweId": "CWE-XXX", ...}]}],
      "affected": [{"vendor": "...", "product": "...", "versions": [...]}],
      "references": [{"url": "..."}]
    }
  }
}
```

### Key Fields

| Field | Path | Description |
|-------|------|-------------|
| SSVC | `containers.adp[0].metrics[0].other.content.options` | Exploitation, Automatable, Technical Impact |
| CWE | `containers.cna.problemTypes[0].descriptions[0].cweId` | Weakness type |
| CVSS | `containers.cna.metrics[0].cvssV3_1` | Score, severity, vector |
| KEV | `containers.adp[0].metrics[].other.type == "kev"` | Known Exploited Vulnerability |
| References | `containers.cna.references` | Upstream URLs |

### SSVC Decision Points

| Decision Point | Values | Meaning |
|----------------|--------|---------|
| Exploitation | `none` | No known exploitation |
| | `poc` | Proof-of-concept exists |
| | `active` | Actively exploited in the wild |
| Automatable | `yes` | Can be exploited at scale without human interaction |
| | `no` | Requires human interaction or targeting |
| Technical Impact | `partial` | Limited impact (e.g., DoS, info leak) |
| | `total` | Full system compromise possible |

---

## OVAL Vulnerability Data

Azure Linux publishes OVAL (Open Vulnerability and Assessment Language) files that define which package versions are vulnerable to specific CVEs.

### Repository
- **URL:** https://github.com/microsoft/AzureLinuxVulnerabilityData
- **File for 3.0:** `azurelinux-3.0-oval.xml`

> **Note:** Starting with version 3.0, Azure Linux uses consistent `azurelinux-` naming.

### OVAL Structure

```xml
<definition class="vulnerability" id="oval:com.microsoft.azurelinux:def:XXXXX">
  <metadata>
    <title>CVE-XXXX-XXXXX affecting package NAME for versions less than VERSION</title>
    <reference ref_id="CVE-XXXX-XXXXX" source="CVE"/>
    <patchable>true</patchable>
    <severity>High</severity>
    <description>...</description>
  </metadata>
  <criteria operator="AND">
    <criterion comment="Package NAME is earlier than VERSION, affected by CVE-XXXX-XXXXX"/>
  </criteria>
</definition>
```

### Key Fields
- `patchable`: Whether a fixed version is available
- `severity`: Critical, High, Medium, Low
- `advisory_date`: When the advisory was issued
- Version comparison in `criterion`: Defines vulnerable versions

## Package Specifications

### Repository
- **URL:** https://github.com/microsoft/azurelinux
- **Branch:** `3.0` for Azure Linux 3.0

### Spec File Location
```
SPECS/{package-name}/{package-name}.spec
```

### Spec File Structure
```spec
Name:    openssl
Version: 3.3.5
Release: 3%{?dist}

# Patches
Patch100: 0001-Fix-something.patch
Patch101: CVE-XXXX-XXXXX.patch

%prep
%autosetup -p1  # Applies all patches

%changelog
* Thu Jan 29 2026 Author <email> - 3.3.5-3
- Patch CVE-XXXX-XXXXX
```

### Patch Files
Located alongside spec file:
```
SPECS/{package-name}/
├── {package-name}.spec
├── CVE-XXXX-XXXXX.patch
├── 0001-Some-fix.patch
└── ...
```

## Package Repository

### Base URL
```
https://packages.microsoft.com/azurelinux/3.0/prod/
```

### Repository Structure
```
base/x86_64/          # Base packages
security/x86_64/      # Security updates
updates/x86_64/       # Regular updates
```

### Checking Package Versions
```bash
# Download and parse repodata
curl -s "https://packages.microsoft.com/azurelinux/3.0/prod/base/x86_64/repodata/primary.xml.gz" | \
  gunzip | grep -A 10 "<name>openssl</name>"
```

## NVD API

### Endpoint
```
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXXX
```

### Response Structure
```json
{
  "vulnerabilities": [{
    "cve": {
      "id": "CVE-XXXX-XXXXX",
      "published": "2026-01-27T...",
      "descriptions": [{"value": "..."}],
      "metrics": {
        "cvssMetricV31": [{
          "cvssData": {
            "baseSeverity": "HIGH",
            "baseScore": 8.1
          }
        }]
      },
      "references": [
        {"url": "https://github.com/.../commit/...", "tags": ["Patch"]},
        {"url": "https://openssl-library.org/news/secadv/...", "tags": ["Vendor Advisory"]},
        {"url": "https://dev.gnupg.org/T8045", "tags": ["Issue Tracking"]}
      ]
    }
  }]
}
```

### Important: Mining References

The `references` array is **critical** for finding upstream fixes. Look for:

| Tag | Meaning | Action |
|-----|---------|--------|
| `Patch` | Direct link to fix commit | Fetch and compare to AZL patch |
| `Vendor Advisory` | Official security advisory | Read for affected versions, fix details |
| `Issue Tracking` | Bug tracker link | Find discussion, related commits |
| `Third Party Advisory` | External analysis | Additional context |

**Common reference URL patterns:**
- `github.com/.../commit/SHA` - Direct fix commit
- `github.com/.../pull/NNN` - PR containing fix
- `openssl-library.org/news/secadv/` - OpenSSL advisories
- `dev.gnupg.org/TNNNN` - GnuPG bug tracker
- `bugzilla.redhat.com/` - Red Hat bug reports
- `www.openwall.com/lists/oss-security/` - Security mailing list
```

## GitHub Security Advisories

### Search URL
```
https://github.com/advisories?query=CVE-XXXX-XXXXX
```

### Advisory Content
- CVE description
- Affected versions
- Patched versions
- Links to fix commits
- CVSS score

## Commit Search

### Azure Linux Commits
```
https://github.com/microsoft/azurelinux/search?q=CVE-XXXX-XXXXX&type=commits
```

### Common Commit Patterns
- `[AutoPR-Security] Patch {package} for CVE-XXXX-XXXXX`
- `[AUTO-CHERRYPICK] ... CVE-XXXX-XXXXX`
- `Upgrade {package} to X.Y.Z for CVE-XXXX-XXXXX`
