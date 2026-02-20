# Azure Linux Data Sources Reference

## OVAL Vulnerability Data

Azure Linux publishes OVAL (Open Vulnerability and Assessment Language) files that define which package versions are vulnerable to specific CVEs.

### Repository
- **URL:** https://github.com/microsoft/AzureLinuxVulnerabilityData
- **Files:**
  - `azurelinux-3.0-oval.xml` - Azure Linux 3.0 vulnerabilities
  - `cbl-mariner-2.0-oval.xml` - CBL-Mariner 2.0 vulnerabilities

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
        {"url": "https://github.com/.../commit/..."}
      ]
    }
  }]
}
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
