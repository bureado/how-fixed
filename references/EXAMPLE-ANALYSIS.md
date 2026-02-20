# Example Analysis: CVE-2026-22796 in OpenSSL

This document demonstrates a complete CVE analysis for Azure Linux 3.0.

## CVE Details

| Field | Value |
|-------|-------|
| CVE ID | CVE-2026-22796 |
| Package | openssl |
| CVSS Score | Low |
| Description | ASN1_TYPE type confusion in PKCS7_digest_from_attributes() |

## Step 1: NVD Information

From the National Vulnerability Database:
- **Affected versions:** OpenSSL 3.6, 3.5, 3.4, 3.3, 3.0, 1.1.1, 1.0.2
- **Fix available:** Yes, in OpenSSL 3.6.1, 3.5.5, 3.4.4, 3.3.6, 3.0.19
- **Attack vector:** Network (requires malformed PKCS#7 data)

## Step 2: OVAL Data

From `azurelinux-3.0-oval.xml`:

```xml
<definition class="vulnerability" id="oval:com.microsoft.azurelinux:def:75299">
  <title>CVE-2026-22796 affecting package openssl for versions less than 3.3.5-3</title>
  <patchable>true</patchable>
  <severity>Low</severity>
  <description>CVE-2026-22796 affecting package openssl for versions less than 3.3.5-3. A patched version of the package is available.</description>
</definition>
```

**Key finding:** Azure Linux considers `openssl < 3.3.5-3` vulnerable, and marks it as patchable.

## Step 3: RPM Spec Analysis

From `SPECS/openssl/openssl.spec`:

```spec
Version: 3.3.5
Release: 3%{?dist}

# Security patches
Patch110: CVE-2026-22796.patch

%changelog
* Thu Jan 29 2026 Lynsey Rydberg <lyrydber@microsoft.com> - 3.3.5-3
- Patch CVE-2025-69419, CVE-2026-22795, and CVE-2026-22796
```

**Key finding:** This is a **backport** - Azure Linux stays on 3.3.5 but applies the upstream fix as a patch.

## Step 4: Patch Content

From `SPECS/openssl/CVE-2026-22796.patch`:

```diff
From eeee3cbd4d682095ed431052f00403004596373e Mon Sep 17 00:00:00 2001
From: Bob Beck <beck@openssl.org>
Date: Wed, 7 Jan 2026 11:29:48 -0700
Subject: [PATCH] Ensure ASN1 types are checked before use.

--- a/crypto/pkcs7/pk7_doit.c
+++ b/crypto/pkcs7/pk7_doit.c
@@ -1178,6 +1178,8 @@ ASN1_OCTET_STRING *PKCS7_digest_from_attributes(...)
     ASN1_TYPE *astype;
     if ((astype = get_attribute(sk, NID_pkcs9_messageDigest)) == NULL)
         return NULL;
+    if (astype->type != V_ASN1_OCTET_STRING)
+        return NULL;
     return astype->value.octet_string;
 }
```

**Key finding:** The patch is the exact upstream commit `eeee3cbd4d682095ed431052f00403004596373e`, cherry-picked and applied to 3.3.5.

## Step 5: Summary

| Field | Value |
|-------|-------|
| CVE ID | CVE-2026-22796 |
| Affected Package | openssl |
| Severity | Low |
| Azure Linux Status | **Fixed** |
| Remediation Type | **Backport** |
| Fixed Version | 3.3.5-3 |
| Upstream Fix | OpenSSL 3.3.6 |
| Fix Mechanism | Cherry-picked commit `eeee3cbd` from upstream applied as Patch110 |

## Why Backport Instead of Upgrade?

Azure Linux chose to backport because:
1. **Stability:** OpenSSL 3.3.5 is the established base; upgrading to 3.3.6 would introduce more changes
2. **Minimal change:** The security fix is small (adding type validation)
3. **Enterprise approach:** Backporting is standard practice for enterprise Linux distributions
4. **Faster turnaround:** Patches can be validated and released quickly

## Verification

Users can verify they have the fixed version:

```bash
rpm -q openssl
# Should show: openssl-3.3.5-3.azl3 or later
```
