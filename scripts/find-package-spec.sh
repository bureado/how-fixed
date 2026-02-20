#!/bin/bash
# find-package-spec.sh - Find and display Azure Linux package spec info
# Usage: ./find-package-spec.sh PACKAGE_NAME [CVE_ID]

set -e

PACKAGE="${1:?Usage: $0 PACKAGE_NAME [CVE_ID]}"
CVE_ID="${2:-}"

REPO_URL="https://raw.githubusercontent.com/microsoft/azurelinux/3.0"
SPEC_PATH="SPECS/$PACKAGE/$PACKAGE.spec"

echo "=== Package: $PACKAGE ==="
echo ""

# Fetch spec file
echo "[1/3] Fetching spec file..."
SPEC_URL="$REPO_URL/$SPEC_PATH"
SPEC_CONTENT=$(curl -sf "$SPEC_URL" 2>/dev/null || echo "")

if [ -z "$SPEC_CONTENT" ]; then
    echo "  ✗ Spec file not found at $SPEC_PATH"
    echo "  → Check: https://github.com/microsoft/azurelinux/tree/3.0/SPECS"
    exit 1
fi

echo "  ✓ Found spec file"

# Extract version info
echo ""
echo "[2/3] Version information:"
echo "$SPEC_CONTENT" | grep -E "^(Name|Version|Release):" | head -3

# List patches
echo ""
echo "[3/3] Security patches:"
PATCHES=$(echo "$SPEC_CONTENT" | grep -E "^Patch[0-9]+:" || true)
if [ -n "$PATCHES" ]; then
    echo "$PATCHES" | tail -20
else
    echo "  No patches defined"
fi

# If CVE specified, search for it
if [ -n "$CVE_ID" ]; then
    echo ""
    echo "=== Searching for $CVE_ID ==="
    
    # Check changelog
    echo ""
    echo "Changelog mentions:"
    echo "$SPEC_CONTENT" | grep -i "$CVE_ID" || echo "  Not found in changelog"
    
    # Check for patch file
    echo ""
    echo "Related patch files:"
    PATCH_NAME=$(echo "$CVE_ID" | tr '[:upper:]' '[:lower:]')
    curl -sf "$REPO_URL/SPECS/$PACKAGE/$CVE_ID.patch" > /dev/null && \
        echo "  ✓ $CVE_ID.patch exists" || \
        echo "  ✗ No dedicated $CVE_ID.patch file"
fi
