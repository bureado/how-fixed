#!/bin/bash
# find-package-spec.sh - Find Azure Linux package spec and fetch patches
# Usage: ./find-package-spec.sh PACKAGE_NAME [CVE_ID]

set -e

PACKAGE="${1:?Usage: $0 PACKAGE_NAME [CVE_ID]}"
CVE_ID="${2:-}"
OUTPUT_DIR="${3:-.}"

REPO_BASE="https://raw.githubusercontent.com/microsoft/azurelinux/3.0"
GITHUB_BASE="https://github.com/microsoft/azurelinux/blob/3.0"
SPEC_PATH="SPECS/$PACKAGE/$PACKAGE.spec"

echo "=== Package: $PACKAGE ==="
echo ""

# Fetch spec file
echo "[1/4] Fetching spec file..."
SPEC_URL="$REPO_BASE/$SPEC_PATH"
SPEC_FILE="$OUTPUT_DIR/${PACKAGE}.spec"
curl -sf "$SPEC_URL" -o "$SPEC_FILE" 2>/dev/null

if [ ! -s "$SPEC_FILE" ]; then
    echo "  ✗ Spec file not found at $SPEC_PATH"
    echo "  → Check: https://github.com/microsoft/azurelinux/tree/3.0/SPECS"
    exit 1
fi

echo "  ✓ Spec file saved to $SPEC_FILE"
echo "  → $GITHUB_BASE/$SPEC_PATH"

# Extract version info
echo ""
echo "[2/4] Version information:"
grep -E "^(Name|Version|Release):" "$SPEC_FILE" | head -3 | sed 's/^/  /'

# List and fetch patches
echo ""
echo "[3/4] Patches defined in spec:"
PATCHES=$(grep -E "^Patch[0-9]+:" "$SPEC_FILE" | awk '{print $2}' || true)

if [ -n "$PATCHES" ]; then
    echo "$PATCHES" | while read -r PATCH_FILE; do
        PATCH_URL="$REPO_BASE/SPECS/$PACKAGE/$PATCH_FILE"
        PATCH_LINK="$GITHUB_BASE/SPECS/$PACKAGE/$PATCH_FILE"
        
        # Try to fetch the patch
        PATCH_CONTENT=$(curl -sf "$PATCH_URL" 2>/dev/null || echo "")
        
        if [ -n "$PATCH_CONTENT" ]; then
            echo "  ✓ $PATCH_FILE"
            echo "    Link: $PATCH_LINK"
            
            # Extract upstream reference if present
            UPSTREAM_REF=$(echo "$PATCH_CONTENT" | grep -E "(Upstream-reference|From [0-9a-f]{40})" | head -1 || true)
            if [ -n "$UPSTREAM_REF" ]; then
                echo "    Upstream: $UPSTREAM_REF"
            fi
            
            # Save patch locally
            echo "$PATCH_CONTENT" > "$OUTPUT_DIR/$PATCH_FILE"
        else
            echo "  ? $PATCH_FILE (not found or empty)"
        fi
    done
else
    echo "  No patches defined"
fi

# If CVE specified, search for it specifically
if [ -n "$CVE_ID" ]; then
    echo ""
    echo "[4/4] Searching for $CVE_ID..."
    
    # Check changelog
    echo ""
    echo "  Changelog mentions:"
    grep -i "$CVE_ID" "$SPEC_FILE" | sed 's/^/    /' || echo "    Not found in changelog"
    
    # Check for dedicated patch file
    echo ""
    echo "  CVE-specific patch:"
    CVE_PATCH_URL="$REPO_BASE/SPECS/$PACKAGE/$CVE_ID.patch"
    CVE_PATCH_CONTENT=$(curl -sf "$CVE_PATCH_URL" 2>/dev/null || echo "")
    
    if [ -n "$CVE_PATCH_CONTENT" ]; then
        echo "    ✓ Found: $GITHUB_BASE/SPECS/$PACKAGE/$CVE_ID.patch"
        echo "$CVE_PATCH_CONTENT" > "$OUTPUT_DIR/$CVE_ID.patch"
        echo ""
        echo "  Patch header:"
        echo "$CVE_PATCH_CONTENT" | head -20 | sed 's/^/    /'
    else
        echo "    ✗ No dedicated $CVE_ID.patch file"
        echo "    → CVE may be fixed via numbered patch or version upgrade"
    fi
    
    # Search all patches for CVE mention
    echo ""
    echo "  Scanning all patches for $CVE_ID references..."
    for PATCH_FILE in $PATCHES; do
        if [ -f "$OUTPUT_DIR/$PATCH_FILE" ]; then
            if grep -qi "$CVE_ID" "$OUTPUT_DIR/$PATCH_FILE" 2>/dev/null; then
                echo "    ✓ Found in: $PATCH_FILE"
            fi
        fi
    done
fi

echo ""
echo "=== Analysis complete ===" 
echo "Saved files in $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR"/*.spec "$OUTPUT_DIR"/*.patch 2>/dev/null | sed 's/^/  /' || echo "  (none)"
