#!/bin/bash
# Example CI pipeline integration for Yocto-based builds
#
# This script runs after a successful BitBake build and invokes the
# security report tool. It can be called from Jenkins, GitLab CI,
# GitHub Actions, or any CI system.
#
# Prerequisites:
#   - The Yocto build must have security-check.bbclass inherited
#   - Or run this as a manual post-build step

set -euo pipefail

# ---- Configuration ----
API_URL="${SEC_API_URL:-http://security-dashboard.internal:8000/api/v1}"
API_TOKEN="${SEC_API_TOKEN:-}"

# Paths from the Yocto build
BUILD_DIR="${YOCTO_BUILD_DIR:-build}"
IMAGE_NAME="${IMAGE_NAME:-core-image-minimal}"
MACHINE="${MACHINE:-qemux86-64}"

REPORT_DIR="${BUILD_DIR}/tmp/security-reports/${IMAGE_NAME}"

# ---- Check prerequisites ----
if [ ! -f "${REPORT_DIR}/packages.json" ]; then
    echo "ERROR: packages.json not found. Did the security-check class run?"
    echo "Expected at: ${REPORT_DIR}/packages.json"
    exit 1
fi

echo "=== Security Report for ${IMAGE_NAME} ==="
echo "Build dir: ${BUILD_DIR}"
echo "Report dir: ${REPORT_DIR}"

# ---- Run security report ----
python3 tools/security_report.py \
    --packages "${REPORT_DIR}/packages.json" \
    --build-config "${REPORT_DIR}/build-config.json" \
    --kernel-config "${REPORT_DIR}/kernel.config" \
    --output-dir "${REPORT_DIR}" \
    --api-url "${API_URL}" \
    --api-token "${API_TOKEN}" \
    --osv-batch-size 100

exit_code=$?

# ---- Evaluate results ----
if [ $exit_code -eq 0 ]; then
    echo "=== Security check PASSED ==="
    echo "No critical vulnerabilities found."
elif [ $exit_code -eq 2 ]; then
    echo "=== Security check FAILED ==="
    echo "Critical CVEs found! Review: ${REPORT_DIR}/security-report.json"
    # Optionally block the pipeline:
    # exit 1
else
    echo "=== Security check WARNING (exit code ${exit_code}) ==="
fi

# ---- Archive report as CI artifact ----
if [ -n "${CI_ARTIFACT_DIR:-}" ]; then
    mkdir -p "${CI_ARTIFACT_DIR}"
    cp "${REPORT_DIR}/security-report.json" "${CI_ARTIFACT_DIR}/"
    echo "Report archived to ${CI_ARTIFACT_DIR}/security-report.json"
fi
