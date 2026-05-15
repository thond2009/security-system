#!/usr/bin/env python3
"""
Post-build security report tool for Yocto images.

Orchestrates:
  1. Parse package manifest (JSON list of {name, version, layer, recipe_class, src_uri})
  2. Map each package to a PURL identifier
  3. Query OSV.dev for CVEs affecting each package
  4. Version matching: filter CVEs to those actually affecting the installed version
  5. Deduplicate CVEs by canonical CVE ID
  6. Evaluate hardening rules against kernel config, compiler flags, distro features, rootfs
  7. Generate a JSON report and optionally upload to the dashboard API

Can be invoked by security-check.bbclass during CI or run standalone by developers.
"""
import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

import httpx

from tools.osv_client import (
    extract_cve_id,
    extract_severity,
    find_fixed_version,
    get_affected_versions,
    query_batch,
)
from tools.purl_mapper import recipe_to_purl
from tools.rule_engine import (
    BuildContext,
    RuleEngine,
    inspect_rootfs,
    load_rules_from_dir,
    parse_kernel_config,
)
from tools.version_normalizer import is_version_in_range, normalize_yocto_version

logger = logging.getLogger("security-report")


def parse_package_manifest(manifest_path: str) -> list[dict]:
    """Load the package manifest JSON file."""
    with open(manifest_path) as f:
        packages = json.load(f)
    if not isinstance(packages, list):
        raise ValueError("Package manifest must be a JSON array")
    return packages


def map_packages_to_purls(packages: list[dict]) -> list[dict]:
    """Add a 'purl' field to each package dict based on recipe metadata."""
    for pkg in packages:
        pkg["purl"] = recipe_to_purl(
            name=pkg.get("name", ""),
            version=pkg.get("version", ""),
            recipe_class=pkg.get("recipe_class", ""),
            src_uri=pkg.get("src_uri", ""),
            homepage=pkg.get("homepage", ""),
        )
    return packages


def query_cves_for_packages(packages: list[dict], batch_size: int = 100) -> dict[str, list[dict]]:
    """Query OSV for all packages and return raw vulnerability results keyed by purl."""
    purl_version_pairs = [(p["purl"], p["version"]) for p in packages]
    return query_batch(purl_version_pairs)


def match_affected_versions(
    packages: list[dict],
    cve_results: dict[str, list[dict]],
) -> list[dict]:
    """Match CVEs against package versions and return deduplicated findings."""
    findings = {}
    purl_to_name = {p["purl"]: p["name"] for p in packages}

    for purl, vulns in cve_results.items():
        pkg_name = purl_to_name.get(purl, purl)
        pkg_info = next((p for p in packages if p["purl"] == purl), None)
        pkg_version = pkg_info["version"] if pkg_info else "0"

        for vuln in vulns:
            cve_id = extract_cve_id(vuln)
            if not cve_id:
                continue

            affected = get_affected_versions(vuln)
            is_affected = False
            fixed_in = None

            for a in affected:
                pkg_ref = a.get("package", {})
                if pkg_ref.get("purl", "") and pkg_ref["purl"] != purl:
                    continue
                for r in a.get("ranges", []):
                    events = r.get("events", [])
                    introduced = None
                    fixed = None
                    for ev in events:
                        if "introduced" in ev:
                            introduced = ev["introduced"]
                        if "fixed" in ev:
                            fixed = ev["fixed"]
                    if introduced is not None and fixed is not None:
                        if is_version_in_range(pkg_version, introduced, fixed):
                            is_affected = True
                            fixed_in = fixed
                            break
                    elif introduced == "0" and fixed is not None:
                        if is_version_in_range(pkg_version, introduced, fixed):
                            is_affected = True
                            fixed_in = fixed
                            break
                if is_affected:
                    break

            if not is_affected:
                continue

            severity, cvss_score, cvss_vector = extract_severity(vuln)
            if fixed_in is None:
                fixed_in = find_fixed_version(vuln, purl)

            if cve_id in findings:
                existing = findings[cve_id]
                existing_aliases = set(existing.get("aliases", []))
                new_aliases = set(vuln.get("aliases", []))
                existing["aliases"] = sorted(existing_aliases | new_aliases)
                if severity == "CRITICAL" or (
                    severity == "HIGH" and existing.get("severity") not in ("CRITICAL",)
                ):
                    existing["severity"] = severity
                    existing["cvss_score"] = cvss_score
                continue

            findings[cve_id] = {
                "package_name": pkg_name,
                "package_version": pkg_version,
                "cve_id": cve_id,
                "osv_id": vuln.get("id"),
                "summary": vuln.get("summary"),
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "affected_version": pkg_version,
                "fixed_version": fixed_in,
                "aliases": sorted(vuln.get("aliases", [])),
                "status": "new",
            }

    return list(findings.values())


def evaluate_hardening(args, build_config: dict) -> list[dict]:
    """Run hardening rule evaluation against build artifacts. Returns list of result dicts."""
    if not args.rules_dir or not os.path.isdir(args.rules_dir):
        return []

    logger.info("Loading hardening rules from %s", args.rules_dir)
    rules = load_rules_from_dir(args.rules_dir)
    logger.info("Loaded %d hardening rules", len(rules))

    if not rules:
        return []

    kernel_config = {}
    if args.kernel_config and os.path.isfile(args.kernel_config):
        kernel_config = parse_kernel_config(args.kernel_config)
        logger.info("Parsed kernel config: %d keys", len(kernel_config))

    cflags = {}
    if args.build_flags and os.path.isfile(args.build_flags):
        with open(args.build_flags) as f:
            cflags = json.load(f)

    distro_features = build_config.get("distro_features", "").split()
    image_features = build_config.get("image_features", "").split()

    ctx = BuildContext(
        kernel_config=kernel_config,
        distro_features=distro_features,
        image_features=image_features,
        cflags=cflags,
        rootfs_path=args.rootfs if args.rootfs and os.path.isfile(args.rootfs) else None,
    )

    if ctx.rootfs_path:
        logger.info("Inspecting rootfs for runtime hardening checks")
        ctx = inspect_rootfs(ctx.rootfs_path, ctx)

    engine = RuleEngine(ctx)
    rule_results = engine.evaluate(rules)

    results = []
    for rr in rule_results:
        results.append({
            "rule_id": rr.rule_id,
            "status": rr.status,
            "message": rr.message,
            "evidence": rr.evidence,
        })

    passes = sum(1 for r in results if r["status"] == "PASS")
    fails = sum(1 for r in results if r["status"] == "FAIL")
    errors = sum(1 for r in results if r["status"] == "ERROR")
    logger.info("Hardening: %d pass, %d fail, %d error (of %d rules)",
                passes, fails, errors, len(results))
    return results


def upload_to_api(
    api_url: str,
    api_token: str,
    build_data: dict,
    packages: list[dict],
    findings: list[dict],
    hardening_results: Optional[list[dict]] = None,
) -> dict:
    """Upload build, packages, and CVE findings to the dashboard API."""
    payload = {
        **build_data,
        "metadata_": build_data.pop("metadata_", None),
        "packages": [
            {
                "name": p["name"],
                "version": p["version"],
                "purl": p["purl"],
                "layer": p.get("layer"),
                "recipe_class": p.get("recipe_class"),
                "license_": p.get("license"),
                "is_kernel": p.get("is_kernel", False),
            }
            for p in packages
        ],
        "cve_findings": findings,
    }

    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

    try:
        resp = httpx.post(f"{api_url}/builds", json=payload, headers=headers, timeout=30)
        resp.raise_for_status()
        build = resp.json()
        logger.info("Uploaded build %s to dashboard API", build["id"])

        if hardening_results and build.get("id"):
            hr_payload = [
                {
                    "rule_id": r["rule_id"],
                    "status": r["status"],
                    "message": r.get("message"),
                    "evidence": r.get("evidence"),
                }
                for r in hardening_results
            ]
            hr_resp = httpx.post(
                f"{api_url}/builds/{build['id']}/hardening",
                json=hr_payload,
                headers=headers,
                timeout=30,
            )
            hr_resp.raise_for_status()

        return build
    except httpx.HTTPError as e:
        logger.error("Failed to upload to API: %s", e)
        raise


def main():
    parser = argparse.ArgumentParser(description="Yocto post-build security report tool")
    parser.add_argument("--packages", required=True, help="Path to packages.json manifest")
    parser.add_argument("--sbom", help="Path to SPDX SBOM file (optional)")
    parser.add_argument("--kernel-config", help="Path to kernel .config (optional)")
    parser.add_argument("--build-config", help="Path to build-config.json (optional)")
    parser.add_argument("--build-flags", help="Path to build-flags.json (optional)")
    parser.add_argument("--rootfs", help="Path to rootfs tar.gz (optional)")
    parser.add_argument("--api-url", default="http://localhost:8000/api/v1", help="Dashboard API URL")
    parser.add_argument("--api-token", default="", help="Dashboard API token")
    parser.add_argument("--osv-batch-size", type=int, default=100, help="OSV batch query size")
    parser.add_argument("--rules-dir", default="rules", help="Directory containing hardening rule YAML files")
    parser.add_argument("--output-dir", default=".", help="Directory for output reports")
    parser.add_argument("--upload/--no-upload", default=True, help="Upload results to API")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # 1. Load packages
    logger.info("Loading package manifest from %s", args.packages)
    packages = parse_package_manifest(args.packages)
    logger.info("Loaded %d packages", len(packages))

    # 2. Map to PURLs
    packages = map_packages_to_purls(packages)
    logger.info("Mapped %d packages to PURLs", len(packages))

    # 3. Query OSV.dev
    logger.info("Querying OSV.dev for CVEs (batch size: %d)", args.osv_batch_size)
    cve_results = query_cves_for_packages(packages, batch_size=args.osv_batch_size)
    logger.info("OSV returned vulnerabilities for %d packages", len(cve_results))

    # 4. Match versions and deduplicate
    findings = match_affected_versions(packages, cve_results)
    logger.info("Found %d unique CVEs affecting installed packages", len(findings))

    # 5. Load build config if provided
    build_config = {}
    if args.build_config:
        with open(args.build_config) as f:
            build_config = json.load(f)

    build_data = {
        "image_name": build_config.get("image_name", "unknown"),
        "product_name": build_config.get("project_name", build_config.get("image_name", "unknown")),
        "machine": build_config.get("target_arch", "unknown"),
        "distro": build_config.get("distro", "unknown"),
        "distro_version": build_config.get("distro_version"),
        "yocto_version": build_config.get("yocto_version"),
        "build_number": 1,
        "total_packages": len(packages),
        "status": "completed",
        "metadata_": {
            "distro_features": build_config.get("distro_features", ""),
            "image_features": build_config.get("image_features", ""),
        },
    }

    # 5a. Evaluate hardening rules
    hardening_results = evaluate_hardening(args, build_config)

    # 6. Generate output report
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "build": build_data,
        "packages": packages,
        "cve_findings": findings,
        "hardening_results": hardening_results,
        "summary": {
            "total_packages": len(packages),
            "packages_with_cves": len(cve_results),
            "total_unique_cves": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
            "hardening_pass": sum(1 for r in hardening_results if r["status"] == "PASS"),
            "hardening_fail": sum(1 for r in hardening_results if r["status"] == "FAIL"),
            "hardening_total": len(hardening_results),
        },
    }

    report_path = f"{args.output_dir}/security-report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report written to %s", report_path)

    # 7. Upload to dashboard API
    if args.upload and args.api_token:
        logger.info("Uploading to dashboard API at %s", args.api_url)
        try:
            upload_to_api(args.api_url, args.api_token, build_data, packages, findings, hardening_results)
        except Exception as e:
            logger.error("Upload failed (report saved locally): %s", e)
            sys.exit(1)

    # 8. Print summary
    s = report["summary"]
    print(f"\nSecurity Report Summary")
    print(f"=======================")
    print(f"Packages scanned:     {s['total_packages']}")
    print(f"Packages with CVEs:   {s['packages_with_cves']}")
    print(f"Unique CVEs found:    {s['total_unique_cves']}")
    print(f"  Critical: {s['critical']}  High: {s['high']}  Medium: {s['medium']}  Low: {s['low']}")
    if s.get("hardening_total", 0) > 0:
        score = round(s["hardening_pass"] / s["hardening_total"] * 100, 1) if s["hardening_total"] else 0
        print(f"Hardening compliance: {score}% ({s['hardening_pass']}/{s['hardening_total']} passed)")
    print()

    if s["critical"] > 0:
        sys.exit(2)  # Signal CI to optionally block on critical CVEs


if __name__ == "__main__":
    main()
