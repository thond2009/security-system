"""
OSV.dev API client for querying vulnerabilities by PURL.

OSV.dev supports batch queries (POST /v1/queryBatch) with up to 1000 packages per request.
No API key needed, no documented rate limits.
"""
import logging
from typing import Optional

import httpx

OSV_API_URL = "https://api.osv.dev/v1"
BATCH_SIZE = 100

logger = logging.getLogger(__name__)


class OSVQueryError(Exception):
    pass


def _build_query(purl: str, version: str) -> dict:
    """Build an OSV query dict for a single package."""
    return {
        "package": {"purl": purl},
        "version": version,
    }


def query_batch(
    packages: list[tuple[str, str]],  # [(purl, version), ...]
    api_url: str = OSV_API_URL,
    timeout: int = 60,
) -> dict[str, list[dict]]:
    """
    Query OSV.dev for vulnerabilities affecting a batch of packages.

    Returns a dict mapping purl -> list of vulnerability records.
    """
    results: dict[str, list[dict]] = {}

    for i in range(0, len(packages), BATCH_SIZE):
        chunk = packages[i : i + BATCH_SIZE]
        queries = [_build_query(purl, ver) for purl, ver in chunk]

        try:
            response = httpx.post(
                f"{api_url}/querybatch",
                json={"queries": queries},
                timeout=timeout,
            )
            response.raise_for_status()
            data = response.json()

            for j, result in enumerate(data.get("results", [])):
                purl = chunk[j][0]
                vulns = result.get("vulns", [])
                if vulns:
                    results[purl] = vulns

        except httpx.HTTPError as e:
            logger.error("OSV batch query failed: %s", e)
            raise OSVQueryError(f"OSV API request failed: {e}") from e

    return results


def query_single_package(purl: str, version: str, api_url: str = OSV_API_URL) -> list[dict]:
    """Query OSV.dev for a single package/version."""
    try:
        response = httpx.post(
            f"{api_url}/query",
            json=_build_query(purl, version),
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        return data.get("vulns", [])
    except httpx.HTTPError as e:
        logger.error("OSV query failed for %s: %s", purl, e)
        raise OSVQueryError(f"OSV API request failed: {e}") from e


def extract_cve_id(vuln: dict) -> Optional[str]:
    """Extract the canonical CVE ID from an OSV vulnerability record."""
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    # Some records use the OSV id itself if no CVE alias
    osv_id = vuln.get("id", "")
    if osv_id.startswith("CVE-"):
        return osv_id
    return None


def extract_severity(vuln: dict) -> tuple[Optional[str], Optional[float], Optional[str]]:
    """Extract severity, CVSS score, and CVSS vector from a vulnerability record."""
    severity_list = vuln.get("severity", [])
    for sev in severity_list:
        if sev.get("type") == "CVSS_V3":
            score_str = sev.get("score")
            score = None
            if score_str:
                try:
                    score = float(score_str)
                except (ValueError, TypeError):
                    pass
            if score is not None:
                if score >= 9.0:
                    return "CRITICAL", score, score_str
                if score >= 7.0:
                    return "HIGH", score, score_str
                if score >= 4.0:
                    return "MEDIUM", score, score_str
                return "LOW", score, score_str
    return None, None, None


def get_affected_versions(vuln: dict) -> list[dict]:
    """Extract affected version ranges from a vulnerability record."""
    return vuln.get("affected", [])


def find_fixed_version(vuln: dict, purl: str) -> Optional[str]:
    """Try to extract a fixed version from the vulnerability record for a given package."""
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("purl", "") == purl:
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return None
