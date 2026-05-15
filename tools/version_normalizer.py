"""
Normalize Yocto package version strings for comparison against CVE affected ranges.

Yocto version strings often include build-time suffixes like +gitAUTOINC+deadbeef,
+AUTOINC+<hash>, or _p<rev> that don't correspond to upstream versions.
"""
import re


def normalize_yocto_version(version: str, recipe_name: str = "") -> str:
    v = version.strip()

    # Strip git auto-increment suffixes
    v = re.sub(r"\+gitAUTOINC\+[a-f0-9]+.*$", "", v)
    v = re.sub(r"\+AUTOINC\+[a-f0-9]+.*$", "", v)
    v = re.sub(r"\+gitr[A-Z]*\+[a-f0-9]+.*$", "", v)

    # Strip common Yocto suffixes
    v = re.sub(r"-r\d+(\.\d+)?$", "", v)
    v = re.sub(r"_p\d+$", "", v)
    v = re.sub(r"\+r\d+$", "", v)

    return v.strip()


def _split_version(version: str) -> list:
    """Split version into comparable parts: numeric parts as ints, string parts as strings."""
    parts = []
    for part in re.split(r"[.\-_+]", version):
        if part.isdigit():
            parts.append(int(part))
        else:
            parts.append(part)
    while parts and parts[-1] == "":
        parts.pop()
    return parts


def compare_versions(v1: str, v2: str) -> int:
    """
    Compare two version strings.
    Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
    """
    p1 = _split_version(v1)
    p2 = _split_version(v2)

    for a, b in zip(p1, p2):
        # int vs int
        if isinstance(a, int) and isinstance(b, int):
            if a < b:
                return -1
            if a > b:
                return 1
        # str vs str
        elif isinstance(a, str) and isinstance(b, str):
            if a < b:
                return -1
            if a > b:
                return 1
        # Type mismatch: int comes before str (3.0 < 3.alpha)
        elif isinstance(a, int):
            return -1
        else:
            return 1

    if len(p1) < len(p2):
        return -1
    if len(p1) > len(p2):
        return 1
    return 0


def is_version_in_range(version: str, introduced: str, fixed: str) -> bool:
    """Check if version is in [introduced, fixed) range."""
    n = normalize_yocto_version(version)
    if introduced == "0":
        return compare_versions(n, fixed) < 0
    return compare_versions(n, introduced) >= 0 and compare_versions(n, fixed) < 0
