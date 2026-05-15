"""
Map Yocto recipe metadata to PURL (Package URL) identifiers for OSV.dev queries.

Yocto recipes don't natively use PURL. This module uses recipe class, SRC_URI, and
homepage heuristics to infer the correct PURL type (pypi, npm, cargo, golang, etc.).
"""
from fnmatch import fnmatch


# Mapping from recipe class pattern to PURL type
CLASS_TO_PURL_TYPE = {
    "cargo*.bbclass": "cargo",
    "python_*.bbclass": "pypi",
    "python3*.bbclass": "pypi",
    "npm.bbclass": "npm",
    "go.bbclass": "golang",
    "cmake.bbclass": None,   # needs SRC_URI inspection
    "autotools*.bbclass": None,
    "meson.bbclass": None,
    "kernel*.bbclass": None,
}


def normalize_pypi_name(name: str) -> str:
    """Convert Yocto recipe name to PyPI package name."""
    name = name.lower()
    name = name.replace("python3-", "").replace("python-", "")
    name = name.replace("_", "-")
    return name


def normalize_go_name(name: str) -> str:
    """Convert Yocto recipe name to Go module-style name."""
    return name.lower()


def infer_purl_from_src_uri(src_uri: str, name: str, version: str) -> str:
    """Infer PURL type from SRC_URI contents when recipe class alone isn't enough."""
    uri_lower = src_uri.lower() if src_uri else ""

    if "github.com" in uri_lower:
        return f"pkg:github/{name.lower()}@{version}"
    if "gitlab" in uri_lower:
        return f"pkg:gitlab/{name.lower()}@{version}"
    if "pypi.org" in uri_lower or "pypi.python.org" in uri_lower:
        return f"pkg:pypi/{normalize_pypi_name(name)}@{version}"
    if "registry.npmjs.org" in uri_lower:
        return f"pkg:npm/{name.lower()}@{version}"
    if "crates.io" in uri_lower:
        return f"pkg:cargo/{name.lower()}@{version}"
    if "proxy.golang.org" in uri_lower:
        return f"pkg:golang/{normalize_go_name(name)}@{version}"

    return f"pkg:generic/{name.lower()}@{version}"


def recipe_to_purl(
    name: str,
    version: str,
    recipe_class: str = "",
    src_uri: str = "",
    homepage: str = "",
) -> str:
    """Convert a Yocto recipe to its best PURL identifier."""
    name_clean = name.lower().strip()

    # Check recipe class patterns
    for pattern, purl_type in CLASS_TO_PURL_TYPE.items():
        if fnmatch(recipe_class, pattern):
            if purl_type == "pypi":
                return f"pkg:pypi/{normalize_pypi_name(name)}@{version}"
            if purl_type == "npm":
                return f"pkg:npm/{name_clean}@{version}"
            if purl_type == "cargo":
                return f"pkg:cargo/{name_clean}@{version}"
            if purl_type == "golang":
                return f"pkg:golang/{normalize_go_name(name)}@{version}"
            if purl_type is None:
                # Ambiguous class: inspect SRC_URI
                return infer_purl_from_src_uri(src_uri, name, version)

    # Heuristic-based fallback
    if "kernel" in name_clean:
        return f"pkg:generic/linux-kernel@{version}"

    if any(kw in name_clean for kw in ("lib", "library", "-dev", "-dbg")):
        return infer_purl_from_src_uri(src_uri, name, version)

    return f"pkg:generic/{name_clean}@{version}"
