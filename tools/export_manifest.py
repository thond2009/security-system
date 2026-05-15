#!/usr/bin/env python3
"""
Export build manifest from Yocto build artifacts.

Reads the image manifest (list of installed packages) and optionally the
buildhistory data to enrich each package with recipe class and source URI info.

Usage:
  python export_manifest.py --image-manifest <path> --output packages.json
  python export_manifest.py --image-manifest <path> --buildhistory-dir <path> --output packages.json
"""
import argparse
import json
import logging
import re

logger = logging.getLogger(__name__)


def parse_image_manifest(path: str) -> list[dict]:
    """
    Parse Yocto image manifest.
    Format: <package_name> <arch> <version>
    One package per line.
    """
    packages = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 3:
                packages.append({
                    "name": parts[0],
                    "arch": parts[1],
                    "version": parts[2],
                    "recipe_class": "",
                    "src_uri": "",
                    "homepage": "",
                    "license": "",
                    "layer": "",
                })
            elif len(parts) >= 1:
                packages.append({
                    "name": parts[0],
                    "arch": "",
                    "version": "",
                    "recipe_class": "",
                    "src_uri": "",
                    "homepage": "",
                    "license": "",
                    "layer": "",
                })
    return packages


def enrich_from_buildhistory(packages: list[dict], buildhistory_dir: str):
    """
    Enrich package info from Yocto buildhistory data.

    Buildhistory stores per-package metadata under:
      buildhistory/packages/<arch>/<recipe>/<package>/
    """
    import os

    name_to_pkg = {p["name"]: p for p in packages}
    packages_root = f"{buildhistory_dir}/packages"

    if not os.path.isdir(packages_root):
        logger.warning("Buildhistory packages dir not found: %s", packages_root)
        return

    for arch in os.listdir(packages_root):
        arch_dir = os.path.join(packages_root, arch)
        if not os.path.isdir(arch_dir):
            continue
        for recipe in os.listdir(arch_dir):
            recipe_dir = os.path.join(arch_dir, recipe)
            if not os.path.isdir(recipe_dir):
                continue
            # Look for the main package (recipe name matches package name)
            for pkg_name in os.listdir(recipe_dir):
                base_pkg = pkg_name
                # Strip -dev, -dbg, -doc, -locale suffixes to find the recipe
                for suffix in ("-dev", "-dbg", "-doc", "-locale", "-staticdev", "-ptest"):
                    if pkg_name.endswith(suffix):
                        base_pkg = pkg_name[: -len(suffix)]
                        break

                if base_pkg in name_to_pkg:
                    pkg = name_to_pkg[base_pkg]
                    pkg["recipe_name"] = recipe
                    # Read license
                    license_file = os.path.join(recipe_dir, pkg_name, "license")
                    if os.path.isfile(license_file):
                        with open(license_file) as f:
                            pkg["license"] = f.read().strip()
                    # Read latest version
                    ver_file = os.path.join(recipe_dir, pkg_name, "latest_version")
                    if os.path.isfile(ver_file):
                        with open(ver_file) as f:
                            pkg["latest_version"] = f.read().strip()


def main():
    parser = argparse.ArgumentParser(description="Export Yocto package manifest")
    parser.add_argument("--image-manifest", required=True, help="Path to image .manifest file")
    parser.add_argument("--buildhistory-dir", help="Path to buildhistory directory")
    parser.add_argument("--output", required=True, help="Output JSON path")
    args = parser.parse_args()

    packages = parse_image_manifest(args.image_manifest)
    logger.info("Parsed %d packages from manifest", len(packages))

    if args.buildhistory_dir:
        enrich_from_buildhistory(packages, args.buildhistory_dir)
        logger.info("Enriched packages from buildhistory")

    with open(args.output, "w") as f:
        json.dump(packages, f, indent=2)

    logger.info("Wrote %d packages to %s", len(packages), args.output)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    main()
