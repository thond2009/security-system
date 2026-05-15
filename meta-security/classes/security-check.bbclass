# security-check.bbclass
#
# Yocto integration class for the security management system.
# Hooks into do_image_complete to generate SBOM, kernel config, build manifest,
# and invoke the security-report.py tool.
#
# Inherit this in your image recipe:
#   inherit security-check
#
# Required variables to set in local.conf or distro config:
#   SECURITY_CHECK_API_URL     - Dashboard API URL (default: http://localhost:8000/api/v1)
#   SECURITY_CHECK_API_TOKEN   - CI API token for authentication
#   SECURITY_CHECK_PROJECT_NAME - Product/project name for grouping builds
#
# Optional:
#   SECURITY_CHECK_OSV_BATCH_SIZE    - Packages per OSV batch query (default: 100)
#   SECURITY_CHECK_FAIL_ON_CRITICAL  - If "1", fail the build on critical CVEs
#   SECURITY_CHECK_CFLAG_PACKAGES    - Space-separated list of packages to check CFLAGS for

SECURITY_CHECK_API_URL         ??= "http://localhost:8000/api/v1"
SECURITY_CHECK_API_TOKEN       ??= ""
SECURITY_CHECK_OSV_BATCH_SIZE  ??= "100"
SECURITY_CHECK_FAIL_ON_CRITICAL ??= "0"
SECURITY_CHECK_PROJECT_NAME    ??= "${IMAGE_BASENAME}"
SECURITY_CHECK_CFLAG_PACKAGES  ??= ""

# Directory for security report artifacts
SECURITY_REPORT_DIR = "${TMPDIR}/security-reports/${IMAGE_NAME}"

python do_security_check() {
    import json
    import os
    import subprocess

    report_dir = d.getVar("SECURITY_REPORT_DIR")
    os.makedirs(report_dir, exist_ok=True)

    image_name = d.getVar("IMAGE_NAME")
    bb.note(f"Security check starting for {image_name}")

    # Step 1: Export package manifest
    manifest_src = os.path.join(d.getVar("IMGDEPLOYDIR"), f"{image_name}.manifest")
    packages_json = os.path.join(report_dir, "packages.json")
    export_script = os.path.join(d.getVar("THISDIR"), "tools", "export_manifest.py")

    if os.path.isfile(manifest_src):
        cmd = [
            d.getVar("PYTHON"), export_script,
            "--image-manifest", manifest_src,
            "--output", packages_json,
        ]
        buildhistory_dir = os.path.join(d.getVar("TMPDIR"), "buildhistory")
        if os.path.isdir(buildhistory_dir):
            cmd.extend(["--buildhistory-dir", buildhistory_dir])
        subprocess.run(cmd, check=True)
        bb.note(f"Package manifest exported to {packages_json}")
    else:
        bb.warn(f"Image manifest not found: {manifest_src}")
        # Create minimal packages.json from package list
        packages = []
        pkgdata_dir = d.getVar("PKGDATA_DIR")
        if pkgdata_dir and os.path.isdir(pkgdata_dir):
            for entry in os.listdir(pkgdata_dir):
                if os.path.isdir(os.path.join(pkgdata_dir, entry)):
                    pv_file = os.path.join(pkgdata_dir, entry, "PV")
                    pe_file = os.path.join(pkgdata_dir, entry, "PE")
                    version = "unknown"
                    if os.path.isfile(pv_file):
                        with open(pv_file) as f:
                            version = f.read().strip()
                            epoch = ""
                            if os.path.isfile(pe_file):
                                with open(pe_file) as f:
                                    epoch = f.read().strip()
                            if epoch and epoch != "0":
                                version = f"{epoch}:{version}"
                    packages.append({"name": entry, "version": version, "arch": "", "recipe_class": "", "src_uri": "", "homepage": "", "license": "", "layer": ""})
        with open(packages_json, "w") as f:
            json.dump(packages, f, indent=2)

    # Step 2: Copy kernel config if available
    kernel_config = os.path.join(report_dir, "kernel.config")
    deploy_dir = d.getVar("DEPLOY_DIR_IMAGE")
    kernel_artifact = d.getVar("KERNEL_ARTIFACT_NAME")
    if kernel_artifact:
        config_src = os.path.join(deploy_dir, f"config-{kernel_artifact}")
        if os.path.isfile(config_src):
            with open(config_src, "rb") as src:
                with open(kernel_config, "wb") as dst:
                    dst.write(src.read())
            bb.note("Kernel config captured")

    # Step 3: Export build configuration
    build_config = {
        "image_name": image_name,
        "distro": d.getVar("DISTRO"),
        "distro_version": d.getVar("DISTRO_VERSION"),
        "target_arch": d.getVar("TARGET_ARCH"),
        "machine": d.getVar("MACHINE"),
        "build_hostname": d.getVar("BUILD_HOSTNAME"),
        "yocto_version": d.getVar("YOCTO_VERSION") or "",
        "distro_features": d.getVar("DISTRO_FEATURES") or "",
        "image_features": d.getVar("IMAGE_FEATURES") or "",
        "project_name": d.getVar("SECURITY_CHECK_PROJECT_NAME"),
    }
    build_config_path = os.path.join(report_dir, "build-config.json")
    with open(build_config_path, "w") as f:
        json.dump(build_config, f, indent=2)

    # Step 4: Run security-report.py
    security_report_script = os.path.join(d.getVar("THISDIR"), "tools", "security_report.py")
    cmd = [
        d.getVar("PYTHON"), security_report_script,
        "--packages", packages_json,
        "--build-config", build_config_path,
        "--output-dir", report_dir,
        "--api-url", d.getVar("SECURITY_CHECK_API_URL"),
        "--api-token", d.getVar("SECURITY_CHECK_API_TOKEN"),
        "--osv-batch-size", d.getVar("SECURITY_CHECK_OSV_BATCH_SIZE"),
    ]

    if os.path.isfile(kernel_config):
        cmd.extend(["--kernel-config", kernel_config])

    rootfs_tar = os.path.join(d.getVar("IMGDEPLOYDIR"), f"{image_name}-{d.getVar('MACHINE')}.rootfs.tar.gz")
    if os.path.isfile(rootfs_tar):
        cmd.extend(["--rootfs", rootfs_tar])

    bb.note(f"Running security-report.py...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.stdout:
        bb.plain(result.stdout)
    if result.stderr:
        for line in result.stderr.strip().split("\n"):
            bb.plain(f"[security-check] {line}")

    if result.returncode == 2:
        fail_on_critical = d.getVar("SECURITY_CHECK_FAIL_ON_CRITICAL")
        if fail_on_critical == "1":
            bb.fatal(f"Security check FAILED: critical CVEs found in {image_name}")
        else:
            bb.warn(f"Security check: critical CVEs found in {image_name} (not failing build)")
    elif result.returncode != 0:
        bb.warn(f"Security check completed with warnings (exit code {result.returncode})")
    else:
        bb.note(f"Security check passed for {image_name}")
}

addtask do_security_check after do_image_complete before do_build
do_security_check[doc] = "Run post-build security vulnerability and hardening analysis"
