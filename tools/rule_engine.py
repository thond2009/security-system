"""
Hardening rule evaluation engine.

Loads rules from YAML files and evaluates them against build artifacts:
kernel config, compiler flags, distro features, and rootfs contents.
"""
import logging
import os
import re
import tarfile
from dataclasses import dataclass
from typing import Any, Callable, Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class BuildContext:
    kernel_config: dict[str, str]       # CONFIG_KEY -> value
    distro_features: list[str]
    image_features: list[str]
    cflags: dict[str, str]             # package -> CFLAGS
    rootfs_path: Optional[str]         # path to rootfs tar.gz

    services: list[str] = None         # populated from rootfs
    config_files: dict[str, str] = None # populated from rootfs
    file_permissions: dict[str, dict] = None  # populated from rootfs

    def __post_init__(self):
        if self.services is None:
            self.services = []
        if self.config_files is None:
            self.config_files = {}
        if self.file_permissions is None:
            self.file_permissions = {}


class RuleResult:
    def __init__(self, rule_id: str, status: str, message: str = "", evidence: dict = None):
        self.rule_id = rule_id
        self.status = status  # PASS, FAIL, ERROR, SKIPPED
        self.message = message
        self.evidence = evidence or {}


class RuleEngine:
    def __init__(self, build_context: BuildContext):
        self.ctx = build_context
        self.evaluators: dict[str, Callable] = {
            "kernel_config_not_set": self._eval_kernel_config_not_set,
            "kernel_config_is_set": self._eval_kernel_config_is_set,
            "kernel_config_equals": self._eval_kernel_config_equals,
            "cflag_contains": self._eval_cflag_contains,
            "distro_features_contain": self._eval_distro_features_contain,
            "service_list_match": self._eval_service_list_match,
            "file_content_check": self._eval_file_content_check,
            "file_permission_check": self._eval_file_permission_check,
            "pn_blacklist_check": self._eval_pn_blacklist_check,
        }

    def evaluate(self, rules: list[dict]) -> list[RuleResult]:
        results = []
        for rule in rules:
            eval_type = rule.get("eval_type", "")
            evaluator = self.evaluators.get(eval_type)
            if not evaluator:
                results.append(RuleResult(
                    rule["id"], "ERROR",
                    f"No evaluator for eval_type '{eval_type}'"
                ))
                continue
            try:
                result = evaluator(rule.get("params", {}))
                result.rule_id = rule["id"]
                results.append(result)
            except Exception as e:
                logger.exception("Error evaluating rule %s", rule.get("id"))
                results.append(RuleResult(
                    rule["id"], "ERROR", str(e)
                ))
        return results

    # ---- Kernel config evaluators ----

    def _eval_kernel_config_not_set(self, params: dict) -> RuleResult:
        config_keys = params.get("config_keys", [])
        failures = []
        for key in config_keys:
            val = self.ctx.kernel_config.get(key, "is not set")
            if val.strip() != "is not set":
                failures.append(f"{key}=y or {key}=m")
        if failures:
            return RuleResult("", "FAIL", f"Enabled configs: {', '.join(failures)}",
                              {"enabled": failures})
        return RuleResult("", "PASS", "All specified configs are disabled")

    def _eval_kernel_config_is_set(self, params: dict) -> RuleResult:
        config_key = params.get("config_key", "")
        expected = params.get("expected_value", "y")
        actual = self.ctx.kernel_config.get(config_key, "is not set")
        if expected == "is not set":
            return RuleResult("", "PASS" if actual.strip() == "is not set" else "FAIL",
                              f"{config_key}={actual}")
        if actual.strip() == "is not set":
            return RuleResult("", "FAIL", f"{config_key} is not set",
                              {"expected": expected, "actual": "is not set"})
        if actual.strip() == expected.strip():
            return RuleResult("", "PASS", f"{config_key}={actual}")
        return RuleResult("", "FAIL", f"{config_key}={actual}, expected={expected}",
                          {"expected": expected, "actual": actual})

    def _eval_kernel_config_equals(self, params: dict) -> RuleResult:
        return self._eval_kernel_config_is_set(params)

    # ---- Compiler flag evaluators ----

    def _eval_cflag_contains(self, params: dict) -> RuleResult:
        flag = params.get("flag", "")
        scope = params.get("scope", "all_packages")
        min_packages = params.get("min_packages", 0)

        matching = []
        missing = []
        packages = list(self.ctx.cflags.keys()) if scope == "all_packages" else [scope]

        for pkg in packages:
            cflags = self.ctx.cflags.get(pkg, "")
            if flag in cflags:
                matching.append(pkg)
            else:
                missing.append(pkg)

        if len(matching) >= len(packages):
            return RuleResult("", "PASS", f"Flag '{flag}' found in all {len(matching)} packages")
        if len(matching) >= min_packages:
            return RuleResult("", "PASS",
                              f"Flag '{flag}' found in {len(matching)}/{len(packages)} packages",
                              {"matching": matching, "missing": missing})
        return RuleResult("", "FAIL",
                          f"Flag '{flag}' found in only {len(matching)}/{len(packages)} packages",
                          {"matching": matching, "missing": missing})

    # ---- Distro features ----

    def _eval_distro_features_contain(self, params: dict) -> RuleResult:
        required = set(params.get("required_features", []))
        actual = set(self.ctx.distro_features)
        missing = required - actual
        if not missing:
            return RuleResult("", "PASS", f"All {len(required)} required features enabled")
        return RuleResult("", "FAIL",
                          f"Missing DISTRO_FEATURES: {', '.join(sorted(missing))}",
                          {"missing": sorted(missing)})

    # ---- Runtime checks (rootfs inspection) ----

    def _eval_service_list_match(self, params: dict) -> RuleResult:
        allowed = set(params.get("allowed_services", []))
        allow_extra = params.get("allow_extra", True)
        actual = set(self.ctx.services)

        extra = actual - allowed
        if extra and not allow_extra:
            return RuleResult("", "FAIL",
                              f"Unexpected services: {', '.join(sorted(extra))}",
                              {"unexpected": sorted(extra)})
        return RuleResult("", "PASS",
                          f"All services within allowed set ({len(actual)} services)")

    def _eval_file_content_check(self, params: dict) -> RuleResult:
        path = params.get("path", "")
        must_contain_regex = params.get("must_contain_regex")
        must_not_contain_regex = params.get("must_not_contain_regex")
        min_matches = params.get("min_matches", 1)

        content = self.ctx.config_files.get(path, "")
        if not content:
            return RuleResult("", "FAIL", f"File not found in rootfs: {path}")

        if must_contain_regex:
            matches = re.findall(must_contain_regex, content, re.MULTILINE)
            if len(matches) < min_matches:
                return RuleResult("", "FAIL",
                                  f"{path}: expected {min_matches} matches for '{must_contain_regex}', got {len(matches)}")

        if must_not_contain_regex:
            if re.search(must_not_contain_regex, content, re.MULTILINE):
                return RuleResult("", "FAIL",
                                  f"{path}: found disallowed pattern '{must_not_contain_regex}'")

        return RuleResult("", "PASS", f"File content check passed for {path}")

    def _eval_file_permission_check(self, params: dict) -> RuleResult:
        path = params.get("path", "")
        max_mode = params.get("max_mode", 0o644)
        expected_uid = params.get("expected_uid", 0)

        perms = self.ctx.file_permissions.get(path)
        if not perms:
            return RuleResult("", "FAIL", f"File not found in rootfs: {path}")

        failures = []
        if (perms["mode"] & 0o777) > max_mode:
            failures.append(f"permissions too open: {oct(perms['mode'])} > {oct(max_mode)}")
        if expected_uid is not None and perms["uid"] != expected_uid:
            failures.append(f"wrong owner uid: {perms['uid']} != {expected_uid}")

        if failures:
            return RuleResult("", "FAIL", "; ".join(failures), {"perms": perms})
        return RuleResult("", "PASS", f"Permissions OK for {path}")

    # ---- Build config ----

    def _eval_pn_blacklist_check(self, params: dict) -> RuleResult:
        blacklisted = set(params.get("blacklisted", []))
        # This requires a build-time PNBLACKLIST, which is part of build config
        # For now, check against a passed-in list
        pnblacklist_raw = params.get("pnblacklist", "")
        actual = set(filter(None, pnblacklist_raw.split()))

        if not actual.intersection(blacklisted):
            return RuleResult("", "PASS", "No blacklisted packages in build")
        return RuleResult("", "FAIL",
                          f"Blacklisted packages found: {', '.join(actual & blacklisted)}")


def load_rules_from_yaml(path: str) -> list[dict]:
    """Load hardening rules from a YAML file."""
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("rules", []) if isinstance(data, dict) else data


def load_rules_from_dir(directory: str) -> list[dict]:
    """Load all hardening rules from YAML files in a directory tree."""
    rules = []
    for root, _, files in os.walk(directory):
        for fname in sorted(files):
            if fname.endswith((".yaml", ".yml")):
                path = os.path.join(root, fname)
                rules.extend(load_rules_from_yaml(path))
    return rules


def inspect_rootfs(rootfs_tgz: str, build_context: BuildContext) -> BuildContext:
    """Extract metadata from rootfs archive without full extraction."""
    services = []
    config_files = {}
    file_permissions = {}

    try:
        with tarfile.open(rootfs_tgz, "r:gz") as tar:
            for member in tar:
                name = member.name.lstrip("./")

                # Systemd services
                if "etc/systemd/system/" in name and not name.endswith("/"):
                    svc = os.path.basename(name)
                    if svc.endswith(".service"):
                        services.append(svc)

                # Config files we care about
                interesting_configs = [
                    "etc/chrony/chrony.conf", "etc/ntp.conf",
                    "etc/ssh/sshd_config", "etc/syslog.conf",
                    "etc/login.defs", "etc/pam.d/",
                    "etc/sysctl.conf", "etc/sysctl.d/",
                ]
                for cfg_path in interesting_configs:
                    if name.startswith(cfg_path) and member.isfile():
                        f = tar.extractfile(member)
                        if f:
                            config_files[name] = f.read().decode("utf-8", errors="replace")

                # Track permissions
                if member.isfile():
                    file_permissions[name] = {
                        "mode": member.mode,
                        "uid": member.uid,
                        "gid": member.gid,
                    }

    except (tarfile.TarError, OSError) as e:
        logger.warning("Failed to inspect rootfs: %s", e)

    build_context.services = services
    build_context.config_files = config_files
    build_context.file_permissions = file_permissions
    return build_context


def parse_kernel_config(path: str) -> dict[str, str]:
    """Parse a Linux kernel .config file into a dict."""
    config = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                # Handle "# CONFIG_FOO is not set"
                not_set = re.match(r"^#\s+(CONFIG_\w+)\s+is not set", line)
                if not_set:
                    config[not_set.group(1)] = "is not set"
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                config[key.strip()] = val.strip().strip('"')
    return config
