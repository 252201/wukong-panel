#!/usr/bin/env python3
"""Select PR checks from the complete Git diff; unknown inputs expand coverage."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess

SCOPES = ("frontend", "backend", "installers", "security")
VERSION_LINE = re.compile(r"^(VERSION[ \t]+\?=[ \t]+)\d+\.\d+\.\d+([ \t]*)$", re.M)
SECURITY_PREFIXES = (
    "internal/hostsecurity/", "internal/agent/", "internal/model/",
    "internal/config/", "internal/store/", "internal/security/", "internal/web/", "cmd/wukong-panel/",
)


def version_only(path, before, after):
    if before is None or after is None:
        return False
    if path == "Makefile":
        if len(VERSION_LINE.findall(before)) != 1 or len(VERSION_LINE.findall(after)) != 1:
            return False
        return VERSION_LINE.sub(r"\1<version>\2", before) == VERSION_LINE.sub(r"\1<version>\2", after)
    if path not in ("web/package.json", "web/package-lock.json"):
        return False
    try:
        old, new = json.loads(before), json.loads(after)
        for value in (old, new):
            if not re.fullmatch(r"\d+\.\d+\.\d+", value["version"]):
                return False
            del value["version"]
            if path.endswith("package-lock.json"):
                root = value["packages"][""]
                if not re.fullmatch(r"\d+\.\d+\.\d+", root["version"]):
                    return False
                del root["version"]
        return old == new
    except (ValueError, KeyError, TypeError):
        return False


def classify(paths, read_blob=lambda revision, path: None):
    selected = {scope: False for scope in SCOPES}
    for path in paths:
        # Generated web resources are UI changes, not host-security Go changes.
        if path in ("Makefile", "web/package.json", "web/package-lock.json"):
            if version_only(path, read_blob("base", path), read_blob("head", path)):
                continue
        if path.startswith(("web/", "internal/web/dist/")):
            selected["frontend"] = True
        elif path.startswith((".github/", "scripts/ci_")) or path in ("Makefile", "go.mod", "go.sum", "scripts/build-release.sh"):
            return dict.fromkeys(SCOPES, True)
        elif path.startswith("scripts/security/") or path == "scripts/test-host-security-native.sh":
            selected["backend"] = selected["security"] = True
        elif path in ("install.sh", "uninstall.sh", "bootstrap.sh", "probe-install.sh") or path.startswith(("compat/", "scripts/test-install", "scripts/test-singbox")):
            selected["installers"] = True
        elif path.startswith(SECURITY_PREFIXES):
            selected["backend"] = selected["security"] = True
        elif path.startswith(("internal/monitor/", "internal/probe/", "internal/netcheck/", "internal/hostlocation/", "internal/singboxconfig/", "cmd/wukong-probe/")):
            selected["backend"] = True
        elif path == "README.md" or path.startswith(("docs/", "assets/")) or path.endswith(".md"):
            continue
        else:
            # A new script, toolchain file or unclassified build input must not
            # silently receive the documentation-only fast path.
            return dict.fromkeys(SCOPES, True)
    return selected if paths else dict.fromkeys(SCOPES, True)


def validate_versions(root):
    make = (root / "Makefile").read_text()
    matches = re.findall(r"^VERSION[ \t]+\?=[ \t]+(\d+\.\d+\.\d+)[ \t]*$", make, re.M)
    if len(matches) != 1:
        raise ValueError("Makefile must contain exactly one literal VERSION")
    version = matches[0]
    package = json.loads((root / "web/package.json").read_text())
    lock = json.loads((root / "web/package-lock.json").read_text())
    if any(v != version for v in (package["version"], lock["version"], lock["packages"][""]["version"])):
        raise ValueError("Makefile, package.json and both lockfile versions disagree")
    readme = (root / "README.md").read_text()
    if f"version-v{version}-" not in readme or f"--version v{version}" not in readme:
        raise ValueError("README version badge or installation example disagrees")


def check_jobs(needs):
    if needs["changes"]["result"] != "success":
        raise ValueError("Change detection failed or was cancelled")
    outputs = needs["changes"]["outputs"]
    expected = {
        "frontend": "frontend", "backend": "backend",
        "host-security-matrix": "security",
        "installer-regressions": "installers",
    }
    for job, scope in expected.items():
        value = outputs[scope]
        if value not in ("true", "false"):
            raise ValueError(f"Missing or invalid scope: {scope}")
        wanted = "success" if value == "true" else "skipped"
        if needs[job]["result"] != wanted:
            raise ValueError(f"{job}: expected {wanted}, got {needs[job]['result']}")
    # Preserve existing required matrix check names; no Docker is started when
    # installers are out of scope, but each compatibility job still completes.
    if needs["installer-matrix"]["result"] != "success":
        raise ValueError("Installer checks failed or were cancelled")


def git(*args):
    return subprocess.check_output(("git", *args), stderr=subprocess.PIPE)


def changed_scope(base, head):
    if not all(re.fullmatch(r"[0-9a-fA-F]{40}", rev) for rev in (base, head)):
        raise ValueError("Expected full base and head commit SHAs")
    base = git("merge-base", base, head).decode().strip()
    # No API pagination/300-file truncation, and both sides of renames count.
    paths = [p.decode("utf-8", "surrogateescape") for p in git("diff", "--no-renames", "--name-only", "-z", base, head, "--").split(b"\0") if p]

    def read_blob(revision, path):
        try:
            return git("show", f"{base if revision == 'base' else head}:{path}").decode()
        except (subprocess.CalledProcessError, UnicodeDecodeError):
            return None

    return paths, classify(paths, read_blob)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--check-jobs", action="store_true")
    args = parser.parse_args()
    if args.check_jobs:
        check_jobs(json.loads(os.environ["CI_NEEDS"]))
        print("All checks selected for this PR passed.")
        return
    validate_versions(Path.cwd())
    paths, selected = changed_scope(args.base, args.head)
    print(json.dumps({"changed_files": len(paths), "checks": selected}))
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            for key, value in selected.items():
                output.write(f"{key}={str(value).lower()}\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(f"## PR verification scope\n\nChanged files: {len(paths)}\n\n")
            for key, value in selected.items():
                summary.write(f"- {key}: {'run' if value else 'not affected'}\n")


if __name__ == "__main__":
    main()
