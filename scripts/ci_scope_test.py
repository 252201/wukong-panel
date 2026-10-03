import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from ci_scope import SCOPES, changed_scope, check_jobs, classify, validate_versions, version_only


class ScopeTests(unittest.TestCase):
    def assertScopes(self, paths, *expected):
        actual = classify(paths)
        self.assertEqual({name for name, enabled in actual.items() if enabled}, set(expected))

    def test_frontend_source_and_generated_assets_only(self):
        self.assertScopes(["web/src/App.vue", "internal/web/dist/assets/new.js", "internal/web/dist/index.html"], "frontend")

    def test_frontend_dependencies_require_frontend(self):
        self.assertScopes(["web/package-lock.json"], "frontend")

    def test_monitor_and_probe_do_not_trigger_security(self):
        for path in ("internal/monitor/process_service.go", "internal/probe/linux.go", "internal/netcheck/check.go", "cmd/wukong-probe/main.go"):
            with self.subTest(path=path):
                self.assertScopes([path], "backend")

    def test_security_and_shared_dependencies_trigger_native_checks(self):
        for path in ("internal/hostsecurity/firewall.go", "internal/model/model.go", "internal/config/config.go", "internal/security/auth.go", "internal/agent/manager.go", "internal/store/store.go", "internal/web/server.go", "cmd/wukong-panel/main.go", "scripts/security/setup.sh", "scripts/test-host-security-native.sh"):
            with self.subTest(path=path):
                self.assertScopes([path], "backend", "security")

    def test_installer_source_and_fixtures(self):
        for path in ("install.sh", "bootstrap.sh", "probe-install.sh", "uninstall.sh", "compat/deploy-hy2.sh", "scripts/test-install-hardening.sh", "scripts/test-singbox-lifecycle.sh"):
            with self.subTest(path=path):
                self.assertScopes([path], "installers")

    def test_docs_and_posters_need_no_business_tests(self):
        self.assertScopes(["README.md", "docs/host-security.md", "assets/poster.jpg"])

    def test_unknown_inputs_toolchain_and_ci_expand_to_all(self):
        for path in ("go.mod", "go.sum", "Makefile", ".github/workflows/ci.yml", "scripts/ci_scope.py", "scripts/ci_scope_test.py", "scripts/build-release.sh", ".gitignore", "new-build-tool", "internal/newshared/helper.go"):
            with self.subTest(path=path):
                self.assertScopes([path], *SCOPES)
        self.assertScopes([], *SCOPES)

    def test_combined_scope_unions_checks(self):
        self.assertScopes(["web/src/SecurityPanel.vue", "install.sh", "internal/monitor/monitor.go"], "frontend", "backend", "installers")

    def test_only_root_versions_are_ignored(self):
        package = {"version": "1.7.5", "dependencies": {"vue": "3.5.39"}}
        lock = {**package, "packages": {"": copy.deepcopy(package), "node_modules/vue": {"version": "3.5.39"}}}
        for path, old in (("web/package.json", package), ("web/package-lock.json", lock)):
            new = copy.deepcopy(old)
            new["version"] = "1.7.6"
            if path.endswith("lock.json"):
                new["packages"][""]["version"] = "1.7.6"
            before, after = json.dumps(old), json.dumps(new)
            self.assertTrue(version_only(path, before, after))
            self.assertEqual(classify([path], lambda revision, _: before if revision == "base" else after), dict.fromkeys(SCOPES, False))
            new["dependencies"]["vue"] = "4.0.0"
            self.assertFalse(version_only(path, before, json.dumps(new)))
        new = copy.deepcopy(lock)
        new["packages"]["node_modules/vue"]["version"] = "4.0.0"
        self.assertFalse(version_only("web/package-lock.json", json.dumps(lock), json.dumps(new)))

    def test_make_version_does_not_hide_other_build_changes(self):
        before = "VERSION ?= 1.7.5\nbuild:\n\tgo build ./cmd/wukong-panel\n"
        after = before.replace("1.7.5", "1.7.6")
        self.assertTrue(version_only("Makefile", before, after))
        self.assertFalse(version_only("Makefile", before, after.replace("go build", "go build -race")))
        self.assertFalse(version_only("Makefile", before, "VERSION ?= $(shell command)\n"))
        self.assertFalse(version_only("Makefile", None, after))
        self.assertFalse(version_only("web/package.json", "{}", "invalid"))


def needs_fixture(selected):
    return {
        "changes": {"result": "success", "outputs": {scope: str(scope in selected).lower() for scope in SCOPES}},
        "frontend": {"result": "success" if "frontend" in selected else "skipped"},
        "backend": {"result": "success" if "backend" in selected else "skipped"},
        "installer-regressions": {"result": "success" if "installers" in selected else "skipped"},
        "host-security-matrix": {"result": "success" if "security" in selected else "skipped"},
        "installer-matrix": {"result": "success"},
    }


class GateTests(unittest.TestCase):
    def test_valid_skips_and_full_success(self):
        for selected in ((), ("frontend",), SCOPES):
            check_jobs(needs_fixture(selected))

    def test_failures_cancellations_and_unexpected_skips_block_gate(self):
        for job in needs_fixture(SCOPES):
            for result in ("failure", "cancelled", "skipped"):
                with self.subTest(job=job, result=result):
                    needs = needs_fixture(SCOPES)
                    needs[job]["result"] = result
                    with self.assertRaises(ValueError):
                        check_jobs(needs)

    def test_missing_or_invalid_scope_blocks_gate(self):
        for scope in SCOPES:
            needs = needs_fixture(())
            needs["changes"]["outputs"][scope] = ""
            with self.assertRaises(ValueError):
                check_jobs(needs)

    def test_unselected_job_failure_is_not_hidden(self):
        needs = needs_fixture(())
        needs["backend"]["result"] = "failure"
        with self.assertRaises(ValueError):
            check_jobs(needs)


class GitDiffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.previous = Path.cwd()
        os.chdir(self.tmp.name)
        self.addCleanup(self.restore)
        self.git("init", "-q")
        self.git("config", "user.name", "CI test")
        self.git("config", "user.email", "ci@example.invalid")
        self.write("README.md", "initial")
        self.commit()
        self.base = self.git("rev-parse", "HEAD")

    def restore(self):
        os.chdir(self.previous)
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.check_output(("git", *args), stderr=subprocess.PIPE).decode().strip()

    def write(self, path, content="fixture"):
        file = Path(path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")

    def test_large_diff_does_not_omit_security_file(self):
        for index in range(350):
            self.write(f"docs/{index}.md")
        self.write("internal/hostsecurity/firewall.go")
        self.commit()
        paths, selected = changed_scope(self.base, self.git("rev-parse", "HEAD"))
        self.assertEqual(len(paths), 351)
        self.assertTrue(selected["security"])

    def test_rename_out_of_security_and_deletion_still_trigger_it(self):
        self.write("internal/hostsecurity/old.go")
        self.commit()
        base = self.git("rev-parse", "HEAD")
        self.git("mv", "internal/hostsecurity/old.go", "README2.md")
        self.commit()
        paths, selected = changed_scope(base, self.git("rev-parse", "HEAD"))
        self.assertIn("internal/hostsecurity/old.go", paths)
        self.assertTrue(selected["security"])

    def test_filenames_are_data_and_shas_cannot_be_options(self):
        self.write("web/src/$(touch injected)\nname.vue")
        self.commit()
        paths, selected = changed_scope(self.base, self.git("rev-parse", "HEAD"))
        self.assertEqual(len(paths), 1)
        self.assertTrue(selected["frontend"])
        self.assertFalse(Path("injected").exists())
        with self.assertRaises(ValueError):
            changed_scope("--output=unsafe", self.base)

    def test_missing_commit_does_not_silently_skip(self):
        with self.assertRaises(subprocess.CalledProcessError):
            changed_scope("a" * 40, self.base)

    def test_version_comparison_uses_merge_base(self):
        self.write("Makefile", "VERSION ?= 1.7.5\nbuild:\n\tgo build\n")
        self.commit()
        fork = self.git("rev-parse", "HEAD")
        self.write("Makefile", "VERSION ?= 1.7.5\nbuild:\n\tgo build -race\n")
        self.commit()
        base = self.git("rev-parse", "HEAD")
        self.git("checkout", "-q", "--detach", fork)
        self.write("Makefile", "VERSION ?= 1.7.6\nbuild:\n\tgo build\n")
        self.commit()
        _, selected = changed_scope(base, self.git("rev-parse", "HEAD"))
        self.assertFalse(any(selected.values()))

    def test_version_validation_rejects_partial_bumps(self):
        self.write("Makefile", "VERSION ?= 1.7.6\n")
        self.write("web/package.json", '{"version":"1.7.6"}')
        self.write("web/package-lock.json", '{"version":"1.7.6","packages":{"":{"version":"1.7.5"}}}')
        self.write("README.md", "version-v1.7.6-color --version v1.7.6")
        with self.assertRaises(ValueError):
            validate_versions(Path.cwd())
        self.write("web/package-lock.json", '{"version":"1.7.6","packages":{"":{"version":"1.7.6"}}}')
        validate_versions(Path.cwd())
        self.write("README.md", "version-v1.7.5-color --version v1.7.5")
        with self.assertRaises(ValueError):
            validate_versions(Path.cwd())


if __name__ == "__main__":
    unittest.main()
