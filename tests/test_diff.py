"""阶段 C-1：Git 增量审计测试。

全部用例在临时 Git 仓库中运行，不依赖外部仓库状态。
若环境没有 git，整组用例跳过。
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from audit.diff import (
    analyze_incremental,
    build_old_snapshot,
    build_revision_snapshot,
    collect_diff,
    compare_authorization,
    compute_closure,
    is_git_repo,
    load_baseline_details,
    needs_revision_snapshot,
)
from audit.authz import collect_authorization
from audit.findings import Finding, Location

SKIP = shutil.which("git") is None

SECURE_CONTROLLER = """package lab.demo;

import java.nio.file.Files;
import java.nio.file.Paths;

@RestController
@RequestMapping("/report")
public class ReportController {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/export")
    public String export(@RequestParam String file) throws Exception {
        return new String(Files.readAllBytes(Paths.get(file)));
    }
}
"""

WEAKENED_CONTROLLER = """package lab.demo;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Statement;

@RestController
@RequestMapping("/report")
public class ReportController {

    @GetMapping("/export")
    public String export(@RequestParam String file) throws Exception {
        return new String(Files.readAllBytes(Paths.get(file)));
    }

    @GetMapping("/search")
    public String search(@RequestParam String q) throws Exception {
        Statement stmt = null;
        return stmt.executeQuery(q).toString();
    }
}
"""

SERVICE_FILE = """package lab.demo;

import lab.demo.ReportController;

public class ReportService {
    private ReportController controller;
}
"""


def _git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(cwd), *args], capture_output=True, text=True, encoding="utf-8"
    )
    if completed.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} 失败：{completed.stderr}")
    return completed.stdout


@unittest.skipIf(SKIP, "环境未安装 git")
class GitDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="jal-diff-")
        self.root = Path(self.temp.name)
        _git(self.root, "init", "-q")
        _git(self.root, "config", "user.email", "lab@example.com")
        _git(self.root, "config", "user.name", "Java Audit Lab")
        _git(self.root, "config", "commit.gpgsign", "false")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _commit(self, message: str) -> None:
        _git(self.root, "add", "-A")
        _git(self.root, "commit", "-q", "-m", message)

    # ---------- 基础能力 ----------

    def test_repo_detection(self):
        self.assertTrue(is_git_repo(self.root))
        self.assertFalse(is_git_repo(Path(tempfile.gettempdir())))

    def test_working_mode_detects_uncommitted_change(self):
        self._write("src/main/java/lab/demo/ReportController.java", SECURE_CONTROLLER)
        self._commit("v1")
        self._write("src/main/java/lab/demo/ReportController.java", WEAKENED_CONTROLLER)

        context = collect_diff(self.root, "WORKING" if False else None)
        self.assertTrue(context.available)
        self.assertEqual(context.mode, "working")
        self.assertEqual(context.stats["java_files_changed"], 1)
        self.assertGreater(context.stats["lines_changed"], 0)

        # 新增的 /search 端点在第 18 行附近，必须落在变更区间内
        rel = "src/main/java/lab/demo/ReportController.java"
        self.assertTrue(context.hits_change(rel, 18))
        # 未变更的首行不应命中
        self.assertFalse(context.hits_change(rel, 1))

    def test_untracked_file_is_counted_as_added(self):
        self._write("src/main/java/lab/demo/ReportController.java", SECURE_CONTROLLER)
        self._commit("v1")
        self._write("src/main/java/lab/demo/NewController.java", WEAKENED_CONTROLLER)
        context = collect_diff(self.root)
        paths = {item.path for item in context.files if item.status == "added"}
        self.assertIn("src/main/java/lab/demo/NewController.java", paths)

    def test_ref_mode_compares_against_branch(self):
        self._write("src/main/java/lab/demo/ReportController.java", SECURE_CONTROLLER)
        self._commit("v1")
        _git(self.root, "branch", "main")
        self._write("src/main/java/lab/demo/ReportController.java", WEAKENED_CONTROLLER)
        self._commit("v2")

        context = collect_diff(self.root, diff_ref="main")
        self.assertEqual(context.mode, "ref")
        self.assertEqual(context.base, "main")
        self.assertEqual(context.stats["java_files_changed"], 1)

    def test_commit_mode(self):
        self._write("src/main/java/lab/demo/ReportController.java", SECURE_CONTROLLER)
        self._commit("v1")
        self._write("src/main/java/lab/demo/ReportController.java", WEAKENED_CONTROLLER)
        self._commit("v2")

        context = collect_diff(self.root, commit_ref="HEAD")
        self.assertEqual(context.mode, "commit")
        self.assertEqual(context.stats["java_files_changed"], 1)

    def test_revision_snapshot_for_historical_commit(self):
        """分析历史提交时，必须按该提交的状态重建源码，否则会漏报该提交引入的问题。"""
        self._write("src/main/java/lab/demo/ReportController.java", SECURE_CONTROLLER)
        self._commit("v1")
        self._write("src/main/java/lab/demo/ReportController.java", WEAKENED_CONTROLLER)
        self._commit("v2")

        # HEAD 就是被分析的提交，工作树状态一致，不需要快照
        current = collect_diff(self.root, commit_ref="HEAD")
        self.assertFalse(needs_revision_snapshot(current))

        # HEAD~1 是历史提交，工作树早已不是它的状态
        historical = collect_diff(self.root, commit_ref="HEAD~1")
        self.assertTrue(needs_revision_snapshot(historical))

        with tempfile.TemporaryDirectory(prefix="jal-rev-") as tmp:
            snapshot = build_revision_snapshot(self.root, "HEAD~1", Path(tmp) / "rev")
            text = (snapshot / "src/main/java/lab/demo/ReportController.java").read_text(encoding="utf-8")
        self.assertIn("PreAuthorize", text)
        self.assertNotIn("/search", text)

    def test_non_git_repo_falls_back(self):
        with tempfile.TemporaryDirectory(prefix="jal-nogit-") as plain:
            context = collect_diff(Path(plain))
            self.assertFalse(context.available)
            self.assertEqual(context.mode, "none")
            self.assertTrue(any("Git" in note for note in context.notes))

    # ---------- 依赖闭包 ----------

    def test_closure_includes_importer_and_same_package(self):
        self._write("src/main/java/lab/demo/ReportController.java", SECURE_CONTROLLER)
        self._write("src/main/java/lab/demo/ReportService.java", SERVICE_FILE)
        self._write("src/main/java/lab/other/Unrelated.java", "package lab.other;\npublic class Unrelated {}\n")
        self._commit("v1")
        self._write("src/main/java/lab/demo/ReportController.java", WEAKENED_CONTROLLER)

        changed = ["src/main/java/lab/demo/ReportController.java"]
        closure = compute_closure(self.root, changed)
        self.assertIn("src/main/java/lab/demo/ReportService.java", closure)
        self.assertNotIn("src/main/java/lab/other/Unrelated.java", closure)

    def test_changed_only_disables_closure(self):
        self._write("src/main/java/lab/demo/ReportController.java", SECURE_CONTROLLER)
        self._write("src/main/java/lab/demo/ReportService.java", SERVICE_FILE)
        self._commit("v1")
        self._write("src/main/java/lab/demo/ReportController.java", WEAKENED_CONTROLLER)

        context = collect_diff(self.root, closure=False)
        self.assertEqual(context.closure, [])
        self.assertEqual(context.scan_scope(changed_only=True), ["src/main/java/lab/demo/ReportController.java"])

    # ---------- 权限变更对比 ----------

    def test_authorization_weakened_is_detected(self):
        self._write("src/main/java/lab/demo/ReportController.java", SECURE_CONTROLLER)
        self._commit("v1")
        self._write("src/main/java/lab/demo/ReportController.java", WEAKENED_CONTROLLER)

        context = collect_diff(self.root)
        with tempfile.TemporaryDirectory(prefix="jal-old-") as old_dir:
            snapshot = build_old_snapshot(self.root, context, Path(old_dir) / "old")
            self.assertIsNotNone(snapshot)
            old_matrix = collect_authorization(snapshot)
        new_matrix = collect_authorization(self.root)
        changes = compare_authorization(old_matrix, new_matrix)

        weakened = [item for item in changes if item["change"] == "weakened"]
        self.assertTrue(weakened, f"未检测到权限放宽：{changes}")
        export = next(item for item in weakened if "/report/export" in str(item["route"]))
        self.assertEqual(export["old_requirement"], "role")
        self.assertEqual(export["old_roles"], ["ADMIN"])
        self.assertEqual(export["risk"], "high")
        self.assertIn("权限声明被移除", str(export["detail"]))

    def test_new_endpoint_without_authz_is_flagged(self):
        self._write("src/main/java/lab/demo/ReportController.java", SECURE_CONTROLLER)
        self._commit("v1")
        self._write("src/main/java/lab/demo/ReportController.java", WEAKENED_CONTROLLER)

        context = collect_diff(self.root)
        with tempfile.TemporaryDirectory(prefix="jal-old-") as old_dir:
            snapshot = build_old_snapshot(self.root, context, Path(old_dir) / "old")
            old_matrix = collect_authorization(snapshot) if snapshot else None
        new_matrix = collect_authorization(self.root)
        changes = compare_authorization(old_matrix, new_matrix) if old_matrix else []
        added = [item for item in changes if item["change"] == "added"]
        self.assertTrue(any("/report/search" in str(item["route"]) for item in added))

    # ---------- 增量结论 ----------

    def test_analyze_incremental_marks_changed_lines(self):
        self._write("src/main/java/lab/demo/ReportController.java", SECURE_CONTROLLER)
        self._commit("v1")
        self._write("src/main/java/lab/demo/ReportController.java", WEAKENED_CONTROLLER)
        context = collect_diff(self.root)

        rel = "src/main/java/lab/demo/ReportController.java"
        changed_hit = Finding(
            rule_id="JAL-SQL-001", title="SQL 注入", severity="high", confidence="high",
            cwe="CWE-89", scanner="builtin", location=Location(rel, 19, 1),
            evidence="stmt.executeQuery(q)", description="", review_steps=[], remediation="",
            fingerprint="fp-new",
        )
        stable = Finding(
            rule_id="JAL-PATH-001", title="路径穿越", severity="high", confidence="high",
            cwe="CWE-22", scanner="builtin", location=Location(rel, 3, 1),
            evidence="Paths.get(file)", description="", review_steps=[], remediation="",
            fingerprint="fp-old",
        )
        result = analyze_incremental(context, [changed_hit, stable], None, None, [])
        self.assertTrue(result["enabled"])
        paths = {item["path"] + ":" + str(item["line"]) for item in result["new_findings"]}
        self.assertIn(f"{rel}:19", paths)
        self.assertNotIn(f"{rel}:3", paths)

    def test_fixed_but_surviving_is_flagged(self):
        self._write("src/main/java/lab/demo/ReportController.java", SECURE_CONTROLLER)
        self._commit("v1")
        self._write("src/main/java/lab/demo/ReportController.java", WEAKENED_CONTROLLER)
        context = collect_diff(self.root)
        rel = "src/main/java/lab/demo/ReportController.java"

        baseline = {"enabled": True, "new": [], "existing": [], "fixed": ["fp-old"]}
        details = {"fp-old": {"rule_id": "JAL-PATH-001", "path": rel, "line": 15, "severity": "high", "cwe": "CWE-22"}}
        survivor = Finding(
            rule_id="JAL-PATH-001", title="路径穿越", severity="high", confidence="high",
            cwe="CWE-22", scanner="builtin", location=Location(rel, 14, 1),
            evidence="Paths.get(file)", description="", review_steps=[], remediation="",
            fingerprint="fp-new",
        )
        result = analyze_incremental(context, [survivor], baseline, details, [])
        self.assertEqual(len(result["fixed_findings"]), 1)
        self.assertEqual(result["fixed_findings"][0]["status"], "疑似未真正修复")
        self.assertIn("同规则残留", " ".join(str(item) for item in result["review_focus"]))

    def test_baseline_details_loader(self):
        import json
        with tempfile.TemporaryDirectory(prefix="jal-base-") as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(json.dumps({"findings": [
                {"fingerprint": "abc", "rule_id": "R1", "location": {"path": "a.java", "line": 7}, "severity": "high"},
            ]}), encoding="utf-8")
            details = load_baseline_details(path)
        self.assertEqual(details["abc"]["rule_id"], "R1")
        self.assertEqual(details["abc"]["line"], 7)
        self.assertEqual(load_baseline_details(None), {})


if __name__ == "__main__":
    unittest.main()
