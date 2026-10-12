"""CLI 机器可读摘要（--json-summary）与退出码契约的回归测试。

契约：同一 schema_version 内只新增字段，不改名、不改类型、不删字段。
CI 依赖 stdout 是唯一且完整的 JSON，人类可读日志必须走 stderr。
"""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEMO = REPO / "examples" / "vulnerable-demo"

from audit.cli import SUMMARY_SCHEMA, build_summary, main  # noqa: E402


def _empty_baseline() -> dict:
    return {"enabled": False, "new": [], "existing": [], "fixed": [], "relocated": []}


class SummaryContractTest(unittest.TestCase):
    def test_schema_version_is_stable(self):
        self.assertEqual(SUMMARY_SCHEMA, "jal-summary/1")

    def test_required_fields_present(self):
        payload = build_summary(
            target="/demo", scanners=["builtin"], findings=[], baseline=_empty_baseline(),
            playbook={"progress": {"total": 3, "completed": 1, "partial": 2}},
            reports={"json": "/out/report.json"}, fail_on="none", exit_code=0,
        )
        for key in ("schema_version", "status", "tool", "target", "scanners", "counts",
                    "baseline", "playbook", "reports", "fail_on", "exit_code"):
            self.assertIn(key, payload)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["counts"]["findings"], 0)
        self.assertEqual(payload["baseline"]["enabled"], False)
        self.assertEqual(payload["playbook"]["completed"], 1)

    def test_severity_buckets_cover_all_levels(self):
        payload = build_summary(
            target="/demo", scanners=["builtin"], findings=[], baseline=_empty_baseline(),
            playbook=None, reports={}, fail_on="none", exit_code=0,
        )
        self.assertEqual(
            set(payload["counts"]["by_severity"]),
            {"critical", "high", "medium", "low", "info"},
        )

    def test_playbook_defaults_when_missing(self):
        payload = build_summary(
            target="/demo", scanners=[], findings=[], baseline={},
            playbook=None, reports={}, fail_on="none", exit_code=0,
        )
        self.assertEqual(payload["playbook"], {"total": 0, "completed": 0, "partial": 0})
        self.assertEqual(payload["baseline"]["new"], 0)


class JsonSummaryEndToEndTest(unittest.TestCase):
    def _run(self, extra_args: list[str]) -> tuple[int, str]:
        out = io.StringIO()
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            argv = ["scan", str(DEMO), "-o", str(Path(tmp) / "report"), "--yes",
                    "-s", "builtin", "--json-summary", *extra_args]
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(argv)
        return code, out.getvalue()

    def test_stdout_contains_only_json(self):
        code, stdout = self._run([])
        self.assertEqual(code, 0)
        payload = json.loads(stdout)  # 有任何非 JSON 输出就会在这里失败
        self.assertEqual(payload["schema_version"], SUMMARY_SCHEMA)
        self.assertEqual(payload["status"], "ok")
        self.assertGreater(payload["counts"]["findings"], 0)
        self.assertEqual(payload["exit_code"], 0)

    def test_human_readable_logs_move_to_stderr(self):
        code, stdout = self._run([])
        self.assertEqual(code, 0)
        # 摘要里不能有扫描阶段的人类可读标记漏到 stdout
        self.assertNotIn("[阶段]", stdout)
        self.assertNotIn("[运行]", stdout)

    def test_fail_on_sets_exit_code_one(self):
        code, stdout = self._run(["-f", "high"])
        self.assertEqual(code, 1)
        payload = json.loads(stdout)
        self.assertEqual(payload["exit_code"], 1)
        self.assertEqual(payload["fail_on"], "high")

    def test_error_path_returns_error_summary(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main(["scan", str(REPO / "does-not-exist"), "--yes", "--json-summary"])
        self.assertEqual(code, 2)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["exit_code"], 2)
        self.assertEqual(payload["schema_version"], SUMMARY_SCHEMA)


if __name__ == "__main__":
    unittest.main()
