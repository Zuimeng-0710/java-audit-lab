# -*- coding: utf-8 -*-
"""Issue #6 回归测试：基线身份在无关行插入时保持稳定。

验收标准：
1. 在命中行上方插入空行或注释行，基线身份不变。
2. 修改命中表达式本身，产生新身份。
3. 同一文件里重复的相同命中仍可区分。
另覆盖：基线二次对齐（旧指纹方案 / 行号漂移不产生 new+fixed 噪声）。
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from audit.baseline import compare_with_baseline
from audit.findings import Finding, Location
from audit.runners.builtin import BuiltinRunner
from audit.runners.secrets import _scan_config
from audit.runners.semgrep import SemgrepRunner
from audit.taint import run_taint


JAVA_CODE = '''package demo;

public class Demo {
    void run(String input) throws Exception {
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM t WHERE x = '" + input + "'");
    }
}
'''


class BaselineIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def _write_java(self, text: str) -> None:
        java = self.root / "src" / "main" / "java" / "Demo.java"
        java.parent.mkdir(parents=True, exist_ok=True)
        java.write_text(text, encoding="utf-8", newline="\n")

    def _scan_java(self) -> list[Finding]:
        findings = BuiltinRunner().run(self.root, self.root).findings
        self.assertTrue(findings, "样例应至少命中一条内置规则")
        return findings

    def test_blank_and_comment_insertion_preserves_identity(self):
        self._write_java(JAVA_CODE)
        before = self._scan_java()[0].fingerprint

        lines = JAVA_CODE.splitlines(keepends=True)
        padded = lines[:5] + ["\n", "\n", "    // 无关注释行\n", *lines[5:]]
        self._write_java("".join(padded))
        after = self._scan_java()[0].fingerprint

        self.assertEqual(before, after)

    def test_expression_change_produces_new_identity(self):
        self._write_java(JAVA_CODE)
        before = self._scan_java()[0].fingerprint

        self._write_java(JAVA_CODE.replace("+ input +", "+ data +"))
        after = self._scan_java()[0].fingerprint

        self.assertNotEqual(before, after)

    def test_repeated_identical_matches_stay_distinguishable(self):
        duplicated = JAVA_CODE.replace(
            '''        st.executeQuery("SELECT * FROM t WHERE x = '" + input + "'");
''',
            '''        st.executeQuery("SELECT * FROM t WHERE x = '" + input + "'");
        st.executeQuery("SELECT * FROM t WHERE x = '" + input + "'");
''',
        )
        self._write_java(duplicated)
        findings = [f for f in self._scan_java() if f.location.line in (6, 7)]

        self.assertEqual(len(findings), 2)
        self.assertNotEqual(findings[0].fingerprint, findings[1].fingerprint)

    def test_config_secret_identity_ignores_line_shift(self):
        config = self.root / "app.properties"
        config.write_text("db.password=SuperSecretValue1\n", encoding="utf-8")
        before = _scan_config(config, self.root)[0].fingerprint

        config.write_text(
            "# 数据源配置\n# 变更说明\n\ndb.password=SuperSecretValue1\n",
            encoding="utf-8",
        )
        after = _scan_config(config, self.root)[0].fingerprint
        self.assertEqual(before, after)

        config.write_text(
            "db.password=SuperSecretValue1\ndb.password=AnotherSecretValue2\n",
            encoding="utf-8",
        )
        two = _scan_config(config, self.root)
        self.assertNotEqual(two[0].fingerprint, two[1].fingerprint)

    def test_semgrep_identity_ignores_line_shift(self):
        runner = SemgrepRunner()
        template = {
            "check_id": "java.demo.rule",
            "path": "src/A.java",
            "start": {"line": 10, "col": 1},
            "extra": {"severity": "WARNING", "message": "m", "lines": "foo(input);", "metadata": {}},
        }
        # 每次 run 都用全新计数器：同一命中换行后序号仍从 0 起，身份不变
        first = runner._convert(template, self.root, {})
        shifted = dict(template, start={"line": 40, "col": 1})
        second = runner._convert(shifted, self.root, {})
        self.assertEqual(first.fingerprint, second.fingerprint)

        changed = dict(template, extra=dict(template["extra"], lines="foo(other);"))
        third = runner._convert(changed, self.root, {})
        self.assertNotEqual(first.fingerprint, third.fingerprint)

        # 同一次扫描内的重复命中仍可区分
        occurrences: dict = {}
        dup_first = runner._convert(template, self.root, occurrences)
        dup_second = runner._convert(template, self.root, occurrences)
        self.assertNotEqual(dup_first.fingerprint, dup_second.fingerprint)

    def test_taint_identity_ignores_line_shift(self):
        code = '''package demo;

public class Demo {
    public void handle(javax.servlet.http.HttpServletRequest req) {
        String input = req.getParameter("q");
        new File("/srv/data/" + input);
    }
}
'''
        self._write_java(code)
        before = run_taint(self.root)[0].fingerprint

        lines = code.splitlines(keepends=True)
        padded = lines[:2] + ["\n", "    // 无关注释\n", *lines[2:]]
        self._write_java("".join(padded))
        after = run_taint(self.root)[0].fingerprint

        self.assertEqual(before, after)

    # ---- 基线二次对齐 ----

    def _baseline_file(self, payload: dict) -> Path:
        path = self.root / "baseline.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    def test_baseline_secondary_alignment_absorbs_line_drift(self):
        finding = Finding(
            "JAL-SQL-001", "SQL", "high", "medium", "CWE-89", "builtin",
            Location("src/A.java", 12), 'st.executeQuery("x" + input)', "d", [], "fix",
            fingerprint="newfp",
        )
        # 旧指纹方案（含行号）+ 行号已漂移 + 文本有空白差异：归一化后仍是同一条
        baseline = self._baseline_file({"findings": [{
            "fingerprint": "oldfp",
            "rule_id": "JAL-SQL-001",
            "location": {"path": "src\\A.java", "line": 10},
            "evidence": 'st.executeQuery("x"  + input)',
        }]})
        result = compare_with_baseline([finding], baseline)

        self.assertEqual(result["existing"], ["newfp"])
        self.assertEqual(result["new"], [])
        self.assertEqual(result["fixed"], [])
        self.assertEqual(result["relocated"], ["newfp"])

    def test_baseline_secondary_alignment_keeps_real_changes(self):
        finding = Finding(
            "JAL-SQL-001", "SQL", "high", "medium", "CWE-89", "builtin",
            Location("src/A.java", 12), 'st.executeQuery("y" + other)', "d", [], "fix",
            fingerprint="newfp",
        )
        baseline = self._baseline_file({"findings": [{
            "fingerprint": "oldfp",
            "rule_id": "JAL-SQL-001",
            "location": {"path": "src/A.java", "line": 10},
            "evidence": 'st.executeQuery("x" + input)',
        }]})
        result = compare_with_baseline([finding], baseline)

        self.assertEqual(result["new"], ["newfp"])
        self.assertEqual(result["fixed"], ["oldfp"])
        self.assertEqual(result["existing"], [])

    def test_baseline_secondary_match_consumes_each_previous_once(self):
        first = Finding(
            "JAL-SQL-001", "SQL", "high", "medium", "CWE-89", "builtin",
            Location("src/A.java", 12), "same text", "d", [], "fix", fingerprint="fp-a",
        )
        second = Finding(
            "JAL-SQL-001", "SQL", "high", "medium", "CWE-89", "builtin",
            Location("src/A.java", 30), "same text", "d", [], "fix", fingerprint="fp-b",
        )
        baseline = self._baseline_file({"findings": [{
            "fingerprint": "oldfp",
            "rule_id": "JAL-SQL-001",
            "location": {"path": "src/A.java", "line": 10},
            "evidence": "same text",
        }]})
        result = compare_with_baseline([first, second], baseline)

        self.assertEqual(len(result["existing"]), 1)
        self.assertEqual(len(result["new"]), 1)
        self.assertNotEqual(result["existing"], result["new"])


if __name__ == "__main__":
    unittest.main()
