# -*- coding: utf-8 -*-
"""污点精度回归测试：字面量去噪、字面量主机反证、净化函数识别。

这些用例全部来自语料评测暴露的真实误报，防止同类回归。
"""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from audit.taint import analyze_method, strip_literals
from audit.runners.taint import TaintRunner


class StripLiteralsTests(unittest.TestCase):
    def test_string_content_is_not_a_variable_reference(self):
        # "?nonce=" 里的 nonce 只是字符串内容，不是变量
        self.assertNotIn("nonce", strip_literals('new URL("https://h.example.com/x?nonce=" + encoded);').replace("encoded", ""))
        self.assertIn("encoded", strip_literals('new URL("https://h.example.com/x?nonce=" + encoded);'))

    def test_line_comment_is_removed(self):
        self.assertNotIn("userInput", strip_literals("int x = 1; // userInput flows here"))

    def test_code_outside_literals_is_kept(self):
        stripped = strip_literals('String sql = "SELECT " + col + " FROM t";')
        self.assertIn("col", stripped)
        self.assertNotIn("SELECT", stripped)


class TaintEvidenceTests(unittest.TestCase):
    def _run(self, code: str) -> list:
        with TemporaryDirectory() as temp:
            java = Path(temp) / "Demo.java"
            java.write_text(code, encoding="utf-8", newline="\n")
            findings = analyze_method(
                java.read_text(encoding="utf-8").splitlines(), 1, "Demo.java", "demo"
            )
        return findings

    def test_literal_host_url_yields_counter_evidence(self):
        code = (
            "public class Demo {\n"
            "    public void check(javax.servlet.http.HttpServletRequest req) throws Exception {\n"
            "        String nonce = req.getParameter(\"nonce\");\n"
            "        String encoded = URLEncoder.encode(nonce, StandardCharsets.UTF_8);\n"
            "        URL target = new URL(\"https://status.example.com/api?nonce=\" + encoded);\n"
            "        target.openStream();\n"
            "    }\n"
            "}\n"
        )
        findings = [f for f in self._run(code) if f.rule_id == "JAL-SSRF-101"]
        self.assertTrue(findings, "污点仍应报告（不断言安全）")
        against = " ".join(note for f in findings for note in f.evidence_against)
        self.assertIn("字面量目标主机", against)
        self.assertTrue(all(f.confidence == "low" for f in findings))

    def test_dynamic_host_url_has_no_counter_evidence(self):
        code = (
            "public class Demo {\n"
            "    public void fetch(javax.servlet.http.HttpServletRequest req) throws Exception {\n"
            "        String userUrl = req.getParameter(\"url\");\n"
            "        URL target = new URL(userUrl);\n"
            "        target.openConnection();\n"
            "    }\n"
            "}\n"
        )
        findings = [f for f in self._run(code) if f.rule_id == "JAL-SSRF-101"]
        self.assertTrue(findings)
        self.assertFalse(any("字面量目标主机" in f.evidence_against for f in findings))

    def test_filename_extraction_yields_counter_evidence(self):
        code = (
            "public class Demo {\n"
            "    public void preview(javax.servlet.http.HttpServletRequest req) {\n"
            "        String reportRef = req.getParameter(\"report\");\n"
            "        String base = FilenameUtils.getName(reportRef);\n"
            "        File preview = new File(\"/srv/app/cache\", base);\n"
            "    }\n"
            "}\n"
        )
        findings = [f for f in self._run(code) if f.rule_id == "JAL-PATH-101"]
        self.assertTrue(findings, "污点仍应报告（不断言安全）")
        against = " ".join(note for f in findings for note in f.evidence_against)
        self.assertIn("文件名剥离", against)

    def test_propagation_survives_lines_without_source(self):
        # 回归防护：传播步骤曾因缩进错误被嵌进 source 循环，
        # 导致「先污染、下一行才到 sink」的两步传播全部失效。
        code = (
            "public class Demo {\n"
            "    public void run(javax.servlet.http.HttpServletRequest req) throws Exception {\n"
            "        String userUrl = req.getParameter(\"url\");\n"
            "        URL target = new URL(userUrl);\n"
            "        target.openConnection();\n"
            "    }\n"
            "}\n"
        )
        findings = self._run(code)
        self.assertEqual(len(findings), 2, "new URL(userUrl) 与 openConnection 都应命中")


if __name__ == "__main__":
    unittest.main()
