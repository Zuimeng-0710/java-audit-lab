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

    def test_spring_param_extraction_supports_generic_types(self):
        # 回归防护：Map<String, String> 泛型中的空格曾让变量名解析成 "String"，
        # @RequestBody 的整个 payload 参数丢失污点标记。
        code = (
            "public class Demo {\n"
            "    public Object search(@RequestBody java.util.Map<String, String> payload) {\n"
            "        String filter = payload.get(\"filter\");\n"
            "        org.springframework.expression.ExpressionParser parser =\n"
            "                new org.springframework.expression.spel.standard.SpelExpressionParser();\n"
            "        return parser.parseExpression(filter);\n"
            "    }\n"
            "}\n"
        )
        findings = [f for f in self._run(code) if f.rule_id == "JAL-EL-101"]
        self.assertTrue(findings, "泛型参数 payload 的污点必须传播到表达式解析")

    def test_spring_param_extraction_does_not_swallow_next_param(self):
        # 回归防护：类型字符类里的逗号曾跨参数吞并，把 @RequestParam 之后的
        # HttpServletResponse response 也错标为污点，导致固定字面量 sendRedirect 误报。
        code = (
            "public class Demo {\n"
            "    public void logout(@RequestParam String redirect, javax.servlet.http.HttpServletResponse response)\n"
            "            throws Exception {\n"
            "        response.sendRedirect(\"https://app.example.com/home\");\n"
            "    }\n"
            "}\n"
        )
        findings = [f for f in self._run(code) if f.rule_id == "JAL-REDIR-101"]
        self.assertFalse(findings, "字面量重定向目标不应因相邻参数被误标污点而报告")

    def test_transferTo_only_reports_as_upload_sink(self):
        # 回归防护：transferTo 曾同时挂在 PATH-101 与 UPLOAD-101 两个 sink 上，
        # 同一行产生双重身份，安全样本被路径规则误报。
        code = (
            "public class Demo {\n"
            "    public String upload(org.springframework.web.multipart.MultipartFile file) throws Exception {\n"
            "        String storedName = java.util.UUID.randomUUID() + \".png\";\n"
            "        java.nio.file.Path target = java.nio.file.Path.of(\"/srv/uploads\", storedName);\n"
            "        file.transferTo(target);\n"
            "        return storedName;\n"
            "    }\n"
            "}\n"
        )
        findings = self._run(code)
        rules = {f.rule_id for f in findings}
        self.assertIn("JAL-UPLOAD-101", rules)
        self.assertNotIn("JAL-PATH-101", rules, "transferTo 不应再作为路径 sink 重复命中")

    def test_http_client_sink_requires_client_receiver(self):
        # 回归防护：.exchange( 曾不限调用者，任意业务方法 exchange(code) 都被当成
        # RestTemplate 出站请求。sink 现在要求 restTemplate/webClient/httpClient/client 前缀。
        code = (
            "public class Demo {\n"
            "    public String callback(javax.servlet.http.HttpServletRequest req) {\n"
            "        String code = req.getParameter(\"code\");\n"
            "        return oauthService.exchange(code);\n"
            "    }\n"
            "}\n"
        )
        findings = [f for f in self._run(code) if f.rule_id == "JAL-SSRF-101"]
        self.assertFalse(findings, "业务方法 exchange 不应被当成 HTTP 客户端出站请求")


class FullyQualifiedUrlRuleTest(unittest.TestCase):
    """行级 SSRF 规则必须识别全限定写法 new java.net.URL(...)。

    第二轮语料扩产（SSRF-103）发现的盲区：真实代码常写全限定类名，
    原 `new\\s+URL` 正则完全漏掉这种形式。
    """

    def test_fully_qualified_url_is_detected(self):
        from audit.runners.builtin import RULES
        rule = next(r for r in RULES if r.rule_id == "JAL-SSRF-001")
        self.assertTrue(rule.pattern.search("java.net.URL u = new java.net.URL(url);"))
        self.assertTrue(rule.pattern.search("URL u = new URL(userUrl);"))
        # 字面量目标仍不应命中（那是 taint 引擎按传播链处理的场景）
        self.assertFalse(rule.pattern.search('URL u = new URL("https://a.example.com");'))


if __name__ == "__main__":
    unittest.main()
