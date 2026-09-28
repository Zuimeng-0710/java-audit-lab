"""阶段 A 多引擎证据层测试：SARIF 深度解析、Semgrep 数据流、统一证据记录。"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from audit.evidence import build_evidence_record
from audit.findings import Finding, Location, assess_path, consolidate_findings
from audit.importers import parse_sarif
from audit.runners.semgrep import SemgrepRunner


CODEQL_SARIF = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [{
            "id": "java/xss",
            "shortDescription": {"text": "XSS in servlet"},
            "properties": {"security-severity": "9.3", "tags": ["security", "external/cwe/cwe-079"]},
            "relationships": [{"target": {"id": "external/cwe/cwe-079"}, "kinds": ["superset"]}],
            "helpUri": "https://codeql.github.com/",
        }]}},
        "results": [{
            "ruleId": "java/xss",
            "level": "error",
            "message": {"text": "{0} flows to {1} and is not sanitized.", "arguments": ["userInput", "response.getWriter()"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/main/java/Demo.java"}, "region": {"startLine": 12, "startColumn": 9}}}],
            "codeFlows": [{"threadFlows": [{"locations": [
                {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/main/java/Demo.java"}, "region": {"startLine": 8}}, "message": {"text": "request.getParameter"}}},
                {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/main/java/Demo.java"}, "region": {"startLine": 10}}, "message": {"text": "String param"}}},
                {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/main/java/Demo.java"}, "region": {"startLine": 12}}, "message": {"text": "response.getWriter().write"}}},
            ]}]}],
            "relatedLocations": [{"physicalLocation": {"artifactLocation": {"uri": "src/main/java/Demo.java"}, "region": {"startLine": 4}}, "message": {"text": "servlet 入口"}}],
            "suppressions": [{"kind": "inSource", "justification": "@SuppressWarnings"}],
        }],
    }],
}

SEMGREP_JSON_RESULT = {
    "check_id": "java.lang.security.audit.sqli",
    "path": "src/main/java/Demo.java",
    "start": {"line": 30, "col": 20},
    "extra": {
        "message": "User data flows into query",
        "severity": "ERROR",
        "lines": "stmt.executeQuery(userInput);",
        "metadata": {"cwe": ["CWE-89: SQL Injection"], "confidence": "HIGH"},
        "dataflow_trace": {
            "taint_source": {"location": {"path": "src/main/java/Demo.java", "start": {"line": 22}}, "content": "request.getParameter(\"id\")"},
            "intermediate_vars": [{"location": {"path": "src/main/java/Demo.java", "start": {"line": 26}}, "content": "String id"}],
            "taint_sink": {"location": {"path": "src/main/java/Demo.java", "start": {"line": 30}}, "content": "executeQuery"},
        },
    },
}


class SarifImportTests(unittest.TestCase):
    def test_codeql_sarif_full_pipeline(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src/main/java").mkdir(parents=True)
            (root / "src/main/java/Demo.java").write_text("class Demo {}", encoding="utf-8")
            sarif_path = root / "codeql.sarif"
            sarif_path.write_text(json.dumps(CODEQL_SARIF), encoding="utf-8")
            findings = parse_sarif(sarif_path, root)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.scanner, "CodeQL")
        self.assertEqual(finding.severity, "critical")  # security-severity 9.3
        self.assertEqual(finding.cwe, "CWE-79")  # relationships / tags
        self.assertIn("userInput", finding.description)  # arguments 插值
        self.assertIn("response.getWriter()", finding.description)
        self.assertEqual(len(finding.trace), 4)  # 3 flow + 1 related
        self.assertEqual(finding.trace[3]["kind"], "related")
        self.assertEqual(finding.evidence_against, ["引擎报告抑制（inSource）：@SuppressWarnings"])
        self.assertEqual(finding.metadata["help_uri"], "https://codeql.github.com/")
        assess_path(finding)
        self.assertEqual(finding.metadata["path_assessment"]["conclusion"], "proven")

    def test_codeql_security_severity_bands(self):
        bands = {"9.3": "critical", "7.5": "high", "5.0": "medium", "2.1": "low", "0.5": "info"}
        for score, expected in bands.items():
            payload = json.loads(json.dumps(CODEQL_SARIF))
            payload["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] = score
            with TemporaryDirectory() as temp:
                root = Path(temp)
                path = root / "s.sarif"
                path.write_text(json.dumps(payload), encoding="utf-8")
                finding = parse_sarif(path, root)[0]
            self.assertEqual(finding.severity, expected, f"security-severity {score} 应为 {expected}")

    def test_cwe_from_relationships_only(self):
        payload = json.loads(json.dumps(CODEQL_SARIF))
        rule = payload["runs"][0]["tool"]["driver"]["rules"][0]
        rule["properties"] = {"security-severity": "8.0"}
        rule.pop("tags", None)
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "s.sarif"
            path.write_text(json.dumps(payload), encoding="utf-8")
            finding = parse_sarif(path, root)[0]
        self.assertEqual(finding.cwe, "CWE-79")


class SemgrepDataflowTests(unittest.TestCase):
    def test_dataflow_trace_becomes_proven_path(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            finding = SemgrepRunner()._convert(SEMGREP_JSON_RESULT, root)
        self.assertEqual(finding.cwe, "CWE-89")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.confidence, "high")
        self.assertEqual(len(finding.trace), 3)
        self.assertEqual(finding.trace[0]["label"], "污点源：request.getParameter(\"id\")")
        self.assertEqual(finding.trace[1]["kind"], "flow")
        self.assertEqual(finding.trace[2]["kind"], "sink")
        self.assertEqual(finding.metadata["engine_evidence"], "semgrep-pro")
        assess_path(finding)
        self.assertEqual(finding.metadata["path_assessment"]["conclusion"], "proven")

    def test_oss_semgrep_without_trace(self):
        item = json.loads(json.dumps(SEMGREP_JSON_RESULT))
        item["extra"].pop("dataflow_trace")
        with TemporaryDirectory() as temp:
            root = Path(temp)
            finding = SemgrepRunner()._convert(item, root)
        self.assertEqual(finding.trace, [])
        self.assertEqual(finding.metadata["engine_evidence"], "semgrep-oss")


class EvidenceRecordTests(unittest.TestCase):
    def _prepared(self):
        finding = Finding(
            rule_id="java/xss", title="XSS", severity="high", confidence="high",
            cwe="CWE-79", scanner="CodeQL",
            location=Location("src/main/java/Demo.java", 12),
            evidence="e", description="d", review_steps=[], remediation="r",
            trace=[
                {"kind": "source-candidate", "path": "src/main/java/Demo.java", "line": 8, "label": "request.getParameter"},
                {"kind": "flow", "path": "src/main/java/Demo.java", "line": 10, "label": "param"},
                {"kind": "sink", "path": "src/main/java/Demo.java", "line": 12, "label": "write"},
            ],
            evidence_against=["引擎报告抑制（inSource）"],
            metadata={
                "entry_coverage": True,
                "suppressions": [{"kind": "inSource", "justification": "@SuppressWarnings"}],
                "corroboration": [
                    {"scanner": "builtin", "rule_id": "JAL-XSS-001", "line": 12, "evidence": "write(userInput)"},
                ],
            },
        )
        assess_path(finding)
        return finding

    def test_record_structure_matches_blueprint(self):
        record = build_evidence_record(self._prepared())
        self.assertEqual(record["entry"]["covered"], True)
        self.assertEqual(record["source"]["line"], 8)
        self.assertEqual(len(record["propagation"]), 1)
        self.assertEqual(record["sink"]["kind"], "sink")
        self.assertEqual(record["sink"]["line"], 12)
        self.assertEqual(len(record["sanitizers"]), 1)
        self.assertEqual(record["sanitizers"][0]["origin"], "sarif-suppression")
        self.assertEqual(record["authorization"]["status"], "未采集")
        self.assertEqual(len(record["engine_evidence"]), 1)
        self.assertEqual(record["engine_evidence"][0]["scanner"], "builtin")
        self.assertEqual(record["path_conclusion"], "引擎已证明")  # trace 含 flow 步骤

    def test_record_missing_evidence_is_honest(self):
        finding = Finding(
            rule_id="r", title="t", severity="low", confidence="low", cwe="CWE-Unknown",
            scanner="builtin", location=Location("A.java", 1),
            evidence="", description="", review_steps=[], remediation="",
        )
        assess_path(finding)
        record = build_evidence_record(finding)
        self.assertEqual(record["source"]["kind"], "missing")
        self.assertEqual(record["sink"]["kind"], "rule-hit")
        self.assertEqual(record["entry"]["covered"], False)
        self.assertEqual(record["engine_evidence"], [])
        self.assertEqual(record["path_conclusion"], "路径缺失")

    def test_unresolved_dynamic_call_recorded(self):
        finding = Finding(
            rule_id="r", title="t", severity="medium", confidence="medium", cwe="CWE-78",
            scanner="builtin", location=Location("A.java", 3),
            evidence="", description="", review_steps=[], remediation="",
            metadata={"dynamic_call_on_path": True},
        )
        assess_path(finding)
        record = build_evidence_record(finding)
        self.assertEqual(record["path_conclusion"], "存在未解析调用")
        self.assertTrue(record["unresolved_steps"])

    def test_cross_engine_merge_feeds_record(self):
        codeql = Finding(
            rule_id="java/xss", title="XSS", severity="critical", confidence="high",
            cwe="CWE-79", scanner="CodeQL", location=Location("src/main/java/Demo.java", 12),
            evidence="a", description="a", review_steps=[], remediation="a",
            trace=[{"kind": "flow", "path": "src/main/java/Demo.java", "line": 9, "label": "flow"}],
        )
        builtin = Finding(
            rule_id="JAL-XSS-001", title="XSS", severity="medium", confidence="medium",
            cwe="CWE-79", scanner="builtin", location=Location("src/main/java/Demo.java", 13),
            evidence="b", description="b", review_steps=[], remediation="b",
        )
        merged = consolidate_findings([codeql, builtin])
        self.assertEqual(len(merged), 1)
        primary = merged[0]
        assess_path(primary)
        record = build_evidence_record(primary)
        self.assertEqual(sorted(record["engine_evidence"][0]["scanner"] for _ in [0]), ["CodeQL"])
        self.assertTrue(len(primary.metadata["scanners"]) >= 2)
        self.assertEqual(record["path_conclusion"], "引擎已证明")


if __name__ == "__main__":
    unittest.main()
