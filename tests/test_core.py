from pathlib import Path
from tempfile import TemporaryDirectory
import io
import re
import shutil
import subprocess
import unittest
from unittest.mock import patch

from audit.project import detect_project
from audit.importers import parse_dependency_check_json, parse_sarif, parse_spotbugs_xml, write_sarif
from audit.baseline import compare_with_baseline, load_reviews
from audit.cache import project_digest
from audit.cli import _doctor
from audit.config import discover_config, load_config
from audit.findings import Finding, Location, assess_path, consolidate_findings, generalize_findings
from audit.benchmark import run_benchmark
from audit.playbook import evaluate_playbook
from audit.report import write_reports
from audit.runners.builtin import BuiltinRunner, load_extra_rules
from audit.surface import collect_surface


class CoreTests(unittest.TestCase):
    def test_detects_maven_project_and_java_files(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "pom.xml").write_text("<project/>", encoding="utf-8")
            source = root / "src/main/java/Demo.java"
            source.parent.mkdir(parents=True)
            source.write_text("class Demo {}", encoding="utf-8")
            info = detect_project(root)
            self.assertEqual(info.build_system, "maven")
            self.assertEqual(info.java_files, 1)

    def test_builtin_finding_contains_review_evidence(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "Demo.java"
            source.write_text('class Demo { void x(String userInput) throws Exception { Runtime.getRuntime().exec(userInput); } }', encoding="utf-8")
            result = BuiltinRunner().run(root, root)
            self.assertTrue(result.success)
            self.assertEqual(result.findings[0].cwe, "CWE-78")
            self.assertTrue(result.findings[0].review_steps)
            self.assertIn("exec", result.findings[0].evidence)

    def test_report_contains_review_controls(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Demo.java").write_text('class Demo { String password = "secret-value"; }', encoding="utf-8")
            info = detect_project(root)
            result = BuiltinRunner().run(root, root)
            _, html_path, md_path = write_reports(root / "report", info, result.findings, [result])
            page = html_path.read_text(encoding="utf-8")
            self.assertIn("确认漏洞", page)
            self.assertIn("误报", page)
            self.assertIn("审计阶段 · Evidence Driven Playbook", page)
            self.assertIn("漏洞成立五问", page)
            self.assertIn(".page{width:100%;max-width:none", page)
            self.assertIn("text-overflow:ellipsis", page)
            self.assertIn("@media(max-width:760px)", page)
            markdown = md_path.read_text(encoding="utf-8")
            self.assertIn("待人工确认项", markdown)
            self.assertIn("授权状态：由使用者自行确认", markdown)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for JavaScript syntax validation")
    def test_report_inline_javascript_is_valid(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Demo.java").write_text('class Demo { String password = "secret-value"; }', encoding="utf-8")
            info = detect_project(root)
            result = BuiltinRunner().run(root, root)
            _, html_path, _ = write_reports(root / "report", info, result.findings, [result])
            page = html_path.read_text(encoding="utf-8")
            scripts = re.findall(r"<script>(.*?)</script>", page, re.S)
            script_path = root / "report-inline.js"
            script_path.write_text("\n".join(scripts), encoding="utf-8")
            checked = subprocess.run(
                [shutil.which("node"), "--check", str(script_path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_doctor_output_is_gbk_safe(self):
        output = io.BytesIO()
        stream = io.TextIOWrapper(output, encoding="gbk")
        with patch("sys.stdout", stream):
            self.assertEqual(_doctor(), 0)
        stream.flush()
        self.assertIn("Java Audit Lab", output.getvalue().decode("gbk"))

    def test_external_rules_and_settings_invalidate_cache(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Demo.java").write_text("class Demo {}", encoding="utf-8")
            rules = root / "rules.yaml"
            rules.write_text("- id: EXT-1\n  pattern: demoOne\n", encoding="utf-8")
            loaded = load_extra_rules([str(rules)])
            self.assertEqual(loaded[-1].rule_id, "EXT-1")
            first = project_digest(root, "builtin", "1", settings="a", extra_paths=[rules])
            rules.write_text("- id: EXT-2\n  pattern: demoTwo\n", encoding="utf-8")
            second = project_digest(root, "builtin", "1", settings="a", extra_paths=[rules])
            third = project_digest(root, "builtin", "1", settings="b", extra_paths=[rules])
            self.assertNotEqual(first, second)
            self.assertNotEqual(second, third)

    def test_detects_uppercase_secret_name(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Demo.java").write_text('class Demo { String API_KEY = "secret-value"; }', encoding="utf-8")
            result = BuiltinRunner().run(root, root)
            self.assertEqual([item.cwe for item in result.findings], ["CWE-798"])

    def test_sarif_round_trip_preserves_finding(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Demo.java").write_text('class Demo { String password = "secret-value"; }', encoding="utf-8")
            original = BuiltinRunner().run(root, root).findings
            sarif = write_sarif(root / "result.sarif", original)
            imported = parse_sarif(sarif, root)
            self.assertEqual(imported[0].rule_id, original[0].rule_id)
            self.assertEqual(imported[0].location.path, "Demo.java")

    def test_parses_spotbugs_xml(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            report = root / "spotbugs.xml"
            report.write_text('''<BugCollection><BugInstance type="SQL_INJECTION_JDBC" rank="8" category="SECURITY"><ShortMessage>SQL injection</ShortMessage><LongMessage>Unsafe SQL</LongMessage><SourceLine sourcepath="src/Demo.java" start="12"/></BugInstance></BugCollection>''', encoding="utf-8")
            items = parse_spotbugs_xml(report, root)
            self.assertEqual(items[0].cwe, "CWE-89")
            self.assertEqual(items[0].location.line, 12)

    def test_parses_windows_spotbugs_gbk_and_resolves_source_root(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "src/main/java/lab/Demo.java"
            source.parent.mkdir(parents=True)
            source.write_text("class Demo {}", encoding="utf-8")
            report = root / "spotbugs.xml"
            xml = '''<?xml version="1.0" encoding="gbk"?><BugCollection><BugInstance type="SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE" cweid="89" rank="10"><LongMessage>中文 SQL 风险</LongMessage><SourceLine sourcepath="lab/Demo.java" start="9" primary="true"/></BugInstance></BugCollection>'''
            report.write_bytes(xml.encode("gbk"))
            item = parse_spotbugs_xml(report, root)[0]
            self.assertEqual(item.location.path, "src/main/java/lab/Demo.java")
            self.assertEqual(item.cwe, "CWE-89")

    def test_parses_dependency_check_json(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            report = root / "dependency.json"
            report.write_text('{"dependencies":[{"fileName":"demo.jar","vulnerabilities":[{"name":"CVE-2099-0001","severity":"HIGH","cwes":["CWE-79"],"description":"demo"}]}]}', encoding="utf-8")
            items = parse_dependency_check_json(report, root)
            self.assertEqual(items[0].rule_id, "CVE-2099-0001")
            self.assertEqual(items[0].severity, "high")

    def test_new_java_rule_families(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Demo.java").write_text('''class Demo { void x(String url, String expression) throws Exception { new java.net.URL(url).openConnection(); parser.parseExpression(expression); java.security.MessageDigest.getInstance("MD5"); input.readObject(); } }''', encoding="utf-8")
            cwes = {item.cwe for item in BuiltinRunner().run(root, root).findings}
            self.assertTrue({"CWE-918", "CWE-917", "CWE-327", "CWE-502"}.issubset(cwes))

    def test_baseline_and_review_import(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Demo.java").write_text('class Demo { String API_KEY = "secret-value"; }', encoding="utf-8")
            findings = BuiltinRunner().run(root, root).findings
            baseline = root / "baseline.json"
            baseline.write_text('{"findings": []}', encoding="utf-8")
            comparison = compare_with_baseline(findings, baseline)
            self.assertEqual(len(comparison["new"]), 1)
            review = root / "review.json"
            review.write_text('{"reviews":{"abc":{"verdict":"confirmed"}}}', encoding="utf-8")
            self.assertEqual(load_reviews(review)["abc"]["verdict"], "confirmed")

    def test_detects_frameworks_from_maven_manifest(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "pom.xml").write_text('<artifactId>spring-boot-starter-security</artifactId><artifactId>mybatis</artifactId>', encoding="utf-8")
            info = detect_project(root)
            self.assertIn("Spring Boot", info.frameworks)
            self.assertIn("Spring Security", info.frameworks)
            self.assertIn("MyBatis", info.frameworks)

    def test_semantic_consolidation_keeps_corroboration(self):
        first = Finding("rule-a", "SQL", "high", "medium", "CWE-89", "semgrep", Location("A.java", 10), "a", "a", [], "fix", fingerprint="a")
        second = Finding("rule-b", "SQL", "high", "high", "CWE-89", "codeql", Location("A.java", 12), "b", "b", [], "fix", fingerprint="b", trace=[{"kind": "sink", "line": 12}])
        merged = consolidate_findings([first, second])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].metadata["scanners"], ["codeql", "semgrep"])
        self.assertGreater(merged[0].review_priority, 50)
        self.assertTrue(merged[0].priority_factors)

    def test_loads_simple_yaml_config(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / ".java-audit.yml"
            path.write_text("scanners:\n  - builtin\nfail_on: high\ncache: false\n", encoding="utf-8")
            config = load_config(path)
            self.assertEqual(config["scanners"], ["builtin"])
            self.assertEqual(config["fail_on"], "high")
            self.assertFalse(config["cache"])

    def test_rejects_missing_explicit_config_and_invalid_list_fields(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(FileNotFoundError):
                discover_config(root, str(root / "missing.yml"))
            config_path = root / ".java-audit.yml"
            config_path.write_text("exclude_paths: src/test/*\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exclude_paths"):
                load_config(config_path)

    def test_packaged_benchmark_passes(self):
        manifest = Path(__file__).resolve().parents[1] / "audit" / "benchmarks" / "manifest.json"
        result = run_benchmark(manifest)
        self.assertEqual(result["precision"], 1.0)
        self.assertEqual(result["recall"], 1.0)
        self.assertTrue(all(case["passed"] for case in result["cases"]))


class PlaybookTests(unittest.TestCase):
    def test_collects_spring_surface_and_controls(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "src/main/java/DemoController.java"
            source.parent.mkdir(parents=True)
            source.write_text('''import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api")
public class DemoController {
    @GetMapping("/users")
    public String find(@RequestParam String name) { return name; }
}''', encoding="utf-8")
            safe = root / "src/main/java/Guarded.java"
            safe.write_text("class Guarded { ObjectInputFilter filter; }", encoding="utf-8")
            surface = collect_surface(root)
            kinds = {entry.kind for entry in surface.entries}
            self.assertIn("controller", kinds)
            self.assertIn("request-source", kinds)
            routes = [entry for entry in surface.entries if entry.kind == "controller" and entry.route]
            self.assertTrue(any(entry.route == "/api/users" for entry in routes))
            self.assertTrue(any(control.kind == "deserialization-filter" for control in surface.controls))

    def test_path_assessment_classifies_evidence_levels(self):
        proven = Finding("r", "t", "high", "high", "CWE-89", "codeql", Location("A.java", 5), "e", "d", [], "fix",
                         trace=[{"kind": "flow", "line": 2}, {"kind": "sink", "line": 5}])
        assess_path(proven)
        self.assertEqual(proven.metadata["path_assessment"]["conclusion"], "proven")
        inferred = Finding("r", "t", "high", "low", "CWE-89", "builtin", Location("A.java", 5), "e", "d", [], "fix",
                           trace=[{"kind": "source-candidate", "line": 2}, {"kind": "sink", "line": 5}])
        assess_path(inferred)
        self.assertEqual(inferred.metadata["path_assessment"]["conclusion"], "inferred")
        missing = Finding("r", "t", "high", "low", "CWE-89", "builtin", Location("A.java", 5), "e", "d", [], "fix")
        assess_path(missing)
        self.assertEqual(missing.metadata["path_assessment"]["conclusion"], "missing")
        unresolved = Finding("r", "t", "high", "low", "CWE-89", "builtin", Location("A.java", 5), "e", "d", [], "fix",
                             metadata={"dynamic_call_on_path": True})
        assess_path(unresolved)
        self.assertEqual(unresolved.metadata["path_assessment"]["conclusion"], "unresolved")

    def test_generalization_finds_sibling_locations(self):
        findings = [
            Finding("JAL-SQL-001", "SQL", "high", "medium", "CWE-89", "builtin", Location("A.java", 10), "e", "d", [], "fix", fingerprint="a"),
            Finding("JAL-SQL-001", "SQL", "high", "medium", "CWE-89", "builtin", Location("B.java", 30), "e", "d", [], "fix", fingerprint="b"),
        ]
        generalize_findings(findings)
        self.assertEqual(findings[0].metadata["generalization"]["same_rule_count"], 1)
        self.assertEqual(findings[0].metadata["generalization"]["same_rule"][0]["path"], "B.java")

    def test_playbook_reports_stage_progress(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Demo.java").write_text('class Demo { String password = "secret-value"; }', encoding="utf-8")
            project = detect_project(root)
            result = BuiltinRunner().run(root, root)
            surface = collect_surface(root)
            findings = consolidate_findings(result.findings)
            for finding in findings:
                assess_path(finding)
            generalize_findings(findings)
            playbook = evaluate_playbook(project, surface, [result], findings, {}, {"enabled": False, "new": [], "existing": [], "fixed": []}, ["JSON", "Markdown"])
            stages = {stage["id"]: stage for stage in playbook["stages"]}
            self.assertEqual(stages["profile"]["status"], "partial")
            self.assertEqual(stages["generalize"]["status"], "completed")
            self.assertEqual(stages["conclude"]["status"], "partial")
            self.assertEqual(playbook["progress"]["total"], 9)


if __name__ == "__main__":
    unittest.main()
