from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from audit.runners.taint import TaintRunner
from audit.taint import analyze_method, run_taint
from audit.findings import assess_path


class TaintAnalysisTests(unittest.TestCase):
    def test_request_parameter_reaches_command_sink(self):
        lines = [
            "public void run(@RequestParam String command) throws Exception {",
            "    String value = command;",
            "    Runtime.getRuntime().exec(value);",
            "}",
        ]
        findings = analyze_method(lines, 1, "Demo.java", "run")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "JAL-CMD-101")
        self.assertEqual(findings[0].location.path, "Demo.java")
        self.assertEqual(findings[0].metadata["taint"]["variable"], "value")
        self.assertTrue(any(step["kind"] == "propagation-candidate" for step in findings[0].trace))
        assess_path(findings[0])
        self.assertEqual(findings[0].metadata["path_assessment"]["conclusion"], "inferred")

    def test_untainted_sink_is_not_reported(self):
        lines = [
            "public void run() throws Exception {",
            '    Runtime.getRuntime().exec("fixed-command");',
            "}",
        ]
        self.assertEqual(analyze_method(lines, 1, "Demo.java", "run"), [])

    def test_sanitizer_is_recorded_as_counterevidence(self):
        lines = [
            "public void open(@RequestParam String path) throws Exception {",
            "    String normalized = Paths.get(path).normalize().toString();",
            "    new File(normalized);",
            "}",
        ]
        findings = analyze_method(lines, 1, "Demo.java", "open")
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any(item.evidence_against for item in findings))
        self.assertTrue(any(item.confidence == "low" for item in findings))

    def test_runner_returns_location_objects(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Demo.java").write_text(
                "public class Demo {\n"
                "  public void run(@RequestParam String command) throws Exception {\n"
                "    Runtime.getRuntime().exec(command);\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )
            findings = run_taint(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].location.path, "Demo.java")
            result = TaintRunner(workers=1).run(root, root)
            self.assertTrue(result.success)
            self.assertEqual(len(result.findings), 1)


if __name__ == "__main__":
    unittest.main()
