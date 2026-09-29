from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest


REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "corpus"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


evaluator = _load("corpus_evaluator", CORPUS / "tools" / "evaluate_corpus.py")
validator = _load("corpus_validator", CORPUS / "tools" / "validate_corpus.py")


class CorpusTests(unittest.TestCase):
    def _single_case(self, source: Path) -> tuple[TemporaryDirectory, Path, Path]:
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        target = root / "cases" / source.parent.name / source.name
        target.parent.mkdir(parents=True)
        shutil.copytree(source, target)
        expected = json.loads((target / "expected.json").read_text(encoding="utf-8"))
        manifest = {
            "version": "test", "split": "train", "scanners": ["builtin"],
            "cases": [{
                "case_id": expected["case_id"], "category": expected["category"],
                "expected": expected["expected"], "variant": source.name.rsplit("-", 1)[-1],
                "path": target.relative_to(root).as_posix(),
            }],
        }
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return temp, root, target

    def test_pilot_corpus_passes_strict_evaluation(self):
        result = evaluator.evaluate(CORPUS, strict_locations=True)
        self.assertEqual(result["totals"], {"cases": 12, "TP": 4, "FP": 0, "FN": 0, "TN": 8, "UNSCORED": 0})
        self.assertFalse(evaluator.should_fail(result, "any", True))

    def test_every_expected_rule_is_required(self):
        _, root, case = self._single_case(CORPUS / "cases" / "sql-injection" / "SQL-001-vulnerable")
        path = case / "expected.json"
        expected = json.loads(path.read_text(encoding="utf-8"))
        expected["expected_rules"].append("JAL-PATH-001")
        path.write_text(json.dumps(expected), encoding="utf-8")
        result = evaluator.evaluate(root, strict_locations=True)
        self.assertEqual(result["totals"]["FN"], 1)
        self.assertEqual(result["cases"][0]["missing_rules"], ["JAL-PATH-001"])
        self.assertTrue(evaluator.should_fail(result, "any", True))

    def test_safe_case_extra_finding_is_false_positive(self):
        _, root, case = self._single_case(CORPUS / "cases" / "sql-injection" / "SQL-002-safe")
        java = next(case.rglob("*.java"))
        java.write_text(java.read_text(encoding="utf-8") + '\nclass Extra { String password = "CORPUS_FAKE_SECRET_123"; }\n', encoding="utf-8")
        result = evaluator.evaluate(root, strict_locations=False)
        self.assertEqual(result["totals"]["FP"], 1)
        self.assertIn("JAL-SECRET-001", result["cases"][0]["unexpected_rules"])

    def test_strict_location_miss_fails(self):
        _, root, case = self._single_case(CORPUS / "cases" / "sql-injection" / "SQL-001-vulnerable")
        path = case / "expected.json"
        expected = json.loads(path.read_text(encoding="utf-8"))
        expected["expected_locations"][0]["line"] = 1
        path.write_text(json.dumps(expected), encoding="utf-8")
        result = evaluator.evaluate(root, strict_locations=True)
        self.assertTrue(result["cases"][0]["location_misses"])
        self.assertTrue(evaluator.should_fail(result, "any", True))

    def test_hygiene_error_never_echoes_secret(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            secret = "sk-this-is-a-realistic-looking-secret-123456"
            (root / ".env").write_text(f"API_KEY={secret}\n", encoding="utf-8")
            errors: list[str] = []
            validator.hygiene_scan(root, errors, label_root=root)
        self.assertTrue(errors)
        self.assertNotIn(secret, " ".join(errors))
        self.assertIn("内容已隐藏", errors[0])


if __name__ == "__main__":
    unittest.main()
