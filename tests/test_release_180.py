from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from audit.authz import collect_authorization
from audit.project import source_scope
from audit.runners.builtin import BuiltinRunner
from audit.runners.secrets import SecretsRunner


class Release180Tests(unittest.TestCase):
    def test_config_secret_is_found_without_retaining_value(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            secret = "live-secret-value-123"
            (root / "application.yml").write_text(
                f"service:\n  api-key: {secret}\n  password: ${{DB_PASSWORD}}\n",
                encoding="utf-8",
            )
            result = SecretsRunner().run(root, root)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.evidence, "api-key: <redacted>")
        self.assertNotIn(secret, str(finding.to_dict()))

    def test_ssrf_requires_network_use_not_uri_parsing(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Demo.java").write_text(
                'class Demo { void parse(String fileUrl) { URI uri = URI.create(fileUrl); } '
                'void fetch(String target) throws Exception { new URL(target).openConnection(); } }',
                encoding="utf-8",
            )
            result = BuiltinRunner().run(root, root)
        ssrf = [item for item in result.findings if item.rule_id == "JAL-SSRF-001"]
        self.assertEqual(len(ssrf), 1)
        self.assertIn("openConnection", ssrf[0].evidence)

    def test_sensitive_java_patterns_are_explainable(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Demo.java").write_text(
                'class Demo { void x(String password, Object loginDTO, HttpServletRequest request) {'
                ' if (password.equals(savedPassword)) {} logger.info("login {}", loginDTO);'
                ' request.getParameter(jwtProperties.getAdminTokenName()); } }', encoding="utf-8")
            rules = {item.rule_id for item in BuiltinRunner().run(root, root).findings}
        self.assertTrue({"JAL-AUTH-001", "JAL-LOG-001", "JAL-TOKEN-001"}.issubset(rules))

    def test_configured_public_endpoint_is_explicit(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "LoginController.java").write_text(
                '@RestController class LoginController { @PostMapping("/login") String login(){return "";} }',
                encoding="utf-8",
            )
            matrix = collect_authorization(root, public_patterns=["/login"])
        endpoint = next(item for item in matrix.endpoints if item.route == "/login")
        self.assertEqual(endpoint.requirement, "anonymous")
        self.assertEqual(endpoint.status, "proven")

    def test_source_scope_classification(self):
        self.assertEqual(source_scope("src/main/java/App.java"), "production")
        self.assertEqual(source_scope("src/test/java/AppTest.java"), "test")
        self.assertEqual(source_scope("examples/demo/App.java"), "example")


if __name__ == "__main__":
    unittest.main()
