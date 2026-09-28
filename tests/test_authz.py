"""阶段 B 端点与权限矩阵测试。"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from audit.authz import (
    AuthorizationMatrix,
    collect_authorization,
    link_findings_to_endpoints,
)
from audit.findings import Finding, Location

DEMO_ROOT = Path(__file__).resolve().parents[1] / "examples" / "spring-security-demo"


def _endpoint(matrix: AuthorizationMatrix, route: str):
    return next((item for item in matrix.endpoints if item.route == route), None)


class AuthorizationMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = collect_authorization(DEMO_ROOT)

    def test_endpoints_detected_without_class_level_phantoms(self):
        routes = sorted(item.route for item in self.matrix.endpoints)
        self.assertIn("/admin/export", routes)
        self.assertIn("/user/search", routes)
        # 类级 @RequestMapping("/admin") 不应被当成端点
        self.assertNotIn("/admin/admin", routes)
        self.assertNotIn("/user/user", routes)

    def test_pre_authorize_role(self):
        endpoint = _endpoint(self.matrix, "/admin/export")
        self.assertEqual(endpoint.requirement, "role")
        self.assertEqual(endpoint.roles, ["ADMIN"])
        self.assertEqual(endpoint.status, "proven")

    def test_has_any_role_parses_multiple_roles(self):
        endpoint = _endpoint(self.matrix, "/admin/run")
        self.assertEqual(endpoint.roles, ["ADMIN", "OPS"])
        self.assertEqual(endpoint.http_method, "POST")

    def test_secured_and_roles_allowed(self):
        self.assertEqual(_endpoint(self.matrix, "/user/audit").roles, ["ROLE_AUDITOR"])
        self.assertEqual(_endpoint(self.matrix, "/user/list").roles, ["ADMIN", "AUDITOR"])

    def test_shiro_annotations(self):
        self.assertEqual(_endpoint(self.matrix, "/order/delete").requirement, "role")
        self.assertEqual(_endpoint(self.matrix, "/order/delete").roles, ["admin"])
        purge = _endpoint(self.matrix, "/order/purge")
        self.assertEqual(purge.requirement, "permission")
        self.assertEqual(purge.permissions, ["order:purge"])

    def test_ownership_expression(self):
        endpoint = _endpoint(self.matrix, "/user/profile")
        self.assertEqual(endpoint.requirement, "ownership")

    def test_config_rule_fallback_for_unannotated_endpoint(self):
        endpoint = _endpoint(self.matrix, "/admin/config")
        self.assertEqual(endpoint.requirement, "role")
        self.assertEqual(endpoint.roles, ["ADMIN"])
        # 证据里应能看到配置链来源
        self.assertTrue(any(item["kind"] == "spring-security" for item in endpoint.evidence))

    def test_shiro_chain_fallback(self):
        endpoint = _endpoint(self.matrix, "/order/detail")
        self.assertEqual(endpoint.requirement, "role")
        self.assertEqual(endpoint.roles, ["admin"])

    def test_missing_permission_is_reported_not_guessed(self):
        endpoint = _endpoint(self.matrix, "/user/search")
        self.assertEqual(endpoint.requirement, "unknown")
        self.assertEqual(endpoint.status, "missing")

    def test_spring_security_rules_parsed(self):
        rules = [item for item in self.matrix.rules if item["kind"] == "spring-security"]
        patterns = {pattern for item in rules for pattern in item["patterns"]}
        self.assertIn("/admin/**", patterns)
        self.assertTrue(any(item["requirement"] == "anonymous" for item in rules))

    def test_shiro_chain_rules_parsed(self):
        rules = [item for item in self.matrix.rules if item["kind"] == "shiro-chain"]
        self.assertTrue(any(item["patterns"] == ["/login"] and item["requirement"] == "anonymous" for item in rules))
        self.assertTrue(any(item["permissions"] == ["report:view"] for item in rules))


class LinkFindingsTests(unittest.TestCase):
    def test_finding_absorbs_endpoint_authorization(self):
        matrix = collect_authorization(DEMO_ROOT)
        search = _endpoint(matrix, "/user/search")
        finding = Finding(
            rule_id="JAL-SQL-001", title="SQL", severity="high", confidence="medium",
            cwe="CWE-89", scanner="builtin",
            location=Location("src/main/java/lab/security/UserController.java", search.line + 2),
            evidence="e", description="d", review_steps=[], remediation="r",
            metadata={"evidence_record": {"authorization": {"status": "未采集"}}},
        )
        link_findings_to_endpoints([finding], matrix)
        authorization = finding.metadata["authorization"]
        self.assertEqual(authorization["status"], "权限缺失")
        self.assertEqual(authorization["requirement"], "未知")
        self.assertEqual(finding.metadata["evidence_record"]["authorization"]["status"], "权限缺失")
        self.assertEqual(search.finding_count, 1)
        self.assertIn("JAL-SQL-001", search.dangerous_ops)
        # 重算后应识别出"无保护且存在危险操作"的端点
        self.assertEqual(matrix.coverage["unprotected_high_risk"], 1)

    def test_finding_outside_any_endpoint_is_untouched(self):
        matrix = collect_authorization(DEMO_ROOT)
        finding = Finding(
            rule_id="X", title="t", severity="low", confidence="low", cwe="CWE-000",
            scanner="builtin", location=Location("src/main/java/lab/other/Other.java", 5),
            evidence="", description="", review_steps=[], remediation="",
        )
        link_findings_to_endpoints([finding], matrix)
        self.assertNotIn("authorization", finding.metadata)


class NonWebProjectTests(unittest.TestCase):
    def test_plain_java_project_has_no_endpoints(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Demo.java").write_text("class Demo { void run() {} }", encoding="utf-8")
            matrix = collect_authorization(root)
        self.assertEqual(matrix.endpoints, [])
        self.assertEqual(matrix.coverage["endpoints"], 0)


class MvcInterceptorTests(unittest.TestCase):
    """Spring MVC 自定义拦截器（WebMvcConfigurer.addInterceptors）——国内项目最常见写法。"""

    CONFIG = '''
package com.demo.config;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    @Autowired
    private AdminLoginTokenInterceptor adminLoginTokenInterceptor;
    @Autowired
    private AccessLogInterceptor accessLogInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(adminLoginTokenInterceptor)
                .addPathPatterns("/user/**")
                .addPathPatterns("/api/chat/**")
                .excludePathPatterns("/user/login");
        registry.addInterceptor(accessLogInterceptor)
                .addPathPatterns("/**");
    }
}
'''

    CONTROLLER = '''
@RestController
@RequestMapping("/user")
public class UserController {
    @GetMapping("/profile")
    public String profile() { return ""; }

    @PostMapping("/login")
    public String login() { return ""; }
}
'''

    ADMIN = '''
@RestController
@RequestMapping("/admin/employee")
public class EmployeeController {
    @DeleteMapping("/{id}")
    public String delete() { return ""; }
}
'''

    def _build(self, extra: dict[str, str] | None = None):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / "WebMvcConfig.java").write_text(self.CONFIG, encoding="utf-8")
        (root / "UserController.java").write_text(self.CONTROLLER, encoding="utf-8")
        (root / "EmployeeController.java").write_text(self.ADMIN, encoding="utf-8")
        for name, text in (extra or {}).items():
            (root / name).write_text(text, encoding="utf-8")
        return collect_authorization(root)

    def test_interceptor_patterns_become_rules(self):
        matrix = self._build()
        kinds = {rule["kind"] for rule in matrix.rules}
        self.assertIn("mvc-interceptor", kinds)
        patterns = [p for rule in matrix.rules for p in rule["patterns"]]
        self.assertIn("/user/**", patterns)
        self.assertIn("/api/chat/**", patterns)

    def test_log_interceptor_is_not_treated_as_authz(self):
        """日志拦截器覆盖 /**，不能因此把全部端点判成已鉴权。"""
        matrix = self._build()
        for rule in matrix.rules:
            if "/**" in rule.get("patterns", []):
                self.fail("非鉴权拦截器不应生成权限规则")
        delete = _endpoint(matrix, "/admin/employee/{id}")
        self.assertIsNotNone(delete)
        self.assertEqual(delete.status, "missing")

    def test_named_interceptor_without_implementation_is_inferred(self):
        matrix = self._build()
        profile = _endpoint(matrix, "/user/profile")
        self.assertEqual(profile.requirement, "authenticated")
        self.assertEqual(profile.status, "inferred")

    def test_verified_interceptor_implementation_is_proven(self):
        matrix = self._build({"AdminLoginTokenInterceptor.java": '''
public class AdminLoginTokenInterceptor implements HandlerInterceptor {
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String token = request.getHeader("token");
        try { JwtUtil.parseJWT("key", token); return true; }
        catch (Exception ex) { response.setStatus(401); return false; }
    }
}
'''})
        self.assertEqual(_endpoint(matrix, "/user/profile").status, "proven")

    def test_exclude_path_wins_over_include(self):
        matrix = self._build()
        login = _endpoint(matrix, "/user/login")
        self.assertEqual(login.requirement, "anonymous")
        self.assertEqual(login.status, "proven")

    def test_route_without_leading_slash_still_matches(self):
        """类级注解写成 @RequestMapping("user") 时也要能匹配 /user/**。"""
        matrix = self._build({"PlainController.java": '''
@RestController
@RequestMapping("user")
public class PlainController {
    @GetMapping("/list")
    public String list() { return ""; }
}
'''})
        target = next((e for e in matrix.endpoints if e.route.endswith("user/list")), None)
        self.assertIsNotNone(target)
        self.assertEqual(target.requirement, "authenticated")

    def test_role_check_in_interceptor_is_noted_not_overclaimed(self):
        """实现里有角色判断时只补充说明，不擅自把要求升级为具体角色。"""
        matrix = self._build({"AdminLoginTokenInterceptor.java": '''
@Component
public class AdminLoginTokenInterceptor implements HandlerInterceptor {
    public boolean preHandle(HttpServletRequest req, HttpServletResponse resp, Object handler) {
        Integer role = user.getRole();
        if (role == 0) { return false; }
        return true;
    }
}
'''})
        rule = next(r for r in matrix.rules if r["kind"] == "mvc-interceptor")
        self.assertEqual(rule["requirement"], "authenticated")
        self.assertIn("角色判断", rule["detail"])
        self.assertEqual(rule["roles"], [])


if __name__ == "__main__":
    unittest.main()
