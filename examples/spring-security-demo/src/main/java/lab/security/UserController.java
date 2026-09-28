package lab.security;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;
import java.sql.Connection;
import java.sql.Statement;

@RestController
@RequestMapping("/user")
public class UserController {

    // 没有任何授权注解，配置链也匹配不到 /user/search → 权限缺失 + SQL 注入
    @GetMapping("/search")
    public void search(Connection connection, String userInput) throws Exception {
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM users WHERE name='" + userInput + "'");
    }

    // 数据归属校验：只能查自己的资料
    @GetMapping("/profile")
    @PreAuthorize("#id == authentication.name")
    public void profile(String id) throws Exception {
        Runtime.getRuntime().exec("cat " + id);
    }

    // JSR-250 注解
    @GetMapping("/list")
    @RolesAllowed({"ADMIN", "AUDITOR"})
    public void list(String keyword) throws Exception {
        Runtime.getRuntime().exec(keyword);
    }

    // Spring @Secured
    @GetMapping("/audit")
    @Secured("ROLE_AUDITOR")
    public void audit(String report) throws Exception {
        Runtime.getRuntime().exec(report);
    }
}
