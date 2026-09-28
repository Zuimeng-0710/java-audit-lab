package lab.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;

@RestController
@RequestMapping("/admin")
public class AdminController {

    // 方法级注解优先于配置：需 ADMIN 角色，且内部有路径遍历
    @GetMapping("/export")
    @PreAuthorize("hasRole('ADMIN')")
    public File export(String fileName) {
        return new File("uploads/" + fileName);
    }

    // 多个角色任一即可
    @PostMapping("/run")
    @PreAuthorize("hasAnyRole('ADMIN','OPS')")
    public void run(String command) throws Exception {
        Runtime.getRuntime().exec(command);
    }

    // 无方法级注解，靠配置链 /admin/** hasRole ADMIN 命中
    @GetMapping("/config")
    public void config(String target) throws Exception {
        Runtime.getRuntime().exec(target);
    }
}
