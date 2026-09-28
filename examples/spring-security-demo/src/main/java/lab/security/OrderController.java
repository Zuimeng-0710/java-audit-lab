package lab.security;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/order")
public class OrderController {

    // Shiro 角色注解 + 命令注入
    @GetMapping("/delete")
    @RequiresRoles("admin")
    public void delete(String orderId) throws Exception {
        Runtime.getRuntime().exec("rm -rf " + orderId);
    }

    // Shiro 权限注解
    @DeleteMapping("/purge")
    @RequiresPermissions("order:purge")
    public void purge(String day) throws Exception {
        Runtime.getRuntime().exec("sh /opt/purge.sh " + day);
    }

    // 只有过滤链 /order/** authc,roles[admin] 覆盖
    @GetMapping("/detail")
    public void detail(String orderId) throws Exception {
        Runtime.getRuntime().exec("cat /data/" + orderId);
    }
}
