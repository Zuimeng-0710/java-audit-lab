package lab.security;

import org.apache.shiro.spring.web.ShiroFilterFactoryBean;

import java.util.LinkedHashMap;
import java.util.Map;

public class ShiroConfig {

    public ShiroFilterFactoryBean shiroFilter() {
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        Map<String, String> chain = new LinkedHashMap<>();
        chain.put("/login", "anon");
        chain.put("/logout", "logout");
        chain.put("/order/**", "authc, roles[admin]");
        chain.put("/report/**", "authc, perms[report:view]");
        bean.setFilterChainDefinitionMap(chain);
        return bean;
    }
}
