package lab.corpus.ldap;

import org.springframework.ldap.support.LdapEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @PostMapping("/login2")
    public boolean login(@RequestParam String username, @RequestParam String password) throws Exception {
        String safeUser = LdapEncoder.filterEncode(username);
        String safePass = LdapEncoder.filterEncode(password);
        return ldapAuthService.authenticate("ou=people,dc=example,dc=com", safeUser, safePass);
    }
}
