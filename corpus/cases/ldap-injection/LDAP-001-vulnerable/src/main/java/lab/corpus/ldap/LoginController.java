package lab.corpus.ldap;

import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.directory.InitialDirContext;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @PostMapping("/login")
    public boolean login(@RequestParam String username, @RequestParam String password) throws Exception {
        DirContext ctx = new InitialDirContext();
        String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
        NamingEnumeration<SearchResult> results =
                ctx.search("ou=people,dc=example,dc=com", filter, new SearchControls());
        return results.hasMore();
    }
}
