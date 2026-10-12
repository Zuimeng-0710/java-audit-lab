package lab.corpus.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginAuditController {

    private static final Logger log = LoggerFactory.getLogger(LoginAuditController.class);

    @PostMapping("/login")
    public boolean login(@RequestParam String username, @RequestParam String password) {
        boolean ok = authService.verify(username, password);
        if (!ok) {
            log.info("login failed, username={}, password={}", username, password);
        }
        return ok;
    }
}
