package lab.corpus.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    private static final Logger logger = LoggerFactory.getLogger(LoginController.class);

    private final AuditService auditService;

    public LoginController(AuditService auditService) {
        this.auditService = auditService;
    }

    @PostMapping("/login")
    public String login(@RequestParam String accountId, @RequestParam String token) {
        String outcome = verify(accountId, token);
        auditService.recordLogin(accountId, token);
        return outcome;
    }

    private String verify(String accountId, String token) {
        return "ok";
    }
}
