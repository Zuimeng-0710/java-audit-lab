package lab.corpus.log;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    private final AuditService auditService;

    public LoginController(AuditService auditService) {
        this.auditService = auditService;
    }

    @PostMapping("/login")
    public String login(@RequestParam String accountId, @RequestParam String token) {
        String outcome = verify(accountId, token);
        auditService.recordLogin(accountId);
        return outcome;
    }

    private String verify(String accountId, String token) {
        return "ok";
    }
}
