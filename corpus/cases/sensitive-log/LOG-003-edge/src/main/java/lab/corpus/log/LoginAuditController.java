package lab.corpus.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginAuditController {

    private static final Logger log = LoggerFactory.getLogger(LoginAuditController.class);

    @PostMapping("/api/token")
    public String issue(@RequestParam String username) {
        String token = tokenService.issue(username);
        log.info("token issued, token={}", mask(token));
        return token;
    }

    private String mask(String value) {
        return value.length() <= 8 ? "****" : value.substring(0, 4) + "****" + value.substring(value.length() - 4);
    }
}
