package lab.corpus.secrets;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * 语料样本（边界）：变量名含 token/password 字样，但值并非凭据本体。
 */
@RestController
public class TokenStyleController {

    private static final String TOKEN_TYPE = "Bearer";

    private static final String PASSWORD_LABEL = "password-field";

    @GetMapping("/api/auth/context")
    public String context(@RequestHeader("Authorization") String authorizationHeader) {
        boolean usesBearer = authorizationHeader != null && authorizationHeader.startsWith(TOKEN_TYPE);
        return "tokenType=" + (usesBearer ? TOKEN_TYPE : "Basic")
                + ", passwordLabel=" + PASSWORD_LABEL;
    }
}
