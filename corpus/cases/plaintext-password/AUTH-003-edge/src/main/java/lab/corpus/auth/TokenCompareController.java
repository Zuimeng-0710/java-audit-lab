package lab.corpus.auth;

import java.security.MessageDigest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenCompareController {

    @PostMapping("/api/admin")
    public boolean admin(@RequestHeader("X-Admin-Token") String provided) throws Exception {
        String expected = configService.get("admin_token_hash");
        String providedHash = sha256(provided);
        return MessageDigest.isEqual(expected.getBytes(), providedHash.getBytes());
    }
}
