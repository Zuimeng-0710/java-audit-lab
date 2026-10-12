package lab.corpus.crypto;

import java.security.MessageDigest;
import java.util.HexFormat;
import org.springframework.stereotype.Service;

@Service
public class PasswordHashService {

    public String hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        return HexFormat.of().formatHex(digest);
    }
}
