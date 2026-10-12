package lab.corpus.crypto;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class PasswordHashService {

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    public String hash(String password) {
        return encoder.encode(password);
    }
}
