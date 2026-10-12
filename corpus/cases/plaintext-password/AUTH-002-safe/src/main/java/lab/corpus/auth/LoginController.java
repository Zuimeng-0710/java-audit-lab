package lab.corpus.auth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @PostMapping("/login")
    public boolean login(@RequestParam String username, @RequestParam String password) {
        String storedHash = userRepository.findPasswordHash(username);
        return passwordEncoder.matches(password, storedHash);
    }
}
