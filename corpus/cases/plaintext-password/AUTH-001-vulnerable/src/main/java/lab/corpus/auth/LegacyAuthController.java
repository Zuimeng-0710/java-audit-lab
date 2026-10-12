package lab.corpus.auth;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LegacyAuthController {

    @PostMapping("/legacy/login")
    public boolean legacyLogin(@RequestParam String username, @RequestParam String password) {
        String stored = userRepository.findPassword(username);
        return stored.equals(password);
    }
}
