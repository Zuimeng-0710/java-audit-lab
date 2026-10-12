package lab.corpus.redirect;

import java.net.URI;
import java.util.Set;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogoutController {

    private static final Set<String> ALLOWED_HOSTS = Set.of("app.example.com", "portal.example.com");

    @GetMapping("/logout2")
    public void logout(@RequestParam String redirect, HttpServletResponse response) throws Exception {
        URI target = URI.create(redirect);
        if (!ALLOWED_HOSTS.contains(target.getHost())) {
            response.sendError(400);
            return;
        }
        sessionService.clear();
        response.sendRedirect("https://app.example.com/sso/callback");
    }
}
